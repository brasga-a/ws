//! Length-prefixed deterministic binary wire codec for [`IpcRequest`] and [`IpcResponse`].

use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use bit_core::{
    AmbiguousCaseError, ApplyAction, ApplyConflict, ApplyConflictKind, ApplyOutput, ApplyPlan,
    BaseId, BaseInfo, BaseSelector, ContentHash, CoreError, DiffChange, DiffEntry, EntryName,
    HexDigestError, IdError, ModelError, NodeKind, PathError, RelPath, RemoveBaseOutput,
    StoreError, TagName, Timestamp, TreeEntry, ViewId, ViewInfo,
};

use crate::message::{
    DaemonStatus, FreezeSummary, IpcRequest, IpcResponse, RemoteError, ViewSummary,
};
use crate::transport::IpcError;

/// 4-byte wire magic prefix identifying Bit IPC frames (version 1).
pub const FRAME_MAGIC: [u8; 4] = *b"BIT1";

/// Maximum permitted payload length for a single IPC frame (64 MiB).
pub const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

/// Maximum collection element count accepted when decoding untrusted/corrupt frames.
const MAX_COLLECTION_LEN: usize = 4 * 1024 * 1024;

/// Wire serialization / deserialization error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// Frame header did not start with [`FRAME_MAGIC`].
    InvalidMagic([u8; 4]),
    /// Frame length exceeded [`MAX_FRAME_LEN`].
    FrameTooLarge(usize),
    /// Payload ended before expected field bytes were read.
    UnexpectedEof,
    /// Unrecognized enum discriminant tag.
    UnknownTag { context: &'static str, tag: u8 },
    /// String field was not valid UTF-8.
    InvalidUtf8,
    /// Domain validation rejected a decoded value.
    InvalidDomainValue(String),
    /// Unconsumed trailing bytes remained after decoding a complete message.
    TrailingBytes(usize),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic(got) => write!(f, "invalid IPC frame magic: {got:?}"),
            Self::FrameTooLarge(len) => {
                write!(f, "IPC frame length {len} exceeds maximum {MAX_FRAME_LEN}")
            }
            Self::UnexpectedEof => f.write_str("unexpected end of IPC frame payload"),
            Self::UnknownTag { context, tag } => {
                write!(f, "unknown wire tag 0x{tag:02x} while decoding {context}")
            }
            Self::InvalidUtf8 => f.write_str("invalid UTF-8 in IPC string field"),
            Self::InvalidDomainValue(msg) => write!(f, "invalid domain value in IPC frame: {msg}"),
            Self::TrailingBytes(rem) => {
                write!(f, "unexpected {rem} trailing byte(s) in IPC frame")
            }
        }
    }
}

impl std::error::Error for CodecError {}

/// Writes a length-prefixed frame (`FRAME_MAGIC` + big-endian `u32` length + `payload`).
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), IpcError> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(IpcError::Codec(CodecError::FrameTooLarge(payload.len())));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| IpcError::Codec(CodecError::FrameTooLarge(payload.len())))?;
    let mut header = [0u8; 8];
    header[..4].copy_from_slice(&FRAME_MAGIC);
    header[4..8].copy_from_slice(&len.to_be_bytes());
    writer.write_all(&header)?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

/// Reads the next length-prefixed frame, returning `Ok(None)` if `reader` reaches clean EOF
/// before the first header byte.
pub fn read_frame_opt<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, IpcError> {
    let mut first = [0u8; 1];
    if !read_exact_or_eof(reader, &mut first)? {
        return Ok(None);
    }
    let mut rest_header = [0u8; 7];
    reader.read_exact(&mut rest_header).map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            IpcError::Codec(CodecError::UnexpectedEof)
        } else {
            IpcError::from(err)
        }
    })?;

    let magic = [first[0], rest_header[0], rest_header[1], rest_header[2]];
    if magic != FRAME_MAGIC {
        return Err(IpcError::Codec(CodecError::InvalidMagic(magic)));
    }
    let len = u32::from_be_bytes([
        rest_header[3],
        rest_header[4],
        rest_header[5],
        rest_header[6],
    ]) as usize;
    if len > MAX_FRAME_LEN {
        return Err(IpcError::Codec(CodecError::FrameTooLarge(len)));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            IpcError::Codec(CodecError::UnexpectedEof)
        } else {
            IpcError::from(err)
        }
    })?;
    Ok(Some(payload))
}

/// Reads the next length-prefixed frame, returning [`IpcError::ConnectionClosed`] on clean EOF.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, IpcError> {
    read_frame_opt(reader)?.ok_or(IpcError::ConnectionClosed)
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8; 1]) -> Result<bool, IpcError> {
    loop {
        match reader.read(buf) {
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(true),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(IpcError::from(err)),
        }
    }
}

/// Encodes an [`IpcRequest`] into a deterministic payload byte vector.
pub fn encode_request(req: &IpcRequest) -> Vec<u8> {
    let mut w = WireWriter::new();
    match req {
        IpcRequest::Ping => w.write_u8(1),
        IpcRequest::Status => w.write_u8(2),
        IpcRequest::Shutdown => w.write_u8(3),
        IpcRequest::CreateBase { dir, tag, excludes } => {
            w.write_u8(4);
            w.write_path(dir);
            w.write_opt(tag.as_ref(), |w, t| w.write_tag_name(t));
            w.write_slice(excludes, |w, pat| w.write_str(pat));
        }
        IpcRequest::ListBases => w.write_u8(5),
        IpcRequest::SetTag { tag, base } => {
            w.write_u8(6);
            w.write_tag_name(tag);
            w.write_base_selector(base);
        }
        IpcRequest::DeleteTag { tag } => {
            w.write_u8(7);
            w.write_tag_name(tag);
        }
        IpcRequest::RemoveBase { selector, cascade } => {
            w.write_u8(8);
            w.write_base_selector(selector);
            w.write_bool(*cascade);
        }
        IpcRequest::CreateView {
            base,
            view_id,
            link_path,
        } => {
            w.write_u8(9);
            w.write_base_selector(base);
            w.write_opt(view_id.as_ref(), |w, id| w.write_view_id(id));
            w.write_opt(link_path.as_deref(), |w, p| w.write_path(p));
        }
        IpcRequest::ListViews => w.write_u8(10),
        IpcRequest::ViewPath { view_id } => {
            w.write_u8(11);
            w.write_view_id(view_id);
        }
        IpcRequest::RemoveView { view_id } => {
            w.write_u8(12);
            w.write_view_id(view_id);
        }
        IpcRequest::DiffView { view_id } => {
            w.write_u8(13);
            w.write_view_id(view_id);
        }
        IpcRequest::FreezeView { view_id, tag } => {
            w.write_u8(14);
            w.write_view_id(view_id);
            w.write_opt(tag.as_ref(), |w, t| w.write_tag_name(t));
        }
        IpcRequest::ApplyView {
            view_id,
            target_dir,
            force,
        } => {
            w.write_u8(15);
            w.write_view_id(view_id);
            w.write_path(target_dir);
            w.write_bool(*force);
        }
    }
    w.into_bytes()
}

/// Decodes an [`IpcRequest`] from a payload byte slice.
pub fn decode_request(bytes: &[u8]) -> Result<IpcRequest, CodecError> {
    let mut r = WireReader::new(bytes);
    let req = match r.read_u8()? {
        1 => IpcRequest::Ping,
        2 => IpcRequest::Status,
        3 => IpcRequest::Shutdown,
        4 => IpcRequest::CreateBase {
            dir: r.read_path()?,
            tag: r.read_opt(|r| r.read_tag_name())?,
            excludes: r.read_vec(|r| r.read_string())?,
        },
        5 => IpcRequest::ListBases,
        6 => IpcRequest::SetTag {
            tag: r.read_tag_name()?,
            base: r.read_base_selector()?,
        },
        7 => IpcRequest::DeleteTag {
            tag: r.read_tag_name()?,
        },
        8 => IpcRequest::RemoveBase {
            selector: r.read_base_selector()?,
            cascade: r.read_bool()?,
        },
        9 => IpcRequest::CreateView {
            base: r.read_base_selector()?,
            view_id: r.read_opt(|r| r.read_view_id())?,
            link_path: r.read_opt(|r| r.read_path())?,
        },
        10 => IpcRequest::ListViews,
        11 => IpcRequest::ViewPath {
            view_id: r.read_view_id()?,
        },
        12 => IpcRequest::RemoveView {
            view_id: r.read_view_id()?,
        },
        13 => IpcRequest::DiffView {
            view_id: r.read_view_id()?,
        },
        14 => IpcRequest::FreezeView {
            view_id: r.read_view_id()?,
            tag: r.read_opt(|r| r.read_tag_name())?,
        },
        15 => IpcRequest::ApplyView {
            view_id: r.read_view_id()?,
            target_dir: r.read_path()?,
            force: r.read_bool()?,
        },
        tag => {
            return Err(CodecError::UnknownTag {
                context: "IpcRequest",
                tag,
            })
        }
    };
    r.finish()?;
    Ok(req)
}

/// Encodes an [`IpcResponse`] into a deterministic payload byte vector.
pub fn encode_response(resp: &IpcResponse) -> Vec<u8> {
    let mut w = WireWriter::new();
    match resp {
        IpcResponse::Pong => w.write_u8(1),
        IpcResponse::Status(status) => {
            w.write_u8(2);
            w.write_u32(status.pid);
            w.write_path(&status.mount_dir);
            w.write_path(&status.store_dir);
            w.write_path(&status.ipc_endpoint);
            w.write_str(&status.vfs_backend);
            w.write_bool(status.vfs_mounted);
            w.write_usize(status.base_count);
            w.write_usize(status.view_count);
        }
        IpcResponse::ShuttingDown => w.write_u8(3),
        IpcResponse::BaseCreated(info) => {
            w.write_u8(4);
            w.write_base_info(info);
        }
        IpcResponse::BaseList(list) => {
            w.write_u8(5);
            w.write_slice(list, |w, b| w.write_base_info(b));
        }
        IpcResponse::TagSet { tag, base_id } => {
            w.write_u8(6);
            w.write_tag_name(tag);
            w.write_base_id(base_id);
        }
        IpcResponse::TagDeleted => w.write_u8(7),
        IpcResponse::BaseRemoved(out) => {
            w.write_u8(8);
            w.write_base_id(&out.base_id);
            w.write_slice(&out.removed_views, |w, v| w.write_view_id(v));
            w.write_slice(&out.removed_tags, |w, t| w.write_tag_name(t));
        }
        IpcResponse::ViewCreated(summary) => {
            w.write_u8(9);
            w.write_view_summary(summary);
        }
        IpcResponse::ViewList(views) => {
            w.write_u8(10);
            w.write_slice(views, |w, v| w.write_view_summary(v));
        }
        IpcResponse::ViewPath(path) => {
            w.write_u8(11);
            w.write_path(path);
        }
        IpcResponse::ViewRemoved => w.write_u8(12),
        IpcResponse::ViewDiff(entries) => {
            w.write_u8(13);
            w.write_slice(entries, |w, d| w.write_diff_entry(d));
        }
        IpcResponse::ViewFrozen(frozen) => {
            w.write_u8(14);
            w.write_base_id(&frozen.base_id);
            w.write_opt(frozen.tag.as_ref(), |w, t| w.write_tag_name(t));
            w.write_usize(frozen.entry_count);
        }
        IpcResponse::ViewApplied(applied) => {
            w.write_u8(15);
            w.write_apply_output(applied);
        }
        IpcResponse::Error(err) => {
            w.write_u8(16);
            w.write_remote_error(err);
        }
    }
    w.into_bytes()
}

/// Decodes an [`IpcResponse`] from a payload byte slice.
pub fn decode_response(bytes: &[u8]) -> Result<IpcResponse, CodecError> {
    let mut r = WireReader::new(bytes);
    let resp = match r.read_u8()? {
        1 => IpcResponse::Pong,
        2 => IpcResponse::Status(DaemonStatus {
            pid: r.read_u32()?,
            mount_dir: r.read_path()?,
            store_dir: r.read_path()?,
            ipc_endpoint: r.read_path()?,
            vfs_backend: r.read_string()?,
            vfs_mounted: r.read_bool()?,
            base_count: r.read_usize()?,
            view_count: r.read_usize()?,
        }),
        3 => IpcResponse::ShuttingDown,
        4 => IpcResponse::BaseCreated(r.read_base_info()?),
        5 => IpcResponse::BaseList(r.read_vec(|r| r.read_base_info())?),
        6 => IpcResponse::TagSet {
            tag: r.read_tag_name()?,
            base_id: r.read_base_id()?,
        },
        7 => IpcResponse::TagDeleted,
        8 => IpcResponse::BaseRemoved(RemoveBaseOutput {
            base_id: r.read_base_id()?,
            removed_views: r.read_vec(|r| r.read_view_id())?,
            removed_tags: r.read_vec(|r| r.read_tag_name())?,
        }),
        9 => IpcResponse::ViewCreated(r.read_view_summary()?),
        10 => IpcResponse::ViewList(r.read_vec(|r| r.read_view_summary())?),
        11 => IpcResponse::ViewPath(r.read_path()?),
        12 => IpcResponse::ViewRemoved,
        13 => IpcResponse::ViewDiff(r.read_vec(|r| r.read_diff_entry())?),
        14 => IpcResponse::ViewFrozen(FreezeSummary {
            base_id: r.read_base_id()?,
            tag: r.read_opt(|r| r.read_tag_name())?,
            entry_count: r.read_usize()?,
        }),
        15 => IpcResponse::ViewApplied(r.read_apply_output()?),
        16 => IpcResponse::Error(r.read_remote_error()?),
        tag => {
            return Err(CodecError::UnknownTag {
                context: "IpcResponse",
                tag,
            })
        }
    };
    r.finish()?;
    Ok(resp)
}

/// Encodes and writes an [`IpcRequest`] frame to `writer`.
pub fn write_request<W: Write>(writer: &mut W, req: &IpcRequest) -> Result<(), IpcError> {
    let payload = encode_request(req);
    write_frame(writer, &payload)
}

/// Reads and decodes an [`IpcRequest`] frame from `reader`, returning `Ok(None)` on clean EOF.
pub fn read_request_opt<R: Read>(reader: &mut R) -> Result<Option<IpcRequest>, IpcError> {
    match read_frame_opt(reader)? {
        None => Ok(None),
        Some(payload) => Ok(Some(decode_request(&payload)?)),
    }
}

/// Reads and decodes an [`IpcRequest`] frame from `reader`.
pub fn read_request<R: Read>(reader: &mut R) -> Result<IpcRequest, IpcError> {
    let payload = read_frame(reader)?;
    Ok(decode_request(&payload)?)
}

/// Encodes and writes an [`IpcResponse`] frame to `writer`.
pub fn write_response<W: Write>(writer: &mut W, resp: &IpcResponse) -> Result<(), IpcError> {
    let payload = encode_response(resp);
    write_frame(writer, &payload)
}

/// Reads and decodes an [`IpcResponse`] frame from `reader`.
pub fn read_response<R: Read>(reader: &mut R) -> Result<IpcResponse, IpcError> {
    let payload = read_frame(reader)?;
    Ok(decode_response(&payload)?)
}

struct WireWriter {
    buf: Vec<u8>,
}

impl WireWriter {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(128),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn write_bool(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }

    fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn write_i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn write_usize(&mut self, v: usize) {
        self.write_u64(v as u64);
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_u32(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
    }

    fn write_str(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }

    fn write_path(&mut self, path: &Path) {
        if let Some(utf8) = path.to_str() {
            self.write_u8(0);
            self.write_str(utf8);
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            self.write_u8(1);
            self.write_bytes(path.as_os_str().as_bytes());
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            self.write_u8(2);
            let units: Vec<u16> = path.as_os_str().encode_wide().collect();
            self.write_u32(units.len() as u32);
            for u in units {
                self.buf.extend_from_slice(&u.to_be_bytes());
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            self.write_u8(0);
            self.write_str(&path.to_string_lossy());
        }
    }

    fn write_opt<T, F>(&mut self, opt: Option<T>, f: F)
    where
        F: FnOnce(&mut Self, T),
    {
        match opt {
            None => self.write_u8(0),
            Some(val) => {
                self.write_u8(1);
                f(self, val);
            }
        }
    }

    fn write_slice<T, F>(&mut self, items: &[T], mut f: F)
    where
        F: FnMut(&mut Self, &T),
    {
        self.write_u32(items.len() as u32);
        for item in items {
            f(self, item);
        }
    }

    fn write_content_hash(&mut self, hash: &ContentHash) {
        self.buf.extend_from_slice(hash.as_bytes());
    }

    fn write_base_id(&mut self, id: &BaseId) {
        self.buf.extend_from_slice(id.as_bytes());
    }

    fn write_tag_name(&mut self, tag: &TagName) {
        self.write_str(tag.as_str());
    }

    fn write_view_id(&mut self, id: &ViewId) {
        self.write_str(id.as_str());
    }

    fn write_entry_name(&mut self, name: &EntryName) {
        self.write_str(name.as_str());
    }

    fn write_rel_path(&mut self, path: &RelPath) {
        self.write_str(path.as_str());
    }

    fn write_base_selector(&mut self, sel: &BaseSelector) {
        match sel {
            BaseSelector::Id(id) => {
                self.write_u8(0);
                self.write_base_id(id);
            }
            BaseSelector::Tag(tag) => {
                self.write_u8(1);
                self.write_tag_name(tag);
            }
        }
    }

    fn write_timestamp(&mut self, ts: Timestamp) {
        self.write_i64(ts.secs);
        self.write_u32(ts.nanos);
    }

    fn write_node_kind(&mut self, kind: NodeKind) {
        match kind {
            NodeKind::File => self.write_u8(0),
            NodeKind::Directory => self.write_u8(1),
            NodeKind::Symlink => self.write_u8(2),
        }
    }

    fn write_tree_entry(&mut self, entry: &TreeEntry) {
        match entry {
            TreeEntry::File {
                content,
                size,
                mode,
                mtime,
            } => {
                self.write_u8(0);
                self.write_content_hash(content);
                self.write_u64(*size);
                self.write_u32(*mode);
                self.write_timestamp(*mtime);
            }
            TreeEntry::Directory { mode, mtime } => {
                self.write_u8(1);
                self.write_u32(*mode);
                self.write_timestamp(*mtime);
            }
            TreeEntry::Symlink {
                target,
                mode,
                mtime,
            } => {
                self.write_u8(2);
                self.write_str(target);
                self.write_u32(*mode);
                self.write_timestamp(*mtime);
            }
        }
    }

    fn write_base_info(&mut self, info: &BaseInfo) {
        self.write_base_id(&info.id);
        self.write_slice(&info.tags, |w, t| w.write_tag_name(t));
        self.write_usize(info.entry_count);
        self.write_usize(info.view_count);
    }

    fn write_view_info(&mut self, info: &ViewInfo) {
        self.write_view_id(&info.id);
        self.write_base_id(&info.base_id);
        self.write_usize(info.overlay_entry_count);
        self.write_timestamp(info.created_at);
    }

    fn write_view_summary(&mut self, summary: &ViewSummary) {
        self.write_view_info(&summary.info);
        self.write_path(&summary.mount_path);
        self.write_opt(summary.link_path.as_deref(), |w, p| w.write_path(p));
    }

    fn write_diff_change(&mut self, change: DiffChange) {
        match change {
            DiffChange::Added => self.write_u8(0),
            DiffChange::Modified => self.write_u8(1),
            DiffChange::Deleted => self.write_u8(2),
        }
    }

    fn write_diff_entry(&mut self, diff: &DiffEntry) {
        self.write_rel_path(&diff.path);
        self.write_diff_change(diff.change);
        self.write_opt(diff.before.as_ref(), |w, e| w.write_tree_entry(e));
        self.write_opt(diff.after.as_ref(), |w, e| w.write_tree_entry(e));
    }

    fn write_apply_conflict_kind(&mut self, kind: ApplyConflictKind) {
        match kind {
            ApplyConflictKind::ExternalModified => self.write_u8(0),
            ApplyConflictKind::ExternalDeleted => self.write_u8(1),
            ApplyConflictKind::CollidingCreate => self.write_u8(2),
            ApplyConflictKind::DirectoryNotEmpty => self.write_u8(3),
        }
    }

    fn write_apply_conflict(&mut self, conflict: &ApplyConflict) {
        self.write_rel_path(&conflict.path);
        self.write_apply_conflict_kind(conflict.kind);
        self.write_opt(conflict.expected.as_ref(), |w, e| w.write_tree_entry(e));
        self.write_opt(conflict.actual.as_ref(), |w, e| w.write_tree_entry(e));
    }

    fn write_apply_action(&mut self, action: &ApplyAction) {
        match action {
            ApplyAction::RemoveLeaf { path } => {
                self.write_u8(0);
                self.write_rel_path(path);
            }
            ApplyAction::RemoveDirectory { path } => {
                self.write_u8(1);
                self.write_rel_path(path);
            }
            ApplyAction::CreateDirectory { path, mode } => {
                self.write_u8(2);
                self.write_rel_path(path);
                self.write_u32(*mode);
            }
            ApplyAction::UpdateDirectoryMode { path, mode } => {
                self.write_u8(3);
                self.write_rel_path(path);
                self.write_u32(*mode);
            }
            ApplyAction::WriteFile { path, entry } => {
                self.write_u8(4);
                self.write_rel_path(path);
                self.write_tree_entry(entry);
            }
            ApplyAction::WriteSymlink { path, target } => {
                self.write_u8(5);
                self.write_rel_path(path);
                self.write_str(target);
            }
        }
    }

    fn write_apply_output(&mut self, out: &ApplyOutput) {
        self.write_view_id(&out.view_id);
        self.write_base_id(&out.base_id);
        self.write_slice(&out.plan.diff, |w, d| w.write_diff_entry(d));
        self.write_slice(&out.plan.actions, |w, a| w.write_apply_action(a));
    }

    fn write_path_error(&mut self, err: &PathError) {
        match err {
            PathError::EmptyComponent => self.write_u8(0),
            PathError::ContainsNul => self.write_u8(1),
            PathError::InvalidSlash => self.write_u8(2),
            PathError::ContainsBackslash => self.write_u8(3),
            PathError::DotTraversal(seg) => {
                self.write_u8(4);
                self.write_str(seg);
            }
        }
    }

    fn write_id_error(&mut self, err: &IdError) {
        match err {
            IdError::Empty => self.write_u8(0),
            IdError::TooLong(len) => {
                self.write_u8(1);
                self.write_usize(*len);
            }
            IdError::DotSegment => self.write_u8(2),
            IdError::TrailingDotOrSpace => self.write_u8(3),
            IdError::InvalidCharacter { ch, index } => {
                self.write_u8(4);
                self.write_u32(*ch as u32);
                self.write_usize(*index);
            }
            IdError::WindowsReservedName(name) => {
                self.write_u8(5);
                self.write_str(name);
            }
            IdError::ReservedTagFormat(reason) => {
                self.write_u8(6);
                self.write_str(reason);
            }
            IdError::InvalidHex(HexDigestError::InvalidLength(len)) => {
                self.write_u8(7);
                self.write_usize(*len);
            }
            IdError::InvalidHex(HexDigestError::InvalidHexByte { index, byte }) => {
                self.write_u8(8);
                self.write_usize(*index);
                self.write_u8(*byte);
            }
        }
    }

    fn write_model_error(&mut self, err: &ModelError) {
        match err {
            ModelError::InvalidSymlinkTarget(reason) => {
                self.write_u8(0);
                self.write_str(reason);
            }
            ModelError::RootEntryNotAllowed => self.write_u8(1),
            ModelError::ParentNotDirectory {
                path,
                ancestor,
                actual,
            } => {
                self.write_u8(2);
                self.write_rel_path(path);
                self.write_rel_path(ancestor);
                self.write_node_kind(*actual);
            }
            ModelError::BaseIdMismatch { expected, actual } => {
                self.write_u8(3);
                self.write_base_id(expected);
                self.write_base_id(actual);
            }
            ModelError::InvalidPath(pe) => {
                self.write_u8(4);
                self.write_path_error(pe);
            }
            ModelError::AmbiguousCase(amb) => {
                self.write_u8(5);
                self.write_entry_name(&amb.requested);
                self.write_slice(&amb.candidates, |w, c| w.write_entry_name(c));
            }
        }
    }

    fn write_store_error(&mut self, err: &StoreError) {
        match err {
            StoreError::BlobNotFound(h) => {
                self.write_u8(0);
                self.write_content_hash(h);
            }
            StoreError::BaseNotFound(id) => {
                self.write_u8(1);
                self.write_base_id(id);
            }
            StoreError::TagNotFound(tag) => {
                self.write_u8(2);
                self.write_tag_name(tag);
            }
            StoreError::ViewNotFound(id) => {
                self.write_u8(3);
                self.write_view_id(id);
            }
            StoreError::CorruptData(msg) => {
                self.write_u8(4);
                self.write_str(msg);
            }
            StoreError::Io(msg) => {
                self.write_u8(5);
                self.write_str(msg);
            }
        }
    }

    fn write_core_error(&mut self, err: &CoreError) {
        match err {
            CoreError::BaseNotFound(id) => {
                self.write_u8(0);
                self.write_base_id(id);
            }
            CoreError::TagNotFound(tag) => {
                self.write_u8(1);
                self.write_tag_name(tag);
            }
            CoreError::ViewNotFound(id) => {
                self.write_u8(2);
                self.write_view_id(id);
            }
            CoreError::ViewAlreadyExists(id) => {
                self.write_u8(3);
                self.write_view_id(id);
            }
            CoreError::BaseInUse { base_id, views } => {
                self.write_u8(4);
                self.write_base_id(base_id);
                self.write_slice(views, |w, v| w.write_view_id(v));
            }
            CoreError::ApplyConflicts(conflicts) => {
                self.write_u8(5);
                self.write_slice(conflicts, |w, c| w.write_apply_conflict(c));
            }
            CoreError::UnsupportedFilesystemEntry { path, reason } => {
                self.write_u8(6);
                self.write_str(path);
                self.write_str(reason);
            }
            CoreError::InvalidId(e) => {
                self.write_u8(7);
                self.write_id_error(e);
            }
            CoreError::InvalidPath(e) => {
                self.write_u8(8);
                self.write_path_error(e);
            }
            CoreError::Model(e) => {
                self.write_u8(9);
                self.write_model_error(e);
            }
            CoreError::Store(e) => {
                self.write_u8(10);
                self.write_store_error(e);
            }
            CoreError::UnexpectedNodeKind {
                path,
                expected,
                actual,
            } => {
                self.write_u8(11);
                self.write_rel_path(path);
                self.write_node_kind(*expected);
                self.write_node_kind(*actual);
            }
        }
    }

    fn write_remote_error(&mut self, err: &RemoteError) {
        match err {
            RemoteError::Core(ce) => {
                self.write_u8(0);
                self.write_core_error(ce);
            }
            RemoteError::Daemon(msg) => {
                self.write_u8(1);
                self.write_str(msg);
            }
        }
    }
}

struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn finish(self) -> Result<(), CodecError> {
        let rem = self.buf.len().saturating_sub(self.pos);
        if rem == 0 {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes(rem))
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::UnexpectedEof)?;
        if end > self.buf.len() {
            return Err(CodecError::UnexpectedEof);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn read_bool(&mut self) -> Result<bool, CodecError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(CodecError::UnknownTag {
                context: "bool",
                tag,
            }),
        }
    }

    fn read_u32(&mut self) -> Result<u32, CodecError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, CodecError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_i64(&mut self) -> Result<i64, CodecError> {
        let b = self.take(8)?;
        Ok(i64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_usize(&mut self) -> Result<usize, CodecError> {
        let raw = self.read_u64()?;
        usize::try_from(raw)
            .map_err(|_| CodecError::InvalidDomainValue(format!("usize overflow: {raw}")))
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], CodecError> {
        let len = self.read_u32()? as usize;
        self.take(len)
    }

    fn read_string(&mut self) -> Result<String, CodecError> {
        let raw = self.read_bytes()?;
        std::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| CodecError::InvalidUtf8)
    }

    fn read_path(&mut self) -> Result<PathBuf, CodecError> {
        match self.read_u8()? {
            0 => Ok(PathBuf::from(self.read_string()?)),
            1 => {
                let raw = self.read_bytes()?;
                #[cfg(unix)]
                {
                    use std::ffi::OsString;
                    use std::os::unix::ffi::OsStringExt;
                    Ok(PathBuf::from(OsString::from_vec(raw.to_vec())))
                }
                #[cfg(not(unix))]
                {
                    std::str::from_utf8(raw)
                        .map(PathBuf::from)
                        .map_err(|_| CodecError::InvalidUtf8)
                }
            }
            2 => {
                let count = self.read_u32()? as usize;
                let raw = self.take(count.checked_mul(2).ok_or(CodecError::UnexpectedEof)?)?;
                let mut units = Vec::with_capacity(count);
                for &[hi, lo] in raw.as_chunks::<2>().0 {
                    units.push(u16::from_be_bytes([hi, lo]));
                }
                #[cfg(windows)]
                {
                    use std::ffi::OsString;
                    use std::os::windows::ffi::OsStringExt;
                    Ok(PathBuf::from(OsString::from_wide(&units)))
                }
                #[cfg(not(windows))]
                {
                    String::from_utf16(&units)
                        .map(PathBuf::from)
                        .map_err(|_| CodecError::InvalidUtf8)
                }
            }
            tag => Err(CodecError::UnknownTag {
                context: "PathBuf",
                tag,
            }),
        }
    }

    fn read_opt<T, F>(&mut self, f: F) -> Result<Option<T>, CodecError>
    where
        F: FnOnce(&mut Self) -> Result<T, CodecError>,
    {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(f(self)?)),
            tag => Err(CodecError::UnknownTag {
                context: "Option",
                tag,
            }),
        }
    }

    fn read_vec<T, F>(&mut self, mut f: F) -> Result<Vec<T>, CodecError>
    where
        F: FnMut(&mut Self) -> Result<T, CodecError>,
    {
        let count = self.read_u32()? as usize;
        if count > MAX_COLLECTION_LEN {
            return Err(CodecError::FrameTooLarge(count));
        }
        let mut out = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            out.push(f(self)?);
        }
        Ok(out)
    }

    fn read_hash_32(&mut self) -> Result<[u8; 32], CodecError> {
        let slice = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn read_content_hash(&mut self) -> Result<ContentHash, CodecError> {
        Ok(ContentHash::from_bytes(self.read_hash_32()?))
    }

    fn read_base_id(&mut self) -> Result<BaseId, CodecError> {
        Ok(BaseId::from_bytes(self.read_hash_32()?))
    }

    fn read_tag_name(&mut self) -> Result<TagName, CodecError> {
        let s = self.read_string()?;
        TagName::new(s).map_err(|e| CodecError::InvalidDomainValue(e.to_string()))
    }

    fn read_view_id(&mut self) -> Result<ViewId, CodecError> {
        let s = self.read_string()?;
        ViewId::new(s).map_err(|e| CodecError::InvalidDomainValue(e.to_string()))
    }

    fn read_entry_name(&mut self) -> Result<EntryName, CodecError> {
        let s = self.read_string()?;
        EntryName::new(s).map_err(|e| CodecError::InvalidDomainValue(e.to_string()))
    }

    fn read_rel_path(&mut self) -> Result<RelPath, CodecError> {
        let s = self.read_string()?;
        RelPath::new(s).map_err(|e| CodecError::InvalidDomainValue(e.to_string()))
    }

    fn read_base_selector(&mut self) -> Result<BaseSelector, CodecError> {
        match self.read_u8()? {
            0 => Ok(BaseSelector::Id(self.read_base_id()?)),
            1 => Ok(BaseSelector::Tag(self.read_tag_name()?)),
            tag => Err(CodecError::UnknownTag {
                context: "BaseSelector",
                tag,
            }),
        }
    }

    fn read_timestamp(&mut self) -> Result<Timestamp, CodecError> {
        let secs = self.read_i64()?;
        let nanos = self.read_u32()?;
        Ok(Timestamp::new(secs, nanos))
    }

    fn read_node_kind(&mut self) -> Result<NodeKind, CodecError> {
        match self.read_u8()? {
            0 => Ok(NodeKind::File),
            1 => Ok(NodeKind::Directory),
            2 => Ok(NodeKind::Symlink),
            tag => Err(CodecError::UnknownTag {
                context: "NodeKind",
                tag,
            }),
        }
    }

    fn read_tree_entry(&mut self) -> Result<TreeEntry, CodecError> {
        let entry = match self.read_u8()? {
            0 => TreeEntry::File {
                content: self.read_content_hash()?,
                size: self.read_u64()?,
                mode: self.read_u32()?,
                mtime: self.read_timestamp()?,
            },
            1 => TreeEntry::Directory {
                mode: self.read_u32()?,
                mtime: self.read_timestamp()?,
            },
            2 => TreeEntry::Symlink {
                target: self.read_string()?,
                mode: self.read_u32()?,
                mtime: self.read_timestamp()?,
            },
            tag => {
                return Err(CodecError::UnknownTag {
                    context: "TreeEntry",
                    tag,
                })
            }
        };
        entry
            .validated()
            .map_err(|e| CodecError::InvalidDomainValue(e.to_string()))
    }

    fn read_base_info(&mut self) -> Result<BaseInfo, CodecError> {
        Ok(BaseInfo {
            id: self.read_base_id()?,
            tags: self.read_vec(|r| r.read_tag_name())?,
            entry_count: self.read_usize()?,
            view_count: self.read_usize()?,
        })
    }

    fn read_view_info(&mut self) -> Result<ViewInfo, CodecError> {
        Ok(ViewInfo {
            id: self.read_view_id()?,
            base_id: self.read_base_id()?,
            overlay_entry_count: self.read_usize()?,
            created_at: self.read_timestamp()?,
        })
    }

    fn read_view_summary(&mut self) -> Result<ViewSummary, CodecError> {
        Ok(ViewSummary {
            info: self.read_view_info()?,
            mount_path: self.read_path()?,
            link_path: self.read_opt(|r| r.read_path())?,
        })
    }

    fn read_diff_change(&mut self) -> Result<DiffChange, CodecError> {
        match self.read_u8()? {
            0 => Ok(DiffChange::Added),
            1 => Ok(DiffChange::Modified),
            2 => Ok(DiffChange::Deleted),
            tag => Err(CodecError::UnknownTag {
                context: "DiffChange",
                tag,
            }),
        }
    }

    fn read_diff_entry(&mut self) -> Result<DiffEntry, CodecError> {
        Ok(DiffEntry {
            path: self.read_rel_path()?,
            change: self.read_diff_change()?,
            before: self.read_opt(|r| r.read_tree_entry())?,
            after: self.read_opt(|r| r.read_tree_entry())?,
        })
    }

    fn read_apply_conflict_kind(&mut self) -> Result<ApplyConflictKind, CodecError> {
        match self.read_u8()? {
            0 => Ok(ApplyConflictKind::ExternalModified),
            1 => Ok(ApplyConflictKind::ExternalDeleted),
            2 => Ok(ApplyConflictKind::CollidingCreate),
            3 => Ok(ApplyConflictKind::DirectoryNotEmpty),
            tag => Err(CodecError::UnknownTag {
                context: "ApplyConflictKind",
                tag,
            }),
        }
    }

    fn read_apply_conflict(&mut self) -> Result<ApplyConflict, CodecError> {
        Ok(ApplyConflict {
            path: self.read_rel_path()?,
            kind: self.read_apply_conflict_kind()?,
            expected: self.read_opt(|r| r.read_tree_entry())?,
            actual: self.read_opt(|r| r.read_tree_entry())?,
        })
    }

    fn read_apply_action(&mut self) -> Result<ApplyAction, CodecError> {
        match self.read_u8()? {
            0 => Ok(ApplyAction::RemoveLeaf {
                path: self.read_rel_path()?,
            }),
            1 => Ok(ApplyAction::RemoveDirectory {
                path: self.read_rel_path()?,
            }),
            2 => Ok(ApplyAction::CreateDirectory {
                path: self.read_rel_path()?,
                mode: self.read_u32()?,
            }),
            3 => Ok(ApplyAction::UpdateDirectoryMode {
                path: self.read_rel_path()?,
                mode: self.read_u32()?,
            }),
            4 => Ok(ApplyAction::WriteFile {
                path: self.read_rel_path()?,
                entry: self.read_tree_entry()?,
            }),
            5 => Ok(ApplyAction::WriteSymlink {
                path: self.read_rel_path()?,
                target: self.read_string()?,
            }),
            tag => Err(CodecError::UnknownTag {
                context: "ApplyAction",
                tag,
            }),
        }
    }

    fn read_apply_output(&mut self) -> Result<ApplyOutput, CodecError> {
        Ok(ApplyOutput {
            view_id: self.read_view_id()?,
            base_id: self.read_base_id()?,
            plan: ApplyPlan {
                diff: self.read_vec(|r| r.read_diff_entry())?,
                actions: self.read_vec(|r| r.read_apply_action())?,
            },
        })
    }

    fn read_path_error(&mut self) -> Result<PathError, CodecError> {
        match self.read_u8()? {
            0 => Ok(PathError::EmptyComponent),
            1 => Ok(PathError::ContainsNul),
            2 => Ok(PathError::InvalidSlash),
            3 => Ok(PathError::ContainsBackslash),
            4 => Ok(PathError::DotTraversal(self.read_string()?)),
            tag => Err(CodecError::UnknownTag {
                context: "PathError",
                tag,
            }),
        }
    }

    fn read_id_error(&mut self) -> Result<IdError, CodecError> {
        match self.read_u8()? {
            0 => Ok(IdError::Empty),
            1 => Ok(IdError::TooLong(self.read_usize()?)),
            2 => Ok(IdError::DotSegment),
            3 => Ok(IdError::TrailingDotOrSpace),
            4 => {
                let code = self.read_u32()?;
                let ch = char::from_u32(code).ok_or_else(|| {
                    CodecError::InvalidDomainValue(format!("invalid char scalar 0x{code:x}"))
                })?;
                Ok(IdError::InvalidCharacter {
                    ch,
                    index: self.read_usize()?,
                })
            }
            5 => Ok(IdError::WindowsReservedName(self.read_string()?)),
            6 => Ok(IdError::ReservedTagFormat(self.read_string()?)),
            7 => Ok(IdError::InvalidHex(HexDigestError::InvalidLength(
                self.read_usize()?,
            ))),
            8 => Ok(IdError::InvalidHex(HexDigestError::InvalidHexByte {
                index: self.read_usize()?,
                byte: self.read_u8()?,
            })),
            tag => Err(CodecError::UnknownTag {
                context: "IdError",
                tag,
            }),
        }
    }

    fn read_model_error(&mut self) -> Result<ModelError, CodecError> {
        match self.read_u8()? {
            0 => Ok(ModelError::InvalidSymlinkTarget(self.read_string()?)),
            1 => Ok(ModelError::RootEntryNotAllowed),
            2 => Ok(ModelError::ParentNotDirectory {
                path: self.read_rel_path()?,
                ancestor: self.read_rel_path()?,
                actual: self.read_node_kind()?,
            }),
            3 => Ok(ModelError::BaseIdMismatch {
                expected: self.read_base_id()?,
                actual: self.read_base_id()?,
            }),
            4 => Ok(ModelError::InvalidPath(self.read_path_error()?)),
            5 => Ok(ModelError::AmbiguousCase(AmbiguousCaseError {
                requested: self.read_entry_name()?,
                candidates: self.read_vec(|r| r.read_entry_name())?,
            })),
            tag => Err(CodecError::UnknownTag {
                context: "ModelError",
                tag,
            }),
        }
    }

    fn read_store_error(&mut self) -> Result<StoreError, CodecError> {
        match self.read_u8()? {
            0 => Ok(StoreError::BlobNotFound(self.read_content_hash()?)),
            1 => Ok(StoreError::BaseNotFound(self.read_base_id()?)),
            2 => Ok(StoreError::TagNotFound(self.read_tag_name()?)),
            3 => Ok(StoreError::ViewNotFound(self.read_view_id()?)),
            4 => Ok(StoreError::CorruptData(self.read_string()?)),
            5 => Ok(StoreError::Io(self.read_string()?)),
            tag => Err(CodecError::UnknownTag {
                context: "StoreError",
                tag,
            }),
        }
    }

    fn read_core_error(&mut self) -> Result<CoreError, CodecError> {
        match self.read_u8()? {
            0 => Ok(CoreError::BaseNotFound(self.read_base_id()?)),
            1 => Ok(CoreError::TagNotFound(self.read_tag_name()?)),
            2 => Ok(CoreError::ViewNotFound(self.read_view_id()?)),
            3 => Ok(CoreError::ViewAlreadyExists(self.read_view_id()?)),
            4 => Ok(CoreError::BaseInUse {
                base_id: self.read_base_id()?,
                views: self.read_vec(|r| r.read_view_id())?,
            }),
            5 => Ok(CoreError::ApplyConflicts(
                self.read_vec(|r| r.read_apply_conflict())?,
            )),
            6 => Ok(CoreError::UnsupportedFilesystemEntry {
                path: self.read_string()?,
                reason: self.read_string()?,
            }),
            7 => Ok(CoreError::InvalidId(self.read_id_error()?)),
            8 => Ok(CoreError::InvalidPath(self.read_path_error()?)),
            9 => Ok(CoreError::Model(self.read_model_error()?)),
            10 => Ok(CoreError::Store(self.read_store_error()?)),
            11 => Ok(CoreError::UnexpectedNodeKind {
                path: self.read_rel_path()?,
                expected: self.read_node_kind()?,
                actual: self.read_node_kind()?,
            }),
            tag => Err(CodecError::UnknownTag {
                context: "CoreError",
                tag,
            }),
        }
    }

    fn read_remote_error(&mut self) -> Result<RemoteError, CodecError> {
        match self.read_u8()? {
            0 => Ok(RemoteError::Core(self.read_core_error()?)),
            1 => Ok(RemoteError::Daemon(self.read_string()?)),
            tag => Err(CodecError::UnknownTag {
                context: "RemoteError",
                tag,
            }),
        }
    }
}
