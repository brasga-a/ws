//! Deterministic SHA-256-checksummed binary frame codec for `Base`, `Tag`, and `View` records.

use std::collections::BTreeMap;

use bit_core::{
    Base, BaseId, ContentHash, DirectoryTree, Overlay, OverlayNode, RelPath, Sha256, StoreError,
    TagName, Timestamp, TreeEntry, View, ViewId,
};

const BASE_MAGIC: &[u8; 8] = b"BITBASE1";
const TAG_MAGIC: &[u8; 8] = b"BITTAG01";
const VIEW_MAGIC: &[u8; 8] = b"BITVIEW1";

const KIND_FILE: u8 = 0x01;
const KIND_DIR: u8 = 0x02;
const KIND_SYMLINK: u8 = 0x03;

const OVERLAY_WHITEOUT: u8 = 0x00;
const OVERLAY_UPSERT: u8 = 0x01;

fn wrap_frame(magic: &[u8; 8], payload: &[u8]) -> Vec<u8> {
    let checksum = Sha256::digest(payload);
    let mut out = Vec::with_capacity(8 + 32 + payload.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&checksum);
    out.extend_from_slice(payload);
    out
}

fn unwrap_frame<'a>(expected_magic: &[u8; 8], bytes: &'a [u8]) -> Result<&'a [u8], StoreError> {
    if bytes.len() < 40 {
        return Err(StoreError::CorruptData(
            "metadata frame shorter than 40-byte header".to_owned(),
        ));
    }
    if &bytes[..8] != expected_magic {
        return Err(StoreError::CorruptData(
            "metadata frame magic header mismatch".to_owned(),
        ));
    }
    let payload = &bytes[40..];
    let computed = Sha256::digest(payload);
    if computed.as_slice() != &bytes[8..40] {
        return Err(StoreError::CorruptData(
            "metadata frame SHA-256 checksum mismatch".to_owned(),
        ));
    }
    Ok(payload)
}

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
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

    fn write_bytes_32(&mut self, bytes: &[u8; 32]) {
        self.buf.extend_from_slice(bytes);
    }

    fn write_str(&mut self, s: &str) -> Result<(), StoreError> {
        let len = u32::try_from(s.len())
            .map_err(|_| StoreError::CorruptData("string exceeds u32 length".to_owned()))?;
        self.write_u32(len);
        self.buf.extend_from_slice(s.as_bytes());
        Ok(())
    }

    fn write_timestamp(&mut self, ts: Timestamp) {
        self.write_i64(ts.secs);
        self.write_u32(ts.nanos);
    }

    fn write_tree_entry(&mut self, entry: &TreeEntry) -> Result<(), StoreError> {
        match entry {
            TreeEntry::File {
                content,
                size,
                mode,
                mtime,
            } => {
                self.write_u8(KIND_FILE);
                self.write_bytes_32(content.as_bytes());
                self.write_u64(*size);
                self.write_u32(*mode);
                self.write_timestamp(*mtime);
            }
            TreeEntry::Directory { mode, mtime } => {
                self.write_u8(KIND_DIR);
                self.write_u32(*mode);
                self.write_timestamp(*mtime);
            }
            TreeEntry::Symlink {
                target,
                mode,
                mtime,
            } => {
                self.write_u8(KIND_SYMLINK);
                self.write_u32(*mode);
                self.write_timestamp(*mtime);
                self.write_str(target)?;
            }
        }
        Ok(())
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| StoreError::CorruptData("frame cursor overflow".to_owned()))?;
        if end > self.data.len() {
            return Err(StoreError::CorruptData(
                "unexpected EOF in metadata frame".to_owned(),
            ));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn finish(self) -> Result<(), StoreError> {
        if self.pos != self.data.len() {
            return Err(StoreError::CorruptData(
                "trailing unconsumed bytes in metadata frame".to_owned(),
            ));
        }
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.take(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, StoreError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, StoreError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_i64(&mut self) -> Result<i64, StoreError> {
        let b = self.take(8)?;
        Ok(i64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_bytes_32(&mut self) -> Result<[u8; 32], StoreError> {
        let b = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(b);
        Ok(out)
    }

    fn read_str(&mut self) -> Result<String, StoreError> {
        let len = self.read_u32()? as usize;
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|e| StoreError::CorruptData(format!("invalid UTF-8 in frame: {e}")))
    }

    fn read_timestamp(&mut self) -> Result<Timestamp, StoreError> {
        let secs = self.read_i64()?;
        let nanos = self.read_u32()?;
        if nanos >= 1_000_000_000 {
            return Err(StoreError::CorruptData(
                "timestamp nanoseconds out of range".to_owned(),
            ));
        }
        Ok(Timestamp::new(secs, nanos))
    }

    fn read_tree_entry(&mut self) -> Result<TreeEntry, StoreError> {
        let tag = self.read_u8()?;
        let entry = match tag {
            KIND_FILE => {
                let content = ContentHash::from_bytes(self.read_bytes_32()?);
                let size = self.read_u64()?;
                let mode = self.read_u32()?;
                let mtime = self.read_timestamp()?;
                TreeEntry::File {
                    content,
                    size,
                    mode,
                    mtime,
                }
            }
            KIND_DIR => {
                let mode = self.read_u32()?;
                let mtime = self.read_timestamp()?;
                TreeEntry::Directory { mode, mtime }
            }
            KIND_SYMLINK => {
                let mode = self.read_u32()?;
                let mtime = self.read_timestamp()?;
                let target = self.read_str()?;
                TreeEntry::Symlink {
                    target,
                    mode,
                    mtime,
                }
            }
            other => {
                return Err(StoreError::CorruptData(format!(
                    "unknown TreeEntry discriminant 0x{other:02x}"
                )));
            }
        };
        entry
            .validated()
            .map_err(|e| StoreError::CorruptData(e.to_string()))
    }
}

/// Encodes a `Base` manifest into a checksummed binary frame.
pub fn encode_base(base: &Base) -> Result<Vec<u8>, StoreError> {
    let mut w = Writer::new();
    w.write_bytes_32(base.id().as_bytes());
    w.write_u32(base.tree().root_mode());
    w.write_timestamp(base.tree().root_mtime());
    w.write_u64(base.entries().len() as u64);

    for (path, entry) in base.entries() {
        w.write_str(path.as_str())?;
        w.write_tree_entry(entry)?;
    }

    Ok(wrap_frame(BASE_MAGIC, &w.buf))
}

/// Decodes and integrity-verifies a `Base` manifest frame.
pub fn decode_base(bytes: &[u8]) -> Result<Base, StoreError> {
    let payload = unwrap_frame(BASE_MAGIC, bytes)?;
    let mut r = Reader::new(payload);
    let id = BaseId::from_bytes(r.read_bytes_32()?);
    let root_mode = r.read_u32()?;
    let root_mtime = r.read_timestamp()?;
    let count = usize::try_from(r.read_u64()?)
        .map_err(|_| StoreError::CorruptData("entry count overflow".to_owned()))?;

    let mut entries = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let raw_path = r.read_str()?;
        let rel = RelPath::new(raw_path).map_err(|e| StoreError::CorruptData(e.to_string()))?;
        let entry = r.read_tree_entry()?;
        entries.push((rel, entry));
    }
    r.finish()?;

    let tree = DirectoryTree::with_root_and_entries(root_mode, root_mtime, entries)
        .map_err(|e| StoreError::CorruptData(e.to_string()))?;
    Base::with_verified_id(id, tree).map_err(|e| StoreError::CorruptData(e.to_string()))
}

/// Encodes a `(TagName, BaseId)` record into a checksummed binary frame.
pub fn encode_tag(tag: &TagName, base_id: &BaseId) -> Result<Vec<u8>, StoreError> {
    let mut w = Writer::new();
    w.write_str(tag.as_str())?;
    w.write_bytes_32(base_id.as_bytes());
    Ok(wrap_frame(TAG_MAGIC, &w.buf))
}

/// Decodes a `(TagName, BaseId)` record from a checksummed binary frame.
pub fn decode_tag(bytes: &[u8]) -> Result<(TagName, BaseId), StoreError> {
    let payload = unwrap_frame(TAG_MAGIC, bytes)?;
    let mut r = Reader::new(payload);
    let tag_raw = r.read_str()?;
    let tag = TagName::new(tag_raw).map_err(|e| StoreError::CorruptData(e.to_string()))?;
    let base_id = BaseId::from_bytes(r.read_bytes_32()?);
    r.finish()?;
    Ok((tag, base_id))
}

/// Encodes a `View` (including its `Overlay` whiteouts and opaque directory markers) into a checksummed binary frame.
pub fn encode_view(view: &View) -> Result<Vec<u8>, StoreError> {
    let mut w = Writer::new();
    w.write_str(view.id().as_str())?;
    w.write_bytes_32(view.base_id().as_bytes());
    w.write_timestamp(view.created_at());

    match view.overlay().root_mode() {
        None => w.write_u8(0),
        Some(m) => {
            w.write_u8(1);
            w.write_u32(m);
        }
    }
    match view.overlay().root_mtime() {
        None => w.write_u8(0),
        Some(ts) => {
            w.write_u8(1);
            w.write_timestamp(ts);
        }
    }

    w.write_u64(view.overlay().entries().len() as u64);
    for (path, node) in view.overlay().entries() {
        w.write_str(path.as_str())?;
        match node {
            OverlayNode::Whiteout => {
                w.write_u8(OVERLAY_WHITEOUT);
            }
            OverlayNode::Upsert { entry, opaque } => {
                w.write_u8(OVERLAY_UPSERT);
                w.write_u8(u8::from(*opaque));
                w.write_tree_entry(entry)?;
            }
        }
    }

    Ok(wrap_frame(VIEW_MAGIC, &w.buf))
}

/// Decodes a `View` from a checksummed binary frame.
pub fn decode_view(bytes: &[u8]) -> Result<View, StoreError> {
    let payload = unwrap_frame(VIEW_MAGIC, bytes)?;
    let mut r = Reader::new(payload);
    let view_id = ViewId::new(r.read_str()?).map_err(|e| StoreError::CorruptData(e.to_string()))?;
    let base_id = BaseId::from_bytes(r.read_bytes_32()?);
    let created_at = r.read_timestamp()?;

    let root_mode = match r.read_u8()? {
        0 => None,
        1 => Some(r.read_u32()?),
        other => {
            return Err(StoreError::CorruptData(format!(
                "invalid root_mode option byte {other}"
            )));
        }
    };
    let root_mtime = match r.read_u8()? {
        0 => None,
        1 => Some(r.read_timestamp()?),
        other => {
            return Err(StoreError::CorruptData(format!(
                "invalid root_mtime option byte {other}"
            )));
        }
    };

    let count = usize::try_from(r.read_u64()?)
        .map_err(|_| StoreError::CorruptData("overlay count overflow".to_owned()))?;
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let path =
            RelPath::new(r.read_str()?).map_err(|e| StoreError::CorruptData(e.to_string()))?;
        let kind = r.read_u8()?;
        let node = match kind {
            OVERLAY_WHITEOUT => OverlayNode::Whiteout,
            OVERLAY_UPSERT => {
                let opaque = match r.read_u8()? {
                    0 => false,
                    1 => true,
                    other => {
                        return Err(StoreError::CorruptData(format!(
                            "invalid opaque flag byte {other}"
                        )));
                    }
                };
                let entry = r.read_tree_entry()?;
                OverlayNode::Upsert { entry, opaque }
            }
            other => {
                return Err(StoreError::CorruptData(format!(
                    "invalid OverlayNode discriminant {other}"
                )));
            }
        };
        entries.insert(path, node);
    }
    r.finish()?;

    let overlay = Overlay::from_parts(root_mode, root_mtime, entries);
    Ok(View::from_parts(view_id, base_id, overlay, created_at))
}
