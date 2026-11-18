//! Linux kernel FUSE v7.x wire protocol constants, opcodes, headers, and safe little-endian
//! codecs (`<linux/fuse.h>`).

use std::fmt;
use std::time::Duration;

use bit_core::model::NodeKind;
use bit_core::vfs::{VfsAttr, ROOT_INO};

/// Supported FUSE kernel ABI major version.
pub const FUSE_KERNEL_VERSION: u32 = 7;

/// Supported FUSE kernel ABI minor version.
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 31;

/// Reserved FUSE root inode (`1`, matching [`ROOT_INO`]).
pub const FUSE_ROOT_ID: u64 = ROOT_INO;

/// Default block size reported in `FuseAttr` and `FuseStatfsOut` (`4096` bytes).
pub const FUSE_BLOCK_SIZE: u32 = 4096;

/// Extra byte room reserved above `max_write` when reading packets from `/dev/fuse`.
pub const FUSE_BUFFER_HEADER_ROOM: usize = 16 * 1024;

// --- Standard Linux POSIX `errno` values (OS-independent constants) ---

/// Operation not permitted (`EPERM`).
pub const EPERM: i32 = 1;
/// No such file or directory (`ENOENT`).
pub const ENOENT: i32 = 2;
/// Input/output error (`EIO`).
pub const EIO: i32 = 5;
/// Bad file descriptor / handle (`EBADF`).
pub const EBADF: i32 = 9;
/// Permission denied (`EACCES`).
pub const EACCES: i32 = 13;
/// File exists (`EEXIST`).
pub const EEXIST: i32 = 17;
/// Invalid cross-device link / cross-`View` rename (`EXDEV`).
pub const EXDEV: i32 = 18;
/// No such device (`ENODEV`, signaled by `/dev/fuse` upon unmount).
pub const ENODEV: i32 = 19;
/// Not a directory (`ENOTDIR`).
pub const ENOTDIR: i32 = 20;
/// Is a directory (`EISDIR`).
pub const EISDIR: i32 = 21;
/// Invalid argument (`EINVAL`).
pub const EINVAL: i32 = 22;
/// Read-only filesystem (`EROFS`, enforced at `<mount>/`).
pub const EROFS: i32 = 30;
/// File name too long (`ENAMETOOLONG`).
pub const ENAMETOOLONG: i32 = 36;
/// Function not implemented (`ENOSYS`).
pub const ENOSYS: i32 = 38;
/// Directory not empty (`ENOTEMPTY`).
pub const ENOTEMPTY: i32 = 39;
/// Too many levels of symbolic links (`ELOOP`).
pub const ELOOP: i32 = 40;
/// Protocol error (`EPROTO`).
pub const EPROTO: i32 = 71;
/// Operation not supported on endpoint (`EOPNOTSUPP`, returned on `LINK` / `MKNOD`).
pub const EOPNOTSUPP: i32 = 95;
/// Transport endpoint is not connected (`ENOTCONN`, stale FUSE mount indicator).
pub const ENOTCONN: i32 = 107;

// --- Linux `<fcntl.h>` open flags ---

/// Access-mode mask (`O_RDONLY | O_WRONLY | O_RDWR`).
pub const LINUX_O_ACCMODE: u32 = 0o3;
/// Open for reading only (`O_RDONLY`).
pub const LINUX_O_RDONLY: u32 = 0o0;
/// Open for writing only (`O_WRONLY`).
pub const LINUX_O_WRONLY: u32 = 0o1;
/// Open for reading and writing (`O_RDWR`).
pub const LINUX_O_RDWR: u32 = 0o2;
/// Create file if missing (`O_CREAT`).
pub const LINUX_O_CREAT: u32 = 0o100;
/// Fail if file already exists (`O_EXCL`).
pub const LINUX_O_EXCL: u32 = 0o200;
/// Truncate existing file to zero length (`O_TRUNC`).
pub const LINUX_O_TRUNC: u32 = 0o1000;
/// Append writes to end of file (`O_APPEND`).
pub const LINUX_O_APPEND: u32 = 0o2000;

// --- Linux `FATTR_*` validity bits for `FUSE_SETATTR` ---

/// `mode` field is valid.
pub const FATTR_MODE: u32 = 1 << 0;
/// `uid` field is valid.
pub const FATTR_UID: u32 = 1 << 1;
/// `gid` field is valid.
pub const FATTR_GID: u32 = 1 << 2;
/// `size` field is valid (`truncate`).
pub const FATTR_SIZE: u32 = 1 << 3;
/// `atime` field is valid.
pub const FATTR_ATIME: u32 = 1 << 4;
/// `mtime` field is valid.
pub const FATTR_MTIME: u32 = 1 << 5;
/// `fh` field is valid.
pub const FATTR_FH: u32 = 1 << 6;
/// Set `atime` to current clock.
pub const FATTR_ATIME_NOW: u32 = 1 << 7;
/// Set `mtime` to current clock.
pub const FATTR_MTIME_NOW: u32 = 1 << 8;
/// `lock_owner` field is valid.
pub const FATTR_LOCKOWNER: u32 = 1 << 9;
/// `ctime` field is valid.
pub const FATTR_CTIME: u32 = 1 << 10;

// --- Linux `RENAME_*` flags for `FUSE_RENAME2` ---

/// Do not overwrite existing destination (`RENAME_NOREPLACE`).
pub const RENAME_NOREPLACE: u32 = 1 << 0;
/// Atomically exchange both paths (`RENAME_EXCHANGE`).
pub const RENAME_EXCHANGE: u32 = 1 << 1;
/// Create whiteout object at old path (`RENAME_WHITEOUT`).
pub const RENAME_WHITEOUT: u32 = 1 << 2;

// --- Linux `access(2)` mode masks ---

/// Test for read permission (`R_OK`).
pub const ACCESS_R_OK: u32 = 4;
/// Test for write permission (`W_OK`).
pub const ACCESS_W_OK: u32 = 2;
/// Test for execute/search permission (`X_OK`).
pub const ACCESS_X_OK: u32 = 1;

// --- `FuseDirent` file type values (`DT_*`) ---

/// Directory entry (`DT_DIR`).
pub const DT_DIR: u32 = 4;
/// Regular file entry (`DT_REG`).
pub const DT_REG: u32 = 8;
/// Symbolic link entry (`DT_LNK`).
pub const DT_LNK: u32 = 10;

/// Maps [`NodeKind`] to POSIX `d_type` (`DT_REG`, `DT_DIR`, `DT_LNK`).
pub const fn node_kind_to_dirent_type(kind: NodeKind) -> u32 {
    match kind {
        NodeKind::File => DT_REG,
        NodeKind::Directory => DT_DIR,
        NodeKind::Symlink => DT_LNK,
    }
}

/// FUSE kernel request opcodes (`enum fuse_opcode` in `<linux/fuse.h>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum FuseOpcode {
    Lookup = 1,
    Forget = 2,
    GetAttr = 3,
    SetAttr = 4,
    ReadLink = 5,
    Symlink = 6,
    Mknod = 8,
    Mkdir = 9,
    Unlink = 10,
    Rmdir = 11,
    Rename = 12,
    Link = 13,
    Open = 14,
    Read = 15,
    Write = 16,
    Statfs = 17,
    Release = 18,
    Fsync = 20,
    Flush = 25,
    Init = 26,
    OpenDir = 27,
    ReadDir = 28,
    ReleaseDir = 29,
    FsyncDir = 30,
    Access = 34,
    Create = 35,
    Destroy = 38,
    BatchForget = 42,
    Rename2 = 45,
}

impl FuseOpcode {
    /// Decodes a raw `u32` opcode from [`FuseInHeader::opcode`].
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Lookup),
            2 => Some(Self::Forget),
            3 => Some(Self::GetAttr),
            4 => Some(Self::SetAttr),
            5 => Some(Self::ReadLink),
            6 => Some(Self::Symlink),
            8 => Some(Self::Mknod),
            9 => Some(Self::Mkdir),
            10 => Some(Self::Unlink),
            11 => Some(Self::Rmdir),
            12 => Some(Self::Rename),
            13 => Some(Self::Link),
            14 => Some(Self::Open),
            15 => Some(Self::Read),
            16 => Some(Self::Write),
            17 => Some(Self::Statfs),
            18 => Some(Self::Release),
            20 => Some(Self::Fsync),
            25 => Some(Self::Flush),
            26 => Some(Self::Init),
            27 => Some(Self::OpenDir),
            28 => Some(Self::ReadDir),
            29 => Some(Self::ReleaseDir),
            30 => Some(Self::FsyncDir),
            34 => Some(Self::Access),
            35 => Some(Self::Create),
            38 => Some(Self::Destroy),
            42 => Some(Self::BatchForget),
            45 => Some(Self::Rename2),
            _ => None,
        }
    }

    /// Returns the numeric `<linux/fuse.h>` opcode value.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Returns `true` for one-way notifications (`FORGET`, `BATCH_FORGET`) that must not emit a
    /// `FuseOutHeader` reply on `/dev/fuse`.
    pub const fn is_no_reply(self) -> bool {
        matches!(self, Self::Forget | Self::BatchForget)
    }
}

/// Wire framing or payload decoding failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuseProtocolError {
    /// Frame was shorter than required for a fixed header or payload structure.
    UnexpectedEof { expected: usize, actual: usize },
    /// Frame `len` field did not match the supplied byte slice.
    FrameLengthMismatch { declared: usize, actual: usize },
    /// Expected a NUL-terminated UTF-8 string in payload.
    MissingNulTerminator,
    /// String in FUSE payload was not valid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for FuseProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { expected, actual } => {
                write!(
                    f,
                    "truncated FUSE payload: expected at least {expected} bytes, got {actual}"
                )
            }
            Self::FrameLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "FUSE frame length mismatch: header declared {declared} bytes, got {actual}"
                )
            }
            Self::MissingNulTerminator => f.write_str("missing NUL terminator in FUSE C-string"),
            Self::InvalidUtf8 => f.write_str("invalid UTF-8 in FUSE string payload"),
        }
    }
}

impl std::error::Error for FuseProtocolError {}

/// Safe little-endian binary reader over a byte slice.
pub struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    /// Wraps `buf` at offset `0`.
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns remaining unread byte count.
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Returns the unread tail slice.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Reads an exact `N`-byte array.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], FuseProtocolError> {
        let end = self
            .pos
            .checked_add(N)
            .ok_or(FuseProtocolError::UnexpectedEof {
                expected: usize::MAX,
                actual: self.buf.len(),
            })?;
        if end > self.buf.len() {
            return Err(FuseProtocolError::UnexpectedEof {
                expected: end,
                actual: self.buf.len(),
            });
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..end]);
        self.pos = end;
        Ok(out)
    }

    /// Reads `len` raw bytes.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], FuseProtocolError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(FuseProtocolError::UnexpectedEof {
                expected: usize::MAX,
                actual: self.buf.len(),
            })?;
        if end > self.buf.len() {
            return Err(FuseProtocolError::UnexpectedEof {
                expected: end,
                actual: self.buf.len(),
            });
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn read_u16(&mut self) -> Result<u16, FuseProtocolError> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    pub fn read_u32(&mut self) -> Result<u32, FuseProtocolError> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    pub fn read_i32(&mut self) -> Result<i32, FuseProtocolError> {
        Ok(i32::from_le_bytes(self.read_array::<4>()?))
    }

    pub fn read_u64(&mut self) -> Result<u64, FuseProtocolError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    /// Reads a NUL-terminated UTF-8 string (advancing past the NUL byte).
    pub fn read_cstr(&mut self) -> Result<&'a str, FuseProtocolError> {
        let tail = self.rest();
        let nul_idx = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or(FuseProtocolError::MissingNulTerminator)?;
        let s =
            std::str::from_utf8(&tail[..nul_idx]).map_err(|_| FuseProtocolError::InvalidUtf8)?;
        self.pos += nul_idx + 1;
        Ok(s)
    }
}

/// Safe little-endian binary writer backed by `Vec<u8>`.
#[derive(Debug, Default)]
pub struct WireWriter {
    buf: Vec<u8>,
}

impl WireWriter {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn write_cstr(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// 40-byte request header (`struct fuse_in_header`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub padding: u32,
}

impl FuseInHeader {
    pub const SIZE: usize = 40;

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            len: r.read_u32()?,
            opcode: r.read_u32()?,
            unique: r.read_u64()?,
            nodeid: r.read_u64()?,
            uid: r.read_u32()?,
            gid: r.read_u32()?,
            pid: r.read_u32()?,
            padding: r.read_u32()?,
        })
    }

    pub fn encode_into(&self, w: &mut WireWriter) {
        w.write_u32(self.len);
        w.write_u32(self.opcode);
        w.write_u64(self.unique);
        w.write_u64(self.nodeid);
        w.write_u32(self.uid);
        w.write_u32(self.gid);
        w.write_u32(self.pid);
        w.write_u32(self.padding);
    }
}

/// 16-byte response header (`struct fuse_out_header`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseOutHeader {
    pub len: u32,
    /// `0` on success, `-errno` on error.
    pub error: i32,
    pub unique: u64,
}

impl FuseOutHeader {
    pub const SIZE: usize = 16;

    /// Builds a successful response frame wrapping `body`.
    pub fn ok_frame(unique: u64, body: &[u8]) -> Vec<u8> {
        let total_len = Self::SIZE + body.len();
        let mut w = WireWriter::with_capacity(total_len);
        w.write_u32(total_len as u32);
        w.write_i32(0);
        w.write_u64(unique);
        w.write_bytes(body);
        w.into_vec()
    }

    /// Builds an error response frame with `error = -errno.abs()`.
    pub fn error_frame(unique: u64, posix_errno: i32) -> Vec<u8> {
        let neg = -(posix_errno.abs());
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u32(Self::SIZE as u32);
        w.write_i32(neg);
        w.write_u64(unique);
        w.into_vec()
    }

    /// Decodes a `FuseOutHeader` from the start of `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            len: r.read_u32()?,
            error: r.read_i32()?,
            unique: r.read_u64()?,
        })
    }

    /// Returns the positive POSIX `errno` if this header represents an error (`error < 0`).
    pub const fn posix_errno(&self) -> Option<i32> {
        if self.error < 0 {
            Some(-self.error)
        } else {
            None
        }
    }
}

/// Builds a complete wire request packet (`FuseInHeader` + `body`) for dispatching or testing.
pub fn build_request_frame(
    unique: u64,
    opcode: FuseOpcode,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    body: &[u8],
) -> Vec<u8> {
    let total_len = FuseInHeader::SIZE + body.len();
    let hdr = FuseInHeader {
        len: total_len as u32,
        opcode: opcode.as_u32(),
        unique,
        nodeid,
        uid,
        gid,
        pid,
        padding: 0,
    };
    let mut w = WireWriter::with_capacity(total_len);
    hdr.encode_into(&mut w);
    w.write_bytes(body);
    w.into_vec()
}

/// Parses a complete wire response packet into `(FuseOutHeader, body_slice)`.
pub fn parse_response_frame(bytes: &[u8]) -> Result<(FuseOutHeader, &[u8]), FuseProtocolError> {
    let hdr = FuseOutHeader::decode(bytes)?;
    if hdr.len as usize != bytes.len() {
        return Err(FuseProtocolError::FrameLengthMismatch {
            declared: hdr.len as usize,
            actual: bytes.len(),
        });
    }
    Ok((hdr, &bytes[FuseOutHeader::SIZE..]))
}

/// 88-byte FUSE inode attribute structure (`struct fuse_attr`, ABI >= 7.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub padding: u32,
}

impl FuseAttr {
    pub const SIZE: usize = 88;

    /// Converts a [`VfsAttr`] into a wire `FuseAttr` owned by `(uid, gid)`.
    pub fn from_vfs_attr(attr: VfsAttr, uid: u32, gid: u32) -> Self {
        let secs = u64::try_from(attr.mtime.secs).unwrap_or(0);
        let nsec = attr.mtime.nanos;
        let blocks = attr.size.div_ceil(512);
        Self {
            ino: attr.ino,
            size: attr.size,
            blocks,
            atime: secs,
            mtime: secs,
            ctime: secs,
            atimensec: nsec,
            mtimensec: nsec,
            ctimensec: nsec,
            mode: attr.posix_mode(),
            nlink: attr.nlink,
            uid,
            gid,
            rdev: 0,
            blksize: FUSE_BLOCK_SIZE,
            padding: 0,
        }
    }

    pub fn encode_into(&self, w: &mut WireWriter) {
        w.write_u64(self.ino);
        w.write_u64(self.size);
        w.write_u64(self.blocks);
        w.write_u64(self.atime);
        w.write_u64(self.mtime);
        w.write_u64(self.ctime);
        w.write_u32(self.atimensec);
        w.write_u32(self.mtimensec);
        w.write_u32(self.ctimensec);
        w.write_u32(self.mode);
        w.write_u32(self.nlink);
        w.write_u32(self.uid);
        w.write_u32(self.gid);
        w.write_u32(self.rdev);
        w.write_u32(self.blksize);
        w.write_u32(self.padding);
    }

    pub fn decode_from(r: &mut WireReader<'_>) -> Result<Self, FuseProtocolError> {
        Ok(Self {
            ino: r.read_u64()?,
            size: r.read_u64()?,
            blocks: r.read_u64()?,
            atime: r.read_u64()?,
            mtime: r.read_u64()?,
            ctime: r.read_u64()?,
            atimensec: r.read_u32()?,
            mtimensec: r.read_u32()?,
            ctimensec: r.read_u32()?,
            mode: r.read_u32()?,
            nlink: r.read_u32()?,
            uid: r.read_u32()?,
            gid: r.read_u32()?,
            rdev: r.read_u32()?,
            blksize: r.read_u32()?,
            padding: r.read_u32()?,
        })
    }
}

/// 128-byte lookup/create/mkdir/symlink response (`struct fuse_entry_out`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseEntryOut {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: u64,
    pub attr_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: FuseAttr,
}

impl FuseEntryOut {
    pub const SIZE: usize = 128;

    pub fn new(attr: FuseAttr, entry_ttl: Duration, attr_ttl: Duration) -> Self {
        Self {
            nodeid: attr.ino,
            generation: 1,
            entry_valid: entry_ttl.as_secs(),
            attr_valid: attr_ttl.as_secs(),
            entry_valid_nsec: entry_ttl.subsec_nanos(),
            attr_valid_nsec: attr_ttl.subsec_nanos(),
            attr,
        }
    }

    pub fn encode_into(&self, w: &mut WireWriter) {
        w.write_u64(self.nodeid);
        w.write_u64(self.generation);
        w.write_u64(self.entry_valid);
        w.write_u64(self.attr_valid);
        w.write_u32(self.entry_valid_nsec);
        w.write_u32(self.attr_valid_nsec);
        self.attr.encode_into(w);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        self.encode_into(&mut w);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Self::decode_from(&mut r)
    }

    pub fn decode_from(r: &mut WireReader<'_>) -> Result<Self, FuseProtocolError> {
        Ok(Self {
            nodeid: r.read_u64()?,
            generation: r.read_u64()?,
            entry_valid: r.read_u64()?,
            attr_valid: r.read_u64()?,
            entry_valid_nsec: r.read_u32()?,
            attr_valid_nsec: r.read_u32()?,
            attr: FuseAttr::decode_from(r)?,
        })
    }
}

/// 104-byte `GETATTR` / `SETATTR` response (`struct fuse_attr_out`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseAttrOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub dummy: u32,
    pub attr: FuseAttr,
}

impl FuseAttrOut {
    pub const SIZE: usize = 104;

    pub fn new(attr: FuseAttr, attr_ttl: Duration) -> Self {
        Self {
            attr_valid: attr_ttl.as_secs(),
            attr_valid_nsec: attr_ttl.subsec_nanos(),
            dummy: 0,
            attr,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u64(self.attr_valid);
        w.write_u32(self.attr_valid_nsec);
        w.write_u32(self.dummy);
        self.attr.encode_into(&mut w);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            attr_valid: r.read_u64()?,
            attr_valid_nsec: r.read_u32()?,
            dummy: r.read_u32()?,
            attr: FuseAttr::decode_from(&mut r)?,
        })
    }
}

/// 88-byte `FUSE_SETATTR` request (`struct fuse_setattr_in`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuseSetAttrIn {
    pub valid: u32,
    pub padding: u32,
    pub fh: u64,
    pub size: u64,
    pub lock_owner: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub unused4: u32,
    pub uid: u32,
    pub gid: u32,
    pub unused5: u32,
}

impl FuseSetAttrIn {
    pub const SIZE: usize = 88;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u32(self.valid);
        w.write_u32(self.padding);
        w.write_u64(self.fh);
        w.write_u64(self.size);
        w.write_u64(self.lock_owner);
        w.write_u64(self.atime);
        w.write_u64(self.mtime);
        w.write_u64(self.ctime);
        w.write_u32(self.atimensec);
        w.write_u32(self.mtimensec);
        w.write_u32(self.ctimensec);
        w.write_u32(self.mode);
        w.write_u32(self.unused4);
        w.write_u32(self.uid);
        w.write_u32(self.gid);
        w.write_u32(self.unused5);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            valid: r.read_u32()?,
            padding: r.read_u32()?,
            fh: r.read_u64()?,
            size: r.read_u64()?,
            lock_owner: r.read_u64()?,
            atime: r.read_u64()?,
            mtime: r.read_u64()?,
            ctime: r.read_u64()?,
            atimensec: r.read_u32()?,
            mtimensec: r.read_u32()?,
            ctimensec: r.read_u32()?,
            mode: r.read_u32()?,
            unused4: r.read_u32()?,
            uid: r.read_u32()?,
            gid: r.read_u32()?,
            unused5: r.read_u32()?,
        })
    }
}

/// 8-byte `FUSE_OPEN` / `FUSE_OPENDIR` request (`struct fuse_open_in`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuseOpenIn {
    pub flags: u32,
    pub open_flags: u32,
}

impl FuseOpenIn {
    pub const SIZE: usize = 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u32(self.flags);
        w.write_u32(self.open_flags);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            flags: r.read_u32()?,
            open_flags: r.read_u32()?,
        })
    }
}

/// 16-byte `FUSE_OPEN` / `FUSE_OPENDIR` response (`struct fuse_open_out`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuseOpenOut {
    pub fh: u64,
    pub open_flags: u32,
    pub padding: u32,
}

impl FuseOpenOut {
    pub const SIZE: usize = 16;

    pub fn encode_into(&self, w: &mut WireWriter) {
        w.write_u64(self.fh);
        w.write_u32(self.open_flags);
        w.write_u32(self.padding);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        self.encode_into(&mut w);
        w.into_vec()
    }

    pub fn decode_from(r: &mut WireReader<'_>) -> Result<Self, FuseProtocolError> {
        Ok(Self {
            fh: r.read_u64()?,
            open_flags: r.read_u32()?,
            padding: r.read_u32()?,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Self::decode_from(&mut r)
    }
}

/// `FUSE_CREATE` request (`struct fuse_create_in` + NUL-terminated child `name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseCreateIn {
    pub flags: u32,
    pub mode: u32,
    pub umask: u32,
    pub padding: u32,
    pub name: String,
}

impl FuseCreateIn {
    pub const FIXED_SIZE: usize = 16;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::FIXED_SIZE + self.name.len() + 1);
        w.write_u32(self.flags);
        w.write_u32(self.mode);
        w.write_u32(self.umask);
        w.write_u32(self.padding);
        w.write_cstr(&self.name);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        let flags = r.read_u32()?;
        let mode = r.read_u32()?;
        let umask = r.read_u32()?;
        let padding = r.read_u32()?;
        let name = r.read_cstr()?.to_owned();
        Ok(Self {
            flags,
            mode,
            umask,
            padding,
            name,
        })
    }
}

/// 144-byte `FUSE_CREATE` response (`FuseEntryOut` + `FuseOpenOut`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseCreateOut {
    pub entry: FuseEntryOut,
    pub open: FuseOpenOut,
}

impl FuseCreateOut {
    pub const SIZE: usize = FuseEntryOut::SIZE + FuseOpenOut::SIZE;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        self.entry.encode_into(&mut w);
        self.open.encode_into(&mut w);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            entry: FuseEntryOut::decode_from(&mut r)?,
            open: FuseOpenOut::decode_from(&mut r)?,
        })
    }
}

/// `FUSE_READ` / `FUSE_READDIR` request (`struct fuse_read_in`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuseReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

impl FuseReadIn {
    pub const SIZE: usize = 40;
    pub const LEGACY_SIZE: usize = 24;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u64(self.fh);
        w.write_u64(self.offset);
        w.write_u32(self.size);
        w.write_u32(self.read_flags);
        w.write_u64(self.lock_owner);
        w.write_u32(self.flags);
        w.write_u32(self.padding);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        let fh = r.read_u64()?;
        let offset = r.read_u64()?;
        let size = r.read_u32()?;
        let read_flags = r.read_u32()?;
        let (lock_owner, flags, padding) = if r.remaining() >= 16 {
            (r.read_u64()?, r.read_u32()?, r.read_u32()?)
        } else {
            (0, 0, 0)
        };
        Ok(Self {
            fh,
            offset,
            size,
            read_flags,
            lock_owner,
            flags,
            padding,
        })
    }
}

/// `FUSE_WRITE` request (`struct fuse_write_in` followed by `size` data bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseWriteIn<'a> {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
    pub data: &'a [u8],
}

impl<'a> FuseWriteIn<'a> {
    pub const HEADER_SIZE: usize = 40;

    pub fn encode_payload(fh: u64, offset: u64, flags: u32, data: &[u8]) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::HEADER_SIZE + data.len());
        w.write_u64(fh);
        w.write_u64(offset);
        w.write_u32(data.len() as u32);
        w.write_u32(0);
        w.write_u64(0);
        w.write_u32(flags);
        w.write_u32(0);
        w.write_bytes(data);
        w.into_vec()
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        let fh = r.read_u64()?;
        let offset = r.read_u64()?;
        let size = r.read_u32()?;
        let write_flags = r.read_u32()?;
        let lock_owner = r.read_u64()?;
        let flags = r.read_u32()?;
        let padding = r.read_u32()?;
        let data = r.read_bytes(size as usize)?;
        Ok(Self {
            fh,
            offset,
            size,
            write_flags,
            lock_owner,
            flags,
            padding,
            data,
        })
    }
}

/// 8-byte `FUSE_WRITE` response (`struct fuse_write_out`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuseWriteOut {
    pub size: u32,
    pub padding: u32,
}

impl FuseWriteOut {
    pub const SIZE: usize = 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u32(self.size);
        w.write_u32(self.padding);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            size: r.read_u32()?,
            padding: r.read_u32()?,
        })
    }
}

/// `FUSE_MKDIR` request (`struct fuse_mkdir_in` + NUL-terminated `name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseMkdirIn {
    pub mode: u32,
    pub umask: u32,
    pub name: String,
}

impl FuseMkdirIn {
    pub const FIXED_SIZE: usize = 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::FIXED_SIZE + self.name.len() + 1);
        w.write_u32(self.mode);
        w.write_u32(self.umask);
        w.write_cstr(&self.name);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        let mode = r.read_u32()?;
        let umask = r.read_u32()?;
        let name = r.read_cstr()?.to_owned();
        Ok(Self { mode, umask, name })
    }
}

/// `FUSE_RENAME` request (`struct fuse_rename_in` + `oldname\0newname\0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseRenameIn {
    pub newdir: u64,
    pub oldname: String,
    pub newname: String,
}

impl FuseRenameIn {
    pub const FIXED_SIZE: usize = 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(
            Self::FIXED_SIZE + self.oldname.len() + self.newname.len() + 2,
        );
        w.write_u64(self.newdir);
        w.write_cstr(&self.oldname);
        w.write_cstr(&self.newname);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        let newdir = r.read_u64()?;
        let oldname = r.read_cstr()?.to_owned();
        let newname = r.read_cstr()?.to_owned();
        Ok(Self {
            newdir,
            oldname,
            newname,
        })
    }
}

/// `FUSE_RENAME2` request (`struct fuse_rename2_in` + `oldname\0newname\0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseRename2In {
    pub newdir: u64,
    pub flags: u32,
    pub padding: u32,
    pub oldname: String,
    pub newname: String,
}

impl FuseRename2In {
    pub const FIXED_SIZE: usize = 16;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(
            Self::FIXED_SIZE + self.oldname.len() + self.newname.len() + 2,
        );
        w.write_u64(self.newdir);
        w.write_u32(self.flags);
        w.write_u32(self.padding);
        w.write_cstr(&self.oldname);
        w.write_cstr(&self.newname);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        let newdir = r.read_u64()?;
        let flags = r.read_u32()?;
        let padding = r.read_u32()?;
        let oldname = r.read_cstr()?.to_owned();
        let newname = r.read_cstr()?.to_owned();
        Ok(Self {
            newdir,
            flags,
            padding,
            oldname,
            newname,
        })
    }
}

/// `FUSE_LINK` request (`struct fuse_link_in` + NUL-terminated `newname`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseLinkIn {
    pub oldnodeid: u64,
    pub newname: String,
}

impl FuseLinkIn {
    pub const FIXED_SIZE: usize = 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::FIXED_SIZE + self.newname.len() + 1);
        w.write_u64(self.oldnodeid);
        w.write_cstr(&self.newname);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        let oldnodeid = r.read_u64()?;
        let newname = r.read_cstr()?.to_owned();
        Ok(Self { oldnodeid, newname })
    }
}

/// `FUSE_SYMLINK` request (`name\0target\0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseSymlinkIn {
    /// Entry name to create inside `header.nodeid`.
    pub name: String,
    /// Verbatim target string stored in the symbolic link.
    pub target: String,
}

impl FuseSymlinkIn {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(self.name.len() + self.target.len() + 2);
        w.write_cstr(&self.name);
        w.write_cstr(&self.target);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        let name = r.read_cstr()?.to_owned();
        let target = r.read_cstr()?.to_owned();
        Ok(Self { name, target })
    }
}

/// 24-byte `FUSE_FLUSH` request (`struct fuse_flush_in`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuseFlushIn {
    pub fh: u64,
    pub unused: u32,
    pub padding: u32,
    pub lock_owner: u64,
}

impl FuseFlushIn {
    pub const SIZE: usize = 24;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u64(self.fh);
        w.write_u32(self.unused);
        w.write_u32(self.padding);
        w.write_u64(self.lock_owner);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            fh: r.read_u64()?,
            unused: r.read_u32()?,
            padding: r.read_u32()?,
            lock_owner: r.read_u64()?,
        })
    }
}

/// 16-byte `FUSE_FSYNC` / `FUSE_FSYNCDIR` request (`struct fuse_fsync_in`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuseFsyncIn {
    pub fh: u64,
    pub fsync_flags: u32,
    pub padding: u32,
}

impl FuseFsyncIn {
    pub const SIZE: usize = 16;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u64(self.fh);
        w.write_u32(self.fsync_flags);
        w.write_u32(self.padding);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            fh: r.read_u64()?,
            fsync_flags: r.read_u32()?,
            padding: r.read_u32()?,
        })
    }
}

/// 24-byte `FUSE_RELEASE` / `FUSE_RELEASEDIR` request (`struct fuse_release_in`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuseReleaseIn {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}

impl FuseReleaseIn {
    pub const SIZE: usize = 24;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u64(self.fh);
        w.write_u32(self.flags);
        w.write_u32(self.release_flags);
        w.write_u64(self.lock_owner);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            fh: r.read_u64()?,
            flags: r.read_u32()?,
            release_flags: r.read_u32()?,
            lock_owner: r.read_u64()?,
        })
    }
}

/// 8-byte `FUSE_ACCESS` request (`struct fuse_access_in`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuseAccessIn {
    pub mask: u32,
    pub padding: u32,
}

impl FuseAccessIn {
    pub const SIZE: usize = 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u32(self.mask);
        w.write_u32(self.padding);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            mask: r.read_u32()?,
            padding: r.read_u32()?,
        })
    }
}

/// 16-byte `FUSE_INIT` request (`struct fuse_init_in`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuseInitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}

impl FuseInitIn {
    pub const SIZE: usize = 16;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u32(self.major);
        w.write_u32(self.minor);
        w.write_u32(self.max_readahead);
        w.write_u32(self.flags);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            major: r.read_u32()?,
            minor: r.read_u32()?,
            max_readahead: r.read_u32()?,
            flags: r.read_u32()?,
        })
    }
}

/// 64-byte `FUSE_INIT` response (`struct fuse_init_out`, ABI >= 7.23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseInitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
}

impl FuseInitOut {
    pub const SIZE: usize = 64;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u32(self.major);
        w.write_u32(self.minor);
        w.write_u32(self.max_readahead);
        w.write_u32(self.flags);
        w.write_u16(self.max_background);
        w.write_u16(self.congestion_threshold);
        w.write_u32(self.max_write);
        w.write_u32(self.time_gran);
        w.write_u16(self.max_pages);
        w.write_u16(self.map_alignment);
        for _ in 0..8 {
            w.write_u32(0);
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FuseProtocolError> {
        let mut r = WireReader::new(bytes);
        Ok(Self {
            major: r.read_u32()?,
            minor: r.read_u32()?,
            max_readahead: r.read_u32()?,
            flags: r.read_u32()?,
            max_background: r.read_u16()?,
            congestion_threshold: r.read_u16()?,
            max_write: r.read_u32()?,
            time_gran: r.read_u32()?,
            max_pages: r.read_u16()?,
            map_alignment: r.read_u16()?,
        })
    }
}

/// 80-byte `FUSE_STATFS` response (`struct fuse_statfs_out`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseStatfsOut {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
    pub padding: u32,
}

impl Default for FuseStatfsOut {
    fn default() -> Self {
        Self {
            blocks: 1 << 20,
            bfree: 1 << 19,
            bavail: 1 << 19,
            files: 1 << 20,
            ffree: 1 << 19,
            bsize: FUSE_BLOCK_SIZE,
            namelen: 255,
            frsize: FUSE_BLOCK_SIZE,
            padding: 0,
        }
    }
}

impl FuseStatfsOut {
    pub const SIZE: usize = 80;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::with_capacity(Self::SIZE);
        w.write_u64(self.blocks);
        w.write_u64(self.bfree);
        w.write_u64(self.bavail);
        w.write_u64(self.files);
        w.write_u64(self.ffree);
        w.write_u32(self.bsize);
        w.write_u32(self.namelen);
        w.write_u32(self.frsize);
        w.write_u32(self.padding);
        for _ in 0..6 {
            w.write_u32(0);
        }
        w.into_vec()
    }
}

/// Single directory entry encoded inside a `FUSE_READDIR` reply (`struct fuse_dirent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseDirent {
    pub ino: u64,
    /// 1-based next-entry offset cookie for pagination.
    pub off: u64,
    pub typ: u32,
    pub name: String,
}

impl FuseDirent {
    pub const FIXED_SIZE: usize = 24;

    /// Returns the 8-byte-aligned wire byte length for this record.
    pub const fn aligned_len(&self) -> usize {
        (Self::FIXED_SIZE + self.name.len() + 7) & !7
    }

    /// Appends this 8-byte-aligned `fuse_dirent` record to `out` if it fits within `max_bytes`.
    /// Returns `true` if written, or `false` when the buffer is full.
    pub fn append_if_fits(&self, out: &mut Vec<u8>, max_bytes: usize) -> bool {
        let record_len = self.aligned_len();
        if out.len() + record_len > max_bytes {
            return false;
        }
        out.extend_from_slice(&self.ino.to_le_bytes());
        out.extend_from_slice(&self.off.to_le_bytes());
        out.extend_from_slice(&(self.name.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.typ.to_le_bytes());
        out.extend_from_slice(self.name.as_bytes());
        let pad = record_len - (Self::FIXED_SIZE + self.name.len());
        out.extend(std::iter::repeat_n(0u8, pad));
        true
    }
}

/// Decodes a sequence of 8-byte-aligned `FuseDirent` records from a `FUSE_READDIR` payload.
pub fn decode_dirents(bytes: &[u8]) -> Result<Vec<FuseDirent>, FuseProtocolError> {
    let mut r = WireReader::new(bytes);
    let mut entries = Vec::new();
    while r.remaining() > 0 {
        let ino = r.read_u64()?;
        let off = r.read_u64()?;
        let namelen = r.read_u32()? as usize;
        let typ = r.read_u32()?;
        let name_bytes = r.read_bytes(namelen)?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| FuseProtocolError::InvalidUtf8)?
            .to_owned();
        let unaligned = FuseDirent::FIXED_SIZE + namelen;
        let aligned = (unaligned + 7) & !7;
        let pad = aligned - unaligned;
        if pad > 0 {
            let _ = r.read_bytes(pad)?;
        }
        entries.push(FuseDirent {
            ino,
            off,
            typ,
            name,
        });
    }
    Ok(entries)
}
