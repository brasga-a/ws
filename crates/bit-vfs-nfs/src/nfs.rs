//! Stateless `MOUNTv3` (RFC 1813 Appendix I) and `NFSv3` (RFC 1813 §3) RPC dispatcher backed by
//! opaque filehandles mapped through [`InodeTable`] and [`VfsOperations`].

use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bit_core::{
    InodeTable, NodeKind, Timestamp, VfsAttr, VfsError, VfsOperations, VfsSetAttr,
    DEFAULT_DIR_MODE, DEFAULT_FILE_MODE, PERM_MASK, ROOT_INO,
};

use crate::rpc::{
    read_rpc_record, validate_call_credentials, write_rpc_record, RpcAcceptStat, RpcCall, RpcError,
    RpcReply, AUTH_UNIX, RPC_VERSION,
};
use crate::xdr::{xdr_pad_len, XdrError, XdrReader, XdrWriter};

/// ONC-RPC program number for `NFS` (RFC 1813 §3.1).
pub const NFS_PROGRAM: u32 = 100_003;
/// Protocol version `3` for `NFSv3`.
pub const NFS_V3: u32 = 3;

/// ONC-RPC program number for `MOUNT` (RFC 1813 §5.1).
pub const MOUNT_PROGRAM: u32 = 100_005;
/// Protocol version `3` for `MOUNTv3`.
pub const MOUNT_V3: u32 = 3;

/// Maximum opaque `nfs_fh3` / `fhandle3` byte size in NFSv3 (`64`).
pub const NFS3_FHSIZE: usize = 64;
/// Fixed wire byte length of Bit's opaque [`NfsFileHandle`] (`16` bytes).
pub const BIT_FH_LEN: usize = 16;
/// Maximum filename component length in NFSv3 (`255`).
pub const NFS3_MAXNAMLEN: usize = 255;
/// Maximum symlink target or mount path length in NFSv3 (`1024`).
pub const NFS3_MAXPATHLEN: usize = 1024;
/// Maximum single `READ` / `WRITE` payload size advertised via `FSINFO` (`1 MiB`).
pub const NFS3_MAX_IOSIZE: u32 = 1024 * 1024;
/// Preferred `READ` / `WRITE` / `READDIR` transfer size advertised via `FSINFO` (`64 KiB`).
pub const NFS3_PREF_IOSIZE: u32 = 65_536;
/// Default server instance tag embedded in [`NfsFileHandle`] and write verifiers.
pub const DEFAULT_INSTANCE_ID: u32 = 0x0003_0001;
/// Constant filesystem identifier reported in `fattr3.fsid` across the single mount.
pub const MOUNT_FSID: u64 = 1;

const FH_MAGIC: [u8; 4] = *b"BITN";

// -------------------------------------------------------------------------
// MOUNTv3 procedure & status constants (RFC 1813 Appendix I)
// -------------------------------------------------------------------------

/// `MOUNTPROC3_NULL` (`0`).
pub const MOUNTPROC3_NULL: u32 = 0;
/// `MOUNTPROC3_MNT` (`1`).
pub const MOUNTPROC3_MNT: u32 = 1;
/// `MOUNTPROC3_DUMP` (`2`).
pub const MOUNTPROC3_DUMP: u32 = 2;
/// `MOUNTPROC3_UMNT` (`3`).
pub const MOUNTPROC3_UMNT: u32 = 3;
/// `MOUNTPROC3_UMNTALL` (`4`).
pub const MOUNTPROC3_UMNTALL: u32 = 4;

/// `mountstat3::MNT3_OK` (`0`).
pub const MNT3_OK: u32 = 0;
/// `mountstat3::MNT3ERR_PERM` (`1`).
pub const MNT3ERR_PERM: u32 = 1;
/// `mountstat3::MNT3ERR_NOENT` (`2`).
pub const MNT3ERR_NOENT: u32 = 2;
/// `mountstat3::MNT3ERR_IO` (`5`).
pub const MNT3ERR_IO: u32 = 5;
/// `mountstat3::MNT3ERR_ACCES` (`13`).
pub const MNT3ERR_ACCES: u32 = 13;
/// `mountstat3::MNT3ERR_NOTDIR` (`20`).
pub const MNT3ERR_NOTDIR: u32 = 20;
/// `mountstat3::MNT3ERR_INVAL` (`22`).
pub const MNT3ERR_INVAL: u32 = 22;
/// `mountstat3::MNT3ERR_NAMETOOLONG` (`63`).
pub const MNT3ERR_NAMETOOLONG: u32 = 63;
/// `mountstat3::MNT3ERR_NOTSUPP` (`10004`).
pub const MNT3ERR_NOTSUPP: u32 = 10004;
/// `mountstat3::MNT3ERR_SERVERFAULT` (`10006`).
pub const MNT3ERR_SERVERFAULT: u32 = 10006;

// -------------------------------------------------------------------------
// NFSv3 procedure & status constants (RFC 1813 §3)
// -------------------------------------------------------------------------

/// `NFSPROC3_NULL` (`0`).
pub const NFSPROC3_NULL: u32 = 0;
/// `NFSPROC3_GETATTR` (`1`).
pub const NFSPROC3_GETATTR: u32 = 1;
/// `NFSPROC3_SETATTR` (`2`).
pub const NFSPROC3_SETATTR: u32 = 2;
/// `NFSPROC3_LOOKUP` (`3`).
pub const NFSPROC3_LOOKUP: u32 = 3;
/// `NFSPROC3_ACCESS` (`4`).
pub const NFSPROC3_ACCESS: u32 = 4;
/// `NFSPROC3_READLINK` (`5`).
pub const NFSPROC3_READLINK: u32 = 5;
/// `NFSPROC3_READ` (`6`).
pub const NFSPROC3_READ: u32 = 6;
/// `NFSPROC3_WRITE` (`7`).
pub const NFSPROC3_WRITE: u32 = 7;
/// `NFSPROC3_CREATE` (`8`).
pub const NFSPROC3_CREATE: u32 = 8;
/// `NFSPROC3_MKDIR` (`9`).
pub const NFSPROC3_MKDIR: u32 = 9;
/// `NFSPROC3_SYMLINK` (`10`).
pub const NFSPROC3_SYMLINK: u32 = 10;
/// `NFSPROC3_MKNOD` (`11` -> `NFS3ERR_NOTSUPP`).
pub const NFSPROC3_MKNOD: u32 = 11;
/// `NFSPROC3_REMOVE` (`12`).
pub const NFSPROC3_REMOVE: u32 = 12;
/// `NFSPROC3_RMDIR` (`13`).
pub const NFSPROC3_RMDIR: u32 = 13;
/// `NFSPROC3_RENAME` (`14`).
pub const NFSPROC3_RENAME: u32 = 14;
/// `NFSPROC3_LINK` (`15` -> `NFS3ERR_NOTSUPP`).
pub const NFSPROC3_LINK: u32 = 15;
/// `NFSPROC3_READDIR` (`16`).
pub const NFSPROC3_READDIR: u32 = 16;
/// `NFSPROC3_READDIRPLUS` (`17`).
pub const NFSPROC3_READDIRPLUS: u32 = 17;
/// `NFSPROC3_FSSTAT` (`18`).
pub const NFSPROC3_FSSTAT: u32 = 18;
/// `NFSPROC3_FSINFO` (`19`).
pub const NFSPROC3_FSINFO: u32 = 19;
/// `NFSPROC3_PATHCONF` (`20`).
pub const NFSPROC3_PATHCONF: u32 = 20;
/// `NFSv3` procedure `21` (flush unstable writes; no-op since `WRITE` persists stably).
pub const NFSPROC3_FLUSH_WRITES: u32 = 21;

/// `nfsstat3::NFS3_OK` (`0`).
pub const NFS3_OK: u32 = 0;
/// `nfsstat3::NFS3ERR_PERM` (`1`).
pub const NFS3ERR_PERM: u32 = 1;
/// `nfsstat3::NFS3ERR_NOENT` (`2`).
pub const NFS3ERR_NOENT: u32 = 2;
/// `nfsstat3::NFS3ERR_IO` (`5`).
pub const NFS3ERR_IO: u32 = 5;
/// `nfsstat3::NFS3ERR_ACCES` (`13`).
pub const NFS3ERR_ACCES: u32 = 13;
/// `nfsstat3::NFS3ERR_EXIST` (`17`).
pub const NFS3ERR_EXIST: u32 = 17;
/// `nfsstat3::NFS3ERR_XDEV` (`18`).
pub const NFS3ERR_XDEV: u32 = 18;
/// `nfsstat3::NFS3ERR_NOTDIR` (`20`).
pub const NFS3ERR_NOTDIR: u32 = 20;
/// `nfsstat3::NFS3ERR_ISDIR` (`21`).
pub const NFS3ERR_ISDIR: u32 = 21;
/// `nfsstat3::NFS3ERR_INVAL` (`22`).
pub const NFS3ERR_INVAL: u32 = 22;
/// `nfsstat3::NFS3ERR_ROFS` (`30`).
pub const NFS3ERR_ROFS: u32 = 30;
/// `nfsstat3::NFS3ERR_NAMETOOLONG` (`63`).
pub const NFS3ERR_NAMETOOLONG: u32 = 63;
/// `nfsstat3::NFS3ERR_NOTEMPTY` (`66`).
pub const NFS3ERR_NOTEMPTY: u32 = 66;
/// `nfsstat3::NFS3ERR_STALE` (`70`).
pub const NFS3ERR_STALE: u32 = 70;
/// `nfsstat3::NFS3ERR_BADHANDLE` (`10001`).
pub const NFS3ERR_BADHANDLE: u32 = 10001;
/// `nfsstat3` guard mismatch (`10002`).
pub const NFS3ERR_CTIME_MISMATCH: u32 = 10002;
/// `nfsstat3::NFS3ERR_BAD_COOKIE` (`10003`).
pub const NFS3ERR_BAD_COOKIE: u32 = 10003;
/// `nfsstat3::NFS3ERR_NOTSUPP` (`10004`).
pub const NFS3ERR_NOTSUPP: u32 = 10004;
/// `nfsstat3::NFS3ERR_TOOSMALL` (`10005`).
pub const NFS3ERR_TOOSMALL: u32 = 10005;
/// `nfsstat3::NFS3ERR_SERVERFAULT` (`10006`).
pub const NFS3ERR_SERVERFAULT: u32 = 10006;

// -------------------------------------------------------------------------
// ACCESS3 & FSF3 bitmasks
// -------------------------------------------------------------------------

/// `ACCESS3_READ` (`0x0001`).
pub const ACCESS3_READ: u32 = 0x0001;
/// `ACCESS3_LOOKUP` (`0x0002`).
pub const ACCESS3_LOOKUP: u32 = 0x0002;
/// `ACCESS3_MODIFY` (`0x0004`).
pub const ACCESS3_MODIFY: u32 = 0x0004;
/// `ACCESS3_EXTEND` (`0x0008`).
pub const ACCESS3_EXTEND: u32 = 0x0008;
/// `ACCESS3_DELETE` (`0x0010`).
pub const ACCESS3_DELETE: u32 = 0x0010;
/// `ACCESS3_EXECUTE` (`0x0020`).
pub const ACCESS3_EXECUTE: u32 = 0x0020;

/// `FSF3_LINK` (`0x0001`) — intentionally NOT advertised because `link()` is unsupported.
pub const FSF3_LINK: u32 = 0x0001;
/// `FSF3_SYMLINK` (`0x0002`).
pub const FSF3_SYMLINK: u32 = 0x0002;
/// `FSF3_HOMOGENEOUS` (`0x0008`).
pub const FSF3_HOMOGENEOUS: u32 = 0x0008;
/// `FSF3_CANSETTIME` (`0x0010`).
pub const FSF3_CANSETTIME: u32 = 0x0010;

/// `stable_how` discriminant indicating file data and metadata are durably written (`2`).
pub const NFS3_FILE_STABLE: u32 = 2;

/// `ftype3` node kind values in `fattr3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NfsFileType {
    /// Regular file (`NF3REG = 1`).
    Regular = 1,
    /// Directory (`NF3DIR = 2`).
    Directory = 2,
    /// Symbolic link (`NF3LNK = 5`).
    Symlink = 5,
}

impl From<NodeKind> for NfsFileType {
    fn from(kind: NodeKind) -> Self {
        match kind {
            NodeKind::File => Self::Regular,
            NodeKind::Directory => Self::Directory,
            NodeKind::Symlink => Self::Symlink,
        }
    }
}

/// RFC 1813 `nfstime3` (`seconds` + `nseconds`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NfsTime3 {
    /// Seconds since UNIX epoch.
    pub seconds: u32,
    /// Sub-second nanoseconds (`0..1_000_000_000`).
    pub nseconds: u32,
}

impl From<Timestamp> for NfsTime3 {
    fn from(ts: Timestamp) -> Self {
        let seconds = if ts.secs <= 0 {
            0
        } else if ts.secs > i64::from(u32::MAX) {
            u32::MAX
        } else {
            ts.secs as u32
        };
        Self {
            seconds,
            nseconds: ts.nanos,
        }
    }
}

impl NfsTime3 {
    /// Converts `self` into a core [`Timestamp`].
    pub const fn to_timestamp(self) -> Timestamp {
        Timestamp::new(self.seconds as i64, self.nseconds)
    }

    /// Decodes an `nfstime3` from `reader`.
    pub fn decode(reader: &mut XdrReader<'_>) -> Result<Self, XdrError> {
        Ok(Self {
            seconds: reader.read_u32()?,
            nseconds: reader.read_u32()?,
        })
    }

    /// Encodes `self` into `writer`.
    pub fn encode(self, writer: &mut XdrWriter) {
        writer.write_u32(self.seconds);
        writer.write_u32(self.nseconds);
    }
}

/// Opaque 16-byte NFSv3 filehandle (`[4B magic | 4B instance_id | 8B fh_ino]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NfsFileHandle {
    bytes: [u8; BIT_FH_LEN],
}

impl NfsFileHandle {
    /// Constructs an opaque filehandle for `(instance_id, fh_ino)`.
    pub fn new(instance_id: u32, fh_ino: u64) -> Self {
        let mut bytes = [0u8; BIT_FH_LEN];
        bytes[0..4].copy_from_slice(&FH_MAGIC);
        bytes[4..8].copy_from_slice(&instance_id.to_be_bytes());
        bytes[8..16].copy_from_slice(&fh_ino.to_be_bytes());
        Self { bytes }
    }

    /// Borrows the raw 16-byte handle payload.
    pub const fn as_bytes(&self) -> &[u8; BIT_FH_LEN] {
        &self.bytes
    }

    /// Encodes this filehandle as `nfs_fh3` / `fhandle3` (`opaque<64>`).
    pub fn encode(&self, writer: &mut XdrWriter) {
        writer.write_opaque(&self.bytes);
    }

    /// Decodes raw `nfs_fh3` bytes from `reader` (`opaque<64>`).
    pub fn decode_raw<'a>(reader: &mut XdrReader<'a>) -> Result<&'a [u8], XdrError> {
        reader.read_opaque_slice(NFS3_FHSIZE)
    }

    /// Validates raw `nfs_fh3` bytes against `expected_instance_id`, returning `fh_ino`.
    pub fn parse_raw(raw: &[u8], expected_instance_id: u32) -> Result<u64, u32> {
        if raw.len() != BIT_FH_LEN || raw[0..4] != FH_MAGIC {
            return Err(NFS3ERR_BADHANDLE);
        }
        let inst = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
        if inst != expected_instance_id {
            return Err(NFS3ERR_STALE);
        }
        let ino = u64::from_be_bytes([
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]);
        if ino == 0 {
            return Err(NFS3ERR_BADHANDLE);
        }
        Ok(ino)
    }
}

/// RFC 1813 `fattr3` (84-byte file attribute block).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NfsFattr3 {
    /// File type (`NF3REG`, `NF3DIR`, `NF3LNK`).
    pub ftype: NfsFileType,
    /// Permission mode bits (`0..=0o7777`).
    pub mode: u32,
    /// Hard link count.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Logical byte size.
    pub size: u64,
    /// Allocated byte size.
    pub used: u64,
    /// Filesystem ID (`1`).
    pub fsid: u64,
    /// Virtual inode / `fileid3`.
    pub fileid: u64,
    /// Access timestamp.
    pub atime: NfsTime3,
    /// Modification timestamp.
    pub mtime: NfsTime3,
    /// Attribute change timestamp.
    pub ctime: NfsTime3,
}

impl NfsFattr3 {
    /// Converts a core [`VfsAttr`] into `fattr3` with the configured `uid` and `gid`.
    pub fn from_vfs_attr(attr: VfsAttr, uid: u32, gid: u32) -> Self {
        let ts = NfsTime3::from(attr.mtime);
        let used = if attr.size == 0 {
            0
        } else {
            attr.size.div_ceil(512).saturating_mul(512)
        };
        Self {
            ftype: NfsFileType::from(attr.kind),
            mode: attr.mode & PERM_MASK,
            nlink: attr.nlink,
            uid,
            gid,
            size: attr.size,
            used,
            fsid: MOUNT_FSID,
            fileid: attr.ino,
            atime: ts,
            mtime: ts,
            ctime: ts,
        }
    }

    /// Encodes `self` (84 bytes) into `writer`.
    pub fn encode(&self, writer: &mut XdrWriter) {
        writer.write_u32(self.ftype as u32);
        writer.write_u32(self.mode & PERM_MASK);
        writer.write_u32(self.nlink);
        writer.write_u32(self.uid);
        writer.write_u32(self.gid);
        writer.write_u64(self.size);
        writer.write_u64(self.used);
        // specdata3 rdev (specdata1, specdata2)
        writer.write_u32(0);
        writer.write_u32(0);
        writer.write_u64(self.fsid);
        writer.write_u64(self.fileid);
        self.atime.encode(writer);
        self.mtime.encode(writer);
        self.ctime.encode(writer);
    }

    /// Decodes an 84-byte `fattr3` from `reader`.
    pub fn decode(reader: &mut XdrReader<'_>) -> Result<Self, XdrError> {
        let ftype = match reader.read_u32()? {
            1 => NfsFileType::Regular,
            2 => NfsFileType::Directory,
            5 => NfsFileType::Symlink,
            other => return Err(XdrError::InvalidEnumDiscriminant(other)),
        };
        let mode = reader.read_u32()?;
        let nlink = reader.read_u32()?;
        let uid = reader.read_u32()?;
        let gid = reader.read_u32()?;
        let size = reader.read_u64()?;
        let used = reader.read_u64()?;
        let _rdev1 = reader.read_u32()?;
        let _rdev2 = reader.read_u32()?;
        let fsid = reader.read_u64()?;
        let fileid = reader.read_u64()?;
        let atime = NfsTime3::decode(reader)?;
        let mtime = NfsTime3::decode(reader)?;
        let ctime = NfsTime3::decode(reader)?;
        Ok(Self {
            ftype,
            mode,
            nlink,
            uid,
            gid,
            size,
            used,
            fsid,
            fileid,
            atime,
            mtime,
            ctime,
        })
    }
}

/// Decoded RFC 1813 `sattr3` attribute-update request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NfsSattr3 {
    /// Optional permission mode update.
    pub mode: Option<u32>,
    /// Optional numeric uid (informational in single-owner loopback mode).
    pub uid: Option<u32>,
    /// Optional numeric gid (informational in single-owner loopback mode).
    pub gid: Option<u32>,
    /// Optional file byte size (`truncate`).
    pub size: Option<u64>,
    /// Optional resolved `mtime` update.
    pub mtime: Option<Timestamp>,
}

impl NfsSattr3 {
    /// Decodes `sattr3` from `reader`.
    pub fn decode(reader: &mut XdrReader<'_>) -> Result<Self, XdrError> {
        let mode = if reader.read_bool()? {
            Some(reader.read_u32()? & PERM_MASK)
        } else {
            None
        };
        let uid = if reader.read_bool()? {
            Some(reader.read_u32()?)
        } else {
            None
        };
        let gid = if reader.read_bool()? {
            Some(reader.read_u32()?)
        } else {
            None
        };
        let size = if reader.read_bool()? {
            Some(reader.read_u64()?)
        } else {
            None
        };
        // set_atime: 0 = DONT_CHANGE, 1 = SET_TO_SERVER_TIME, 2 = SET_TO_CLIENT_TIME
        match reader.read_u32()? {
            0 | 1 => {}
            2 => {
                let _ = NfsTime3::decode(reader)?;
            }
            other => return Err(XdrError::InvalidEnumDiscriminant(other)),
        }
        // set_mtime
        let mtime = match reader.read_u32()? {
            0 => None,
            1 => Some(Timestamp::now()),
            2 => Some(NfsTime3::decode(reader)?.to_timestamp()),
            other => return Err(XdrError::InvalidEnumDiscriminant(other)),
        };

        Ok(Self {
            mode,
            uid,
            gid,
            size,
            mtime,
        })
    }

    /// Encodes `self` as XDR `sattr3` (for client/test request construction).
    pub fn encode(&self, writer: &mut XdrWriter) {
        match self.mode {
            Some(m) => {
                writer.write_bool(true);
                writer.write_u32(m & PERM_MASK);
            }
            None => writer.write_bool(false),
        }
        match self.uid {
            Some(u) => {
                writer.write_bool(true);
                writer.write_u32(u);
            }
            None => writer.write_bool(false),
        }
        match self.gid {
            Some(g) => {
                writer.write_bool(true);
                writer.write_u32(g);
            }
            None => writer.write_bool(false),
        }
        match self.size {
            Some(sz) => {
                writer.write_bool(true);
                writer.write_u64(sz);
            }
            None => writer.write_bool(false),
        }
        // set_atime = DONT_CHANGE (0)
        writer.write_u32(0);
        // set_mtime
        match self.mtime {
            None => writer.write_u32(0),
            Some(ts) => {
                writer.write_u32(2);
                NfsTime3::from(ts).encode(writer);
            }
        }
    }

    /// Converts `self` into a core [`VfsSetAttr`].
    pub const fn to_vfs_setattr(&self) -> VfsSetAttr {
        VfsSetAttr {
            mode: self.mode,
            size: self.size,
            mtime: self.mtime,
        }
    }
}

fn write_post_op_attr(writer: &mut XdrWriter, attr: Option<VfsAttr>, uid: u32, gid: u32) {
    match attr {
        Some(a) => {
            writer.write_bool(true);
            NfsFattr3::from_vfs_attr(a, uid, gid).encode(writer);
        }
        None => writer.write_bool(false),
    }
}

fn write_pre_op_attr(writer: &mut XdrWriter, attr: Option<VfsAttr>) {
    match attr {
        Some(a) => {
            writer.write_bool(true);
            writer.write_u64(a.size);
            let ts = NfsTime3::from(a.mtime);
            ts.encode(writer);
            ts.encode(writer);
        }
        None => writer.write_bool(false),
    }
}

fn write_wcc_data(
    writer: &mut XdrWriter,
    before: Option<VfsAttr>,
    after: Option<VfsAttr>,
    uid: u32,
    gid: u32,
) {
    write_pre_op_attr(writer, before);
    write_post_op_attr(writer, after, uid, gid);
}

fn write_post_op_fh3(writer: &mut XdrWriter, fh: Option<NfsFileHandle>) {
    match fh {
        Some(handle) => {
            writer.write_bool(true);
            handle.encode(writer);
        }
        None => writer.write_bool(false),
    }
}

fn parent_mount_path(dir_path: &str) -> &str {
    if dir_path.is_empty() {
        ""
    } else {
        match dir_path.rfind('/') {
            Some(idx) => &dir_path[..idx],
            None => "",
        }
    }
}

fn join_mount_path(dir_path: &str, leaf: &str) -> String {
    if dir_path.is_empty() {
        leaf.to_owned()
    } else {
        format!("{dir_path}/{leaf}")
    }
}

fn validate_lookup_name(name: &str) -> Result<(), u32> {
    if name.is_empty() {
        return Err(NFS3ERR_INVAL);
    }
    if name.len() > NFS3_MAXNAMLEN {
        return Err(NFS3ERR_NAMETOOLONG);
    }
    if name.contains('\0') || name.contains('/') || name.contains('\\') {
        return Err(NFS3ERR_INVAL);
    }
    Ok(())
}

fn validate_mutation_leaf(dir_path: &str, name: &str, is_create: bool) -> Result<String, u32> {
    if name.len() > NFS3_MAXNAMLEN {
        return Err(NFS3ERR_NAMETOOLONG);
    }
    if name.is_empty() || name.contains('\0') || name.contains('/') || name.contains('\\') {
        return Err(NFS3ERR_INVAL);
    }
    if dir_path.is_empty() {
        return Err(NFS3ERR_ROFS);
    }
    if name == "." || name == ".." {
        return Err(if is_create {
            NFS3ERR_EXIST
        } else {
            NFS3ERR_INVAL
        });
    }
    Ok(join_mount_path(dir_path, name))
}

/// Stateless `MOUNTv3` + `NFSv3` RPC dispatcher translating protocol calls onto `VfsOperations`
/// and mapping opaque [`NfsFileHandle`]s via [`InodeTable`].
pub struct NfsDispatcher {
    vfs: Arc<dyn VfsOperations>,
    inodes: Arc<InodeTable>,
    owner_uid: u32,
    owner_gid: u32,
    instance_id: u32,
    active_mounts: AtomicUsize,
}

impl std::fmt::Debug for NfsDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfsDispatcher")
            .field("owner_uid", &self.owner_uid)
            .field("owner_gid", &self.owner_gid)
            .field("instance_id", &self.instance_id)
            .field("active_mounts", &self.active_mounts.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl NfsDispatcher {
    /// Creates a stateless `MOUNTv3` + `NFSv3` dispatcher enforcing `owner_uid` on incoming
    /// `AUTH_UNIX` credentials.
    pub fn new(vfs: Arc<dyn VfsOperations>, owner_uid: u32) -> Self {
        Self::with_inode_table(vfs, Arc::new(InodeTable::new()), owner_uid)
    }

    /// Creates a dispatcher sharing an explicit [`InodeTable`].
    pub fn with_inode_table(
        vfs: Arc<dyn VfsOperations>,
        inodes: Arc<InodeTable>,
        owner_uid: u32,
    ) -> Self {
        Self {
            vfs,
            inodes,
            owner_uid,
            owner_gid: 0,
            instance_id: DEFAULT_INSTANCE_ID,
            active_mounts: AtomicUsize::new(0),
        }
    }

    /// Configures the `gid` reported in `fattr3` attributes.
    pub const fn with_owner_gid(mut self, owner_gid: u32) -> Self {
        self.owner_gid = owner_gid;
        self
    }

    /// Configures a server boot/instance identifier embedded in opaque filehandles and write
    /// verifiers.
    pub const fn with_instance_id(mut self, instance_id: u32) -> Self {
        self.instance_id = instance_id;
        self
    }

    /// Returns the mandatory `owner_uid` enforced against `AUTH_UNIX` credentials.
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// Returns the `owner_gid` reported in `fattr3` attributes.
    pub const fn owner_gid(&self) -> u32 {
        self.owner_gid
    }

    /// Returns the opaque filehandle instance identifier.
    pub const fn instance_id(&self) -> u32 {
        self.instance_id
    }

    /// Borrows the [`InodeTable`] backing opaque filehandles.
    pub fn inode_table(&self) -> &Arc<InodeTable> {
        &self.inodes
    }

    /// Returns the root `<mount>/` [`NfsFileHandle`] (`ROOT_INO = 1`).
    pub fn root_file_handle(&self) -> NfsFileHandle {
        NfsFileHandle::new(self.instance_id, ROOT_INO)
    }

    /// Number of active `MOUNTv3` `MNT` sessions observed (decremented by `UMNT`).
    pub fn active_mount_count(&self) -> usize {
        self.active_mounts.load(Ordering::Relaxed)
    }

    fn write_verf_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&FH_MAGIC);
        out[4..8].copy_from_slice(&self.instance_id.to_be_bytes());
        out
    }

    fn handle_for_path(&self, mount_path: &str) -> NfsFileHandle {
        let fh_ino = self.inodes.get_or_alloc(mount_path);
        NfsFileHandle::new(self.instance_id, fh_ino)
    }

    fn resolve_fh_path(&self, raw_fh: &[u8]) -> Result<String, u32> {
        let fh_ino = NfsFileHandle::parse_raw(raw_fh, self.instance_id)?;
        self.inodes.resolve_ino(fh_ino).ok_or(NFS3ERR_STALE)
    }

    fn resolve_dir_fh(&self, raw_fh: &[u8]) -> Result<(String, VfsAttr), (u32, Option<VfsAttr>)> {
        let path = self.resolve_fh_path(raw_fh).map_err(|st| (st, None))?;
        let attr = self
            .vfs
            .getattr(&path)
            .map_err(|e| (e.to_nfs3_stat(), None))?;
        if attr.kind != NodeKind::Directory {
            return Err((NFS3ERR_NOTDIR, Some(attr)));
        }
        Ok((path, attr))
    }

    /// Serves a bidirectional `Read + Write` connection of RFC 5531 record-marked RPC requests
    /// until clean EOF, returning the number of requests processed.
    pub fn serve_connection<S: Read + Write>(&self, stream: &mut S) -> Result<usize, RpcError> {
        let mut count = 0usize;
        while let Some(request_record) = read_rpc_record(stream)? {
            let reply_bytes = self.handle_rpc_message(&request_record)?;
            write_rpc_record(stream, &reply_bytes)?;
            count += 1;
        }
        Ok(count)
    }

    /// Serves a split `(reader, writer)` pair of RFC 5531 record-marked RPC requests until clean
    /// EOF, returning the number of requests processed.
    pub fn serve_stream<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<usize, RpcError> {
        let mut count = 0usize;
        while let Some(request_record) = read_rpc_record(reader)? {
            let reply_bytes = self.handle_rpc_message(&request_record)?;
            write_rpc_record(writer, &reply_bytes)?;
            count += 1;
        }
        Ok(count)
    }

    /// Decodes one unframed ONC-RPC `CALL` message, enforces `AUTH_UNIX` `owner_uid` checks,
    /// dispatches to `MOUNTv3` or `NFSv3`, and returns the encoded unframed `REPLY` bytes.
    pub fn handle_rpc_message(&self, request_bytes: &[u8]) -> Result<Vec<u8>, RpcError> {
        let call = RpcCall::decode(request_bytes)?;
        Ok(self.dispatch_call(&call).encode())
    }

    /// Dispatches a parsed [`RpcCall`] and returns a structured [`RpcReply`].
    pub fn dispatch_call(&self, call: &RpcCall<'_>) -> RpcReply {
        if call.rpcvers != RPC_VERSION {
            return RpcReply::rpc_mismatch(call.xid);
        }

        if let Err(auth_stat) = validate_call_credentials(call, self.owner_uid) {
            return RpcReply::auth_error(call.xid, auth_stat);
        }

        match call.prog {
            MOUNT_PROGRAM => {
                if call.vers != MOUNT_V3 {
                    return RpcReply::accepted_error(
                        call.xid,
                        RpcAcceptStat::ProgMismatch {
                            low: MOUNT_V3,
                            high: MOUNT_V3,
                        },
                    );
                }
                self.dispatch_mount_v3(call.xid, call.proc_num, call.args)
            }
            NFS_PROGRAM => {
                if call.vers != NFS_V3 {
                    return RpcReply::accepted_error(
                        call.xid,
                        RpcAcceptStat::ProgMismatch {
                            low: NFS_V3,
                            high: NFS_V3,
                        },
                    );
                }
                self.dispatch_nfs_v3(call.xid, call.proc_num, call.args)
            }
            _ => RpcReply::accepted_error(call.xid, RpcAcceptStat::ProgUnavail),
        }
    }

    fn dispatch_mount_v3(&self, xid: u32, proc_num: u32, args: &[u8]) -> RpcReply {
        let mut r = XdrReader::new(args);
        let mut w = XdrWriter::new();

        let decode_res: Result<(), XdrError> = match proc_num {
            MOUNTPROC3_NULL => Ok(()),
            MOUNTPROC3_MNT => self.mount_mnt(&mut r, &mut w),
            MOUNTPROC3_DUMP => {
                w.write_bool(false);
                Ok(())
            }
            MOUNTPROC3_UMNT => self.mount_umnt(&mut r),
            MOUNTPROC3_UMNTALL => {
                self.active_mounts.store(0, Ordering::Relaxed);
                Ok(())
            }
            _ => return RpcReply::accepted_error(xid, RpcAcceptStat::ProcUnavail),
        };

        match decode_res {
            Ok(()) => RpcReply::success(xid, w.into_bytes()),
            Err(_) => RpcReply::accepted_error(xid, RpcAcceptStat::GarbageArgs),
        }
    }

    fn mount_mnt(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let dir_path = r.read_string(NFS3_MAXPATHLEN)?;
        let trimmed = dir_path.trim_matches('/');
        if !trimmed.is_empty() {
            w.write_u32(MNT3ERR_NOENT);
            return Ok(());
        }

        if let Err(err) = self.vfs.getattr("") {
            let mnt_stat = match err {
                VfsError::NotFound => MNT3ERR_NOENT,
                VfsError::PermissionDenied => MNT3ERR_ACCES,
                VfsError::NotADirectory => MNT3ERR_NOTDIR,
                VfsError::NameTooLong => MNT3ERR_NAMETOOLONG,
                VfsError::NotSupported => MNT3ERR_NOTSUPP,
                VfsError::InvalidInput(_) | VfsError::AmbiguousCase(_) => MNT3ERR_INVAL,
                _ => MNT3ERR_IO,
            };
            w.write_u32(mnt_stat);
            return Ok(());
        }

        self.active_mounts.fetch_add(1, Ordering::Relaxed);
        w.write_u32(MNT3_OK);
        self.root_file_handle().encode(w);
        // Supported auth_flavors: [AUTH_UNIX]
        w.write_u32(1);
        w.write_u32(AUTH_UNIX);
        Ok(())
    }

    fn mount_umnt(&self, r: &mut XdrReader<'_>) -> Result<(), XdrError> {
        let dir_path = r.read_string(NFS3_MAXPATHLEN)?;
        if dir_path.trim_matches('/').is_empty() {
            loop {
                let cur = self.active_mounts.load(Ordering::Relaxed);
                if cur == 0 {
                    break;
                }
                if self
                    .active_mounts
                    .compare_exchange_weak(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
        Ok(())
    }

    fn dispatch_nfs_v3(&self, xid: u32, proc_num: u32, args: &[u8]) -> RpcReply {
        let mut r = XdrReader::new(args);
        let mut w = XdrWriter::with_capacity(128);

        let decode_res: Result<(), XdrError> = match proc_num {
            NFSPROC3_NULL => Ok(()),
            NFSPROC3_GETATTR => self.nfs_getattr(&mut r, &mut w),
            NFSPROC3_SETATTR => self.nfs_setattr(&mut r, &mut w),
            NFSPROC3_LOOKUP => self.nfs_lookup(&mut r, &mut w),
            NFSPROC3_ACCESS => self.nfs_access(&mut r, &mut w),
            NFSPROC3_READLINK => self.nfs_readlink(&mut r, &mut w),
            NFSPROC3_READ => self.nfs_read(&mut r, &mut w),
            NFSPROC3_WRITE => self.nfs_write(&mut r, &mut w),
            NFSPROC3_CREATE => self.nfs_create(&mut r, &mut w),
            NFSPROC3_MKDIR => self.nfs_mkdir(&mut r, &mut w),
            NFSPROC3_SYMLINK => self.nfs_symlink(&mut r, &mut w),
            NFSPROC3_MKNOD => self.nfs_mknod(&mut r, &mut w),
            NFSPROC3_REMOVE => self.nfs_remove(&mut r, &mut w),
            NFSPROC3_RMDIR => self.nfs_rmdir(&mut r, &mut w),
            NFSPROC3_RENAME => self.nfs_rename(&mut r, &mut w),
            NFSPROC3_LINK => self.nfs_link(&mut r, &mut w),
            NFSPROC3_READDIR => self.nfs_readdir(&mut r, &mut w),
            NFSPROC3_READDIRPLUS => self.nfs_readdirplus(&mut r, &mut w),
            NFSPROC3_FSSTAT => self.nfs_fsstat(&mut r, &mut w),
            NFSPROC3_FSINFO => self.nfs_fsinfo(&mut r, &mut w),
            NFSPROC3_PATHCONF => self.nfs_pathconf(&mut r, &mut w),
            NFSPROC3_FLUSH_WRITES => self.nfs_flush_writes(&mut r, &mut w),
            _ => return RpcReply::accepted_error(xid, RpcAcceptStat::ProcUnavail),
        };

        match decode_res {
            Ok(()) => RpcReply::success(xid, w.into_bytes()),
            Err(_) => RpcReply::accepted_error(xid, RpcAcceptStat::GarbageArgs),
        }
    }

    fn nfs_getattr(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_fh = NfsFileHandle::decode_raw(r)?;
        let path = match self.resolve_fh_path(raw_fh) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                return Ok(());
            }
        };

        match self.vfs.getattr(&path) {
            Ok(attr) => {
                w.write_u32(NFS3_OK);
                NfsFattr3::from_vfs_attr(attr, self.owner_uid, self.owner_gid).encode(w);
            }
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
            }
        }
        Ok(())
    }

    fn nfs_setattr(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_fh = NfsFileHandle::decode_raw(r)?;
        let sattr = NfsSattr3::decode(r)?;
        let guard_ctime = if r.read_bool()? {
            Some(NfsTime3::decode(r)?)
        } else {
            None
        };

        let path = match self.resolve_fh_path(raw_fh) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_wcc_data(w, None, None, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        let pre_attr = match self.vfs.getattr(&path) {
            Ok(a) => a,
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
                write_wcc_data(w, None, None, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        if pre_attr.read_only {
            w.write_u32(NFS3ERR_ROFS);
            write_wcc_data(
                w,
                Some(pre_attr),
                Some(pre_attr),
                self.owner_uid,
                self.owner_gid,
            );
            return Ok(());
        }

        if let Some(expected_ctime) = guard_ctime {
            let current_ctime = NfsTime3::from(pre_attr.mtime);
            if current_ctime != expected_ctime {
                w.write_u32(NFS3ERR_CTIME_MISMATCH);
                write_wcc_data(
                    w,
                    Some(pre_attr),
                    Some(pre_attr),
                    self.owner_uid,
                    self.owner_gid,
                );
                return Ok(());
            }
        }

        let vfs_req = sattr.to_vfs_setattr();
        if vfs_req.mode.is_none() && vfs_req.size.is_none() && vfs_req.mtime.is_none() {
            w.write_u32(NFS3_OK);
            write_wcc_data(
                w,
                Some(pre_attr),
                Some(pre_attr),
                self.owner_uid,
                self.owner_gid,
            );
            return Ok(());
        }

        match self.vfs.setattr(&path, vfs_req) {
            Ok(post_attr) => {
                w.write_u32(NFS3_OK);
                write_wcc_data(
                    w,
                    Some(pre_attr),
                    Some(post_attr),
                    self.owner_uid,
                    self.owner_gid,
                );
            }
            Err(err) => {
                let post_attr = self.vfs.getattr(&path).ok();
                w.write_u32(err.to_nfs3_stat());
                write_wcc_data(w, Some(pre_attr), post_attr, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_lookup(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_dir_fh = NfsFileHandle::decode_raw(r)?;
        let name_raw = r.read_string(NFS3_MAXPATHLEN)?;

        let (dir_path, dir_attr) = match self.resolve_dir_fh(raw_dir_fh) {
            Ok(pair) => pair,
            Err((stat, attr)) => {
                w.write_u32(stat);
                write_post_op_attr(w, attr, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        if let Err(stat) = validate_lookup_name(&name_raw) {
            w.write_u32(stat);
            write_post_op_attr(w, Some(dir_attr), self.owner_uid, self.owner_gid);
            return Ok(());
        }

        let target_path = if name_raw == "." {
            dir_path
        } else if name_raw == ".." {
            parent_mount_path(&dir_path).to_owned()
        } else {
            join_mount_path(&dir_path, &name_raw)
        };

        match self.vfs.getattr(&target_path) {
            Ok(obj_attr) => {
                let obj_fh = self.handle_for_path(&target_path);
                w.write_u32(NFS3_OK);
                obj_fh.encode(w);
                write_post_op_attr(w, Some(obj_attr), self.owner_uid, self.owner_gid);
                write_post_op_attr(w, Some(dir_attr), self.owner_uid, self.owner_gid);
            }
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
                write_post_op_attr(w, Some(dir_attr), self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_access(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_fh = NfsFileHandle::decode_raw(r)?;
        let requested = r.read_u32()?;

        let path = match self.resolve_fh_path(raw_fh) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_post_op_attr(w, None, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        match self.vfs.getattr(&path) {
            Ok(attr) => {
                let mut allowed = 0u32;
                if attr.read_only {
                    if attr.kind == NodeKind::Directory {
                        allowed |= ACCESS3_READ | ACCESS3_LOOKUP;
                    } else {
                        allowed |= ACCESS3_READ;
                    }
                } else {
                    let m = attr.mode;
                    match attr.kind {
                        NodeKind::Directory => {
                            if (m & 0o400) != 0 {
                                allowed |= ACCESS3_READ;
                            }
                            if (m & 0o100) != 0 {
                                allowed |= ACCESS3_LOOKUP;
                            }
                            if (m & 0o200) != 0 {
                                allowed |= ACCESS3_MODIFY | ACCESS3_EXTEND | ACCESS3_DELETE;
                            }
                        }
                        NodeKind::File => {
                            if (m & 0o400) != 0 {
                                allowed |= ACCESS3_READ;
                            }
                            if (m & 0o200) != 0 {
                                allowed |= ACCESS3_MODIFY | ACCESS3_EXTEND;
                            }
                            if (m & 0o100) != 0 {
                                allowed |= ACCESS3_EXECUTE;
                            }
                        }
                        NodeKind::Symlink => {
                            allowed |= ACCESS3_READ;
                        }
                    }
                }
                w.write_u32(NFS3_OK);
                write_post_op_attr(w, Some(attr), self.owner_uid, self.owner_gid);
                w.write_u32(requested & allowed);
            }
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
                write_post_op_attr(w, None, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_readlink(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_fh = NfsFileHandle::decode_raw(r)?;
        let path = match self.resolve_fh_path(raw_fh) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_post_op_attr(w, None, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        let post_attr = self.vfs.getattr(&path).ok();
        match self.vfs.readlink(&path) {
            Ok(target) => {
                w.write_u32(NFS3_OK);
                write_post_op_attr(w, post_attr, self.owner_uid, self.owner_gid);
                w.write_string(&target);
            }
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
                write_post_op_attr(w, post_attr, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_read(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_fh = NfsFileHandle::decode_raw(r)?;
        let offset = r.read_u64()?;
        let count = r.read_u32()?.min(NFS3_MAX_IOSIZE) as usize;

        let path = match self.resolve_fh_path(raw_fh) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_post_op_attr(w, None, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        let attr = match self.vfs.getattr(&path) {
            Ok(a) => a,
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
                write_post_op_attr(w, None, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        match self.vfs.read(&path, offset, count) {
            Ok(bytes) => {
                let eof = offset.saturating_add(bytes.len() as u64) >= attr.size;
                w.write_u32(NFS3_OK);
                write_post_op_attr(w, Some(attr), self.owner_uid, self.owner_gid);
                w.write_u32(bytes.len() as u32);
                w.write_bool(eof);
                w.write_opaque(&bytes);
            }
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
                write_post_op_attr(w, Some(attr), self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_write(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_fh = NfsFileHandle::decode_raw(r)?;
        let offset = r.read_u64()?;
        let count = r.read_u32()? as usize;
        let _stable_requested = r.read_u32()?;
        let data = r.read_opaque_slice(NFS3_MAX_IOSIZE as usize)?;
        let write_slice = &data[..data.len().min(count)];

        let path = match self.resolve_fh_path(raw_fh) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_wcc_data(w, None, None, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        let pre_attr = self.vfs.getattr(&path).ok();
        match self.vfs.write(&path, offset, write_slice) {
            Ok(written) => {
                let post_attr = self.vfs.getattr(&path).ok();
                w.write_u32(NFS3_OK);
                write_wcc_data(w, pre_attr, post_attr, self.owner_uid, self.owner_gid);
                w.write_u32(written as u32);
                w.write_u32(NFS3_FILE_STABLE);
                w.write_fixed_opaque(&self.write_verf_bytes());
            }
            Err(err) => {
                let post_attr = self.vfs.getattr(&path).ok();
                w.write_u32(err.to_nfs3_stat());
                write_wcc_data(w, pre_attr, post_attr, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_create(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_dir_fh = NfsFileHandle::decode_raw(r)?;
        let name = r.read_string(NFS3_MAXPATHLEN)?;
        let create_mode = r.read_u32()?;
        let (exclusive, sattr) = match create_mode {
            0 => (false, NfsSattr3::decode(r)?), // UNCHECKED
            1 => (true, NfsSattr3::decode(r)?),  // GUARDED
            2 => {
                // EXCLUSIVE: 8-byte createverf3
                let _verf = r.read_fixed_opaque::<8>()?;
                (true, NfsSattr3::default())
            }
            other => return Err(XdrError::InvalidEnumDiscriminant(other)),
        };

        let (dir_path, dir_pre) = match self.resolve_dir_fh(raw_dir_fh) {
            Ok(pair) => pair,
            Err((stat, attr)) => {
                w.write_u32(stat);
                write_wcc_data(w, attr, attr, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        let child_path = match validate_mutation_leaf(&dir_path, &name, true) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_wcc_data(
                    w,
                    Some(dir_pre),
                    Some(dir_pre),
                    self.owner_uid,
                    self.owner_gid,
                );
                return Ok(());
            }
        };

        let mode = sattr.mode.unwrap_or(DEFAULT_FILE_MODE);
        match self.vfs.create_file(&child_path, mode, exclusive) {
            Ok(mut obj_attr) => {
                if sattr.size.is_some() || sattr.mtime.is_some() {
                    if let Ok(updated) = self.vfs.setattr(&child_path, sattr.to_vfs_setattr()) {
                        obj_attr = updated;
                    }
                }
                let child_fh = self.handle_for_path(&child_path);
                let dir_post = self.vfs.getattr(&dir_path).ok();
                w.write_u32(NFS3_OK);
                write_post_op_fh3(w, Some(child_fh));
                write_post_op_attr(w, Some(obj_attr), self.owner_uid, self.owner_gid);
                write_wcc_data(w, Some(dir_pre), dir_post, self.owner_uid, self.owner_gid);
            }
            Err(err) => {
                let dir_post = self.vfs.getattr(&dir_path).ok();
                w.write_u32(err.to_nfs3_stat());
                write_wcc_data(w, Some(dir_pre), dir_post, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_mkdir(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_dir_fh = NfsFileHandle::decode_raw(r)?;
        let name = r.read_string(NFS3_MAXPATHLEN)?;
        let sattr = NfsSattr3::decode(r)?;

        let (dir_path, dir_pre) = match self.resolve_dir_fh(raw_dir_fh) {
            Ok(pair) => pair,
            Err((stat, attr)) => {
                w.write_u32(stat);
                write_wcc_data(w, attr, attr, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        let child_path = match validate_mutation_leaf(&dir_path, &name, true) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_wcc_data(
                    w,
                    Some(dir_pre),
                    Some(dir_pre),
                    self.owner_uid,
                    self.owner_gid,
                );
                return Ok(());
            }
        };

        let mode = sattr.mode.unwrap_or(DEFAULT_DIR_MODE);
        match self.vfs.mkdir(&child_path, mode) {
            Ok(mut obj_attr) => {
                if sattr.mtime.is_some() {
                    if let Ok(updated) = self.vfs.setattr(
                        &child_path,
                        VfsSetAttr {
                            mode: sattr.mode,
                            size: None,
                            mtime: sattr.mtime,
                        },
                    ) {
                        obj_attr = updated;
                    }
                }
                let child_fh = self.handle_for_path(&child_path);
                let dir_post = self.vfs.getattr(&dir_path).ok();
                w.write_u32(NFS3_OK);
                write_post_op_fh3(w, Some(child_fh));
                write_post_op_attr(w, Some(obj_attr), self.owner_uid, self.owner_gid);
                write_wcc_data(w, Some(dir_pre), dir_post, self.owner_uid, self.owner_gid);
            }
            Err(err) => {
                let dir_post = self.vfs.getattr(&dir_path).ok();
                w.write_u32(err.to_nfs3_stat());
                write_wcc_data(w, Some(dir_pre), dir_post, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_symlink(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_dir_fh = NfsFileHandle::decode_raw(r)?;
        let name = r.read_string(NFS3_MAXPATHLEN)?;
        let _sym_sattr = NfsSattr3::decode(r)?;
        let target = r.read_string(NFS3_MAXPATHLEN)?;

        let (dir_path, dir_pre) = match self.resolve_dir_fh(raw_dir_fh) {
            Ok(pair) => pair,
            Err((stat, attr)) => {
                w.write_u32(stat);
                write_wcc_data(w, attr, attr, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        let child_path = match validate_mutation_leaf(&dir_path, &name, true) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_wcc_data(
                    w,
                    Some(dir_pre),
                    Some(dir_pre),
                    self.owner_uid,
                    self.owner_gid,
                );
                return Ok(());
            }
        };

        match self.vfs.symlink(&target, &child_path) {
            Ok(obj_attr) => {
                let child_fh = self.handle_for_path(&child_path);
                let dir_post = self.vfs.getattr(&dir_path).ok();
                w.write_u32(NFS3_OK);
                write_post_op_fh3(w, Some(child_fh));
                write_post_op_attr(w, Some(obj_attr), self.owner_uid, self.owner_gid);
                write_wcc_data(w, Some(dir_pre), dir_post, self.owner_uid, self.owner_gid);
            }
            Err(err) => {
                let dir_post = self.vfs.getattr(&dir_path).ok();
                w.write_u32(err.to_nfs3_stat());
                write_wcc_data(w, Some(dir_pre), dir_post, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_mknod(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_dir_fh = NfsFileHandle::decode_raw(r)?;
        let _name = r.read_string(NFS3_MAXPATHLEN)?;
        let ftype = r.read_u32()?;
        match ftype {
            3 | 4 => {
                // NF3BLK | NF3CHR: devdata3 = sattr3 + specdata3
                let _ = NfsSattr3::decode(r)?;
                let _ = r.read_u32()?;
                let _ = r.read_u32()?;
            }
            6 | 7 => {
                // NF3SOCK | NF3FIFO: sattr3
                let _ = NfsSattr3::decode(r)?;
            }
            _ => {}
        }

        let dir_attr = self
            .resolve_fh_path(raw_dir_fh)
            .ok()
            .and_then(|p| self.vfs.getattr(&p).ok());
        w.write_u32(NFS3ERR_NOTSUPP);
        write_wcc_data(w, dir_attr, dir_attr, self.owner_uid, self.owner_gid);
        Ok(())
    }

    fn nfs_remove(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_dir_fh = NfsFileHandle::decode_raw(r)?;
        let name = r.read_string(NFS3_MAXPATHLEN)?;

        let (dir_path, dir_pre) = match self.resolve_dir_fh(raw_dir_fh) {
            Ok(pair) => pair,
            Err((stat, attr)) => {
                w.write_u32(stat);
                write_wcc_data(w, attr, attr, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        let child_path = match validate_mutation_leaf(&dir_path, &name, false) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_wcc_data(
                    w,
                    Some(dir_pre),
                    Some(dir_pre),
                    self.owner_uid,
                    self.owner_gid,
                );
                return Ok(());
            }
        };

        match self.vfs.unlink(&child_path) {
            Ok(()) => {
                self.inodes.remove_subtree(&child_path);
                let dir_post = self.vfs.getattr(&dir_path).ok();
                w.write_u32(NFS3_OK);
                write_wcc_data(w, Some(dir_pre), dir_post, self.owner_uid, self.owner_gid);
            }
            Err(err) => {
                let dir_post = self.vfs.getattr(&dir_path).ok();
                w.write_u32(err.to_nfs3_stat());
                write_wcc_data(w, Some(dir_pre), dir_post, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_rmdir(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_dir_fh = NfsFileHandle::decode_raw(r)?;
        let name = r.read_string(NFS3_MAXPATHLEN)?;

        let (dir_path, dir_pre) = match self.resolve_dir_fh(raw_dir_fh) {
            Ok(pair) => pair,
            Err((stat, attr)) => {
                w.write_u32(stat);
                write_wcc_data(w, attr, attr, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        let child_path = match validate_mutation_leaf(&dir_path, &name, false) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_wcc_data(
                    w,
                    Some(dir_pre),
                    Some(dir_pre),
                    self.owner_uid,
                    self.owner_gid,
                );
                return Ok(());
            }
        };

        match self.vfs.rmdir(&child_path) {
            Ok(()) => {
                self.inodes.remove_subtree(&child_path);
                let dir_post = self.vfs.getattr(&dir_path).ok();
                w.write_u32(NFS3_OK);
                write_wcc_data(w, Some(dir_pre), dir_post, self.owner_uid, self.owner_gid);
            }
            Err(err) => {
                let dir_post = self.vfs.getattr(&dir_path).ok();
                w.write_u32(err.to_nfs3_stat());
                write_wcc_data(w, Some(dir_pre), dir_post, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_rename(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_from_dir = NfsFileHandle::decode_raw(r)?;
        let from_name = r.read_string(NFS3_MAXPATHLEN)?;
        let raw_to_dir = NfsFileHandle::decode_raw(r)?;
        let to_name = r.read_string(NFS3_MAXPATHLEN)?;

        let from_resolved = self.resolve_dir_fh(raw_from_dir);
        let to_resolved = self.resolve_dir_fh(raw_to_dir);

        let ((from_dir_path, from_pre), (to_dir_path, to_pre)) = match (from_resolved, to_resolved)
        {
            (Ok(f), Ok(t)) => (f, t),
            (Err((stat, f_attr)), t_res) => {
                let t_attr = t_res.ok().map(|(_, a)| a);
                w.write_u32(stat);
                write_wcc_data(w, f_attr, f_attr, self.owner_uid, self.owner_gid);
                write_wcc_data(w, t_attr, t_attr, self.owner_uid, self.owner_gid);
                return Ok(());
            }
            (Ok((_, f_attr)), Err((stat, t_attr))) => {
                w.write_u32(stat);
                write_wcc_data(
                    w,
                    Some(f_attr),
                    Some(f_attr),
                    self.owner_uid,
                    self.owner_gid,
                );
                write_wcc_data(w, t_attr, t_attr, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        let from_path = match validate_mutation_leaf(&from_dir_path, &from_name, false) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_wcc_data(
                    w,
                    Some(from_pre),
                    Some(from_pre),
                    self.owner_uid,
                    self.owner_gid,
                );
                write_wcc_data(
                    w,
                    Some(to_pre),
                    Some(to_pre),
                    self.owner_uid,
                    self.owner_gid,
                );
                return Ok(());
            }
        };

        let to_path = match validate_mutation_leaf(&to_dir_path, &to_name, false) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_wcc_data(
                    w,
                    Some(from_pre),
                    Some(from_pre),
                    self.owner_uid,
                    self.owner_gid,
                );
                write_wcc_data(
                    w,
                    Some(to_pre),
                    Some(to_pre),
                    self.owner_uid,
                    self.owner_gid,
                );
                return Ok(());
            }
        };

        match self.vfs.rename(&from_path, &to_path) {
            Ok(()) => {
                self.inodes.rename_subtree(&from_path, &to_path);
                let from_post = self.vfs.getattr(&from_dir_path).ok();
                let to_post = self.vfs.getattr(&to_dir_path).ok();
                w.write_u32(NFS3_OK);
                write_wcc_data(w, Some(from_pre), from_post, self.owner_uid, self.owner_gid);
                write_wcc_data(w, Some(to_pre), to_post, self.owner_uid, self.owner_gid);
            }
            Err(err) => {
                let from_post = self.vfs.getattr(&from_dir_path).ok();
                let to_post = self.vfs.getattr(&to_dir_path).ok();
                w.write_u32(err.to_nfs3_stat());
                write_wcc_data(w, Some(from_pre), from_post, self.owner_uid, self.owner_gid);
                write_wcc_data(w, Some(to_pre), to_post, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_link(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_file_fh = NfsFileHandle::decode_raw(r)?;
        let raw_dir_fh = NfsFileHandle::decode_raw(r)?;
        let link_name = r.read_string(NFS3_MAXPATHLEN)?;

        let file_path_opt = self.resolve_fh_path(raw_file_fh).ok();
        let file_attr = file_path_opt
            .as_deref()
            .and_then(|p| self.vfs.getattr(p).ok());
        let dir_path_opt = self.resolve_fh_path(raw_dir_fh).ok();
        let dir_attr = dir_path_opt
            .as_deref()
            .and_then(|p| self.vfs.getattr(p).ok());

        let stat = match (&file_path_opt, &dir_path_opt) {
            (Some(existing), Some(dir_p)) => {
                let dest = join_mount_path(dir_p, &link_name);
                match self.vfs.link(existing, &dest) {
                    Ok(_) => NFS3ERR_NOTSUPP,
                    Err(err) => err.to_nfs3_stat(),
                }
            }
            _ => NFS3ERR_NOTSUPP,
        };

        w.write_u32(stat);
        write_post_op_attr(w, file_attr, self.owner_uid, self.owner_gid);
        write_wcc_data(w, dir_attr, dir_attr, self.owner_uid, self.owner_gid);
        Ok(())
    }

    fn nfs_readdir(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_dir_fh = NfsFileHandle::decode_raw(r)?;
        let cookie = r.read_u64()?;
        let _cookieverf = r.read_fixed_opaque::<8>()?;
        let max_bytes = r.read_u32()? as usize;

        let (dir_path, dir_attr) = match self.resolve_dir_fh(raw_dir_fh) {
            Ok(pair) => pair,
            Err((stat, attr)) => {
                w.write_u32(stat);
                write_post_op_attr(w, attr, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        if max_bytes < 128 {
            w.write_u32(NFS3ERR_TOOSMALL);
            write_post_op_attr(w, Some(dir_attr), self.owner_uid, self.owner_gid);
            return Ok(());
        }

        let children = match self.vfs.readdir(&dir_path) {
            Ok(list) => list,
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
                write_post_op_attr(w, Some(dir_attr), self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        let parent_path = parent_mount_path(&dir_path);
        let parent_ino = self
            .vfs
            .getattr(parent_path)
            .map(|a| a.ino)
            .unwrap_or(ROOT_INO);

        w.write_u32(NFS3_OK);
        write_post_op_attr(w, Some(dir_attr), self.owner_uid, self.owner_gid);
        w.write_fixed_opaque(&[0u8; 8]); // cookieverf3

        let mut all_entries: Vec<(u64, u64, String)> = Vec::with_capacity(2 + children.len());
        all_entries.push((1, dir_attr.ino, ".".to_owned()));
        all_entries.push((2, parent_ino, "..".to_owned()));
        for (idx, item) in children.into_iter().enumerate() {
            let child_mount = join_mount_path(&dir_path, &item.name);
            let _ = self.inodes.get_or_alloc(&child_mount);
            all_entries.push((3 + idx as u64, item.ino, item.name));
        }

        let mut eof = true;
        for (entry_cookie, fileid, name) in all_entries {
            if entry_cookie <= cookie {
                continue;
            }
            let name_wire = 4 + name.len() + xdr_pad_len(name.len());
            let entry_wire = 4 + 8 + name_wire + 8;
            // Reserve 8 trailing bytes for `value_follows = false` + `eof` bool.
            if w.len() + entry_wire + 8 > max_bytes {
                eof = false;
                break;
            }
            w.write_bool(true);
            w.write_u64(fileid);
            w.write_string(&name);
            w.write_u64(entry_cookie);
        }

        w.write_bool(false);
        w.write_bool(eof);
        Ok(())
    }

    fn nfs_readdirplus(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_dir_fh = NfsFileHandle::decode_raw(r)?;
        let cookie = r.read_u64()?;
        let _cookieverf = r.read_fixed_opaque::<8>()?;
        let _dircount = r.read_u32()?;
        let maxcount = r.read_u32()? as usize;

        let (dir_path, dir_attr) = match self.resolve_dir_fh(raw_dir_fh) {
            Ok(pair) => pair,
            Err((stat, attr)) => {
                w.write_u32(stat);
                write_post_op_attr(w, attr, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        if maxcount < 256 {
            w.write_u32(NFS3ERR_TOOSMALL);
            write_post_op_attr(w, Some(dir_attr), self.owner_uid, self.owner_gid);
            return Ok(());
        }

        let children = match self.vfs.readdir(&dir_path) {
            Ok(list) => list,
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
                write_post_op_attr(w, Some(dir_attr), self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        let parent_path = parent_mount_path(&dir_path).to_owned();
        let parent_attr = self.vfs.getattr(&parent_path).ok();
        let parent_ino = parent_attr.map(|a| a.ino).unwrap_or(ROOT_INO);

        w.write_u32(NFS3_OK);
        write_post_op_attr(w, Some(dir_attr), self.owner_uid, self.owner_gid);
        w.write_fixed_opaque(&[0u8; 8]); // cookieverf3

        let mut rows: Vec<(u64, u64, String, String)> = Vec::with_capacity(2 + children.len());
        rows.push((1, dir_attr.ino, ".".to_owned(), dir_path.clone()));
        rows.push((2, parent_ino, "..".to_owned(), parent_path));
        for (idx, item) in children.into_iter().enumerate() {
            let child_mount = join_mount_path(&dir_path, &item.name);
            rows.push((3 + idx as u64, item.ino, item.name, child_mount));
        }

        let mut eof = true;
        for (entry_cookie, fileid, name, mount_str) in rows {
            if entry_cookie <= cookie {
                continue;
            }
            let name_wire = 4 + name.len() + xdr_pad_len(name.len());
            // bool(4) + fileid(8) + name + cookie(8) + post_op_attr(88) + post_op_fh3(24) = 132 + name_wire
            let entry_wire = 132 + name_wire;
            if w.len() + entry_wire + 8 > maxcount {
                eof = false;
                break;
            }
            let attr_opt = self.vfs.getattr(&mount_str).ok();
            let fh = self.handle_for_path(&mount_str);
            w.write_bool(true);
            w.write_u64(fileid);
            w.write_string(&name);
            w.write_u64(entry_cookie);
            write_post_op_attr(w, attr_opt, self.owner_uid, self.owner_gid);
            write_post_op_fh3(w, Some(fh));
        }

        w.write_bool(false);
        w.write_bool(eof);
        Ok(())
    }

    fn nfs_fsstat(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_fh = NfsFileHandle::decode_raw(r)?;
        let path = match self.resolve_fh_path(raw_fh) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_post_op_attr(w, None, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        match self.vfs.getattr(&path) {
            Ok(attr) => {
                const VIRTUAL_BYTES: u64 = 1_099_511_627_776; // 1 TiB
                const VIRTUAL_FILES: u64 = 1_000_000;
                w.write_u32(NFS3_OK);
                write_post_op_attr(w, Some(attr), self.owner_uid, self.owner_gid);
                w.write_u64(VIRTUAL_BYTES);
                w.write_u64(VIRTUAL_BYTES);
                w.write_u64(VIRTUAL_BYTES);
                w.write_u64(VIRTUAL_FILES);
                w.write_u64(VIRTUAL_FILES);
                w.write_u64(VIRTUAL_FILES);
                w.write_u32(0); // invarsec
            }
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
                write_post_op_attr(w, None, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_fsinfo(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_fh = NfsFileHandle::decode_raw(r)?;
        let path = match self.resolve_fh_path(raw_fh) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_post_op_attr(w, None, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        match self.vfs.getattr(&path) {
            Ok(attr) => {
                w.write_u32(NFS3_OK);
                write_post_op_attr(w, Some(attr), self.owner_uid, self.owner_gid);
                w.write_u32(NFS3_MAX_IOSIZE); // rtmax
                w.write_u32(NFS3_PREF_IOSIZE); // rtpref
                w.write_u32(4096); // rtmult
                w.write_u32(NFS3_MAX_IOSIZE); // wtmax
                w.write_u32(NFS3_PREF_IOSIZE); // wtpref
                w.write_u32(4096); // wtmult
                w.write_u32(NFS3_PREF_IOSIZE); // dtpref
                w.write_u64(i64::MAX as u64); // maxfilesize
                                              // Precision: 1 nanosecond
                (NfsTime3 {
                    seconds: 0,
                    nseconds: 1,
                })
                .encode(w);
                // Omit FSF3_LINK because hard links are unsupported across Base + Overlay.
                w.write_u32(FSF3_SYMLINK | FSF3_HOMOGENEOUS | FSF3_CANSETTIME);
            }
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
                write_post_op_attr(w, None, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_pathconf(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_fh = NfsFileHandle::decode_raw(r)?;
        let path = match self.resolve_fh_path(raw_fh) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_post_op_attr(w, None, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        match self.vfs.getattr(&path) {
            Ok(attr) => {
                w.write_u32(NFS3_OK);
                write_post_op_attr(w, Some(attr), self.owner_uid, self.owner_gid);
                w.write_u32(1); // linkmax = 1 (hard links unsupported)
                w.write_u32(NFS3_MAXNAMLEN as u32); // name_max
                w.write_bool(true); // no_trunc
                w.write_bool(true); // chown_restricted
                w.write_bool(false); // case_insensitive
                w.write_bool(true); // case_preserving
            }
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
                write_post_op_attr(w, None, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }

    fn nfs_flush_writes(&self, r: &mut XdrReader<'_>, w: &mut XdrWriter) -> Result<(), XdrError> {
        let raw_fh = NfsFileHandle::decode_raw(r)?;
        let _offset = r.read_u64()?;
        let _count = r.read_u32()?;

        let path = match self.resolve_fh_path(raw_fh) {
            Ok(p) => p,
            Err(stat) => {
                w.write_u32(stat);
                write_wcc_data(w, None, None, self.owner_uid, self.owner_gid);
                return Ok(());
            }
        };

        match self.vfs.getattr(&path) {
            Ok(attr) => {
                w.write_u32(NFS3_OK);
                write_wcc_data(w, Some(attr), Some(attr), self.owner_uid, self.owner_gid);
                w.write_fixed_opaque(&self.write_verf_bytes());
            }
            Err(err) => {
                w.write_u32(err.to_nfs3_stat());
                write_wcc_data(w, None, None, self.owner_uid, self.owner_gid);
            }
        }
        Ok(())
    }
}
