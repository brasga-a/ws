//! `bit-vfs-nfs`: macOS userspace loopback NFSv3 VFS adapter over [`bit_core::VfsOperations`]
//! (ADR-0002, ADR-0004, ADR-0005).
//!
//! Exposes every active `View` (`Base` + private `Overlay`) under `<mount>/<view-id>/` via a pure
//! `std` ONC-RPC v2 + `MOUNTv3` + stateless `NFSv3` server bound strictly to `127.0.0.1` with
//! mandatory `AUTH_UNIX` `owner_uid` verification and local kernel advisory locks
//! (`vers=3,tcp,nolocks,locallocks`).
//!
//! ### Accepted macOS Trade-off (`FSEvents` / `MNT_LOCAL`) & Future `FSKit` Evolution
//! Avoiding `macFUSE` eliminates third-party kernel extensions on Apple Silicon Macs, at the
//! documented trade-off that XNU mounts NFSv3 volumes without `MNT_LOCAL`; `FSEvents` therefore
//! does not emit push notifications inside `<mount>/<view-id>/`, and file watchers rely on
//! `kqueue`, polling, or Watchman until a future `FSKit` backend is adopted.
#![deny(unsafe_code)]

pub mod config;
pub mod nfs;
pub mod rpc;
pub mod server;
pub mod xdr;

#[cfg(test)]
mod tests;

pub use config::{
    build_stale_umount_args, build_stale_umount_command, NfsConfigError, NfsMountConfig,
    LOOPBACK_NFS_SHARE_SPEC, MACOS_MOUNT_NFS_BIN, MACOS_UMOUNT_BIN,
};
pub use nfs::{
    NfsDispatcher, NfsFattr3, NfsFileHandle, NfsFileType, NfsSattr3, NfsTime3, ACCESS3_DELETE,
    ACCESS3_EXECUTE, ACCESS3_EXTEND, ACCESS3_LOOKUP, ACCESS3_MODIFY, ACCESS3_READ, BIT_FH_LEN,
    DEFAULT_INSTANCE_ID, FSF3_CANSETTIME, FSF3_HOMOGENEOUS, FSF3_LINK, FSF3_SYMLINK, MNT3ERR_ACCES,
    MNT3ERR_INVAL, MNT3ERR_IO, MNT3ERR_NAMETOOLONG, MNT3ERR_NOENT, MNT3ERR_NOTDIR, MNT3ERR_NOTSUPP,
    MNT3ERR_PERM, MNT3ERR_SERVERFAULT, MNT3_OK, MOUNTPROC3_DUMP, MOUNTPROC3_MNT, MOUNTPROC3_NULL,
    MOUNTPROC3_UMNT, MOUNTPROC3_UMNTALL, MOUNT_FSID, MOUNT_PROGRAM, MOUNT_V3, NFS3ERR_ACCES,
    NFS3ERR_BADHANDLE, NFS3ERR_BAD_COOKIE, NFS3ERR_CTIME_MISMATCH, NFS3ERR_EXIST, NFS3ERR_INVAL,
    NFS3ERR_IO, NFS3ERR_ISDIR, NFS3ERR_NAMETOOLONG, NFS3ERR_NOENT, NFS3ERR_NOTDIR,
    NFS3ERR_NOTEMPTY, NFS3ERR_NOTSUPP, NFS3ERR_PERM, NFS3ERR_ROFS, NFS3ERR_SERVERFAULT,
    NFS3ERR_STALE, NFS3ERR_TOOSMALL, NFS3ERR_XDEV, NFS3_FHSIZE, NFS3_FILE_STABLE, NFS3_MAXNAMLEN,
    NFS3_MAXPATHLEN, NFS3_MAX_IOSIZE, NFS3_OK, NFS3_PREF_IOSIZE, NFSPROC3_ACCESS, NFSPROC3_CREATE,
    NFSPROC3_FLUSH_WRITES, NFSPROC3_FSINFO, NFSPROC3_FSSTAT, NFSPROC3_GETATTR, NFSPROC3_LINK,
    NFSPROC3_LOOKUP, NFSPROC3_MKDIR, NFSPROC3_MKNOD, NFSPROC3_NULL, NFSPROC3_PATHCONF,
    NFSPROC3_READ, NFSPROC3_READDIR, NFSPROC3_READDIRPLUS, NFSPROC3_READLINK, NFSPROC3_REMOVE,
    NFSPROC3_RENAME, NFSPROC3_RMDIR, NFSPROC3_SETATTR, NFSPROC3_SYMLINK, NFSPROC3_WRITE,
    NFS_PROGRAM, NFS_V3,
};
pub use rpc::{
    decode_rpc_record, encode_rpc_record, encode_rpc_record_fragmented, read_rpc_record,
    validate_call_credentials, write_rpc_record, AuthStat, AuthUnixCred, OpaqueAuth, RpcAcceptStat,
    RpcCall, RpcError, RpcRejectedReply, RpcReply, RpcReplyBody, AUTH_NONE, AUTH_UNIX,
    LAST_FRAGMENT_BIT, MAX_RPC_RECORD_LEN, RPC_VERSION,
};
pub use server::{NfsLoopbackServer, NfsRunningServer, NfsServerError};
pub use xdr::{xdr_pad_len, XdrError, XdrReader, XdrWriter, XDR_ALIGNMENT};
