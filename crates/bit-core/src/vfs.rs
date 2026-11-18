//! OS-agnostic userspace VFS port (`VfsOperations`, `VfsAttr`, `VfsError`, `MountPath`,
//! `InodeTable`, and `QuiescenceManager`) for `bit-vfs-fuse`, `bit-vfs-nfs`, and `bit-vfs-winfsp`
//! (ADR-0002, ADR-0004, ADR-0005).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, RwLock};

use crate::ids::ViewId;
use crate::model::{EntryMetadata, NodeKind, Timestamp, PERM_MASK, S_IFDIR, S_IFLNK, S_IFREG};
use crate::path::{AmbiguousCaseError, PathError, RelPath};
use crate::store::StoreError;

/// Reserved inode number for the read-only mount root `<mount>/`.
pub const ROOT_INO: u64 = 1;

/// Permission mode reported for the read-only mount root `<mount>/` (`r-xr-xr-x`).
pub const MOUNT_ROOT_MODE: u32 = 0o555;

/// Portable VFS error type with protocol mappings for FUSE (POSIX `errno`), NFSv3 (`nfsstat3`),
/// and WinFsp (`NTSTATUS` categories).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VfsError {
    /// Entry or `View` does not exist (`ENOENT`).
    NotFound,
    /// Entry already exists (`EEXIST`).
    AlreadyExists,
    /// Expected a directory (`ENOTDIR`).
    NotADirectory,
    /// Operation not allowed on a directory (`EISDIR`).
    IsADirectory,
    /// Directory still has live entries (`ENOTEMPTY`).
    DirectoryNotEmpty,
    /// Mutation attempted on the read-only `<mount>/` root (`EROFS`).
    ReadOnly,
    /// `rename` attempted across two distinct `Views` (`EXDEV`).
    CrossDevice,
    /// Unsupported filesystem operation such as hard `link()` or special `mknod` (`EOPNOTSUPP`).
    NotSupported,
    /// Permission denied (`EACCES`).
    PermissionDenied,
    /// Filename or path exceeded limits (`ENAMETOOLONG`).
    NameTooLong,
    /// Malformed path, offset, or argument (`EINVAL`).
    InvalidInput(String),
    /// Case-insensitive lookup matched multiple sibling entries (`EINVAL`).
    AmbiguousCase(String),
    /// Backing store or I/O failure (`EIO`).
    Io(String),
}

impl VfsError {
    /// Maps `self` to standard Linux POSIX `errno` constants.
    pub const fn to_posix_errno(&self) -> i32 {
        match self {
            Self::NotFound => 2,                                  // ENOENT
            Self::Io(_) => 5,                                     // EIO
            Self::PermissionDenied => 13,                         // EACCES
            Self::AlreadyExists => 17,                            // EEXIST
            Self::CrossDevice => 18,                              // EXDEV
            Self::NotADirectory => 20,                            // ENOTDIR
            Self::IsADirectory => 21,                             // EISDIR
            Self::InvalidInput(_) | Self::AmbiguousCase(_) => 22, // EINVAL
            Self::ReadOnly => 30,                                 // EROFS
            Self::NameTooLong => 36,                              // ENAMETOOLONG
            Self::DirectoryNotEmpty => 39,                        // ENOTEMPTY
            Self::NotSupported => 95, // EOPNOTSUPP (Linux; macOS adapters can map NotSupported -> 45)
        }
    }

    /// Maps `self` to RFC 1813 NFSv3 `nfsstat3` status codes.
    pub const fn to_nfs3_stat(&self) -> u32 {
        match self {
            Self::NotFound => 2,                                  // NFS3ERR_NOENT
            Self::Io(_) => 5,                                     // NFS3ERR_IO
            Self::PermissionDenied => 13,                         // NFS3ERR_ACCES
            Self::AlreadyExists => 17,                            // NFS3ERR_EXIST
            Self::CrossDevice => 18,                              // NFS3ERR_XDEV
            Self::NotADirectory => 20,                            // NFS3ERR_NOTDIR
            Self::IsADirectory => 21,                             // NFS3ERR_ISDIR
            Self::InvalidInput(_) | Self::AmbiguousCase(_) => 22, // NFS3ERR_INVAL
            Self::ReadOnly => 30,                                 // NFS3ERR_ROFS
            Self::NameTooLong => 63,                              // NFS3ERR_NAMETOOLONG
            Self::DirectoryNotEmpty => 66,                        // NFS3ERR_NOTEMPTY
            Self::NotSupported => 10004,                          // NFS3ERR_NOTSUPP
        }
    }
}

impl fmt::Display for VfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such file or directory (ENOENT)"),
            Self::AlreadyExists => f.write_str("file already exists (EEXIST)"),
            Self::NotADirectory => f.write_str("not a directory (ENOTDIR)"),
            Self::IsADirectory => f.write_str("is a directory (EISDIR)"),
            Self::DirectoryNotEmpty => f.write_str("directory not empty (ENOTEMPTY)"),
            Self::ReadOnly => f.write_str("mount root is read-only (EROFS)"),
            Self::CrossDevice => f.write_str("cross-view rename is not permitted (EXDEV)"),
            Self::NotSupported => f.write_str("operation is not supported (EOPNOTSUPP)"),
            Self::PermissionDenied => f.write_str("permission denied (EACCES)"),
            Self::NameTooLong => f.write_str("file name too long (ENAMETOOLONG)"),
            Self::InvalidInput(msg) => write!(f, "invalid argument (EINVAL): {msg}"),
            Self::AmbiguousCase(msg) => write!(f, "ambiguous case-insensitive lookup: {msg}"),
            Self::Io(msg) => write!(f, "I/O error (EIO): {msg}"),
        }
    }
}

impl std::error::Error for VfsError {}

impl From<PathError> for VfsError {
    fn from(err: PathError) -> Self {
        Self::InvalidInput(err.to_string())
    }
}

impl From<AmbiguousCaseError> for VfsError {
    fn from(err: AmbiguousCaseError) -> Self {
        Self::AmbiguousCase(err.to_string())
    }
}

impl From<StoreError> for VfsError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::ViewNotFound(_) => Self::NotFound,
            other => Self::Io(other.to_string()),
        }
    }
}

/// Attributes of a node in the userspace VFS mount (`<mount>/` or `<mount>/<view-id>/...`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VfsAttr {
    /// Stable virtual inode / file-handle identifier (`ROOT_INO = 1` for `<mount>/`).
    pub ino: u64,
    /// Node kind (`File`, `Directory`, `Symlink`).
    pub kind: NodeKind,
    /// POSIX permission bits (`0..=0o7777`).
    pub mode: u32,
    /// Logical byte size.
    pub size: u64,
    /// Modification timestamp.
    pub mtime: Timestamp,
    /// Link count (`1` for files/symlinks since `link()` is unsupported; `>= 2` for directories).
    pub nlink: u32,
    /// `true` for `<mount>/`, `false` inside writable `Views`.
    pub read_only: bool,
}

impl VfsAttr {
    /// Constructs a `VfsAttr` from `EntryMetadata` and `ino`.
    pub const fn from_metadata(ino: u64, meta: EntryMetadata, nlink: u32, read_only: bool) -> Self {
        Self {
            ino,
            kind: meta.kind,
            mode: meta.mode & PERM_MASK,
            size: meta.size,
            mtime: meta.mtime,
            nlink,
            read_only,
        }
    }

    /// Returns full POSIX `st_mode` combining `S_IF*` and permission bits.
    pub const fn posix_mode(&self) -> u32 {
        let kind_bits = match self.kind {
            NodeKind::File => S_IFREG,
            NodeKind::Directory => S_IFDIR,
            NodeKind::Symlink => S_IFLNK,
        };
        kind_bits | (self.mode & PERM_MASK)
    }
}

/// Entry returned by `VfsOperations::readdir`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VfsDirEntry {
    /// Entry name (`ViewId` when listing `<mount>/`, or `EntryName` inside a `View`).
    pub name: String,
    /// Virtual inode number.
    pub ino: u64,
    /// Node kind.
    pub kind: NodeKind,
}

/// Attribute mutation request passed to `VfsOperations::setattr`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VfsSetAttr {
    /// Optional new POSIX permission bits (`chmod`).
    pub mode: Option<u32>,
    /// Optional new file byte length (`truncate`).
    pub size: Option<u64>,
    /// Optional new modification timestamp (`utimens`).
    pub mtime: Option<Timestamp>,
}

/// Parsed 1-level mount route under `<mount>/` (ADR-0002).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MountPath {
    /// Read-only mount root `<mount>/`.
    Root,
    /// Direct child of `<mount>/` whose name is not a valid `ViewId` (used to distinguish
    /// `ENOENT` on `lookup`/`getattr` from `EROFS` on mutations at `<mount>/`).
    InvalidRootChild(String),
    /// Path routed to `<mount>/<view-id>/<rel>` (`rel.is_root()` for `<mount>/<view-id>` itself).
    View { view: ViewId, rel: RelPath },
}

impl MountPath {
    /// Parses a mount-relative path (accepting both `'/'` and `'\\'` separators at the VFS edge
    /// only when normalized by Windows adapters via `parse_windows`, while canonical `parse`
    /// enforces POSIX `'/'` routing).
    pub fn parse(raw: &str) -> Result<Self, VfsError> {
        if raw.contains('\0') {
            return Err(VfsError::InvalidInput("path contains NUL byte".to_owned()));
        }
        if raw.contains('\\') {
            return Err(VfsError::InvalidInput(
                "path contains backslash separator".to_owned(),
            ));
        }

        let trimmed = raw.trim_matches('/');
        if trimmed.is_empty() || trimmed == "." {
            return Ok(Self::Root);
        }

        let (first, rest) = match trimmed.split_once('/') {
            Some((head, tail)) => (head, Some(tail)),
            None => (trimmed, None),
        };

        if first == ".." {
            return Err(VfsError::InvalidInput(
                "path traversal '..' outside mount root".to_owned(),
            ));
        }

        let Ok(view_id) = ViewId::new(first) else {
            return match rest {
                None => Ok(Self::InvalidRootChild(first.to_owned())),
                Some(_) => Err(VfsError::NotFound),
            };
        };

        match rest {
            None => Ok(Self::View {
                view: view_id,
                rel: RelPath::root(),
            }),
            Some(tail) => {
                let rel = RelPath::normalize(tail)?;
                Ok(Self::View { view: view_id, rel })
            }
        }
    }

    /// Converts a Windows/WinFsp mount-relative path (`\view-id\dir\file`) into a `MountPath`.
    pub fn parse_winfsp(raw: &str) -> Result<Self, VfsError> {
        let converted = raw.replace('\\', "/");
        Self::parse(&converted)
    }

    /// Returns `true` if `self` refers to `<mount>/` itself or a direct 1-level child of `<mount>/`
    /// (`<mount>/<entry>`), where filesystem create/delete/rename operations are forbidden (`EROFS`).
    pub fn is_root_or_direct_root_child(&self) -> bool {
        match self {
            Self::Root | Self::InvalidRootChild(_) => true,
            Self::View { rel, .. } => rel.is_root(),
        }
    }

    /// Formats back into a canonical mount-relative string (`""` for `Root`, `"view/rel"` otherwise).
    pub fn to_mount_string(&self) -> String {
        match self {
            Self::Root => String::new(),
            Self::InvalidRootChild(name) => name.clone(),
            Self::View { view, rel } => {
                if rel.is_root() {
                    view.as_str().to_owned()
                } else {
                    format!("{}/{}", view.as_str(), rel.as_str())
                }
            }
        }
    }
}

#[derive(Debug)]
struct InodeInner {
    next_ino: u64,
    by_path: BTreeMap<String, u64>,
    by_ino: BTreeMap<u64, String>,
}

/// Bidirectional virtual inode (`u64`) <-> mount-path table for FUSE and loopback NFSv3 file handles.
#[derive(Debug)]
pub struct InodeTable {
    inner: RwLock<InodeInner>,
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

impl InodeTable {
    /// Creates an `InodeTable` pre-seeded with `ROOT_INO = 1` -> `""`.
    pub fn new() -> Self {
        let mut by_path = BTreeMap::new();
        let mut by_ino = BTreeMap::new();
        by_path.insert(String::new(), ROOT_INO);
        by_ino.insert(ROOT_INO, String::new());
        Self {
            inner: RwLock::new(InodeInner {
                next_ino: ROOT_INO + 1,
                by_path,
                by_ino,
            }),
        }
    }

    /// Returns the existing `ino` for `canonical_mount_path`, or allocates a fresh one.
    pub fn get_or_alloc(&self, canonical_mount_path: &str) -> u64 {
        if canonical_mount_path.is_empty() {
            return ROOT_INO;
        }
        {
            let read_guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
            if let Some(&ino) = read_guard.by_path.get(canonical_mount_path) {
                return ino;
            }
        }
        let mut write_guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if let Some(&ino) = write_guard.by_path.get(canonical_mount_path) {
            return ino;
        }
        let ino = write_guard.next_ino;
        write_guard.next_ino += 1;
        write_guard
            .by_path
            .insert(canonical_mount_path.to_owned(), ino);
        write_guard
            .by_ino
            .insert(ino, canonical_mount_path.to_owned());
        ino
    }

    /// Resolves `ino` back to its canonical mount-relative path (`""` for `ROOT_INO`).
    pub fn resolve_ino(&self, ino: u64) -> Option<String> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.by_ino.get(&ino).cloned()
    }

    /// Updates path mappings when `from` (and any subtree `from/...`) is renamed to `to`
    /// inside a `View`, preserving existing `ino` identities across renames.
    pub fn rename_subtree(&self, from_mount_path: &str, to_mount_path: &str) {
        if from_mount_path == to_mount_path || from_mount_path.is_empty() {
            return;
        }
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());

        // Drop any overwritten destination subtree mappings first.
        let to_prefix = format!("{to_mount_path}/");
        let stale_dest: Vec<(String, u64)> = guard
            .by_path
            .iter()
            .filter(|(p, _)| *p == to_mount_path || p.starts_with(&to_prefix))
            .map(|(p, &ino)| (p.clone(), ino))
            .collect();
        for (p, ino) in stale_dest {
            guard.by_path.remove(&p);
            guard.by_ino.remove(&ino);
        }

        // Move `from_mount_path` and `from_mount_path/*` to `to_mount_path`.
        let from_prefix = format!("{from_mount_path}/");
        let moved: Vec<(String, u64)> = guard
            .by_path
            .iter()
            .filter(|(p, _)| *p == from_mount_path || p.starts_with(&from_prefix))
            .map(|(p, &ino)| (p.clone(), ino))
            .collect();
        for (old_p, ino) in moved {
            guard.by_path.remove(&old_p);
            let new_p = if old_p == from_mount_path {
                to_mount_path.to_owned()
            } else {
                format!("{to_mount_path}/{}", &old_p[from_prefix.len()..])
            };
            guard.by_path.insert(new_p.clone(), ino);
            guard.by_ino.insert(ino, new_p);
        }
    }

    /// Removes `mount_path` and any descendants under `mount_path/`.
    pub fn remove_subtree(&self, mount_path: &str) {
        if mount_path.is_empty() {
            return;
        }
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let prefix = format!("{mount_path}/");
        let victims: Vec<(String, u64)> = guard
            .by_path
            .iter()
            .filter(|(p, _)| *p == mount_path || p.starts_with(&prefix))
            .map(|(p, &ino)| (p.clone(), ino))
            .collect();
        for (p, ino) in victims {
            guard.by_path.remove(&p);
            guard.by_ino.remove(&ino);
        }
    }
}

#[derive(Debug, Default)]
struct SlotState {
    active_writers: usize,
    waiting_quiescers: usize,
    quiesced: bool,
}

#[derive(Debug, Default)]
struct ViewQuiesceSlot {
    state: Mutex<SlotState>,
    cvar: Condvar,
}

/// RAII token held for the duration of an in-flight VFS mutation on a single `View`.
#[derive(Debug)]
pub struct ViewWriteGuard {
    slot: Arc<ViewQuiesceSlot>,
}

impl Drop for ViewWriteGuard {
    fn drop(&mut self) {
        let mut state = self.slot.state.lock().unwrap_or_else(|e| e.into_inner());
        state.active_writers -= 1;
        if state.active_writers == 0 {
            self.slot.cvar.notify_all();
        }
    }
}

/// RAII token guaranteeing zero in-flight VFS mutations on a `View` while live `Diff`, `Freeze`,
/// or `Apply` executes (ADR-0002 & ADR-0005).
#[derive(Debug)]
pub struct ViewQuiesceGuard {
    slot: Arc<ViewQuiesceSlot>,
}

impl Drop for ViewQuiesceGuard {
    fn drop(&mut self) {
        let mut state = self.slot.state.lock().unwrap_or_else(|e| e.into_inner());
        state.quiesced = false;
        self.slot.cvar.notify_all();
    }
}

/// Fair per-`View` write quiescence coordinator.
///
/// - VFS mutations on `view_a` never block `Diff`/`Freeze`/`Apply` or mutations on `view_b`.
/// - Pending quiescence on `view_a` parks incoming writers on `view_a` so heavy write workloads
///   cannot starve `Diff`, `Freeze`, or `Apply`, while read syscalls remain non-blocking.
#[derive(Debug, Default)]
pub struct QuiescenceManager {
    slots: Mutex<BTreeMap<ViewId, Arc<ViewQuiesceSlot>>>,
}

impl QuiescenceManager {
    /// Creates an empty `QuiescenceManager`.
    pub fn new() -> Self {
        Self::default()
    }

    fn slot_for(&self, view_id: &ViewId) -> Arc<ViewQuiesceSlot> {
        let mut map = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(view_id.clone())
            .or_insert_with(|| Arc::new(ViewQuiesceSlot::default()))
            .clone()
    }

    /// Acquires an active-writer ticket for `view_id`, waiting if `view_id` is currently
    /// quiescing or quiesced.
    pub fn begin_write(&self, view_id: &ViewId) -> ViewWriteGuard {
        let slot = self.slot_for(view_id);
        let mut state = slot.state.lock().unwrap_or_else(|e| e.into_inner());
        while state.quiesced || state.waiting_quiescers > 0 {
            state = slot.cvar.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        state.active_writers += 1;
        drop(state);
        ViewWriteGuard { slot }
    }

    /// Drains all in-flight VFS writers on `view_id` and blocks new writers on `view_id` until
    /// the returned `ViewQuiesceGuard` is dropped.
    pub fn quiesce(&self, view_id: &ViewId) -> ViewQuiesceGuard {
        let slot = self.slot_for(view_id);
        let mut state = slot.state.lock().unwrap_or_else(|e| e.into_inner());
        state.waiting_quiescers += 1;
        while state.quiesced || state.active_writers > 0 {
            state = slot.cvar.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        state.waiting_quiescers -= 1;
        state.quiesced = true;
        drop(state);
        ViewQuiesceGuard { slot }
    }

    /// Cleans up the slot entry when a `View` is deleted.
    pub fn remove_view(&self, view_id: &ViewId) {
        let mut map = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(view_id);
    }
}

/// Userspace virtual filesystem port implemented by `CoreEngine` and consumed by
/// `bit-vfs-fuse`, `bit-vfs-nfs`, and `bit-vfs-winfsp`.
///
/// Paths are mount-relative (`""` or `"/"` for `<mount>/`, `"<view-id>"` for a `View` root, and
/// `"<view-id>/<rel-path>"` for entries inside a `View`):
/// - `<mount>/` is strictly read-only (`VfsError::ReadOnly` on mutations).
/// - Cross-`View` `rename` returns `VfsError::CrossDevice` (`EXDEV`).
/// - Hard `link()` returns `VfsError::NotSupported` (`EOPNOTSUPP`).
/// - Live `Diff`, `Freeze`, and `Apply` coordinate with VFS mutations via `quiesce_view`.
pub trait VfsOperations: Send + Sync {
    /// Queries node attributes (`stat` / `lookup`).
    fn getattr(&self, path: &str) -> Result<VfsAttr, VfsError>;

    /// Updates `mode`, `size` (`truncate`), and/or `mtime` on an existing entry inside a `View`.
    fn setattr(&self, path: &str, attr: VfsSetAttr) -> Result<VfsAttr, VfsError>;

    /// Lists directory entries (`<mount>/` yields active `Views`; `<mount>/<view>/...` yields merged `Base + Overlay` children).
    fn readdir(&self, path: &str) -> Result<Vec<VfsDirEntry>, VfsError>;

    /// Reads the verbatim UTF-8 target of a symbolic link.
    fn readlink(&self, path: &str) -> Result<String, VfsError>;

    /// Reads up to `size` bytes starting at `offset` from a regular file.
    fn read(&self, path: &str, offset: u64, size: usize) -> Result<Vec<u8>, VfsError>;

    /// Creates (or truncates when `exclusive == false`) a regular file inside a `View`.
    fn create_file(&self, path: &str, mode: u32, exclusive: bool) -> Result<VfsAttr, VfsError>;

    /// Writes `data` at `offset` into an existing regular file inside a `View`, returning bytes written.
    fn write(&self, path: &str, offset: u64, data: &[u8]) -> Result<u64, VfsError>;

    /// Resizes an existing regular file inside a `View` to `size` bytes.
    fn truncate(&self, path: &str, size: u64) -> Result<VfsAttr, VfsError>;

    /// Creates a directory inside a `View` (supporting opaque recreation after `rm -rf dir && mkdir dir`).
    fn mkdir(&self, path: &str, mode: u32) -> Result<VfsAttr, VfsError>;

    /// Removes a regular file or symbolic link inside a `View`.
    fn unlink(&self, path: &str) -> Result<(), VfsError>;

    /// Removes an empty directory inside a `View`.
    fn rmdir(&self, path: &str) -> Result<(), VfsError>;

    /// Creates a symbolic link at `link_path` pointing to verbatim `target`.
    fn symlink(&self, target: &str, link_path: &str) -> Result<VfsAttr, VfsError>;

    /// Renames `from_path` to `to_path` within the same `View` without copying file bytes
    /// (returns `VfsError::CrossDevice` across `Views` and `VfsError::ReadOnly` at `<mount>/`).
    fn rename(&self, from_path: &str, to_path: &str) -> Result<(), VfsError>;

    /// Hard links are unsupported across the virtualized `Base + Overlay` mount (`EOPNOTSUPP`).
    fn link(&self, existing_path: &str, new_link_path: &str) -> Result<VfsAttr, VfsError>;

    /// Acquires the per-`View` write quiescence barrier for `view_id`.
    fn quiesce_view(&self, view_id: &ViewId) -> Result<ViewQuiesceGuard, VfsError>;
}
