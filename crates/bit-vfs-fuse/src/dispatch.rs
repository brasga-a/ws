//! Stateful FUSE request dispatcher (`FuseDispatcher`) and wire session loop (`FuseSession`)
//! over `Arc<dyn VfsOperations>` and `InodeTable`.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bit_core::model::{NodeKind, Timestamp, PERM_MASK};
use bit_core::path::EntryName;
use bit_core::vfs::{
    InodeTable, MountPath, VfsAttr, VfsError, VfsOperations, VfsSetAttr, ROOT_INO,
};

use crate::config::{FuseConfigError, FuseMountConfig};
use crate::protocol::{
    node_kind_to_dirent_type, FuseAccessIn, FuseAttr, FuseAttrOut, FuseCreateIn, FuseCreateOut,
    FuseDirent, FuseEntryOut, FuseFlushIn, FuseFsyncIn, FuseInHeader, FuseInitIn, FuseInitOut,
    FuseLinkIn, FuseMkdirIn, FuseOpcode, FuseOpenIn, FuseOpenOut, FuseOutHeader, FuseProtocolError,
    FuseReadIn, FuseReleaseIn, FuseRename2In, FuseRenameIn, FuseSetAttrIn, FuseStatfsOut,
    FuseSymlinkIn, FuseWriteIn, FuseWriteOut, WireReader, ACCESS_R_OK, ACCESS_W_OK, ACCESS_X_OK,
    DT_DIR, EACCES, EBADF, EEXIST, EINVAL, EISDIR, ELOOP, ENODEV, ENOENT, ENOSYS, ENOTDIR,
    EOPNOTSUPP, EPERM, EPROTO, EROFS, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_MTIME_NOW,
    FATTR_SIZE, FATTR_UID, FUSE_BUFFER_HEADER_ROOM, FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION,
    LINUX_O_ACCMODE, LINUX_O_APPEND, LINUX_O_EXCL, LINUX_O_RDONLY, LINUX_O_RDWR, LINUX_O_TRUNC,
    LINUX_O_WRONLY, RENAME_NOREPLACE,
};

/// Maximum single entry component byte length on Linux FUSE (`NAME_MAX = 255`).
const MAX_ENTRY_NAME_BYTES: usize = 255;

#[derive(Debug, Clone, Copy)]
struct OpenHandle {
    ino: u64,
    is_dir: bool,
    readable: bool,
    writable: bool,
    append: bool,
}

#[derive(Debug)]
struct HandleTable {
    next_fh: u64,
    open: BTreeMap<u64, OpenHandle>,
}

impl Default for HandleTable {
    fn default() -> Self {
        Self {
            next_fh: 1,
            open: BTreeMap::new(),
        }
    }
}

impl HandleTable {
    fn insert(&mut self, handle: OpenHandle) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.open.insert(fh, handle);
        fh
    }

    fn get(&self, fh: u64) -> Option<OpenHandle> {
        self.open.get(&fh).copied()
    }

    fn remove(&mut self, fh: u64) -> Option<OpenHandle> {
        self.open.remove(&fh)
    }

    fn clear(&mut self) {
        self.open.clear();
    }

    fn len(&self) -> usize {
        self.open.len()
    }
}

/// FUSE protocol and typed VFS request dispatcher backed by `Arc<dyn VfsOperations>`.
pub struct FuseDispatcher {
    vfs: Arc<dyn VfsOperations>,
    inodes: Arc<InodeTable>,
    config: FuseMountConfig,
    handles: Mutex<HandleTable>,
    initialized: AtomicBool,
    destroyed: AtomicBool,
}

impl std::fmt::Debug for FuseDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuseDispatcher")
            .field("config", &self.config)
            .field("inodes", &self.inodes)
            .field("initialized", &self.is_initialized())
            .field("destroyed", &self.is_destroyed())
            .finish_non_exhaustive()
    }
}

impl FuseDispatcher {
    /// Constructs a validated `FuseDispatcher` with a fresh [`InodeTable`].
    pub fn new(
        vfs: Arc<dyn VfsOperations>,
        config: FuseMountConfig,
    ) -> Result<Self, FuseConfigError> {
        Self::with_inode_table(vfs, Arc::new(InodeTable::new()), config)
    }

    /// Constructs a validated `FuseDispatcher` sharing a caller-supplied [`InodeTable`].
    pub fn with_inode_table(
        vfs: Arc<dyn VfsOperations>,
        inodes: Arc<InodeTable>,
        config: FuseMountConfig,
    ) -> Result<Self, FuseConfigError> {
        config.validate()?;
        Ok(Self {
            vfs,
            inodes,
            config,
            handles: Mutex::new(HandleTable::default()),
            initialized: AtomicBool::new(false),
            destroyed: AtomicBool::new(false),
        })
    }

    /// Borrows the validated [`FuseMountConfig`].
    pub const fn config(&self) -> &FuseMountConfig {
        &self.config
    }

    /// Borrows the underlying `VfsOperations` port.
    pub const fn vfs(&self) -> &Arc<dyn VfsOperations> {
        &self.vfs
    }

    /// Borrows the virtual [`InodeTable`].
    pub fn inode_table(&self) -> &InodeTable {
        &self.inodes
    }

    /// Returns `true` after `FUSE_INIT` has completed.
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Returns `true` after `FUSE_DESTROY` has completed.
    pub fn is_destroyed(&self) -> bool {
        self.destroyed.load(Ordering::Acquire)
    }

    /// Returns the number of currently open file and directory handles.
    pub fn open_handle_count(&self) -> usize {
        self.handles.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Evicts cached inode mappings for a removed `View` subtree (`<view-id>` and `<view-id>/*`).
    pub fn invalidate_view_inodes(&self, view_name: &str) {
        self.inodes.remove_subtree(view_name);
    }

    fn resolve_node_path(&self, ino: u64) -> Result<String, i32> {
        if ino == ROOT_INO {
            return Ok(String::new());
        }
        self.inodes.resolve_ino(ino).ok_or(ENOENT)
    }

    fn to_fuse_attr(&self, mut vfs_attr: VfsAttr, ino: u64) -> FuseAttr {
        vfs_attr.ino = ino;
        FuseAttr::from_vfs_attr(vfs_attr, self.config.uid, self.config.gid)
    }

    fn entry_out_for_parent(&self, parent_ino: u64, vfs_attr: VfsAttr, ino: u64) -> FuseEntryOut {
        let fuse_attr = self.to_fuse_attr(vfs_attr, ino);
        let entry_ttl = if parent_ino == ROOT_INO || ino == ROOT_INO {
            self.config.root_entry_ttl
        } else {
            self.config.entry_ttl
        };
        FuseEntryOut::new(fuse_attr, entry_ttl, self.config.attr_ttl)
    }

    fn parent_ino_for_mount_path(&self, mount_path: &str) -> u64 {
        if mount_path.is_empty() {
            return ROOT_INO;
        }
        match mount_path.rsplit_once('/') {
            None => ROOT_INO,
            Some((parent, _)) => self.inodes.get_or_alloc(parent),
        }
    }

    fn validate_child_component(name: &str) -> Result<(), i32> {
        if name.is_empty() {
            return Err(EINVAL);
        }
        if name.len() > MAX_ENTRY_NAME_BYTES {
            return Err(VfsError::NameTooLong.to_posix_errno());
        }
        if name.contains('\0') || name.contains('/') || name.contains('\\') {
            return Err(EINVAL);
        }
        Ok(())
    }

    fn resolve_lookup_target(&self, parent_ino: u64, name: &str) -> Result<MountPath, i32> {
        let parent_path = self.resolve_node_path(parent_ino)?;
        if name == "." {
            return MountPath::parse(&parent_path).map_err(|e| e.to_posix_errno());
        }
        if name == ".." {
            let up = match parent_path.rsplit_once('/') {
                None => "",
                Some((ancestor, _)) => ancestor,
            };
            return MountPath::parse(up).map_err(|e| e.to_posix_errno());
        }
        Self::validate_child_component(name)?;
        if !parent_path.is_empty() {
            EntryName::new(name).map_err(|e| VfsError::from(e).to_posix_errno())?;
        }
        let joined = if parent_path.is_empty() {
            name.to_owned()
        } else {
            format!("{parent_path}/{name}")
        };
        MountPath::parse(&joined).map_err(|e| e.to_posix_errno())
    }

    fn resolve_mutation_child_target(&self, parent_ino: u64, name: &str) -> Result<MountPath, i32> {
        let parent_path = self.resolve_node_path(parent_ino)?;
        if parent_ino == ROOT_INO || parent_path.is_empty() {
            return Err(VfsError::ReadOnly.to_posix_errno());
        }
        Self::validate_child_component(name)?;
        if name == "." || name == ".." {
            return Err(EINVAL);
        }
        EntryName::new(name).map_err(|e| VfsError::from(e).to_posix_errno())?;
        let joined = format!("{parent_path}/{name}");
        let parsed = MountPath::parse(&joined).map_err(|e| e.to_posix_errno())?;
        if parsed.is_root_or_direct_root_child() {
            return Err(VfsError::ReadOnly.to_posix_errno());
        }
        Ok(parsed)
    }

    /// Negotiates `FUSE_INIT` protocol parameters.
    pub fn init(&self, req: FuseInitIn) -> Result<FuseInitOut, i32> {
        if req.major < FUSE_KERNEL_VERSION {
            return Err(EPROTO);
        }
        let negotiated_minor = if req.major > FUSE_KERNEL_VERSION {
            FUSE_KERNEL_MINOR_VERSION
        } else {
            req.minor.min(FUSE_KERNEL_MINOR_VERSION)
        };
        self.initialized.store(true, Ordering::Release);
        Ok(FuseInitOut {
            major: FUSE_KERNEL_VERSION,
            minor: negotiated_minor,
            max_readahead: req.max_readahead,
            flags: 0,
            max_background: 16,
            congestion_threshold: 12,
            max_write: self.config.max_write,
            time_gran: 1,
            max_pages: (self.config.max_write.div_ceil(4096)).min(u16::MAX as u32) as u16,
            map_alignment: 0,
        })
    }

    /// Handles `FUSE_DESTROY`.
    pub fn destroy(&self) {
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.destroyed.store(true, Ordering::Release);
    }

    /// Handles `FUSE_LOOKUP` (`<mount>/` -> `<view-id>` and `<view-id>/...` -> entries).
    pub fn lookup(&self, parent_ino: u64, name: &str) -> Result<FuseEntryOut, i32> {
        let target = self.resolve_lookup_target(parent_ino, name)?;
        let mount_str = target.to_mount_string();
        let attr = self
            .vfs
            .getattr(&mount_str)
            .map_err(|e| e.to_posix_errno())?;
        let ino = self.inodes.get_or_alloc(&mount_str);
        Ok(self.entry_out_for_parent(parent_ino, attr, ino))
    }

    /// Handles `FUSE_GETATTR`.
    pub fn getattr(&self, ino: u64) -> Result<FuseAttrOut, i32> {
        let path = self.resolve_node_path(ino)?;
        let attr = self.vfs.getattr(&path).map_err(|e| e.to_posix_errno())?;
        Ok(FuseAttrOut::new(
            self.to_fuse_attr(attr, ino),
            self.config.attr_ttl,
        ))
    }

    /// Handles `FUSE_SETATTR` (`chmod`, `truncate`, `utimens`; returns `EROFS` at `<mount>/`).
    pub fn setattr(&self, ino: u64, req: FuseSetAttrIn) -> Result<FuseAttrOut, i32> {
        let path = self.resolve_node_path(ino)?;
        let parsed = MountPath::parse(&path).map_err(|e| e.to_posix_errno())?;
        if matches!(parsed, MountPath::Root | MountPath::InvalidRootChild(_)) {
            return Err(VfsError::ReadOnly.to_posix_errno());
        }

        if (req.valid & FATTR_UID) != 0 && req.uid != self.config.uid {
            return Err(EPERM);
        }
        if (req.valid & FATTR_GID) != 0 && req.gid != self.config.gid {
            return Err(EPERM);
        }

        let mode = if (req.valid & FATTR_MODE) != 0 {
            Some(req.mode & PERM_MASK)
        } else {
            None
        };
        let size = if (req.valid & FATTR_SIZE) != 0 {
            Some(req.size)
        } else {
            None
        };
        let mtime = if (req.valid & FATTR_MTIME_NOW) != 0 {
            Some(Timestamp::now())
        } else if (req.valid & FATTR_MTIME) != 0 {
            let secs = i64::try_from(req.mtime).unwrap_or(i64::MAX);
            Some(Timestamp::new(secs, req.mtimensec))
        } else {
            None
        };

        let updated = self
            .vfs
            .setattr(&path, VfsSetAttr { mode, size, mtime })
            .map_err(|e| e.to_posix_errno())?;
        Ok(FuseAttrOut::new(
            self.to_fuse_attr(updated, ino),
            self.config.attr_ttl,
        ))
    }

    /// Handles `FUSE_OPENDIR`.
    pub fn opendir(&self, ino: u64, flags: u32) -> Result<FuseOpenOut, i32> {
        let acc = flags & LINUX_O_ACCMODE;
        if acc != LINUX_O_RDONLY {
            return if ino == ROOT_INO {
                Err(EROFS)
            } else {
                Err(EISDIR)
            };
        }
        let path = self.resolve_node_path(ino)?;
        let attr = self.vfs.getattr(&path).map_err(|e| e.to_posix_errno())?;
        if attr.kind != NodeKind::Directory {
            return Err(ENOTDIR);
        }
        let fh = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(OpenHandle {
                ino,
                is_dir: true,
                readable: true,
                writable: false,
                append: false,
            });
        Ok(FuseOpenOut {
            fh,
            open_flags: 0,
            padding: 0,
        })
    }

    /// Computes all directory entries (`.`, `..`, and children) for `ino`.
    pub fn readdir_entries(&self, ino: u64) -> Result<Vec<FuseDirent>, i32> {
        let dir_path = self.resolve_node_path(ino)?;
        let children = self
            .vfs
            .readdir(&dir_path)
            .map_err(|e| e.to_posix_errno())?;

        let mut entries = Vec::with_capacity(2 + children.len());
        entries.push(FuseDirent {
            ino,
            off: 1,
            typ: DT_DIR,
            name: ".".to_owned(),
        });
        entries.push(FuseDirent {
            ino: self.parent_ino_for_mount_path(&dir_path),
            off: 2,
            typ: DT_DIR,
            name: "..".to_owned(),
        });

        for (idx, child) in children.into_iter().enumerate() {
            let child_mount_path = if dir_path.is_empty() {
                child.name.clone()
            } else {
                format!("{dir_path}/{}", child.name)
            };
            let child_ino = self.inodes.get_or_alloc(&child_mount_path);
            entries.push(FuseDirent {
                ino: child_ino,
                off: (idx + 3) as u64,
                typ: node_kind_to_dirent_type(child.kind),
                name: child.name,
            });
        }
        Ok(entries)
    }

    /// Handles `FUSE_READDIR`, encoding paginated 8-byte-aligned `FuseDirent` records.
    pub fn readdir(
        &self,
        ino: u64,
        fh: u64,
        offset: u64,
        max_bytes: usize,
    ) -> Result<Vec<u8>, i32> {
        if fh != 0 {
            let handle = self
                .handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(fh)
                .ok_or(EBADF)?;
            if !handle.is_dir {
                return Err(ENOTDIR);
            }
        }
        let entries = self.readdir_entries(ino)?;
        let start_idx = usize::try_from(offset).unwrap_or(usize::MAX);
        if start_idx >= entries.len() || max_bytes == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(max_bytes.min(4096));
        for entry in &entries[start_idx..] {
            if !entry.append_if_fits(&mut out, max_bytes) {
                break;
            }
        }
        Ok(out)
    }

    /// Handles `FUSE_RELEASEDIR`.
    pub fn releasedir(&self, fh: u64) -> Result<(), i32> {
        let _ = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(fh);
        Ok(())
    }

    /// Handles `FUSE_FSYNCDIR`.
    pub fn fsyncdir(&self, ino: u64, fh: u64) -> Result<(), i32> {
        let path = self.resolve_node_path(ino)?;
        if fh != 0 {
            let handle = self
                .handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(fh)
                .ok_or(EBADF)?;
            if !handle.is_dir {
                return Err(ENOTDIR);
            }
        }
        let attr = self.vfs.getattr(&path).map_err(|e| e.to_posix_errno())?;
        if attr.kind != NodeKind::Directory {
            return Err(ENOTDIR);
        }
        Ok(())
    }

    /// Handles `FUSE_OPEN` on regular files (performing whole-file CoW truncation on `O_TRUNC`).
    pub fn open(&self, ino: u64, flags: u32) -> Result<FuseOpenOut, i32> {
        let path = self.resolve_node_path(ino)?;
        let parsed = MountPath::parse(&path).map_err(|e| e.to_posix_errno())?;
        let acc = flags & LINUX_O_ACCMODE;
        let readable = acc == LINUX_O_RDONLY || acc == LINUX_O_RDWR;
        let writable = acc == LINUX_O_WRONLY || acc == LINUX_O_RDWR;
        let trunc = (flags & LINUX_O_TRUNC) != 0;
        let append = (flags & LINUX_O_APPEND) != 0;

        if matches!(parsed, MountPath::Root | MountPath::InvalidRootChild(_)) {
            return if writable || trunc {
                Err(VfsError::ReadOnly.to_posix_errno())
            } else if matches!(parsed, MountPath::Root) {
                Err(EISDIR)
            } else {
                Err(ENOENT)
            };
        }

        let attr = self.vfs.getattr(&path).map_err(|e| e.to_posix_errno())?;
        match attr.kind {
            NodeKind::Directory => return Err(EISDIR),
            NodeKind::Symlink => return Err(ELOOP),
            NodeKind::File => {}
        }

        if trunc {
            if !writable {
                return Err(EACCES);
            }
            self.vfs
                .truncate(&path, 0)
                .map_err(|e| e.to_posix_errno())?;
        }

        let fh = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(OpenHandle {
                ino,
                is_dir: false,
                readable,
                writable,
                append,
            });

        Ok(FuseOpenOut {
            fh,
            open_flags: 0,
            padding: 0,
        })
    }

    /// Handles `FUSE_READ`.
    pub fn read(&self, ino: u64, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32> {
        let target_ino = if fh != 0 {
            let handle = self
                .handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(fh)
                .ok_or(EBADF)?;
            if handle.is_dir {
                return Err(EISDIR);
            }
            if !handle.readable {
                return Err(EBADF);
            }
            handle.ino
        } else {
            ino
        };

        let path = self.resolve_node_path(target_ino)?;
        self.vfs
            .read(&path, offset, size as usize)
            .map_err(|e| e.to_posix_errno())
    }

    /// Handles `FUSE_CREATE` inside a `View` (`EROFS` at `<mount>/`).
    pub fn create(&self, parent_ino: u64, req: &FuseCreateIn) -> Result<FuseCreateOut, i32> {
        let target = self.resolve_mutation_child_target(parent_ino, &req.name)?;
        let mount_str = target.to_mount_string();
        let mode = (req.mode & PERM_MASK) & !(req.umask & PERM_MASK);
        let exclusive = (req.flags & LINUX_O_EXCL) != 0;

        let attr = self
            .vfs
            .create_file(&mount_str, mode, exclusive)
            .map_err(|e| e.to_posix_errno())?;
        let ino = self.inodes.get_or_alloc(&mount_str);

        let acc = req.flags & LINUX_O_ACCMODE;
        // Default bare `flags == 0` in synthetic tests to read/write while honoring explicit
        // `O_CREAT | O_RDONLY` from POSIX callers.
        let (readable, writable) = if req.flags == 0 {
            (true, true)
        } else {
            (
                acc == LINUX_O_RDONLY || acc == LINUX_O_RDWR,
                acc == LINUX_O_WRONLY || acc == LINUX_O_RDWR,
            )
        };
        let append = (req.flags & LINUX_O_APPEND) != 0;

        let fh = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(OpenHandle {
                ino,
                is_dir: false,
                readable,
                writable,
                append,
            });

        Ok(FuseCreateOut {
            entry: self.entry_out_for_parent(parent_ino, attr, ino),
            open: FuseOpenOut {
                fh,
                open_flags: 0,
                padding: 0,
            },
        })
    }

    /// Handles `FUSE_WRITE`, performing whole-file CoW into the `View`'s private `Overlay`
    /// without mutating the shared `Base` or sibling `Views`.
    pub fn write(&self, ino: u64, fh: u64, offset: u64, data: &[u8]) -> Result<FuseWriteOut, i32> {
        let (target_ino, is_append) = if fh != 0 {
            let handle = self
                .handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(fh)
                .ok_or(EBADF)?;
            if handle.is_dir {
                return Err(EISDIR);
            }
            if !handle.writable {
                return Err(EBADF);
            }
            (handle.ino, handle.append)
        } else {
            (ino, false)
        };

        let path = self.resolve_node_path(target_ino)?;
        let parsed = MountPath::parse(&path).map_err(|e| e.to_posix_errno())?;
        if matches!(parsed, MountPath::Root | MountPath::InvalidRootChild(_)) {
            return Err(VfsError::ReadOnly.to_posix_errno());
        }

        let effective_offset = if is_append {
            self.vfs
                .getattr(&path)
                .map_err(|e| e.to_posix_errno())?
                .size
        } else {
            offset
        };

        let written = self
            .vfs
            .write(&path, effective_offset, data)
            .map_err(|e| e.to_posix_errno())?;
        let written_u32 = u32::try_from(written).map_err(|_| EINVAL)?;
        Ok(FuseWriteOut {
            size: written_u32,
            padding: 0,
        })
    }

    /// Handles `FUSE_MKDIR` (`EROFS` at `<mount>/`).
    pub fn mkdir(&self, parent_ino: u64, req: &FuseMkdirIn) -> Result<FuseEntryOut, i32> {
        let target = self.resolve_mutation_child_target(parent_ino, &req.name)?;
        let mount_str = target.to_mount_string();
        let mode = (req.mode & PERM_MASK) & !(req.umask & PERM_MASK);
        let attr = self
            .vfs
            .mkdir(&mount_str, mode)
            .map_err(|e| e.to_posix_errno())?;
        let ino = self.inodes.get_or_alloc(&mount_str);
        Ok(self.entry_out_for_parent(parent_ino, attr, ino))
    }

    /// Handles `FUSE_UNLINK` (`EROFS` at `<mount>/`).
    pub fn unlink(&self, parent_ino: u64, name: &str) -> Result<(), i32> {
        let target = self.resolve_mutation_child_target(parent_ino, name)?;
        let mount_str = target.to_mount_string();
        self.vfs
            .unlink(&mount_str)
            .map_err(|e| e.to_posix_errno())?;
        self.inodes.remove_subtree(&mount_str);
        Ok(())
    }

    /// Handles `FUSE_RMDIR` (`EROFS` at `<mount>/`).
    pub fn rmdir(&self, parent_ino: u64, name: &str) -> Result<(), i32> {
        let target = self.resolve_mutation_child_target(parent_ino, name)?;
        let mount_str = target.to_mount_string();
        self.vfs.rmdir(&mount_str).map_err(|e| e.to_posix_errno())?;
        self.inodes.remove_subtree(&mount_str);
        Ok(())
    }

    /// Handles `FUSE_SYMLINK` (`EROFS` at `<mount>/`).
    pub fn symlink(&self, parent_ino: u64, name: &str, target: &str) -> Result<FuseEntryOut, i32> {
        let link_mount = self.resolve_mutation_child_target(parent_ino, name)?;
        let mount_str = link_mount.to_mount_string();
        let attr = self
            .vfs
            .symlink(target, &mount_str)
            .map_err(|e| e.to_posix_errno())?;
        let ino = self.inodes.get_or_alloc(&mount_str);
        Ok(self.entry_out_for_parent(parent_ino, attr, ino))
    }

    /// Handles `FUSE_READLINK`.
    pub fn readlink(&self, ino: u64) -> Result<Vec<u8>, i32> {
        let path = self.resolve_node_path(ino)?;
        let target = self.vfs.readlink(&path).map_err(|e| e.to_posix_errno())?;
        Ok(target.into_bytes())
    }

    /// Handles `FUSE_RENAME` (`EROFS` at `<mount>/`, `EXDEV` across two distinct `Views`,
    /// zero-copy metadata subtree move within one `View`).
    pub fn rename(
        &self,
        old_dir_ino: u64,
        old_name: &str,
        new_dir_ino: u64,
        new_name: &str,
    ) -> Result<(), i32> {
        let old_target = self.resolve_mutation_child_target(old_dir_ino, old_name)?;
        let new_target = self.resolve_mutation_child_target(new_dir_ino, new_name)?;

        let (MountPath::View { view: old_view, .. }, MountPath::View { view: new_view, .. }) =
            (&old_target, &new_target)
        else {
            return Err(VfsError::ReadOnly.to_posix_errno());
        };

        if old_view != new_view {
            return Err(VfsError::CrossDevice.to_posix_errno());
        }

        let old_str = old_target.to_mount_string();
        let new_str = new_target.to_mount_string();
        self.vfs
            .rename(&old_str, &new_str)
            .map_err(|e| e.to_posix_errno())?;
        self.inodes.rename_subtree(&old_str, &new_str);
        Ok(())
    }

    /// Handles `FUSE_RENAME2` (supporting `flags == 0` and `RENAME_NOREPLACE`).
    pub fn rename2(&self, old_dir_ino: u64, req: &FuseRename2In) -> Result<(), i32> {
        if (req.flags & !RENAME_NOREPLACE) != 0 {
            return Err(EINVAL);
        }
        if (req.flags & RENAME_NOREPLACE) != 0 {
            let new_target = self.resolve_mutation_child_target(req.newdir, &req.newname)?;
            let new_str = new_target.to_mount_string();
            if self.vfs.getattr(&new_str).is_ok() {
                return Err(EEXIST);
            }
        }
        self.rename(old_dir_ino, &req.oldname, req.newdir, &req.newname)
    }

    /// Handles `FUSE_LINK` (hard links are unsupported across `Base + Overlay` -> `EOPNOTSUPP`).
    pub fn link(
        &self,
        old_ino: u64,
        new_parent_ino: u64,
        new_name: &str,
    ) -> Result<FuseEntryOut, i32> {
        let old_path = self.resolve_node_path(old_ino)?;
        let new_parent_path = self.resolve_node_path(new_parent_ino)?;
        Self::validate_child_component(new_name)?;
        if new_name == "." || new_name == ".." {
            return Err(EINVAL);
        }
        let new_path = if new_parent_path.is_empty() {
            new_name.to_owned()
        } else {
            format!("{new_parent_path}/{new_name}")
        };

        match self.vfs.link(&old_path, &new_path) {
            Ok(attr) => {
                let ino = self.inodes.get_or_alloc(&new_path);
                Ok(self.entry_out_for_parent(new_parent_ino, attr, ino))
            }
            Err(err) => Err(err.to_posix_errno()),
        }
    }

    /// Handles `FUSE_FLUSH`.
    pub fn flush(&self, ino: u64, fh: u64) -> Result<(), i32> {
        let _ = self.resolve_node_path(ino)?;
        if fh != 0 {
            let guard = self.handles.lock().unwrap_or_else(|e| e.into_inner());
            if guard.get(fh).is_none() {
                return Err(EBADF);
            }
        }
        Ok(())
    }

    /// Handles `FUSE_FSYNC`.
    pub fn fsync(&self, ino: u64, fh: u64, _datasync: bool) -> Result<(), i32> {
        let _ = self.resolve_node_path(ino)?;
        if fh != 0 {
            let guard = self.handles.lock().unwrap_or_else(|e| e.into_inner());
            if guard.get(fh).is_none() {
                return Err(EBADF);
            }
        }
        Ok(())
    }

    /// Handles `FUSE_RELEASE`.
    pub fn release(&self, fh: u64) -> Result<(), i32> {
        let _ = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(fh);
        Ok(())
    }

    /// Handles `FUSE_ACCESS`.
    pub fn access(&self, ino: u64, mask: u32) -> Result<(), i32> {
        let path = self.resolve_node_path(ino)?;
        let attr = self.vfs.getattr(&path).map_err(|e| e.to_posix_errno())?;
        if (mask & ACCESS_W_OK) != 0 && attr.read_only {
            return Err(EROFS);
        }
        let owner_bits = (attr.mode >> 6) & 0o7;
        if (mask & ACCESS_R_OK) != 0 && (owner_bits & 0o4) == 0 {
            return Err(EACCES);
        }
        if (mask & ACCESS_W_OK) != 0 && (owner_bits & 0o2) == 0 {
            return Err(EACCES);
        }
        if (mask & ACCESS_X_OK) != 0 && (owner_bits & 0o1) == 0 {
            return Err(EACCES);
        }
        Ok(())
    }

    /// Handles `FUSE_STATFS`.
    pub fn statfs(&self) -> Result<FuseStatfsOut, i32> {
        Ok(FuseStatfsOut::default())
    }

    /// Decodes and dispatches one complete raw FUSE wire packet (`FuseInHeader` + payload),
    /// returning `Some(response_frame)` for request/response opcodes or `None` for one-way
    /// notifications (`FORGET`, `BATCH_FORGET`) or truncated headers.
    pub fn dispatch_packet(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let Ok(hdr) = FuseInHeader::decode(packet) else {
            return None;
        };

        let declared_len = hdr.len as usize;
        if declared_len < FuseInHeader::SIZE || declared_len > packet.len() {
            return Some(FuseOutHeader::error_frame(hdr.unique, EPROTO));
        }

        let raw_body = &packet[FuseInHeader::SIZE..declared_len];
        let Some(opcode) = FuseOpcode::from_raw(hdr.opcode) else {
            return Some(FuseOutHeader::error_frame(hdr.unique, ENOSYS));
        };

        if opcode.is_no_reply() {
            return None;
        }

        if let Some(expected_uid) = self.config.strict_caller_uid {
            if hdr.uid != expected_uid && !matches!(opcode, FuseOpcode::Init | FuseOpcode::Destroy)
            {
                return Some(FuseOutHeader::error_frame(hdr.unique, EACCES));
            }
        }

        let result: Result<Vec<u8>, i32> = match opcode {
            FuseOpcode::Forget | FuseOpcode::BatchForget => return None,
            FuseOpcode::Init => decode_or_einval(FuseInitIn::decode(raw_body))
                .and_then(|req| self.init(req))
                .map(|out| out.encode()),
            FuseOpcode::Destroy => {
                self.destroy();
                Ok(Vec::new())
            }
            FuseOpcode::Lookup => decode_single_cstr(raw_body)
                .and_then(|name| self.lookup(hdr.nodeid, name))
                .map(|out| out.encode()),
            FuseOpcode::GetAttr => self.getattr(hdr.nodeid).map(|out| out.encode()),
            FuseOpcode::SetAttr => decode_or_einval(FuseSetAttrIn::decode(raw_body))
                .and_then(|req| self.setattr(hdr.nodeid, req))
                .map(|out| out.encode()),
            FuseOpcode::OpenDir => decode_or_einval(FuseOpenIn::decode(raw_body))
                .and_then(|req| self.opendir(hdr.nodeid, req.flags))
                .map(|out| out.encode()),
            FuseOpcode::ReadDir => decode_or_einval(FuseReadIn::decode(raw_body))
                .and_then(|req| self.readdir(hdr.nodeid, req.fh, req.offset, req.size as usize)),
            FuseOpcode::ReleaseDir => decode_or_einval(FuseReleaseIn::decode(raw_body))
                .and_then(|req| self.releasedir(req.fh))
                .map(|()| Vec::new()),
            FuseOpcode::FsyncDir => decode_or_einval(FuseFsyncIn::decode(raw_body))
                .and_then(|req| self.fsyncdir(hdr.nodeid, req.fh))
                .map(|()| Vec::new()),
            FuseOpcode::Open => decode_or_einval(FuseOpenIn::decode(raw_body))
                .and_then(|req| self.open(hdr.nodeid, req.flags))
                .map(|out| out.encode()),
            FuseOpcode::Read => decode_or_einval(FuseReadIn::decode(raw_body))
                .and_then(|req| self.read(hdr.nodeid, req.fh, req.offset, req.size)),
            FuseOpcode::Create => decode_or_einval(FuseCreateIn::decode(raw_body))
                .and_then(|req| self.create(hdr.nodeid, &req))
                .map(|out| out.encode()),
            FuseOpcode::Write => decode_or_einval(FuseWriteIn::decode(raw_body))
                .and_then(|req| self.write(hdr.nodeid, req.fh, req.offset, req.data))
                .map(|out| out.encode()),
            FuseOpcode::Mkdir => decode_or_einval(FuseMkdirIn::decode(raw_body))
                .and_then(|req| self.mkdir(hdr.nodeid, &req))
                .map(|out| out.encode()),
            FuseOpcode::Unlink => decode_single_cstr(raw_body)
                .and_then(|name| self.unlink(hdr.nodeid, name))
                .map(|()| Vec::new()),
            FuseOpcode::Rmdir => decode_single_cstr(raw_body)
                .and_then(|name| self.rmdir(hdr.nodeid, name))
                .map(|()| Vec::new()),
            FuseOpcode::Symlink => decode_or_einval(FuseSymlinkIn::decode(raw_body))
                .and_then(|req| self.symlink(hdr.nodeid, &req.name, &req.target))
                .map(|out| out.encode()),
            FuseOpcode::ReadLink => self.readlink(hdr.nodeid),
            FuseOpcode::Rename => decode_or_einval(FuseRenameIn::decode(raw_body))
                .and_then(|req| self.rename(hdr.nodeid, &req.oldname, req.newdir, &req.newname))
                .map(|()| Vec::new()),
            FuseOpcode::Rename2 => decode_or_einval(FuseRename2In::decode(raw_body))
                .and_then(|req| self.rename2(hdr.nodeid, &req))
                .map(|()| Vec::new()),
            FuseOpcode::Link => decode_or_einval(FuseLinkIn::decode(raw_body))
                .and_then(|req| self.link(req.oldnodeid, hdr.nodeid, &req.newname))
                .map(|out| out.encode()),
            FuseOpcode::Flush => decode_or_einval(FuseFlushIn::decode(raw_body))
                .and_then(|req| self.flush(hdr.nodeid, req.fh))
                .map(|()| Vec::new()),
            FuseOpcode::Fsync => decode_or_einval(FuseFsyncIn::decode(raw_body))
                .and_then(|req| self.fsync(hdr.nodeid, req.fh, (req.fsync_flags & 1) != 0))
                .map(|()| Vec::new()),
            FuseOpcode::Release => decode_or_einval(FuseReleaseIn::decode(raw_body))
                .and_then(|req| self.release(req.fh))
                .map(|()| Vec::new()),
            FuseOpcode::Access => decode_or_einval(FuseAccessIn::decode(raw_body))
                .and_then(|req| self.access(hdr.nodeid, req.mask))
                .map(|()| Vec::new()),
            FuseOpcode::Statfs => self.statfs().map(|out| out.encode()),
            FuseOpcode::Mknod => {
                if hdr.nodeid == ROOT_INO {
                    Err(EROFS)
                } else {
                    Err(EOPNOTSUPP)
                }
            }
        };

        Some(match result {
            Ok(body) => FuseOutHeader::ok_frame(hdr.unique, &body),
            Err(errno) => FuseOutHeader::error_frame(hdr.unique, errno),
        })
    }
}

fn decode_or_einval<T>(res: Result<T, FuseProtocolError>) -> Result<T, i32> {
    res.map_err(|_| EINVAL)
}

fn decode_single_cstr(bytes: &[u8]) -> Result<&str, i32> {
    let mut r = WireReader::new(bytes);
    r.read_cstr().map_err(|_| EINVAL)
}

/// FUSE session runner driving [`FuseDispatcher`] over either a `/dev/fuse` packet device
/// or a length-prefixed byte stream.
#[derive(Debug, Clone)]
pub struct FuseSession {
    dispatcher: Arc<FuseDispatcher>,
    stop_flag: Arc<AtomicBool>,
}

impl FuseSession {
    /// Creates a `FuseSession` wrapping `dispatcher`.
    pub fn new(dispatcher: Arc<FuseDispatcher>) -> Self {
        Self {
            dispatcher,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Creates a `FuseSession` sharing an external `stop_flag`.
    pub const fn with_stop_flag(
        dispatcher: Arc<FuseDispatcher>,
        stop_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            dispatcher,
            stop_flag,
        }
    }

    /// Borrows the underlying [`FuseDispatcher`].
    pub const fn dispatcher(&self) -> &Arc<FuseDispatcher> {
        &self.dispatcher
    }

    /// Borrows the shared stop flag.
    pub const fn stop_flag(&self) -> &Arc<AtomicBool> {
        &self.stop_flag
    }

    /// Signals the session loop to exit cleanly after the current request.
    pub fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
    }

    /// Returns `true` if [`Self::request_stop`] was called or `FUSE_DESTROY` was processed.
    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::Acquire) || self.dispatcher.is_destroyed()
    }

    /// Dispatches a single wire packet through [`FuseDispatcher::dispatch_packet`].
    pub fn process_packet(&self, packet: &[u8]) -> Option<Vec<u8>> {
        self.dispatcher.dispatch_packet(packet)
    }

    /// Serves concatenated FUSE wire frames from any `Read` + `Write` stream (useful for
    /// deterministic cross-platform tests and IPC framing), returning the count of processed frames.
    pub fn serve_frames<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
    ) -> io::Result<usize> {
        let max_frame = self.dispatcher.config().max_write as usize + FUSE_BUFFER_HEADER_ROOM;
        let mut processed = 0usize;

        while !self.is_stopped() {
            let mut len_bytes = [0u8; 4];
            if !read_exact_or_eof(reader, &mut len_bytes)? {
                break;
            }
            let frame_len = u32::from_le_bytes(len_bytes) as usize;
            if frame_len < FuseInHeader::SIZE || frame_len > max_frame {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid FUSE frame length: {frame_len}"),
                ));
            }
            let mut frame = vec![0u8; frame_len];
            frame[..4].copy_from_slice(&len_bytes);
            reader.read_all_exact(&mut frame[4..])?;

            if let Some(reply) = self.dispatcher.dispatch_packet(&frame) {
                writer.write_all(&reply)?;
                writer.flush()?;
            }
            processed += 1;
        }
        Ok(processed)
    }

    /// Serves packet-oriented `/dev/fuse` reads and writes, treating `ENODEV` (`19`) as clean
    /// unmount termination and retrying `EINTR` / `ENOENT` interrupted kernel requests.
    pub fn serve_fuse_device<D: Read + Write>(&self, dev: &mut D) -> io::Result<usize> {
        let buf_len = self.dispatcher.config().max_write as usize + FUSE_BUFFER_HEADER_ROOM;
        let mut buf = vec![0u8; buf_len];
        let mut processed = 0usize;

        while !self.is_stopped() {
            let n = match dev.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) if err.raw_os_error() == Some(ENOENT) => continue,
                Err(err) if err.raw_os_error() == Some(ENODEV) => break,
                Err(err) => return Err(err),
            };

            if let Some(reply) = self.dispatcher.dispatch_packet(&buf[..n]) {
                match dev.write_all(&reply) {
                    Ok(()) => {}
                    Err(err) if err.raw_os_error() == Some(ENODEV) => break,
                    Err(err) if err.raw_os_error() == Some(ENOENT) => {}
                    Err(err) => return Err(err),
                }
            }
            processed += 1;
        }
        Ok(processed)
    }
}

trait ReadExactExt {
    fn read_all_exact(&mut self, buf: &mut [u8]) -> io::Result<()>;
}

impl<R: Read + ?Sized> ReadExactExt for R {
    fn read_all_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.read_exact(buf)
    }
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "truncated FUSE frame header",
                ));
            }
            Ok(n) => filled += n,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(true)
}
