//! Stateful WinFsp callback implementation (`WinFspFileSystem`) over `Arc<dyn VfsOperations>`.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::{BitAnd, BitOr, BitOrAssign};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use bit_core::ids::ViewId;
use bit_core::model::{NodeKind, Timestamp};
use bit_core::path::{lookup_entry_in_map, CaseSensitivity, EntryName, RelPath};
use bit_core::vfs::{MountPath, VfsError, VfsOperations, VfsSetAttr};

use crate::attrs::{
    apply_file_attributes_to_mode, file_attributes_to_posix_mode, vfs_attr_to_file_attributes,
    BasicInfoUpdate, FileAttributes, WinFspFileInfo, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
};
use crate::config::{
    SecurityByNameResult, WinFspMountConfig, WinFspVolumeInfo, WinFspVolumeParams,
};
use crate::notify::{DirectoryChangeAction, DirectoryChangeNotifier, NotifyFilter, WatchId};
use crate::reparse::{ReparsePointData, IO_REPARSE_TAG_SYMLINK};
use crate::status::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_CANNOT_DELETE, STATUS_DELETE_PENDING,
    STATUS_DIRECTORY_NOT_EMPTY, STATUS_FILE_IS_A_DIRECTORY, STATUS_INVALID_HANDLE,
    STATUS_IO_REPARSE_DATA_INVALID, STATUS_IO_REPARSE_TAG_NOT_HANDLED,
    STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY, STATUS_NOT_A_REPARSE_POINT,
    STATUS_NOT_SAME_DEVICE, STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND,
};

/// Opaque handle identifier representing a WinFsp `FileContext` (`UserContext2`).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileHandleId(pub u64);

/// Read-only inspection view of an active open handle inside [`WinFspFileSystem`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFileContext {
    /// Allocated handle identifier.
    pub handle_id: FileHandleId,
    /// Canonical `'/'`-separated mount-relative path (`""` for `<mount>\`).
    pub mount_path: String,
    /// Windows `\`-separated mount-relative path (`"\"` for `<mount>\`).
    pub win_path: String,
    /// Tracked [`NodeKind`].
    pub kind: NodeKind,
    /// Whether write/truncate/overwrite operations are permitted on this handle.
    pub write_access: bool,
    /// Whether `cleanup` will unlink/rmdir the target entry on handle close.
    pub delete_on_close: bool,
    /// Whether the handle was opened with `FILE_OPEN_REPARSE_POINT`.
    pub open_reparse_point: bool,
    /// Whether `cleanup` has already removed the underlying entry.
    pub deleted: bool,
}

/// Flags governing [`WinFspFileSystem::open`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenOptions {
    /// Requests write/modify/overwrite access (`FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | DELETE`).
    pub write_access: bool,
    /// Marks the handle for deletion during `cleanup` (`FILE_DELETE_ON_CLOSE`).
    pub delete_on_close: bool,
    /// Requires target to be a directory (`FILE_DIRECTORY_FILE`).
    pub directory_only: bool,
    /// Requires target NOT to be a directory (`FILE_NON_DIRECTORY_FILE`).
    pub non_directory_only: bool,
    /// Opens symbolic link reparse points directly (`FILE_OPEN_REPARSE_POINT`).
    pub open_reparse_point: bool,
    /// Optional WinFsp caller SID checked against [`WinFspMountConfig::owner_sid`].
    pub caller_sid: Option<String>,
}

impl OpenOptions {
    /// Read-only open options.
    pub fn read_only() -> Self {
        Self::default()
    }

    /// Read-write open options.
    pub fn read_write() -> Self {
        Self {
            write_access: true,
            ..Self::default()
        }
    }

    /// Directory open options (`FILE_DIRECTORY_FILE`).
    pub fn directory() -> Self {
        Self {
            directory_only: true,
            ..Self::default()
        }
    }

    /// Delete-on-close open options (`FILE_DELETE_ON_CLOSE`).
    pub fn delete_on_close() -> Self {
        Self {
            write_access: true,
            delete_on_close: true,
            ..Self::default()
        }
    }

    /// Reparse point open options (`FILE_OPEN_REPARSE_POINT`).
    pub fn reparse_point(write_access: bool) -> Self {
        Self {
            write_access,
            open_reparse_point: true,
            ..Self::default()
        }
    }
}

/// Parameters governing [`WinFspFileSystem::create`] (`FSP_FILE_SYSTEM_INTERFACE::Create` / `CreateEx`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateParams {
    /// Initial Windows `FileAttributes` (`FILE_ATTRIBUTE_NORMAL`, `FILE_ATTRIBUTE_DIRECTORY`, etc.).
    pub file_attributes: FileAttributes,
    /// Creates a directory (`FILE_DIRECTORY_FILE`).
    pub is_directory: bool,
    /// Initial allocation hint (`AllocationSize`).
    pub allocation_size: u64,
    /// Marks created handle for deletion on `cleanup` (`FILE_DELETE_ON_CLOSE`).
    pub delete_on_close: bool,
    /// Optional explicit POSIX mode override (when omitted, derived from `file_attributes`).
    pub posix_mode_override: Option<u32>,
    /// Optional initial symbolic link reparse payload (`CreateEx` with `ExtraBufferIsReparsePoint`).
    pub reparse_data: Option<ReparsePointData>,
    /// Optional WinFsp caller SID checked against [`WinFspMountConfig::owner_sid`].
    pub caller_sid: Option<String>,
}

impl CreateParams {
    /// Parameters for creating a regular writable file (`FILE_ATTRIBUTE_NORMAL`).
    pub fn regular_file() -> Self {
        Self {
            file_attributes: FILE_ATTRIBUTE_NORMAL,
            ..Self::default()
        }
    }

    /// Parameters for creating a directory (`FILE_ATTRIBUTE_DIRECTORY`).
    pub fn directory() -> Self {
        Self {
            file_attributes: FILE_ATTRIBUTE_DIRECTORY,
            is_directory: true,
            ..Self::default()
        }
    }

    /// Parameters for atomically creating a symbolic link (`CreateEx` with reparse data).
    pub fn symlink(reparse_data: ReparsePointData) -> Self {
        Self {
            file_attributes: FILE_ATTRIBUTE_REPARSE_POINT,
            reparse_data: Some(reparse_data),
            ..Self::default()
        }
    }
}

/// WinFsp `FspCleanup*` bitflags passed to [`WinFspFileSystem::cleanup`].
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CleanupFlags(pub u32);

impl CleanupFlags {
    /// No special cleanup flags (`0`).
    pub const NONE: Self = Self(0);
    /// `FspCleanupDelete` (`0x01`): unlink or rmdir the file/directory during cleanup.
    pub const DELETE: Self = Self(0x01);
    /// `FspCleanupSetAllocationSize` (`0x02`).
    pub const SET_ALLOCATION_SIZE: Self = Self(0x02);
    /// `FspCleanupSetArchiveBit` (`0x10`).
    pub const SET_ARCHIVE_BIT: Self = Self(0x10);
    /// `FspCleanupSetLastAccessTime` (`0x20`).
    pub const SET_LAST_ACCESS_TIME: Self = Self(0x20);
    /// `FspCleanupSetLastWriteTime` (`0x40`).
    pub const SET_LAST_WRITE_TIME: Self = Self(0x40);
    /// `FspCleanupSetChangeTime` (`0x80`).
    pub const SET_CHANGE_TIME: Self = Self(0x80);

    /// Returns `true` when every bit in `other` is set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for CleanupFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for CleanupFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for CleanupFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

/// Directory entry returned by [`WinFspFileSystem::read_directory`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WinFspDirEntry {
    /// Exact case-preserved entry name (`"."`, `".."`, `ViewId`, or `EntryName`).
    pub name: String,
    /// Full WinFsp `FSP_FSCTL_FILE_INFO` metadata for the entry.
    pub file_info: WinFspFileInfo,
}

impl WinFspDirEntry {
    /// Returns `true` when `self.name` is `"."` or `".."`.
    pub fn is_dot_entry(&self) -> bool {
        self.name == "." || self.name == ".."
    }
}

#[derive(Debug, Clone)]
struct OpenHandleEntry {
    handle_id: FileHandleId,
    mount_path: String,
    kind: NodeKind,
    write_access: bool,
    delete_on_close: bool,
    open_reparse_point: bool,
    deleted: bool,
}

impl OpenHandleEntry {
    fn to_public(&self) -> OpenFileContext {
        let win_path = if self.mount_path.is_empty() {
            r"\".to_owned()
        } else {
            format!(r"\{}", self.mount_path.replace('/', r"\"))
        };
        OpenFileContext {
            handle_id: self.handle_id,
            mount_path: self.mount_path.clone(),
            win_path,
            kind: self.kind,
            write_access: self.write_access,
            delete_on_close: self.delete_on_close,
            open_reparse_point: self.open_reparse_point,
            deleted: self.deleted,
        }
    }
}

/// WinFsp userspace filesystem callback adapter backed by `Arc<dyn VfsOperations>`.
pub struct WinFspFileSystem {
    vfs: Arc<dyn VfsOperations>,
    config: WinFspMountConfig,
    handles: RwLock<BTreeMap<FileHandleId, OpenHandleEntry>>,
    next_handle: AtomicU64,
    notifier: Arc<DirectoryChangeNotifier>,
}

impl fmt::Debug for WinFspFileSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let open_count = self.handles.read().unwrap_or_else(|e| e.into_inner()).len();
        f.debug_struct("WinFspFileSystem")
            .field("config", &self.config)
            .field("open_handles", &open_count)
            .finish()
    }
}

impl WinFspFileSystem {
    /// Constructs a new [`WinFspFileSystem`] over `vfs` and `config`.
    pub fn new(vfs: Arc<dyn VfsOperations>, config: WinFspMountConfig) -> Self {
        Self::with_notifier(vfs, config, Arc::new(DirectoryChangeNotifier::new()))
    }

    /// Constructs a [`WinFspFileSystem`] sharing an explicit [`DirectoryChangeNotifier`].
    pub fn with_notifier(
        vfs: Arc<dyn VfsOperations>,
        config: WinFspMountConfig,
        notifier: Arc<DirectoryChangeNotifier>,
    ) -> Self {
        Self {
            vfs,
            config,
            handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
            notifier,
        }
    }

    /// Mount configuration governing this filesystem instance.
    pub const fn config(&self) -> &WinFspMountConfig {
        &self.config
    }

    /// Negotiated `FSP_FSCTL_VOLUME_PARAMS` for this mount.
    pub fn volume_params(&self) -> WinFspVolumeParams {
        self.config.volume_params()
    }

    /// Borrows the underlying [`VfsOperations`] port.
    pub const fn vfs(&self) -> &Arc<dyn VfsOperations> {
        &self.vfs
    }

    /// Borrows the [`DirectoryChangeNotifier`] hub.
    pub const fn notifier(&self) -> &Arc<DirectoryChangeNotifier> {
        &self.notifier
    }

    /// Number of currently open file/directory handles.
    pub fn open_handle_count(&self) -> usize {
        self.handles.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Inspects an active handle's [`OpenFileContext`], if still open.
    pub fn handle_context(&self, handle: FileHandleId) -> Option<OpenFileContext> {
        let guard = self.handles.read().unwrap_or_else(|e| e.into_inner());
        guard.get(&handle).map(OpenHandleEntry::to_public)
    }

    /// Closes and drops all currently open handles (invoked when stopping a mount).
    pub(crate) fn clear_open_handles(&self) {
        let mut guard = self.handles.write().unwrap_or_else(|e| e.into_inner());
        guard.clear();
    }

    // -------------------------------------------------------------------------
    // Path routing & case-sensitivity helpers
    // -------------------------------------------------------------------------

    fn resolve_view_name(&self, view: &ViewId) -> Result<String, NtStatus> {
        if self.config.case_sensitivity() == CaseSensitivity::CaseSensitive {
            return Ok(view.as_str().to_owned());
        }

        let root_entries = self.vfs.readdir("")?;
        let mut map = BTreeMap::new();
        for item in root_entries {
            if let Ok(en) = EntryName::new(item.name) {
                map.insert(en, ());
            }
        }
        let query = EntryName::new(view.as_str()).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
        let matched = lookup_entry_in_map(&map, &query, self.config.case_sensitivity())
            .into_result(&query)
            .map_err(|_| STATUS_OBJECT_NAME_COLLISION)?;
        match matched {
            Some((canon, ())) => Ok(canon.as_str().to_owned()),
            None => Err(STATUS_OBJECT_NAME_NOT_FOUND),
        }
    }

    fn resolve_existing_rel_under_view(
        &self,
        canonical_view: &str,
        rel: &RelPath,
    ) -> Result<String, NtStatus> {
        if rel.is_root() {
            return Ok(canonical_view.to_owned());
        }
        if self.config.case_sensitivity() == CaseSensitivity::CaseSensitive {
            return Ok(format!("{canonical_view}/{}", rel.as_str()));
        }

        let mut current = canonical_view.to_owned();
        for comp in rel.components() {
            let children = self.vfs.readdir(&current)?;
            let mut map = BTreeMap::new();
            for item in children {
                if let Ok(en) = EntryName::new(item.name) {
                    map.insert(en, item.kind);
                }
            }
            let matched = lookup_entry_in_map(&map, &comp, self.config.case_sensitivity())
                .into_result(&comp)
                .map_err(|_| STATUS_OBJECT_NAME_COLLISION)?;
            let Some((canon_comp, _)) = matched else {
                return Err(STATUS_OBJECT_NAME_NOT_FOUND);
            };
            current = format!("{current}/{}", canon_comp.as_str());
        }
        Ok(current)
    }

    /// Parses a Windows backslash path via [`MountPath::parse_winfsp`] and resolves it to its
    /// canonical `'/'`-separated mount-relative path (`""` for `<mount>\`).
    pub fn resolve_existing_mount_path(&self, raw_path: &str) -> Result<String, NtStatus> {
        match MountPath::parse_winfsp(raw_path)? {
            MountPath::Root => Ok(String::new()),
            MountPath::InvalidRootChild(_) => Err(STATUS_OBJECT_NAME_NOT_FOUND),
            MountPath::View { view, rel } => {
                let canon_view = self.resolve_view_name(&view)?;
                self.resolve_existing_rel_under_view(&canon_view, &rel)
            }
        }
    }

    fn resolve_create_target(&self, raw_path: &str) -> Result<String, NtStatus> {
        let parsed = MountPath::parse_winfsp(raw_path)?;
        if parsed.is_root_or_direct_root_child() {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        let MountPath::View { view, rel } = parsed else {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        };

        let canon_view = self.resolve_view_name(&view)?;
        // Verify the view itself exists even in CaseSensitive mode before resolving children.
        if self.config.case_sensitivity() == CaseSensitivity::CaseSensitive {
            let _ = self.vfs.getattr(&canon_view)?;
        }

        let parent_rel = rel.parent().ok_or(STATUS_MEDIA_WRITE_PROTECTED)?;
        let leaf = rel.file_name().ok_or(STATUS_MEDIA_WRITE_PROTECTED)?;

        let canon_parent = self.resolve_existing_rel_under_view(&canon_view, &parent_rel)?;
        let parent_attr = self.vfs.getattr(&canon_parent)?;
        if parent_attr.kind != NodeKind::Directory {
            return Err(STATUS_NOT_A_DIRECTORY);
        }

        if self.config.case_sensitivity() == CaseSensitivity::CaseInsensitiveUnambiguous {
            let children = self.vfs.readdir(&canon_parent)?;
            let mut map = BTreeMap::new();
            for item in children {
                if let Ok(en) = EntryName::new(item.name) {
                    map.insert(en, item.kind);
                }
            }
            let matched =
                lookup_entry_in_map(&map, &leaf, CaseSensitivity::CaseInsensitiveUnambiguous)
                    .into_result(&leaf)
                    .map_err(|_| STATUS_OBJECT_NAME_COLLISION)?;
            if matched.is_some() {
                return Err(STATUS_OBJECT_NAME_COLLISION);
            }
        }

        Ok(format!("{canon_parent}/{}", leaf.as_str()))
    }

    fn alloc_handle(&self, entry: OpenHandleEntry) -> FileHandleId {
        let id = entry.handle_id;
        let mut guard = self.handles.write().unwrap_or_else(|e| e.into_inner());
        guard.insert(id, entry);
        id
    }

    fn next_handle_id(&self) -> FileHandleId {
        FileHandleId(self.next_handle.fetch_add(1, Ordering::Relaxed))
    }

    fn get_active_handle(&self, handle: FileHandleId) -> Result<OpenHandleEntry, NtStatus> {
        let guard = self.handles.read().unwrap_or_else(|e| e.into_inner());
        let entry = guard.get(&handle).cloned().ok_or(STATUS_INVALID_HANDLE)?;
        if entry.deleted {
            return Err(STATUS_DELETE_PENDING);
        }
        Ok(entry)
    }

    // -------------------------------------------------------------------------
    // WinFsp callbacks
    // -------------------------------------------------------------------------

    /// WinFsp `GetVolumeInfo` callback returning virtualized capacity and volume label.
    pub fn get_volume_info(&self) -> Result<WinFspVolumeInfo, NtStatus> {
        Ok(self.config.volume_info())
    }

    /// WinFsp `GetSecurityByName` pre-open lookup callback.
    pub fn get_security_by_name(&self, raw_path: &str) -> Result<SecurityByNameResult, NtStatus> {
        self.get_security_by_name_as(None, raw_path)
    }

    /// WinFsp `GetSecurityByName` callback with explicit caller SID verification.
    pub fn get_security_by_name_as(
        &self,
        caller_sid: Option<&str>,
        raw_path: &str,
    ) -> Result<SecurityByNameResult, NtStatus> {
        self.config.check_caller_sid(caller_sid)?;
        let mount_path = self.resolve_existing_mount_path(raw_path)?;
        let attr = self.vfs.getattr(&mount_path)?;
        let file_attributes = vfs_attr_to_file_attributes(&attr);
        let reparse_tag = (attr.kind == NodeKind::Symlink).then_some(IO_REPARSE_TAG_SYMLINK);
        let security_descriptor = self.config.security_descriptor(attr.read_only);
        Ok(SecurityByNameResult {
            file_attributes,
            reparse_tag,
            security_descriptor,
        })
    }

    /// WinFsp `Open` callback opening an existing file, directory, or symbolic link.
    pub fn open(
        &self,
        raw_path: &str,
        options: OpenOptions,
    ) -> Result<(FileHandleId, WinFspFileInfo), NtStatus> {
        self.config
            .check_caller_sid(options.caller_sid.as_deref())?;

        let parsed_raw = MountPath::parse_winfsp(raw_path)?;
        if options.delete_on_close && parsed_raw.is_root_or_direct_root_child() {
            // Confirm existence first if it's an invalid root child, otherwise `<mount>\` is write-protected.
            if matches!(parsed_raw, MountPath::InvalidRootChild(_)) {
                return Err(STATUS_OBJECT_NAME_NOT_FOUND);
            }
            let mount_path = self.resolve_existing_mount_path(raw_path)?;
            let _ = self.vfs.getattr(&mount_path)?;
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        let mount_path = self.resolve_existing_mount_path(raw_path)?;
        let attr = self.vfs.getattr(&mount_path)?;

        if options.directory_only && attr.kind != NodeKind::Directory {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        if options.non_directory_only && attr.kind == NodeKind::Directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }

        let win_attrs = vfs_attr_to_file_attributes(&attr);
        if options.delete_on_close && win_attrs.contains(FILE_ATTRIBUTE_READONLY) {
            return Err(if attr.read_only {
                STATUS_MEDIA_WRITE_PROTECTED
            } else {
                STATUS_CANNOT_DELETE
            });
        }
        if options.write_access {
            if attr.read_only {
                return Err(STATUS_MEDIA_WRITE_PROTECTED);
            }
            if attr.kind != NodeKind::Directory && win_attrs.contains(FILE_ATTRIBUTE_READONLY) {
                return Err(STATUS_ACCESS_DENIED);
            }
        }

        let handle_id = self.next_handle_id();
        self.alloc_handle(OpenHandleEntry {
            handle_id,
            mount_path,
            kind: attr.kind,
            write_access: options.write_access,
            delete_on_close: options.delete_on_close,
            open_reparse_point: options.open_reparse_point || attr.kind == NodeKind::Symlink,
            deleted: false,
        });

        Ok((handle_id, WinFspFileInfo::from_vfs_attr(&attr)))
    }

    /// WinFsp `Create` / `CreateEx` callback exclusively creating a new file, directory, or symlink.
    pub fn create(
        &self,
        raw_path: &str,
        params: CreateParams,
    ) -> Result<(FileHandleId, WinFspFileInfo), NtStatus> {
        self.config.check_caller_sid(params.caller_sid.as_deref())?;
        let target_mount_path = self.resolve_create_target(raw_path)?;

        let (attr, created_kind, notify_filter) = if let Some(reparse) = &params.reparse_data {
            if reparse.reparse_tag != IO_REPARSE_TAG_SYMLINK {
                return Err(STATUS_IO_REPARSE_TAG_NOT_HANDLED);
            }
            let created = self.vfs.symlink(&reparse.target, &target_mount_path)?;
            (created, NodeKind::Symlink, NotifyFilter::FILE_NAME)
        } else if params.is_directory || params.file_attributes.contains(FILE_ATTRIBUTE_DIRECTORY) {
            let mode = params.posix_mode_override.unwrap_or_else(|| {
                file_attributes_to_posix_mode(params.file_attributes, NodeKind::Directory)
            });
            let created = self.vfs.mkdir(&target_mount_path, mode)?;
            (created, NodeKind::Directory, NotifyFilter::DIR_NAME)
        } else {
            let mode = params.posix_mode_override.unwrap_or_else(|| {
                file_attributes_to_posix_mode(params.file_attributes, NodeKind::File)
            });
            let created = self.vfs.create_file(&target_mount_path, mode, true)?;
            (created, NodeKind::File, NotifyFilter::FILE_NAME)
        };

        let handle_id = self.next_handle_id();
        self.alloc_handle(OpenHandleEntry {
            handle_id,
            mount_path: target_mount_path.clone(),
            kind: created_kind,
            write_access: true,
            delete_on_close: params.delete_on_close,
            open_reparse_point: created_kind == NodeKind::Symlink,
            deleted: false,
        });

        self.notifier.emit(
            &target_mount_path,
            DirectoryChangeAction::Added,
            notify_filter | NotifyFilter::CREATION,
            created_kind == NodeKind::Directory,
        );

        Ok((handle_id, WinFspFileInfo::from_vfs_attr(&attr)))
    }

    /// WinFsp `Read` callback streaming bytes directly from the content-addressed blob store
    /// without NTFS hydration (ADR-0004).
    pub fn read(
        &self,
        handle: FileHandleId,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, NtStatus> {
        let entry = self.get_active_handle(handle)?;
        if entry.kind == NodeKind::Directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let data = self.vfs.read(&entry.mount_path, offset, buffer.len())?;
        let n = data.len().min(buffer.len());
        buffer[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    /// WinFsp `Write` callback performing Copy-on-Write into the active `View`'s private `Overlay`.
    pub fn write(
        &self,
        handle: FileHandleId,
        offset: u64,
        data: &[u8],
    ) -> Result<(u64, WinFspFileInfo), NtStatus> {
        self.write_ex(handle, offset, data, false, false)
    }

    /// Full WinFsp `Write` callback supporting `WriteToEndOfFile` (append) and `ConstrainedIo`.
    pub fn write_ex(
        &self,
        handle: FileHandleId,
        offset: u64,
        data: &[u8],
        write_to_end_of_file: bool,
        constrained_io: bool,
    ) -> Result<(u64, WinFspFileInfo), NtStatus> {
        let entry = self.get_active_handle(handle)?;
        if entry.kind == NodeKind::Directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        if !entry.write_access {
            return Err(STATUS_ACCESS_DENIED);
        }

        let current_attr = self.vfs.getattr(&entry.mount_path)?;
        let effective_offset = if write_to_end_of_file {
            current_attr.size
        } else {
            offset
        };

        let slice_to_write: &[u8] = if constrained_io {
            if effective_offset >= current_attr.size {
                return Ok((0, WinFspFileInfo::from_vfs_attr(&current_attr)));
            }
            let max_bytes = (current_attr.size - effective_offset) as usize;
            &data[..data.len().min(max_bytes)]
        } else {
            data
        };

        let written = self
            .vfs
            .write(&entry.mount_path, effective_offset, slice_to_write)?;
        let updated_attr = self.vfs.getattr(&entry.mount_path)?;

        self.notifier.emit(
            &entry.mount_path,
            DirectoryChangeAction::Modified,
            NotifyFilter::LAST_WRITE | NotifyFilter::SIZE,
            false,
        );

        Ok((written, WinFspFileInfo::from_vfs_attr(&updated_attr)))
    }

    /// WinFsp `Overwrite` callback truncating an existing regular file to zero bytes and applying
    /// `file_attributes`.
    pub fn overwrite(
        &self,
        handle: FileHandleId,
        file_attributes: FileAttributes,
        replace_file_attributes: bool,
        _allocation_size: u64,
    ) -> Result<WinFspFileInfo, NtStatus> {
        let entry = self.get_active_handle(handle)?;
        if entry.kind == NodeKind::Directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        if !entry.write_access {
            return Err(STATUS_ACCESS_DENIED);
        }

        let current_attr = self.vfs.getattr(&entry.mount_path)?;
        let current_win_attrs = vfs_attr_to_file_attributes(&current_attr);
        if current_win_attrs.contains(FILE_ATTRIBUTE_READONLY) {
            return Err(STATUS_ACCESS_DENIED);
        }

        let new_mode = if replace_file_attributes {
            let effective = if file_attributes.is_empty() {
                FILE_ATTRIBUTE_NORMAL
            } else {
                file_attributes
            };
            apply_file_attributes_to_mode(effective, NodeKind::File, current_attr.mode)
        } else if file_attributes.contains(FILE_ATTRIBUTE_READONLY) {
            apply_file_attributes_to_mode(
                FILE_ATTRIBUTE_READONLY,
                NodeKind::File,
                current_attr.mode,
            )
        } else {
            None
        };

        let updated_attr = self.vfs.setattr(
            &entry.mount_path,
            VfsSetAttr {
                mode: new_mode,
                size: Some(0),
                mtime: Some(Timestamp::now()),
            },
        )?;

        self.notifier.emit(
            &entry.mount_path,
            DirectoryChangeAction::Modified,
            NotifyFilter::SIZE | NotifyFilter::LAST_WRITE | NotifyFilter::ATTRIBUTES,
            false,
        );

        Ok(WinFspFileInfo::from_vfs_attr(&updated_attr))
    }

    /// WinFsp `SetFileSize` callback resizing an open regular file.
    pub fn set_file_size(
        &self,
        handle: FileHandleId,
        new_size: u64,
        set_allocation_size: bool,
    ) -> Result<WinFspFileInfo, NtStatus> {
        let entry = self.get_active_handle(handle)?;
        if entry.kind == NodeKind::Directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        if !entry.write_access {
            return Err(STATUS_ACCESS_DENIED);
        }

        let updated_attr = if set_allocation_size {
            let current = self.vfs.getattr(&entry.mount_path)?;
            if new_size < current.size {
                self.vfs.truncate(&entry.mount_path, new_size)?
            } else {
                current
            }
        } else {
            self.vfs.truncate(&entry.mount_path, new_size)?
        };

        self.notifier.emit(
            &entry.mount_path,
            DirectoryChangeAction::Modified,
            NotifyFilter::SIZE | NotifyFilter::LAST_WRITE,
            false,
        );

        Ok(WinFspFileInfo::from_vfs_attr(&updated_attr))
    }

    /// WinFsp `CanDelete` pre-check verifying that an open handle's target may be deleted.
    pub fn can_delete(&self, handle: FileHandleId) -> Result<(), NtStatus> {
        let entry = self.get_active_handle(handle)?;
        let parsed = MountPath::parse(&entry.mount_path)?;
        if parsed.is_root_or_direct_root_child() {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        let attr = self.vfs.getattr(&entry.mount_path)?;
        if vfs_attr_to_file_attributes(&attr).contains(FILE_ATTRIBUTE_READONLY) {
            return Err(STATUS_CANNOT_DELETE);
        }
        if attr.kind == NodeKind::Directory {
            let children = self.vfs.readdir(&entry.mount_path)?;
            if !children.is_empty() {
                return Err(STATUS_DIRECTORY_NOT_EMPTY);
            }
        }
        Ok(())
    }

    /// WinFsp `SetDelete` / `FileDispositionInformation` handler toggling delete-on-close on `handle`.
    pub fn set_delete_on_close(
        &self,
        handle: FileHandleId,
        delete_on_close: bool,
    ) -> Result<(), NtStatus> {
        if delete_on_close {
            self.can_delete(handle)?;
        }
        let mut guard = self.handles.write().unwrap_or_else(|e| e.into_inner());
        let entry = guard.get_mut(&handle).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.deleted {
            return Err(STATUS_DELETE_PENDING);
        }
        entry.delete_on_close = delete_on_close;
        Ok(())
    }

    /// WinFsp `Cleanup` callback executing delete-on-close (`FspCleanupDelete` or handle disposition)
    /// when a Win32 `HANDLE` closes prior to final `Close`.
    pub fn cleanup(&self, handle: FileHandleId, flags: CleanupFlags) -> Result<(), NtStatus> {
        let handle_record = {
            let guard = self.handles.read().unwrap_or_else(|e| e.into_inner());
            guard.get(&handle).cloned().ok_or(STATUS_INVALID_HANDLE)?
        };

        if handle_record.deleted {
            return Ok(());
        }

        let should_delete = flags.contains(CleanupFlags::DELETE) || handle_record.delete_on_close;
        if !should_delete {
            return Ok(());
        }

        let parsed = MountPath::parse(&handle_record.mount_path)?;
        if parsed.is_root_or_direct_root_child() {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        let is_dir = handle_record.kind == NodeKind::Directory;
        if is_dir {
            self.vfs.rmdir(&handle_record.mount_path)?;
        } else {
            self.vfs.unlink(&handle_record.mount_path)?;
        }

        {
            let mut guard = self.handles.write().unwrap_or_else(|e| e.into_inner());
            for item in guard.values_mut() {
                if item.mount_path == handle_record.mount_path {
                    item.deleted = true;
                }
            }
        }

        let notify_filter = if is_dir {
            NotifyFilter::DIR_NAME
        } else {
            NotifyFilter::FILE_NAME
        };
        self.notifier.emit(
            &handle_record.mount_path,
            DirectoryChangeAction::Removed,
            notify_filter,
            is_dir,
        );

        Ok(())
    }

    /// WinFsp `Close` callback releasing the in-memory `FileHandleId` context.
    pub fn close(&self, handle: FileHandleId) -> Result<(), NtStatus> {
        let mut guard = self.handles.write().unwrap_or_else(|e| e.into_inner());
        guard
            .remove(&handle)
            .map(|_| ())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// WinFsp `GetFileInfo` callback querying metadata on an open handle.
    pub fn get_file_info(&self, handle: FileHandleId) -> Result<WinFspFileInfo, NtStatus> {
        let entry = self.get_active_handle(handle)?;
        let attr = self.vfs.getattr(&entry.mount_path)?;
        Ok(WinFspFileInfo::from_vfs_attr(&attr))
    }

    /// WinFsp `SetBasicInfo` callback updating Windows `FileAttributes` and/or timestamps.
    pub fn set_basic_info(
        &self,
        handle: FileHandleId,
        update: BasicInfoUpdate,
    ) -> Result<WinFspFileInfo, NtStatus> {
        let entry = self.get_active_handle(handle)?;
        if entry.mount_path.is_empty() {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        if !entry.write_access {
            return Err(STATUS_ACCESS_DENIED);
        }

        let current_attr = self.vfs.getattr(&entry.mount_path)?;
        let new_mode = apply_file_attributes_to_mode(
            update.file_attributes,
            current_attr.kind,
            current_attr.mode,
        );
        let new_mtime = update.effective_mtime();

        if new_mode.is_none() && new_mtime.is_none() {
            return Ok(WinFspFileInfo::from_vfs_attr(&current_attr));
        }

        let updated_attr = self.vfs.setattr(
            &entry.mount_path,
            VfsSetAttr {
                mode: new_mode,
                size: None,
                mtime: new_mtime,
            },
        )?;

        let mut filter = NotifyFilter(0);
        if new_mode.is_some() {
            filter |= NotifyFilter::ATTRIBUTES;
        }
        if new_mtime.is_some() {
            filter |= NotifyFilter::LAST_WRITE;
        }
        self.notifier.emit(
            &entry.mount_path,
            DirectoryChangeAction::Modified,
            filter,
            current_attr.kind == NodeKind::Directory,
        );

        Ok(WinFspFileInfo::from_vfs_attr(&updated_attr))
    }

    /// WinFsp `ReadDirectory` callback enumerating `<mount>\` or a `View` directory with optional
    /// wildcard `pattern` (`*`, `?`) and continuation `marker`.
    ///
    /// Non-root directories emit `"."` and `".."` first per WinFsp conventions, followed by
    /// canonical case-preserved child entries.
    pub fn read_directory(
        &self,
        handle: FileHandleId,
        pattern: Option<&str>,
        marker: Option<&str>,
    ) -> Result<Vec<WinFspDirEntry>, NtStatus> {
        let entry = self.get_active_handle(handle)?;
        if entry.kind != NodeKind::Directory {
            return Err(STATUS_NOT_A_DIRECTORY);
        }

        let self_attr = self.vfs.getattr(&entry.mount_path)?;
        let mut all_entries = Vec::new();

        if !entry.mount_path.is_empty() {
            all_entries.push(WinFspDirEntry {
                name: ".".to_owned(),
                file_info: WinFspFileInfo::from_vfs_attr(&self_attr),
            });

            let parent_mount = match entry.mount_path.rfind('/') {
                Some(idx) => &entry.mount_path[..idx],
                None => "",
            };
            let parent_attr = self.vfs.getattr(parent_mount)?;
            all_entries.push(WinFspDirEntry {
                name: "..".to_owned(),
                file_info: WinFspFileInfo::from_vfs_attr(&parent_attr),
            });
        }

        let raw_children = self.vfs.readdir(&entry.mount_path)?;
        for child in raw_children {
            let child_mount = if entry.mount_path.is_empty() {
                child.name.clone()
            } else {
                format!("{}/{}", entry.mount_path, child.name)
            };
            let child_attr = self.vfs.getattr(&child_mount)?;
            all_entries.push(WinFspDirEntry {
                name: child.name,
                file_info: WinFspFileInfo::from_vfs_attr(&child_attr),
            });
        }

        let case_sensitive = self.config.case_sensitivity() == CaseSensitivity::CaseSensitive;
        let past_marker: Vec<WinFspDirEntry> = match marker {
            None => all_entries,
            Some(m) => {
                if let Some(pos) = all_entries
                    .iter()
                    .position(|item| names_equal(&item.name, m, case_sensitive))
                {
                    all_entries.into_iter().skip(pos + 1).collect()
                } else {
                    all_entries
                        .into_iter()
                        .filter(|item| name_after_marker(&item.name, m, case_sensitive))
                        .collect()
                }
            }
        };

        match pattern {
            None | Some("*") => Ok(past_marker),
            Some(pat) => Ok(past_marker
                .into_iter()
                .filter(|item| wildcard_matches(pat, &item.name, case_sensitive))
                .collect()),
        }
    }

    /// WinFsp `Rename` callback invoked on an open `handle` moving it to `new_raw_path`.
    pub fn rename(
        &self,
        handle: FileHandleId,
        new_raw_path: &str,
        replace_if_exists: bool,
    ) -> Result<(), NtStatus> {
        let entry = self.get_active_handle(handle)?;
        self.rename_from_canonical(&entry.mount_path, new_raw_path, replace_if_exists)
    }

    /// Path-based `Rename` entry point (`from_raw_path` -> `to_raw_path`).
    pub fn rename_by_path(
        &self,
        from_raw_path: &str,
        to_raw_path: &str,
        replace_if_exists: bool,
    ) -> Result<(), NtStatus> {
        let from_parsed = MountPath::parse_winfsp(from_raw_path)?;
        let to_parsed = MountPath::parse_winfsp(to_raw_path)?;
        if from_parsed.is_root_or_direct_root_child() || to_parsed.is_root_or_direct_root_child() {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        if let (MountPath::View { view: v1, .. }, MountPath::View { view: v2, .. }) =
            (&from_parsed, &to_parsed)
        {
            let cv1 = self.resolve_view_name(v1)?;
            let cv2 = self.resolve_view_name(v2)?;
            if cv1 != cv2 {
                return Err(STATUS_NOT_SAME_DEVICE);
            }
        }
        let canonical_from = self.resolve_existing_mount_path(from_raw_path)?;
        self.rename_from_canonical(&canonical_from, to_raw_path, replace_if_exists)
    }

    fn rename_from_canonical(
        &self,
        canonical_from: &str,
        to_raw_path: &str,
        replace_if_exists: bool,
    ) -> Result<(), NtStatus> {
        let from_parsed = MountPath::parse(canonical_from)?;
        let to_parsed = MountPath::parse_winfsp(to_raw_path)?;

        if from_parsed.is_root_or_direct_root_child() || to_parsed.is_root_or_direct_root_child() {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        let (
            MountPath::View {
                view: from_view, ..
            },
            MountPath::View {
                view: to_view_raw,
                rel: to_rel,
            },
        ) = (from_parsed, to_parsed)
        else {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        };

        let canon_to_view = self.resolve_view_name(&to_view_raw)?;
        if from_view.as_str() != canon_to_view {
            return Err(STATUS_NOT_SAME_DEVICE);
        }

        let from_attr = self.vfs.getattr(canonical_from)?;
        let to_parent_rel = to_rel.parent().ok_or(STATUS_MEDIA_WRITE_PROTECTED)?;
        let to_leaf = to_rel.file_name().ok_or(STATUS_MEDIA_WRITE_PROTECTED)?;
        let canon_to_parent =
            self.resolve_existing_rel_under_view(&canon_to_view, &to_parent_rel)?;

        let parent_children = self.vfs.readdir(&canon_to_parent)?;
        let mut sibling_map = BTreeMap::new();
        for item in parent_children {
            if let Ok(en) = EntryName::new(item.name) {
                sibling_map.insert(en, item.kind);
            }
        }

        let existing_match =
            lookup_entry_in_map(&sibling_map, &to_leaf, self.config.case_sensitivity())
                .into_result(&to_leaf)
                .map_err(|_| STATUS_OBJECT_NAME_COLLISION)?;

        let requested_dest = format!("{canon_to_parent}/{}", to_leaf.as_str());

        if let Some((matched_name, matched_kind)) = existing_match {
            let existing_dest = format!("{canon_to_parent}/{}", matched_name.as_str());
            if existing_dest == canonical_from {
                // Exact same path is a no-op; differing case (e.g. readme.md -> README.md) updates case!
                if requested_dest == canonical_from {
                    return Ok(());
                }
            } else {
                if !replace_if_exists {
                    return Err(STATUS_OBJECT_NAME_COLLISION);
                }
                let dest_attr = self.vfs.getattr(&existing_dest)?;
                if vfs_attr_to_file_attributes(&dest_attr).contains(FILE_ATTRIBUTE_READONLY) {
                    return Err(STATUS_ACCESS_DENIED);
                }
                if existing_dest != requested_dest {
                    if *matched_kind == NodeKind::Directory {
                        self.vfs.rmdir(&existing_dest)?;
                    } else {
                        self.vfs.unlink(&existing_dest)?;
                    }
                }
            }
        }

        self.vfs.rename(canonical_from, &requested_dest)?;

        // Update any open handles pointing at `canonical_from` or its descendants.
        {
            let from_prefix = format!("{canonical_from}/");
            let mut guard = self.handles.write().unwrap_or_else(|e| e.into_inner());
            for item in guard.values_mut() {
                if item.mount_path == canonical_from {
                    item.mount_path = requested_dest.clone();
                } else if let Some(suffix) = item.mount_path.strip_prefix(&from_prefix) {
                    item.mount_path = format!("{requested_dest}/{suffix}");
                }
            }
        }

        let is_dir = from_attr.kind == NodeKind::Directory;
        let filter = if is_dir {
            NotifyFilter::DIR_NAME
        } else {
            NotifyFilter::FILE_NAME
        };
        self.notifier.emit(
            canonical_from,
            DirectoryChangeAction::RenamedOldName,
            filter,
            is_dir,
        );
        self.notifier.emit(
            &requested_dest,
            DirectoryChangeAction::RenamedNewName,
            filter,
            is_dir,
        );

        Ok(())
    }

    /// WinFsp `GetReparsePoint` callback reading `IO_REPARSE_TAG_SYMLINK` data from an open handle.
    pub fn get_reparse_point(&self, handle: FileHandleId) -> Result<ReparsePointData, NtStatus> {
        let entry = self.get_active_handle(handle)?;
        if entry.kind != NodeKind::Symlink {
            return Err(STATUS_NOT_A_REPARSE_POINT);
        }
        let target = self.vfs.readlink(&entry.mount_path)?;
        ReparsePointData::symlink(target)
    }

    /// WinFsp `GetReparsePointByName` callback reading `IO_REPARSE_TAG_SYMLINK` data by path.
    pub fn get_reparse_point_by_name(&self, raw_path: &str) -> Result<ReparsePointData, NtStatus> {
        let mount_path = self.resolve_existing_mount_path(raw_path)?;
        let attr = self.vfs.getattr(&mount_path)?;
        if attr.kind != NodeKind::Symlink {
            return Err(STATUS_NOT_A_REPARSE_POINT);
        }
        let target = self.vfs.readlink(&mount_path)?;
        ReparsePointData::symlink(target)
    }

    /// WinFsp `SetReparsePoint` (`FSCTL_SET_REPARSE_POINT`) callback converting an empty open file,
    /// empty directory, or existing symbolic link into a symbolic link pointing to `data.target`.
    pub fn set_reparse_point(
        &self,
        handle: FileHandleId,
        data: ReparsePointData,
    ) -> Result<WinFspFileInfo, NtStatus> {
        if data.reparse_tag != IO_REPARSE_TAG_SYMLINK {
            return Err(STATUS_IO_REPARSE_TAG_NOT_HANDLED);
        }
        // Validate reparse payload before touching the VFS entry.
        let validated = ReparsePointData::symlink(data.target)?;

        let entry = self.get_active_handle(handle)?;
        if !entry.write_access {
            return Err(STATUS_ACCESS_DENIED);
        }
        let parsed = MountPath::parse(&entry.mount_path)?;
        if parsed.is_root_or_direct_root_child() {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }

        let current_attr = self.vfs.getattr(&entry.mount_path)?;
        match current_attr.kind {
            NodeKind::File => {
                if current_attr.size != 0 {
                    return Err(STATUS_IO_REPARSE_DATA_INVALID);
                }
                self.vfs.unlink(&entry.mount_path)?;
            }
            NodeKind::Directory => {
                let children = self.vfs.readdir(&entry.mount_path)?;
                if !children.is_empty() {
                    return Err(STATUS_DIRECTORY_NOT_EMPTY);
                }
                self.vfs.rmdir(&entry.mount_path)?;
            }
            NodeKind::Symlink => {
                self.vfs.unlink(&entry.mount_path)?;
            }
        }

        let sym_attr = self.vfs.symlink(&validated.target, &entry.mount_path)?;

        {
            let mut guard = self.handles.write().unwrap_or_else(|e| e.into_inner());
            if let Some(h) = guard.get_mut(&handle) {
                h.kind = NodeKind::Symlink;
                h.open_reparse_point = true;
            }
        }

        self.notifier.emit(
            &entry.mount_path,
            DirectoryChangeAction::Modified,
            NotifyFilter::ATTRIBUTES | NotifyFilter::LAST_WRITE,
            false,
        );

        Ok(WinFspFileInfo::from_vfs_attr(&sym_attr))
    }

    /// Hard link creation handler (`SetInformation(FileLinkInformation)`) — unsupported across
    /// virtualized `Base + Overlay` mounts (`STATUS_NOT_SUPPORTED`).
    pub fn create_hard_link(
        &self,
        raw_existing_path: &str,
        raw_new_link_path: &str,
    ) -> Result<WinFspFileInfo, NtStatus> {
        let existing_mount = MountPath::parse_winfsp(raw_existing_path)?.to_mount_string();
        let new_mount = MountPath::parse_winfsp(raw_new_link_path)?.to_mount_string();
        match self.vfs.link(&existing_mount, &new_mount) {
            Ok(attr) => Ok(WinFspFileInfo::from_vfs_attr(&attr)),
            Err(VfsError::NotSupported) => Err(STATUS_NOT_SUPPORTED),
            Err(other) => Err(NtStatus::from_vfs_error(&other)),
        }
    }

    /// Registers a `ReadDirectoryChangesW` watch after verifying `raw_dir_path` resolves to an
    /// existing directory.
    pub fn watch_directory(
        &self,
        raw_dir_path: &str,
        watch_tree: bool,
        filter: NotifyFilter,
    ) -> Result<WatchId, NtStatus> {
        let canon = self.resolve_existing_mount_path(raw_dir_path)?;
        let attr = self.vfs.getattr(&canon)?;
        if attr.kind != NodeKind::Directory {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        Ok(self
            .notifier
            .subscribe_canonical(&canon, watch_tree, filter))
    }
}

fn names_equal(a: &str, b: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        a == b
    } else {
        a.to_lowercase() == b.to_lowercase()
    }
}

fn name_after_marker(name: &str, marker: &str, case_sensitive: bool) -> bool {
    if marker == "." {
        return name != ".";
    }
    if marker == ".." {
        return name != "." && name != "..";
    }
    if name == "." || name == ".." {
        return false;
    }
    if case_sensitive {
        name > marker
    } else {
        name.to_lowercase() > marker.to_lowercase()
    }
}

fn wildcard_matches(pattern: &str, candidate: &str, case_sensitive: bool) -> bool {
    let pat_chars: Vec<char> = if case_sensitive {
        pattern.chars().collect()
    } else {
        pattern.to_lowercase().chars().collect()
    };
    let cand_chars: Vec<char> = if case_sensitive {
        candidate.chars().collect()
    } else {
        candidate.to_lowercase().chars().collect()
    };

    let (mut pi, mut ci) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ci = 0usize;

    while ci < cand_chars.len() {
        if pi < pat_chars.len() && (pat_chars[pi] == '?' || pat_chars[pi] == cand_chars[ci]) {
            pi += 1;
            ci += 1;
        } else if pi < pat_chars.len() && pat_chars[pi] == '*' {
            star_pi = Some(pi);
            pi += 1;
            star_ci = ci;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ci += 1;
            ci = star_ci;
        } else {
            return false;
        }
    }

    while pi < pat_chars.len() && pat_chars[pi] == '*' {
        pi += 1;
    }
    pi == pat_chars.len()
}
