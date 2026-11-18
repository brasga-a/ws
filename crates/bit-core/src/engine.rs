//! Deterministic `CoreEngine` implementing both `ControlPlane` and `VfsOperations` over any
//! `BlobStore` + `MetadataStore` (including `CoreEngine::in_memory()`).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::control::{
    ApplyTarget, BaseInfo, BaseInput, ControlPlane, CoreError, InputEntry, RemoveBaseOutput,
    ViewInfo,
};
use crate::hash::{BaseId, ContentHash};
use crate::ids::{BaseSelector, TagName, ViewId};
use crate::model::{
    validate_symlink_target, Base, DirectoryTree, EntryMetadata, NodeKind, Timestamp, TreeEntry,
    View, DEFAULT_DIR_MODE, DEFAULT_FILE_MODE, PERM_MASK,
};
use crate::ops::{
    compute_diff, freeze_to_base, plan_apply, ApplyAction, ApplyOutput, DiffEntry, FreezeOutput,
};
use crate::path::{CaseSensitivity, EntryName, RelPath};
use crate::store::{
    BlobStore, InMemoryBlobStore, InMemoryMetadataStore, MetadataStore, StoreError,
};
use crate::vfs::{
    InodeTable, MountPath, QuiescenceManager, VfsAttr, VfsDirEntry, VfsError, VfsOperations,
    VfsSetAttr, ViewQuiesceGuard, MOUNT_ROOT_MODE, ROOT_INO,
};

/// Shorthand type for a purely in-memory deterministic `CoreEngine`.
pub type InMemoryCoreEngine = CoreEngine<InMemoryBlobStore, InMemoryMetadataStore>;

/// OS-agnostic core execution engine implementing `ControlPlane` and `VfsOperations` over
/// pluggable `BlobStore` and `MetadataStore` ports.
#[derive(Debug)]
pub struct CoreEngine<B: BlobStore, M: MetadataStore> {
    blob_store: B,
    metadata_store: M,
    inodes: InodeTable,
    quiescence: QuiescenceManager,
    lifecycle_lock: Mutex<()>,
    view_locks: Mutex<BTreeMap<ViewId, Arc<Mutex<()>>>>,
    case_sensitivity: CaseSensitivity,
}

impl CoreEngine<InMemoryBlobStore, InMemoryMetadataStore> {
    /// Creates a deterministic in-memory `CoreEngine` backed by `InMemoryBlobStore` and `InMemoryMetadataStore`.
    pub fn in_memory() -> Self {
        Self::new(InMemoryBlobStore::new(), InMemoryMetadataStore::new())
    }
}

impl<B: BlobStore, M: MetadataStore> CoreEngine<B, M> {
    /// Constructs a `CoreEngine` over the given `blob_store` and `metadata_store`.
    pub fn new(blob_store: B, metadata_store: M) -> Self {
        Self {
            blob_store,
            metadata_store,
            inodes: InodeTable::new(),
            quiescence: QuiescenceManager::new(),
            lifecycle_lock: Mutex::new(()),
            view_locks: Mutex::new(BTreeMap::new()),
            case_sensitivity: CaseSensitivity::CaseSensitive,
        }
    }

    /// Configures path case-matching behavior (`CaseSensitive` by default; `CaseInsensitiveUnambiguous`
    /// available for macOS/Windows adapters).
    pub fn with_case_sensitivity(mut self, policy: CaseSensitivity) -> Self {
        self.case_sensitivity = policy;
        self
    }

    /// Borrows the underlying `BlobStore`.
    pub const fn blob_store(&self) -> &B {
        &self.blob_store
    }

    /// Borrows the underlying `MetadataStore`.
    pub const fn metadata_store(&self) -> &M {
        &self.metadata_store
    }

    /// Borrows the virtual `InodeTable`.
    pub const fn inode_table(&self) -> &InodeTable {
        &self.inodes
    }

    /// Borrows the per-`View` `QuiescenceManager`.
    pub const fn quiescence(&self) -> &QuiescenceManager {
        &self.quiescence
    }

    fn view_mutex(&self, view_id: &ViewId) -> Arc<Mutex<()>> {
        let mut guard = self.view_locks.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .entry(view_id.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn resolve_base_selector(&self, selector: &BaseSelector) -> Result<BaseId, CoreError> {
        match selector {
            BaseSelector::Id(id) => {
                if self.metadata_store.get_base(id)?.is_some() {
                    Ok(*id)
                } else {
                    Err(CoreError::BaseNotFound(*id))
                }
            }
            BaseSelector::Tag(tag) => {
                let Some(id) = self.metadata_store.get_tag(tag)? else {
                    return Err(CoreError::TagNotFound(tag.clone()));
                };
                if self.metadata_store.get_base(&id)?.is_some() {
                    Ok(id)
                } else {
                    Err(CoreError::BaseNotFound(id))
                }
            }
        }
    }

    fn load_view_and_base(&self, view_id: &ViewId) -> Result<(View, Base), CoreError> {
        let Some(view) = self.metadata_store.get_view(view_id)? else {
            return Err(CoreError::ViewNotFound(view_id.clone()));
        };
        let base_id = view.base_id();
        let Some(base) = self.metadata_store.get_base(&base_id)? else {
            return Err(CoreError::BaseNotFound(base_id));
        };
        Ok((view, base))
    }

    fn load_view_and_base_vfs(&self, view_id: &ViewId) -> Result<(View, Base), VfsError> {
        let Some(view) = self.metadata_store.get_view(view_id)? else {
            return Err(VfsError::NotFound);
        };
        let base_id = view.base_id();
        let Some(base) = self.metadata_store.get_base(&base_id)? else {
            return Err(VfsError::Io(format!(
                "missing backing base {base_id} for view {view_id}"
            )));
        };
        Ok((view, base))
    }

    fn resolve_canonical_rel(
        &self,
        base: &Base,
        view: &View,
        rel: &RelPath,
    ) -> Result<Option<(RelPath, TreeEntry)>, VfsError> {
        Ok(view.resolve_with_case(base, rel, self.case_sensitivity)?)
    }

    fn resolve_parent_for_child(
        &self,
        base: &Base,
        view: &View,
        rel: &RelPath,
    ) -> Result<(RelPath, EntryName), VfsError> {
        let parent_query = rel
            .parent()
            .ok_or_else(|| VfsError::InvalidInput("unexpected root path".to_owned()))?;
        let leaf = rel
            .file_name()
            .ok_or_else(|| VfsError::InvalidInput("unexpected root path".to_owned()))?;

        if parent_query.is_root() {
            return Ok((RelPath::root(), leaf));
        }

        let Some((canonical_parent, parent_entry)) =
            self.resolve_canonical_rel(base, view, &parent_query)?
        else {
            return Err(VfsError::NotFound);
        };
        if parent_entry.kind() != NodeKind::Directory {
            return Err(VfsError::NotADirectory);
        }
        Ok((canonical_parent, leaf))
    }

    fn make_vfs_attr(
        &self,
        view_id: &ViewId,
        canonical_rel: &RelPath,
        meta: EntryMetadata,
    ) -> VfsAttr {
        let mount_str = if canonical_rel.is_root() {
            view_id.as_str().to_owned()
        } else {
            format!("{}/{}", view_id.as_str(), canonical_rel.as_str())
        };
        let ino = self.inodes.get_or_alloc(&mount_str);
        let nlink = if meta.kind == NodeKind::Directory {
            2
        } else {
            1
        };
        VfsAttr::from_metadata(ino, meta, nlink, false)
    }

    fn build_base_info(&self, base_id: BaseId, entry_count: usize) -> Result<BaseInfo, CoreError> {
        let tags_map = self.metadata_store.list_tags()?;
        let tags: Vec<TagName> = tags_map
            .into_iter()
            .filter_map(|(tag, target)| (target == base_id).then_some(tag))
            .collect();
        let view_count = self
            .metadata_store
            .list_views()?
            .iter()
            .filter(|v| v.base_id() == base_id)
            .count();
        Ok(BaseInfo {
            id: base_id,
            tags,
            entry_count,
            view_count,
        })
    }

    fn ingest_entries_input(&self, entries: Vec<InputEntry>) -> Result<DirectoryTree, CoreError> {
        let mut tree_entries = Vec::with_capacity(entries.len());
        for item in entries {
            match item {
                InputEntry::File {
                    path,
                    bytes,
                    mode,
                    mtime,
                } => {
                    let hash = self.blob_store.put_blob(&bytes)?;
                    tree_entries
                        .push((path, TreeEntry::file(hash, bytes.len() as u64, mode, mtime)));
                }
                InputEntry::Directory { path, mode, mtime } => {
                    tree_entries.push((path, TreeEntry::directory(mode, mtime)));
                }
                InputEntry::Symlink {
                    path,
                    target,
                    mtime,
                } => {
                    tree_entries.push((path, TreeEntry::symlink(target, mtime)?));
                }
            }
        }
        Ok(DirectoryTree::from_entries(tree_entries)?)
    }

    fn verify_tree_blobs(&self, tree: &DirectoryTree) -> Result<(), CoreError> {
        for entry in tree.entries().values() {
            if let TreeEntry::File { content, .. } = entry {
                if !self.blob_store.has_blob(content)? {
                    return Err(CoreError::Store(StoreError::BlobNotFound(*content)));
                }
            }
        }
        Ok(())
    }

    fn scan_host_directory(
        &self,
        root_dir: &Path,
        store_blobs: bool,
    ) -> Result<DirectoryTree, CoreError> {
        let root_meta = fs::symlink_metadata(root_dir).map_err(|e| {
            CoreError::Store(StoreError::Io(format!(
                "failed to stat {}: {e}",
                root_dir.display()
            )))
        })?;
        if !root_meta.file_type().is_dir() {
            return Err(CoreError::UnsupportedFilesystemEntry {
                path: root_dir.display().to_string(),
                reason: "root path is not a directory".to_owned(),
            });
        }

        let root_mode = extract_host_mode(&root_meta, true);
        let root_mtime = extract_host_mtime(&root_meta);
        let mut collected = Vec::new();
        self.walk_host_subdir(root_dir, &RelPath::root(), store_blobs, &mut collected)?;
        Ok(DirectoryTree::with_root_and_entries(
            root_mode, root_mtime, collected,
        )?)
    }

    fn walk_host_subdir(
        &self,
        host_dir: &Path,
        rel_prefix: &RelPath,
        store_blobs: bool,
        out: &mut Vec<(RelPath, TreeEntry)>,
    ) -> Result<(), CoreError> {
        let read_dir = fs::read_dir(host_dir).map_err(|e| {
            CoreError::Store(StoreError::Io(format!(
                "failed to read directory {}: {e}",
                host_dir.display()
            )))
        })?;

        let mut dir_entries = Vec::new();
        for item in read_dir {
            let entry = item.map_err(|e| CoreError::Store(StoreError::Io(e.to_string())))?;
            dir_entries.push(entry);
        }
        dir_entries.sort_by_key(|e| e.file_name());

        for entry in dir_entries {
            let raw_name = entry.file_name();
            let Some(utf8_name) = raw_name.to_str() else {
                return Err(CoreError::UnsupportedFilesystemEntry {
                    path: entry.path().display().to_string(),
                    reason: "entry name is not valid UTF-8".to_owned(),
                });
            };
            let entry_name = EntryName::new(utf8_name)?;
            let rel_path = rel_prefix.join(&entry_name);
            let full_path = entry.path();
            let meta = fs::symlink_metadata(&full_path).map_err(|e| {
                CoreError::Store(StoreError::Io(format!(
                    "failed to stat {}: {e}",
                    full_path.display()
                )))
            })?;
            let ft = meta.file_type();
            let mtime = extract_host_mtime(&meta);

            if ft.is_symlink() {
                let link_os = fs::read_link(&full_path).map_err(|e| {
                    CoreError::Store(StoreError::Io(format!(
                        "failed to read symlink {}: {e}",
                        full_path.display()
                    )))
                })?;
                let Some(target_utf8) = link_os.to_str() else {
                    return Err(CoreError::UnsupportedFilesystemEntry {
                        path: full_path.display().to_string(),
                        reason: "symlink target is not valid UTF-8".to_owned(),
                    });
                };
                out.push((rel_path, TreeEntry::symlink(target_utf8, mtime)?));
            } else if ft.is_dir() {
                let mode = extract_host_mode(&meta, true);
                out.push((rel_path.clone(), TreeEntry::directory(mode, mtime)));
                self.walk_host_subdir(&full_path, &rel_path, store_blobs, out)?;
            } else if ft.is_file() {
                let bytes = fs::read(&full_path).map_err(|e| {
                    CoreError::Store(StoreError::Io(format!(
                        "failed to read {}: {e}",
                        full_path.display()
                    )))
                })?;
                let hash = if store_blobs {
                    self.blob_store.put_blob(&bytes)?
                } else {
                    ContentHash::hash_bytes(&bytes)
                };
                let mode = extract_host_mode(&meta, false);
                out.push((
                    rel_path,
                    TreeEntry::file(hash, bytes.len() as u64, mode, mtime),
                ));
            } else {
                return Err(CoreError::UnsupportedFilesystemEntry {
                    path: full_path.display().to_string(),
                    reason: "special OS file (FIFO, socket, or device node) is not supported"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    fn execute_apply_on_host_dir(
        &self,
        root_dir: &Path,
        actions: &[ApplyAction],
    ) -> Result<(), CoreError> {
        for action in actions {
            match action {
                ApplyAction::RemoveLeaf { path } => {
                    let full = root_dir.join(path.as_str());
                    fs::remove_file(&full).map_err(|e| {
                        CoreError::Store(StoreError::Io(format!(
                            "failed to remove {}: {e}",
                            full.display()
                        )))
                    })?;
                }
                ApplyAction::RemoveDirectory { path } => {
                    let full = root_dir.join(path.as_str());
                    fs::remove_dir(&full).map_err(|e| {
                        CoreError::Store(StoreError::Io(format!(
                            "failed to remove directory {}: {e}",
                            full.display()
                        )))
                    })?;
                }
                ApplyAction::CreateDirectory { path, mode } => {
                    let full = root_dir.join(path.as_str());
                    fs::create_dir_all(&full).map_err(|e| {
                        CoreError::Store(StoreError::Io(format!(
                            "failed to create directory {}: {e}",
                            full.display()
                        )))
                    })?;
                    apply_host_mode(&full, *mode)?;
                }
                ApplyAction::UpdateDirectoryMode { path, mode } => {
                    let full = root_dir.join(path.as_str());
                    apply_host_mode(&full, *mode)?;
                }
                ApplyAction::WriteFile { path, entry } => {
                    let TreeEntry::File { content, mode, .. } = entry else {
                        continue;
                    };
                    let bytes = self.blob_store.get_blob(content)?;
                    let full = root_dir.join(path.as_str());
                    if let Ok(meta) = fs::symlink_metadata(&full) {
                        if meta.file_type().is_symlink() {
                            fs::remove_file(&full)
                                .map_err(|e| CoreError::Store(StoreError::Io(e.to_string())))?;
                        }
                    }
                    fs::write(&full, &bytes).map_err(|e| {
                        CoreError::Store(StoreError::Io(format!(
                            "failed to write {}: {e}",
                            full.display()
                        )))
                    })?;
                    apply_host_mode(&full, *mode)?;
                }
                ApplyAction::WriteSymlink { path, target } => {
                    let full = root_dir.join(path.as_str());
                    if fs::symlink_metadata(&full).is_ok() {
                        fs::remove_file(&full)
                            .map_err(|e| CoreError::Store(StoreError::Io(e.to_string())))?;
                    }
                    create_host_symlink(target, &full)?;
                }
            }
        }
        Ok(())
    }
}

fn extract_host_mtime(meta: &fs::Metadata) -> Timestamp {
    meta.modified()
        .map(Timestamp::from)
        .unwrap_or(Timestamp::EPOCH)
}

#[cfg(unix)]
fn extract_host_mode(meta: &fs::Metadata, is_dir: bool) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    let m = meta.permissions().mode() & PERM_MASK;
    if m == 0 {
        if is_dir {
            DEFAULT_DIR_MODE
        } else {
            DEFAULT_FILE_MODE
        }
    } else {
        m
    }
}

#[cfg(not(unix))]
fn extract_host_mode(meta: &fs::Metadata, is_dir: bool) -> u32 {
    if is_dir {
        DEFAULT_DIR_MODE
    } else if meta.permissions().readonly() {
        0o444
    } else {
        DEFAULT_FILE_MODE
    }
}

#[cfg(unix)]
fn apply_host_mode(path: &Path, mode: u32) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode & PERM_MASK)).map_err(|e| {
        CoreError::Store(StoreError::Io(format!(
            "failed to set permissions on {}: {e}",
            path.display()
        )))
    })
}

#[cfg(not(unix))]
fn apply_host_mode(_path: &Path, _mode: u32) -> Result<(), CoreError> {
    Ok(())
}

#[cfg(unix)]
fn create_host_symlink(target: &str, link_path: &Path) -> Result<(), CoreError> {
    std::os::unix::fs::symlink(target, link_path).map_err(|e| {
        CoreError::Store(StoreError::Io(format!(
            "failed to create symlink {}: {e}",
            link_path.display()
        )))
    })
}

#[cfg(not(unix))]
fn create_host_symlink(_target: &str, link_path: &Path) -> Result<(), CoreError> {
    Err(CoreError::UnsupportedFilesystemEntry {
        path: link_path.display().to_string(),
        reason: "host symlink projection requires platform adapter".to_owned(),
    })
}

impl<B: BlobStore, M: MetadataStore> ControlPlane for CoreEngine<B, M> {
    fn create_base(&self, input: BaseInput, tag: Option<TagName>) -> Result<BaseInfo, CoreError> {
        let _guard = self
            .lifecycle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tree = match input {
            BaseInput::Entries(entries) => self.ingest_entries_input(entries)?,
            BaseInput::Tree(tree) => {
                self.verify_tree_blobs(&tree)?;
                tree
            }
            BaseInput::ExternalDir(path) => self.scan_host_directory(&path, true)?,
        };

        let base = Base::from_tree(tree);
        let base_id = base.id();
        let entry_count = base.entry_count();
        self.metadata_store.put_base(&base)?;

        if let Some(tag_name) = tag {
            self.metadata_store.set_tag(&tag_name, &base_id)?;
        }

        self.build_base_info(base_id, entry_count)
    }

    fn set_tag(&self, tag: TagName, base: BaseSelector) -> Result<BaseId, CoreError> {
        let _guard = self
            .lifecycle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let base_id = self.resolve_base_selector(&base)?;
        self.metadata_store.set_tag(&tag, &base_id)?;
        Ok(base_id)
    }

    fn delete_tag(&self, tag: &TagName) -> Result<(), CoreError> {
        let _guard = self
            .lifecycle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.metadata_store.delete_tag(tag)? {
            Ok(())
        } else {
            Err(CoreError::TagNotFound(tag.clone()))
        }
    }

    fn remove_base(
        &self,
        base: BaseSelector,
        cascade: bool,
    ) -> Result<RemoveBaseOutput, CoreError> {
        let _guard = self
            .lifecycle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let base_id = self.resolve_base_selector(&base)?;

        let dependent_views: Vec<ViewId> = self
            .metadata_store
            .list_views()?
            .into_iter()
            .filter(|v| v.base_id() == base_id)
            .map(|v| v.id().clone())
            .collect();

        if !dependent_views.is_empty() && !cascade {
            return Err(CoreError::BaseInUse {
                base_id,
                views: dependent_views,
            });
        }

        for view_id in &dependent_views {
            let _q = self.quiescence.quiesce(view_id);
            self.metadata_store.delete_view(view_id)?;
            self.inodes.remove_subtree(view_id.as_str());
        }
        for view_id in &dependent_views {
            self.quiescence.remove_view(view_id);
            self.view_locks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(view_id);
        }

        let tags_map = self.metadata_store.list_tags()?;
        let mut removed_tags = Vec::new();
        for (tag, target_id) in tags_map {
            if target_id == base_id {
                self.metadata_store.delete_tag(&tag)?;
                removed_tags.push(tag);
            }
        }

        self.metadata_store.delete_base(&base_id)?;

        Ok(RemoveBaseOutput {
            base_id,
            removed_views: dependent_views,
            removed_tags,
        })
    }

    fn list_bases(&self) -> Result<Vec<BaseInfo>, CoreError> {
        let base_ids = self.metadata_store.list_base_ids()?;
        let tags_map = self.metadata_store.list_tags()?;
        let views = self.metadata_store.list_views()?;

        let mut out = Vec::with_capacity(base_ids.len());
        for id in base_ids {
            let entry_count = self
                .metadata_store
                .get_base(&id)?
                .map_or(0, |b| b.entry_count());
            let tags: Vec<TagName> = tags_map
                .iter()
                .filter(|(_, target)| **target == id)
                .map(|(t, _)| t.clone())
                .collect();
            let view_count = views.iter().filter(|v| v.base_id() == id).count();
            out.push(BaseInfo {
                id,
                tags,
                entry_count,
                view_count,
            });
        }
        Ok(out)
    }

    fn create_view(&self, view_id: ViewId, base: BaseSelector) -> Result<ViewInfo, CoreError> {
        let _guard = self
            .lifecycle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.metadata_store.get_view(&view_id)?.is_some() {
            return Err(CoreError::ViewAlreadyExists(view_id));
        }
        let base_id = self.resolve_base_selector(&base)?;
        let created_at = Timestamp::now();
        let view = View::new(view_id.clone(), base_id, created_at);
        self.metadata_store.put_view(&view)?;
        self.inodes.get_or_alloc(view_id.as_str());

        Ok(ViewInfo {
            id: view_id,
            base_id,
            overlay_entry_count: 0,
            created_at,
        })
    }

    fn remove_view(&self, view_id: &ViewId) -> Result<(), CoreError> {
        let _guard = self
            .lifecycle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.metadata_store.get_view(view_id)?.is_none() {
            return Err(CoreError::ViewNotFound(view_id.clone()));
        }
        {
            let _q = self.quiescence.quiesce(view_id);
            self.metadata_store.delete_view(view_id)?;
            self.inodes.remove_subtree(view_id.as_str());
        }
        self.quiescence.remove_view(view_id);
        self.view_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(view_id);
        Ok(())
    }

    fn list_views(&self) -> Result<Vec<ViewInfo>, CoreError> {
        let views = self.metadata_store.list_views()?;
        Ok(views
            .into_iter()
            .map(|v| ViewInfo {
                id: v.id().clone(),
                base_id: v.base_id(),
                overlay_entry_count: v.overlay().len(),
                created_at: v.created_at(),
            })
            .collect())
    }

    fn diff_view(&self, view_id: &ViewId) -> Result<Vec<DiffEntry>, CoreError> {
        if self.metadata_store.get_view(view_id)?.is_none() {
            return Err(CoreError::ViewNotFound(view_id.clone()));
        }
        let _quiesced = self.quiescence.quiesce(view_id);
        let (view, base) = self.load_view_and_base(view_id)?;
        Ok(compute_diff(&base, &view))
    }

    fn freeze_view(
        &self,
        view_id: &ViewId,
        tag: Option<TagName>,
    ) -> Result<FreezeOutput, CoreError> {
        let _guard = self
            .lifecycle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.metadata_store.get_view(view_id)?.is_none() {
            return Err(CoreError::ViewNotFound(view_id.clone()));
        }
        let _quiesced = self.quiescence.quiesce(view_id);
        let (view, base) = self.load_view_and_base(view_id)?;
        let frozen = freeze_to_base(&base, &view, tag.clone());
        self.metadata_store.put_base(&frozen.base)?;
        if let Some(tag_name) = &tag {
            self.metadata_store.set_tag(tag_name, &frozen.base_id)?;
        }
        Ok(frozen)
    }

    fn apply_view(&self, view_id: &ViewId, target: ApplyTarget) -> Result<ApplyOutput, CoreError> {
        if self.metadata_store.get_view(view_id)?.is_none() {
            return Err(CoreError::ViewNotFound(view_id.clone()));
        }
        let _quiesced = self.quiescence.quiesce(view_id);
        let (view, base) = self.load_view_and_base(view_id)?;

        match target {
            ApplyTarget::Tree(external_tree) => {
                let plan =
                    plan_apply(&base, &view, &external_tree).map_err(CoreError::ApplyConflicts)?;
                Ok(ApplyOutput {
                    view_id: view_id.clone(),
                    base_id: base.id(),
                    plan,
                })
            }
            ApplyTarget::ExternalDir(host_dir) => {
                let observed = self.scan_host_directory(&host_dir, false)?;
                let plan =
                    plan_apply(&base, &view, &observed).map_err(CoreError::ApplyConflicts)?;
                self.execute_apply_on_host_dir(&host_dir, &plan.actions)?;
                Ok(ApplyOutput {
                    view_id: view_id.clone(),
                    base_id: base.id(),
                    plan,
                })
            }
        }
    }
}

impl<B: BlobStore, M: MetadataStore> VfsOperations for CoreEngine<B, M> {
    fn getattr(&self, path: &str) -> Result<VfsAttr, VfsError> {
        match MountPath::parse(path)? {
            MountPath::Root => {
                let views = self.metadata_store.list_views()?;
                Ok(VfsAttr {
                    ino: ROOT_INO,
                    kind: NodeKind::Directory,
                    mode: MOUNT_ROOT_MODE,
                    size: 0,
                    mtime: Timestamp::EPOCH,
                    nlink: 2 + views.len() as u32,
                    read_only: true,
                })
            }
            MountPath::InvalidRootChild(_) => Err(VfsError::NotFound),
            MountPath::View { view: view_id, rel } => {
                let (view, base) = self.load_view_and_base_vfs(&view_id)?;
                if rel.is_root() {
                    let meta = view.root_metadata(&base);
                    return Ok(self.make_vfs_attr(&view_id, &rel, meta));
                }
                let Some((canonical_rel, entry)) =
                    self.resolve_canonical_rel(&base, &view, &rel)?
                else {
                    return Err(VfsError::NotFound);
                };
                Ok(self.make_vfs_attr(&view_id, &canonical_rel, entry.metadata()))
            }
        }
    }

    fn setattr(&self, path: &str, attr: VfsSetAttr) -> Result<VfsAttr, VfsError> {
        match MountPath::parse(path)? {
            MountPath::Root => Err(VfsError::ReadOnly),
            MountPath::InvalidRootChild(_) => Err(VfsError::ReadOnly),
            MountPath::View { view: view_id, rel } => {
                let _w = self.quiescence.begin_write(&view_id);
                let v_mutex = self.view_mutex(&view_id);
                let _v_lock = v_mutex.lock().unwrap_or_else(|e| e.into_inner());

                let (mut view, base) = self.load_view_and_base_vfs(&view_id)?;
                if rel.is_root() {
                    if attr.size.is_some() {
                        return Err(VfsError::IsADirectory);
                    }
                    view.set_root_attrs(attr.mode, attr.mtime);
                    self.metadata_store.put_view(&view)?;
                    let meta = view.root_metadata(&base);
                    return Ok(self.make_vfs_attr(&view_id, &rel, meta));
                }

                let Some((canonical_rel, current_entry)) =
                    self.resolve_canonical_rel(&base, &view, &rel)?
                else {
                    return Err(VfsError::NotFound);
                };

                let now = attr.mtime.unwrap_or_else(Timestamp::now);
                let final_entry = if let Some(new_size) = attr.size {
                    let TreeEntry::File { content, mode, .. } = &current_entry else {
                        return Err(if current_entry.kind() == NodeKind::Directory {
                            VfsError::IsADirectory
                        } else {
                            VfsError::InvalidInput("cannot truncate symbolic link".to_owned())
                        });
                    };
                    let mut bytes = self.blob_store.get_blob(content)?;
                    bytes.resize(new_size as usize, 0);
                    let new_hash = self.blob_store.put_blob(&bytes)?;
                    let new_mode = attr.mode.map_or(*mode, |m| m & PERM_MASK);
                    let updated = TreeEntry::file(new_hash, new_size, new_mode, now);
                    view.put_non_dir(&base, canonical_rel.clone(), updated.clone(), now)
                        .map_err(|e| VfsError::InvalidInput(e.to_string()))?;
                    updated
                } else {
                    view.update_attrs(&base, &canonical_rel, attr.mode, attr.mtime)
                        .ok_or(VfsError::NotFound)?
                };

                self.metadata_store.put_view(&view)?;
                Ok(self.make_vfs_attr(&view_id, &canonical_rel, final_entry.metadata()))
            }
        }
    }

    fn readdir(&self, path: &str) -> Result<Vec<VfsDirEntry>, VfsError> {
        match MountPath::parse(path)? {
            MountPath::Root => {
                let views = self.metadata_store.list_views()?;
                Ok(views
                    .into_iter()
                    .map(|v| {
                        let name = v.id().as_str().to_owned();
                        let ino = self.inodes.get_or_alloc(&name);
                        VfsDirEntry {
                            name,
                            ino,
                            kind: NodeKind::Directory,
                        }
                    })
                    .collect())
            }
            MountPath::InvalidRootChild(_) => Err(VfsError::NotFound),
            MountPath::View { view: view_id, rel } => {
                let (view, base) = self.load_view_and_base_vfs(&view_id)?;
                let canonical_dir = if rel.is_root() {
                    RelPath::root()
                } else {
                    let Some((canon, entry)) = self.resolve_canonical_rel(&base, &view, &rel)?
                    else {
                        return Err(VfsError::NotFound);
                    };
                    if entry.kind() != NodeKind::Directory {
                        return Err(VfsError::NotADirectory);
                    }
                    canon
                };

                let children = view
                    .list_dir(&base, &canonical_dir)
                    .ok_or(VfsError::NotADirectory)?;
                let mut out = Vec::with_capacity(children.len());
                for (entry_name, entry) in children {
                    let child_rel = canonical_dir.join(&entry_name);
                    let mount_str = format!("{}/{}", view_id.as_str(), child_rel.as_str());
                    let ino = self.inodes.get_or_alloc(&mount_str);
                    out.push(VfsDirEntry {
                        name: entry_name.into_inner(),
                        ino,
                        kind: entry.kind(),
                    });
                }
                Ok(out)
            }
        }
    }

    fn readlink(&self, path: &str) -> Result<String, VfsError> {
        match MountPath::parse(path)? {
            MountPath::Root => Err(VfsError::InvalidInput(
                "mount root is not a symlink".to_owned(),
            )),
            MountPath::InvalidRootChild(_) => Err(VfsError::NotFound),
            MountPath::View { view: view_id, rel } => {
                if rel.is_root() {
                    return Err(VfsError::InvalidInput(
                        "view root is a directory, not a symlink".to_owned(),
                    ));
                }
                let (view, base) = self.load_view_and_base_vfs(&view_id)?;
                let Some((_, entry)) = self.resolve_canonical_rel(&base, &view, &rel)? else {
                    return Err(VfsError::NotFound);
                };
                match entry {
                    TreeEntry::Symlink { target, .. } => Ok(target),
                    _ => Err(VfsError::InvalidInput("not a symbolic link".to_owned())),
                }
            }
        }
    }

    fn read(&self, path: &str, offset: u64, size: usize) -> Result<Vec<u8>, VfsError> {
        match MountPath::parse(path)? {
            MountPath::Root => Err(VfsError::IsADirectory),
            MountPath::InvalidRootChild(_) => Err(VfsError::NotFound),
            MountPath::View { view: view_id, rel } => {
                if rel.is_root() {
                    return Err(VfsError::IsADirectory);
                }
                let (view, base) = self.load_view_and_base_vfs(&view_id)?;
                let Some((_, entry)) = self.resolve_canonical_rel(&base, &view, &rel)? else {
                    return Err(VfsError::NotFound);
                };
                match entry {
                    TreeEntry::File { content, .. } => {
                        Ok(self.blob_store.read_blob_at(&content, offset, size)?)
                    }
                    TreeEntry::Directory { .. } => Err(VfsError::IsADirectory),
                    TreeEntry::Symlink { .. } => Err(VfsError::InvalidInput(
                        "cannot read bytes directly from symbolic link".to_owned(),
                    )),
                }
            }
        }
    }

    fn create_file(&self, path: &str, mode: u32, exclusive: bool) -> Result<VfsAttr, VfsError> {
        let parsed = MountPath::parse(path)?;
        if parsed.is_root_or_direct_root_child() {
            return Err(VfsError::ReadOnly);
        }
        let MountPath::View { view: view_id, rel } = parsed else {
            return Err(VfsError::ReadOnly);
        };

        let _w = self.quiescence.begin_write(&view_id);
        let v_mutex = self.view_mutex(&view_id);
        let _v_lock = v_mutex.lock().unwrap_or_else(|e| e.into_inner());

        let (mut view, base) = self.load_view_and_base_vfs(&view_id)?;
        let (canonical_parent, leaf) = self.resolve_parent_for_child(&base, &view, &rel)?;
        let target_rel = canonical_parent.join(&leaf);

        let existing = self.resolve_canonical_rel(&base, &view, &target_rel)?;
        let final_rel = match existing {
            Some((canon, existing_entry)) => {
                if exclusive {
                    return Err(VfsError::AlreadyExists);
                }
                if existing_entry.kind() == NodeKind::Directory {
                    return Err(VfsError::IsADirectory);
                }
                canon
            }
            None => target_rel,
        };

        let now = Timestamp::now();
        let empty_hash = self.blob_store.put_blob(b"")?;
        let file_entry = TreeEntry::file(empty_hash, 0, mode, now);
        view.put_non_dir(&base, final_rel.clone(), file_entry.clone(), now)
            .map_err(|e| VfsError::InvalidInput(e.to_string()))?;
        self.metadata_store.put_view(&view)?;

        Ok(self.make_vfs_attr(&view_id, &final_rel, file_entry.metadata()))
    }

    fn write(&self, path: &str, offset: u64, data: &[u8]) -> Result<u64, VfsError> {
        let parsed = MountPath::parse(path)?;
        if matches!(parsed, MountPath::Root | MountPath::InvalidRootChild(_)) {
            return Err(VfsError::ReadOnly);
        }
        let MountPath::View { view: view_id, rel } = parsed else {
            return Err(VfsError::ReadOnly);
        };
        if rel.is_root() {
            return Err(VfsError::IsADirectory);
        }

        let _w = self.quiescence.begin_write(&view_id);
        let v_mutex = self.view_mutex(&view_id);
        let _v_lock = v_mutex.lock().unwrap_or_else(|e| e.into_inner());

        let (mut view, base) = self.load_view_and_base_vfs(&view_id)?;
        let Some((canonical_rel, existing)) = self.resolve_canonical_rel(&base, &view, &rel)?
        else {
            return Err(VfsError::NotFound);
        };

        let TreeEntry::File { content, mode, .. } = existing else {
            return Err(if existing.kind() == NodeKind::Directory {
                VfsError::IsADirectory
            } else {
                VfsError::InvalidInput("cannot write to symbolic link".to_owned())
            });
        };

        let mut buf = self.blob_store.get_blob(&content)?;
        let start = usize::try_from(offset)
            .map_err(|_| VfsError::InvalidInput("write offset overflow".to_owned()))?;
        let end = start
            .checked_add(data.len())
            .ok_or_else(|| VfsError::InvalidInput("write size overflow".to_owned()))?;
        if end > buf.len() {
            buf.resize(end, 0);
        }
        buf[start..end].copy_from_slice(data);

        let new_hash = self.blob_store.put_blob(&buf)?;
        let now = Timestamp::now();
        let updated = TreeEntry::file(new_hash, buf.len() as u64, mode, now);
        view.put_non_dir(&base, canonical_rel, updated, now)
            .map_err(|e| VfsError::InvalidInput(e.to_string()))?;
        self.metadata_store.put_view(&view)?;

        Ok(data.len() as u64)
    }

    fn truncate(&self, path: &str, size: u64) -> Result<VfsAttr, VfsError> {
        self.setattr(
            path,
            VfsSetAttr {
                mode: None,
                size: Some(size),
                mtime: Some(Timestamp::now()),
            },
        )
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<VfsAttr, VfsError> {
        let parsed = MountPath::parse(path)?;
        if parsed.is_root_or_direct_root_child() {
            return Err(VfsError::ReadOnly);
        }
        let MountPath::View { view: view_id, rel } = parsed else {
            return Err(VfsError::ReadOnly);
        };

        let _w = self.quiescence.begin_write(&view_id);
        let v_mutex = self.view_mutex(&view_id);
        let _v_lock = v_mutex.lock().unwrap_or_else(|e| e.into_inner());

        let (mut view, base) = self.load_view_and_base_vfs(&view_id)?;
        let (canonical_parent, leaf) = self.resolve_parent_for_child(&base, &view, &rel)?;
        let target_rel = canonical_parent.join(&leaf);

        if self
            .resolve_canonical_rel(&base, &view, &target_rel)?
            .is_some()
        {
            return Err(VfsError::AlreadyExists);
        }

        let now = Timestamp::now();
        let dir_entry = view
            .put_new_dir(&base, target_rel.clone(), mode, now)
            .map_err(|e| VfsError::InvalidInput(e.to_string()))?;
        self.metadata_store.put_view(&view)?;

        Ok(self.make_vfs_attr(&view_id, &target_rel, dir_entry.metadata()))
    }

    fn unlink(&self, path: &str) -> Result<(), VfsError> {
        let parsed = MountPath::parse(path)?;
        if parsed.is_root_or_direct_root_child() {
            return Err(VfsError::ReadOnly);
        }
        let MountPath::View { view: view_id, rel } = parsed else {
            return Err(VfsError::ReadOnly);
        };

        let _w = self.quiescence.begin_write(&view_id);
        let v_mutex = self.view_mutex(&view_id);
        let _v_lock = v_mutex.lock().unwrap_or_else(|e| e.into_inner());

        let (mut view, base) = self.load_view_and_base_vfs(&view_id)?;
        let Some((canonical_rel, existing)) = self.resolve_canonical_rel(&base, &view, &rel)?
        else {
            return Err(VfsError::NotFound);
        };
        if existing.kind() == NodeKind::Directory {
            return Err(VfsError::IsADirectory);
        }

        let now = Timestamp::now();
        view.remove_entry(&base, &canonical_rel, now);
        self.metadata_store.put_view(&view)?;
        self.inodes
            .remove_subtree(&format!("{}/{}", view_id.as_str(), canonical_rel.as_str()));
        Ok(())
    }

    fn rmdir(&self, path: &str) -> Result<(), VfsError> {
        let parsed = MountPath::parse(path)?;
        if parsed.is_root_or_direct_root_child() {
            return Err(VfsError::ReadOnly);
        }
        let MountPath::View { view: view_id, rel } = parsed else {
            return Err(VfsError::ReadOnly);
        };

        let _w = self.quiescence.begin_write(&view_id);
        let v_mutex = self.view_mutex(&view_id);
        let _v_lock = v_mutex.lock().unwrap_or_else(|e| e.into_inner());

        let (mut view, base) = self.load_view_and_base_vfs(&view_id)?;
        let Some((canonical_rel, existing)) = self.resolve_canonical_rel(&base, &view, &rel)?
        else {
            return Err(VfsError::NotFound);
        };
        if existing.kind() != NodeKind::Directory {
            return Err(VfsError::NotADirectory);
        }

        let children = view
            .list_dir(&base, &canonical_rel)
            .ok_or(VfsError::NotADirectory)?;
        if !children.is_empty() {
            return Err(VfsError::DirectoryNotEmpty);
        }

        let now = Timestamp::now();
        view.remove_entry(&base, &canonical_rel, now);
        self.metadata_store.put_view(&view)?;
        self.inodes
            .remove_subtree(&format!("{}/{}", view_id.as_str(), canonical_rel.as_str()));
        Ok(())
    }

    fn symlink(&self, target: &str, link_path: &str) -> Result<VfsAttr, VfsError> {
        validate_symlink_target(target).map_err(|e| VfsError::InvalidInput(e.to_string()))?;

        let parsed = MountPath::parse(link_path)?;
        if parsed.is_root_or_direct_root_child() {
            return Err(VfsError::ReadOnly);
        }
        let MountPath::View { view: view_id, rel } = parsed else {
            return Err(VfsError::ReadOnly);
        };

        let _w = self.quiescence.begin_write(&view_id);
        let v_mutex = self.view_mutex(&view_id);
        let _v_lock = v_mutex.lock().unwrap_or_else(|e| e.into_inner());

        let (mut view, base) = self.load_view_and_base_vfs(&view_id)?;
        let (canonical_parent, leaf) = self.resolve_parent_for_child(&base, &view, &rel)?;
        let target_rel = canonical_parent.join(&leaf);

        if self
            .resolve_canonical_rel(&base, &view, &target_rel)?
            .is_some()
        {
            return Err(VfsError::AlreadyExists);
        }

        let now = Timestamp::now();
        let sym_entry =
            TreeEntry::symlink(target, now).map_err(|e| VfsError::InvalidInput(e.to_string()))?;
        view.put_non_dir(&base, target_rel.clone(), sym_entry.clone(), now)
            .map_err(|e| VfsError::InvalidInput(e.to_string()))?;
        self.metadata_store.put_view(&view)?;

        Ok(self.make_vfs_attr(&view_id, &target_rel, sym_entry.metadata()))
    }

    fn rename(&self, from_path: &str, to_path: &str) -> Result<(), VfsError> {
        let from_parsed = MountPath::parse(from_path)?;
        let to_parsed = MountPath::parse(to_path)?;

        if from_parsed.is_root_or_direct_root_child() || to_parsed.is_root_or_direct_root_child() {
            return Err(VfsError::ReadOnly);
        }

        let (
            MountPath::View {
                view: from_view,
                rel: from_rel,
            },
            MountPath::View {
                view: to_view,
                rel: to_rel,
            },
        ) = (from_parsed, to_parsed)
        else {
            return Err(VfsError::ReadOnly);
        };

        if from_view != to_view {
            return Err(VfsError::CrossDevice);
        }

        let _w = self.quiescence.begin_write(&from_view);
        let v_mutex = self.view_mutex(&from_view);
        let _v_lock = v_mutex.lock().unwrap_or_else(|e| e.into_inner());

        let (mut view, base) = self.load_view_and_base_vfs(&from_view)?;
        let Some((canonical_from, from_entry)) =
            self.resolve_canonical_rel(&base, &view, &from_rel)?
        else {
            return Err(VfsError::NotFound);
        };

        let (canonical_to_parent, to_leaf) =
            self.resolve_parent_for_child(&base, &view, &to_rel)?;
        let target_candidate = canonical_to_parent.join(&to_leaf);

        let existing_to = self.resolve_canonical_rel(&base, &view, &target_candidate)?;
        let is_self_case_rename = existing_to
            .as_ref()
            .is_some_and(|(canon, _)| *canon == canonical_from);
        let canonical_to = match &existing_to {
            Some((canon, _)) if *canon != canonical_from => canon.clone(),
            _ => target_candidate,
        };

        if canonical_from == canonical_to {
            return Ok(());
        }
        if canonical_to.is_descendant_of(&canonical_from) {
            return Err(VfsError::InvalidInput(
                "cannot rename a directory into one of its own descendants".to_owned(),
            ));
        }

        if !is_self_case_rename {
            if let Some((_, dest_entry)) = existing_to {
                if from_entry.kind() == NodeKind::Directory {
                    if dest_entry.kind() != NodeKind::Directory {
                        return Err(VfsError::NotADirectory);
                    }
                    let dest_children = view
                        .list_dir(&base, &canonical_to)
                        .ok_or(VfsError::NotADirectory)?;
                    if !dest_children.is_empty() {
                        return Err(VfsError::DirectoryNotEmpty);
                    }
                } else if dest_entry.kind() == NodeKind::Directory {
                    return Err(VfsError::IsADirectory);
                }
            }
        }

        let now = Timestamp::now();
        view.move_subtree(&base, &canonical_from, &canonical_to, now);
        self.metadata_store.put_view(&view)?;

        let old_mount = format!("{}/{}", from_view.as_str(), canonical_from.as_str());
        let new_mount = format!("{}/{}", from_view.as_str(), canonical_to.as_str());
        self.inodes.rename_subtree(&old_mount, &new_mount);
        Ok(())
    }

    fn link(&self, _existing_path: &str, _new_link_path: &str) -> Result<VfsAttr, VfsError> {
        Err(VfsError::NotSupported)
    }

    fn quiesce_view(&self, view_id: &ViewId) -> Result<ViewQuiesceGuard, VfsError> {
        if self.metadata_store.get_view(view_id)?.is_none() {
            return Err(VfsError::NotFound);
        }
        Ok(self.quiescence.quiesce(view_id))
    }
}
