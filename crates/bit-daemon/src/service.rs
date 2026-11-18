//! Request dispatcher mapping [`IpcRequest`]s onto `Arc<dyn ControlPlane>`, `bit-store`
//! persistence (`ingest_external_dir_fs` + transactional `execute_apply`), and external symlink
//! lifecycle.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bit_core::{
    ApplyAction, ApplyOutput, ApplyPlan, ApplyTarget, BaseInfo, BaseInput, BlobStore, ControlPlane,
    CoreEngine, CoreError, DiffChange, DiffEntry, MetadataStore, NodeKind, RelPath, StoreError,
    TagName, TreeEntry, VfsOperations, ViewId, PERM_MASK,
};
use bit_ipc::{DaemonStatus, FreezeSummary, IpcRequest, IpcResponse, RemoteError, ViewSummary};
use bit_store::{
    execute_apply, ingest_external_dir, ingest_external_dir_fs, ApplyStoreError,
    PersistentCoreEngine,
};

use crate::exclude::scan_host_dir_with_excludes;
use crate::id_gen::ViewIdGenerator;
use crate::paths::UserPaths;

const LINKS_MAGIC: [u8; 6] = *b"BITL\x00\x01";

/// Backing store hooks allowing `DaemonService` to execute `bit-store`'s streaming
/// `ingest_external_dir_fs` and transactional rollback-journaled `execute_apply` when wired to a
/// `CoreEngine`.
pub(crate) trait EngineStoreBridge: Send + Sync {
    fn create_base_from_dir(
        &self,
        dir: &Path,
        excludes: &[String],
        tag: Option<TagName>,
    ) -> Result<BaseInfo, CoreError>;

    fn apply_view_to_dir(
        &self,
        view_id: &ViewId,
        target_dir: &Path,
        force: bool,
    ) -> Result<ApplyOutput, RemoteError>;
}

pub(crate) struct PersistentStoreBridge {
    pub(crate) engine: Arc<PersistentCoreEngine>,
}

impl EngineStoreBridge for PersistentStoreBridge {
    fn create_base_from_dir(
        &self,
        dir: &Path,
        excludes: &[String],
        tag: Option<TagName>,
    ) -> Result<BaseInfo, CoreError> {
        let ingested = ingest_external_dir_fs(dir, excludes, self.engine.blob_store())?;
        ControlPlane::create_base(&*self.engine, BaseInput::Tree(ingested.tree), tag)
    }

    fn apply_view_to_dir(
        &self,
        view_id: &ViewId,
        target_dir: &Path,
        force: bool,
    ) -> Result<ApplyOutput, RemoteError> {
        apply_via_engine(&self.engine, view_id, target_dir, force)
    }
}

pub(crate) struct GenericEngineBridge<B: BlobStore, M: MetadataStore> {
    pub(crate) engine: Arc<CoreEngine<B, M>>,
}

impl<B: BlobStore + 'static, M: MetadataStore + 'static> EngineStoreBridge
    for GenericEngineBridge<B, M>
{
    fn create_base_from_dir(
        &self,
        dir: &Path,
        excludes: &[String],
        tag: Option<TagName>,
    ) -> Result<BaseInfo, CoreError> {
        let ingested = ingest_external_dir(dir, excludes, self.engine.blob_store())?;
        ControlPlane::create_base(&*self.engine, BaseInput::Tree(ingested.tree), tag)
    }

    fn apply_view_to_dir(
        &self,
        view_id: &ViewId,
        target_dir: &Path,
        force: bool,
    ) -> Result<ApplyOutput, RemoteError> {
        apply_via_engine(&self.engine, view_id, target_dir, force)
    }
}

fn apply_via_engine<B: BlobStore, M: MetadataStore>(
    engine: &CoreEngine<B, M>,
    view_id: &ViewId,
    target_dir: &Path,
    force: bool,
) -> Result<ApplyOutput, RemoteError> {
    if engine
        .metadata_store()
        .get_view(view_id)
        .map_err(CoreError::from)?
        .is_none()
    {
        return Err(RemoteError::Core(CoreError::ViewNotFound(view_id.clone())));
    }

    let _quiesced = engine.quiescence().quiesce(view_id);

    let view = engine
        .metadata_store()
        .get_view(view_id)
        .map_err(CoreError::from)?
        .ok_or_else(|| RemoteError::Core(CoreError::ViewNotFound(view_id.clone())))?;
    let base_id = view.base_id();
    let base = engine
        .metadata_store()
        .get_base(&base_id)
        .map_err(CoreError::from)?
        .ok_or(RemoteError::Core(CoreError::BaseNotFound(base_id)))?;

    let plan = execute_apply(
        &base,
        view.overlay(),
        target_dir,
        engine.blob_store(),
        force,
    )
    .map_err(|err| match err {
        ApplyStoreError::Conflicts(conflicts) => {
            RemoteError::Core(CoreError::ApplyConflicts(conflicts))
        }
        ApplyStoreError::Store(se) => RemoteError::Core(CoreError::from(se)),
        other => RemoteError::Daemon(other.to_string()),
    })?;

    Ok(ApplyOutput {
        view_id: view_id.clone(),
        base_id,
        plan,
    })
}

/// Thread-safe control-plane dispatcher serving IPC requests inside `bit-daemon`.
pub struct DaemonService {
    paths: UserPaths,
    control: Arc<dyn ControlPlane>,
    vfs: Option<Arc<dyn VfsOperations>>,
    store_bridge: Option<Arc<dyn EngineStoreBridge>>,
    links_file: Option<PathBuf>,
    id_gen: ViewIdGenerator,
    view_links: Mutex<BTreeMap<ViewId, PathBuf>>,
    shutdown_requested: Arc<AtomicBool>,
    vfs_backend_name: Mutex<String>,
    vfs_mounted: AtomicBool,
}

impl DaemonService {
    /// Creates a `DaemonService` backed by `paths` and `control`.
    pub fn new(paths: UserPaths, control: Arc<dyn ControlPlane>) -> Self {
        Self {
            paths,
            control,
            vfs: None,
            store_bridge: None,
            links_file: None,
            id_gen: ViewIdGenerator::new(),
            view_links: Mutex::new(BTreeMap::new()),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            vfs_backend_name: Mutex::new("none".to_owned()),
            vfs_mounted: AtomicBool::new(false),
        }
    }

    pub(crate) fn with_store_bridge(mut self, bridge: Arc<dyn EngineStoreBridge>) -> Self {
        self.store_bridge = Some(bridge);
        self
    }

    /// Enables persistent storage of external `--link` associations at `links_file`, loading any
    /// existing entries for still-live `Views`.
    pub fn with_links_file(mut self, links_file: impl Into<PathBuf>) -> Self {
        let file_path = links_file.into();
        let mut loaded = load_links_file(&file_path);
        if let Ok(active_views) = self.control.list_views() {
            let live_ids: BTreeSet<ViewId> = active_views.into_iter().map(|v| v.id).collect();
            loaded.retain(|k, _| live_ids.contains(k));
        }
        self.view_links = Mutex::new(loaded);
        self.links_file = Some(file_path);
        self
    }

    /// Attaches `VfsOperations` so `Apply --force` can read live `View` files directly through
    /// the quiesced VFS port even when no kernel mount or `EngineStoreBridge` is active.
    pub fn with_vfs(mut self, vfs: Arc<dyn VfsOperations>) -> Self {
        self.vfs = Some(vfs);
        self
    }

    /// Sets the reported VFS mount backend name.
    pub fn with_vfs_backend_name(self, name: impl Into<String>) -> Self {
        self.set_vfs_backend_name(name);
        self
    }

    /// Updates the reported VFS mount backend name dynamically.
    pub fn set_vfs_backend_name(&self, name: impl Into<String>) {
        let mut guard = self
            .vfs_backend_name
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = name.into();
    }

    /// Updates whether the VFS mount handle is currently active.
    pub fn set_vfs_mounted(&self, mounted: bool) {
        self.vfs_mounted.store(mounted, Ordering::SeqCst);
    }

    /// Borrows `UserPaths`.
    pub const fn paths(&self) -> &UserPaths {
        &self.paths
    }

    /// Returns a shared handle to the shutdown signal flag.
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown_requested)
    }

    /// Returns `true` if `Shutdown` has been requested.
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Executes one [`IpcRequest`] and produces the corresponding [`IpcResponse`].
    pub fn handle_request(&self, req: IpcRequest) -> IpcResponse {
        match self.dispatch(req) {
            Ok(resp) => resp,
            Err(err) => IpcResponse::Error(err),
        }
    }

    fn dispatch(&self, req: IpcRequest) -> Result<IpcResponse, RemoteError> {
        match req {
            IpcRequest::Ping => Ok(IpcResponse::Pong),
            IpcRequest::Status => {
                let bases = self.control.list_bases()?;
                let views = self.control.list_views()?;
                let vfs_backend = self
                    .vfs_backend_name
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                Ok(IpcResponse::Status(DaemonStatus {
                    pid: std::process::id(),
                    mount_dir: self.paths.mount_dir().to_path_buf(),
                    store_dir: self.paths.store_dir().to_path_buf(),
                    ipc_endpoint: self.paths.ipc_endpoint().to_path_buf(),
                    vfs_backend,
                    vfs_mounted: self.vfs_mounted.load(Ordering::SeqCst),
                    base_count: bases.len(),
                    view_count: views.len(),
                }))
            }
            IpcRequest::Shutdown => {
                self.shutdown_requested.store(true, Ordering::SeqCst);
                Ok(IpcResponse::ShuttingDown)
            }
            IpcRequest::CreateBase { dir, tag, excludes } => {
                let info = if let Some(bridge) = &self.store_bridge {
                    bridge.create_base_from_dir(&dir, &excludes, tag)?
                } else {
                    let entries = scan_host_dir_with_excludes(&dir, &excludes)?;
                    self.control.create_base(BaseInput::Entries(entries), tag)?
                };
                Ok(IpcResponse::BaseCreated(info))
            }
            IpcRequest::ListBases => {
                let list = self.control.list_bases()?;
                Ok(IpcResponse::BaseList(list))
            }
            IpcRequest::SetTag { tag, base } => {
                let base_id = self.control.set_tag(tag.clone(), base)?;
                Ok(IpcResponse::TagSet { tag, base_id })
            }
            IpcRequest::DeleteTag { tag } => {
                self.control.delete_tag(&tag)?;
                Ok(IpcResponse::TagDeleted)
            }
            IpcRequest::RemoveBase { selector, cascade } => {
                let out = self.control.remove_base(selector, cascade)?;
                for removed_view in &out.removed_views {
                    self.cleanup_external_link(removed_view);
                }
                Ok(IpcResponse::BaseRemoved(out))
            }
            IpcRequest::CreateView {
                base,
                view_id,
                link_path,
            } => {
                if let Some(link) = &link_path {
                    if fs::symlink_metadata(link).is_ok() {
                        return Err(RemoteError::Daemon(format!(
                            "external symlink path already exists: {}",
                            link.display()
                        )));
                    }
                }

                let chosen_id = match view_id {
                    Some(explicit) => explicit,
                    None => {
                        let existing = self.control.list_views()?;
                        let ids: Vec<ViewId> = existing.into_iter().map(|v| v.id).collect();
                        self.id_gen.next_available(ids.iter())
                    }
                };

                let info = self.control.create_view(chosen_id, base)?;
                let mount_path = self.paths.view_mount_path(&info.id);

                if let Some(link) = &link_path {
                    if let Err(err) = create_external_view_symlink(&mount_path, link) {
                        let _ = self.control.remove_view(&info.id);
                        return Err(RemoteError::Daemon(err));
                    }
                    let mut links = self.view_links.lock().unwrap_or_else(|e| e.into_inner());
                    links.insert(info.id.clone(), link.clone());
                    self.persist_links_locked(&links);
                }

                Ok(IpcResponse::ViewCreated(ViewSummary {
                    info,
                    mount_path,
                    link_path,
                }))
            }
            IpcRequest::ListViews => {
                let views = self.control.list_views()?;
                let links = self.view_links.lock().unwrap_or_else(|e| e.into_inner());
                let summaries = views
                    .into_iter()
                    .map(|info| {
                        let mount_path = self.paths.view_mount_path(&info.id);
                        let link_path = links.get(&info.id).cloned();
                        ViewSummary {
                            info,
                            mount_path,
                            link_path,
                        }
                    })
                    .collect();
                Ok(IpcResponse::ViewList(summaries))
            }
            IpcRequest::ViewPath { view_id } => {
                let views = self.control.list_views()?;
                if !views.iter().any(|v| v.id == view_id) {
                    return Err(RemoteError::Core(CoreError::ViewNotFound(view_id)));
                }
                Ok(IpcResponse::ViewPath(self.paths.view_mount_path(&view_id)))
            }
            IpcRequest::RemoveView { view_id } => {
                self.control.remove_view(&view_id)?;
                self.cleanup_external_link(&view_id);
                Ok(IpcResponse::ViewRemoved)
            }
            IpcRequest::DiffView { view_id } => {
                let entries = self.control.diff_view(&view_id)?;
                Ok(IpcResponse::ViewDiff(entries))
            }
            IpcRequest::FreezeView { view_id, tag } => {
                let frozen = self.control.freeze_view(&view_id, tag)?;
                Ok(IpcResponse::ViewFrozen(FreezeSummary {
                    base_id: frozen.base_id,
                    tag: frozen.tag,
                    entry_count: frozen.base.entry_count(),
                }))
            }
            IpcRequest::ApplyView {
                view_id,
                target_dir,
                force,
            } => {
                if let Some(bridge) = &self.store_bridge {
                    let out = bridge.apply_view_to_dir(&view_id, &target_dir, force)?;
                    return Ok(IpcResponse::ViewApplied(out));
                }

                match self
                    .control
                    .apply_view(&view_id, ApplyTarget::ExternalDir(target_dir.clone()))
                {
                    Ok(out) => Ok(IpcResponse::ViewApplied(out)),
                    Err(CoreError::ApplyConflicts(_)) if force => {
                        let out = self.force_apply_fallback(&view_id, &target_dir)?;
                        Ok(IpcResponse::ViewApplied(out))
                    }
                    Err(err) => Err(RemoteError::Core(err)),
                }
            }
        }
    }

    fn persist_links_locked(&self, links: &BTreeMap<ViewId, PathBuf>) {
        let Some(path) = &self.links_file else {
            return;
        };
        let _ = save_links_file(path, links);
    }

    fn cleanup_external_link(&self, view_id: &ViewId) {
        let link_opt = {
            let mut links = self.view_links.lock().unwrap_or_else(|e| e.into_inner());
            let removed = links.remove(view_id);
            if removed.is_some() {
                self.persist_links_locked(&links);
            }
            removed
        };
        let Some(link_path) = link_opt else {
            return;
        };
        let Ok(meta) = fs::symlink_metadata(&link_path) else {
            return;
        };
        if !meta.file_type().is_symlink() {
            return;
        }
        let expected_target = self.paths.view_mount_path(view_id);
        if let Ok(actual_target) = fs::read_link(&link_path) {
            if actual_target == expected_target {
                let _ = remove_external_view_symlink(&link_path);
            }
        }
    }

    /// Fallback `--force` implementation used only when `DaemonService` was constructed with an
    /// external `Arc<dyn ControlPlane>` rather than a `CoreEngine`.
    fn force_apply_fallback(
        &self,
        view_id: &ViewId,
        target_dir: &Path,
    ) -> Result<ApplyOutput, RemoteError> {
        let root_meta = fs::symlink_metadata(target_dir).map_err(|e| {
            CoreError::Store(StoreError::Io(format!(
                "failed to stat {}: {e}",
                target_dir.display()
            )))
        })?;
        if !root_meta.file_type().is_dir() {
            return Err(RemoteError::Core(CoreError::UnsupportedFilesystemEntry {
                path: target_dir.display().to_string(),
                reason: "target path is not a directory".to_owned(),
            }));
        }

        let views = self.control.list_views()?;
        let view_info = views
            .into_iter()
            .find(|v| &v.id == view_id)
            .ok_or_else(|| RemoteError::Core(CoreError::ViewNotFound(view_id.clone())))?;

        let diff = self.control.diff_view(view_id)?;
        let _quiesce_guard =
            match &self.vfs {
                Some(vfs) => Some(vfs.quiesce_view(view_id).map_err(|e| {
                    RemoteError::Daemon(format!("failed to quiesce {view_id}: {e}"))
                })?),
                None => None,
            };

        let actions = build_forced_actions(&diff);
        for action in &actions {
            match action {
                ApplyAction::RemoveLeaf { path } | ApplyAction::RemoveDirectory { path } => {
                    remove_any_host_entry(&target_dir.join(path.as_str()))?;
                }
                ApplyAction::CreateDirectory { path, mode }
                | ApplyAction::UpdateDirectoryMode { path, mode } => {
                    ensure_host_directory(&target_dir.join(path.as_str()), *mode)?;
                }
                ApplyAction::WriteFile { path, entry } => {
                    let TreeEntry::File { size, mode, .. } = entry else {
                        continue;
                    };
                    let bytes = self.read_view_file_bytes(view_id, path, *size)?;
                    let full = target_dir.join(path.as_str());
                    prepare_parent_dirs(target_dir, path)?;
                    remove_any_host_entry(&full)?;
                    fs::write(&full, &bytes).map_err(|e| {
                        CoreError::Store(StoreError::Io(format!(
                            "failed to write {}: {e}",
                            full.display()
                        )))
                    })?;
                    set_host_permissions(&full, *mode)?;
                }
                ApplyAction::WriteSymlink { path, target } => {
                    let full = target_dir.join(path.as_str());
                    prepare_parent_dirs(target_dir, path)?;
                    remove_any_host_entry(&full)?;
                    create_tree_symlink(target, &full)?;
                }
            }
        }

        Ok(ApplyOutput {
            view_id: view_id.clone(),
            base_id: view_info.base_id,
            plan: ApplyPlan { diff, actions },
        })
    }

    fn read_view_file_bytes(
        &self,
        view_id: &ViewId,
        rel_path: &RelPath,
        size: u64,
    ) -> Result<Vec<u8>, RemoteError> {
        if let Some(vfs) = &self.vfs {
            let vfs_path = format!("{}/{}", view_id.as_str(), rel_path.as_str());
            let len = usize::try_from(size)
                .map_err(|_| RemoteError::Daemon(format!("file {rel_path} exceeds memory size")))?;
            return vfs
                .read(&vfs_path, 0, len)
                .map_err(|e| RemoteError::Daemon(format!("failed to read {vfs_path}: {e}")));
        }

        let mounted_file = self.paths.view_mount_path(view_id).join(rel_path.as_str());
        fs::read(&mounted_file).map_err(|e| {
            RemoteError::Daemon(format!(
                "cannot read live file {} for forced apply: {e}",
                mounted_file.display()
            ))
        })
    }
}

fn save_links_file(path: &Path, links: &BTreeMap<ViewId, PathBuf>) -> std::io::Result<()> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&LINKS_MAGIC);
    buf.extend_from_slice(&(links.len() as u32).to_be_bytes());
    for (view_id, link_path) in links {
        let id_bytes = view_id.as_str().as_bytes();
        buf.extend_from_slice(&(id_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(id_bytes);

        let path_str = link_path.to_string_lossy();
        let path_bytes = path_str.as_bytes();
        buf.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(path_bytes);
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp_path = path.with_extension("bin.tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)?;
    f.write_all(&buf)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp_path, path)
}

fn load_links_file(path: &Path) -> BTreeMap<ViewId, PathBuf> {
    let Ok(bytes) = fs::read(path) else {
        return BTreeMap::new();
    };
    if bytes.len() < 10 || bytes[..6] != LINKS_MAGIC {
        return BTreeMap::new();
    }
    let count = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    let mut pos = 10usize;
    let mut out = BTreeMap::new();
    for _ in 0..count {
        if pos + 4 > bytes.len() {
            break;
        }
        let id_len =
            u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        pos += 4;
        if pos + id_len > bytes.len() {
            break;
        }
        let Ok(id_str) = std::str::from_utf8(&bytes[pos..pos + id_len]) else {
            break;
        };
        let Ok(view_id) = ViewId::new(id_str) else {
            break;
        };
        pos += id_len;

        if pos + 4 > bytes.len() {
            break;
        }
        let p_len = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        pos += 4;
        if pos + p_len > bytes.len() {
            break;
        }
        let Ok(p_str) = std::str::from_utf8(&bytes[pos..pos + p_len]) else {
            break;
        };
        pos += p_len;
        out.insert(view_id, PathBuf::from(p_str));
    }
    out
}

fn build_forced_actions(diff: &[DiffEntry]) -> Vec<ApplyAction> {
    let mut removals: Vec<(usize, RelPath, NodeKind)> = Vec::new();
    for item in diff {
        match (&item.before, &item.after) {
            (Some(old), None) => {
                removals.push((item.path.depth(), item.path.clone(), old.kind()));
            }
            (Some(old), Some(new)) if old.kind() != new.kind() => {
                removals.push((item.path.depth(), item.path.clone(), old.kind()));
            }
            _ => {}
        }
    }
    removals.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| (a.2 == NodeKind::Directory).cmp(&(b.2 == NodeKind::Directory)))
            .then_with(|| a.1.cmp(&b.1))
    });

    let mut actions = Vec::new();
    for (_, path, kind) in removals {
        if kind == NodeKind::Directory {
            actions.push(ApplyAction::RemoveDirectory { path });
        } else {
            actions.push(ApplyAction::RemoveLeaf { path });
        }
    }

    let mut dir_creates: Vec<(usize, RelPath, u32)> = Vec::new();
    for item in diff {
        if let Some(TreeEntry::Directory { mode, .. }) = &item.after {
            if item.change == DiffChange::Added
                || item
                    .before
                    .as_ref()
                    .is_some_and(|b| b.kind() != NodeKind::Directory)
            {
                dir_creates.push((item.path.depth(), item.path.clone(), *mode));
            }
        }
    }
    dir_creates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    for (_, path, mode) in dir_creates {
        actions.push(ApplyAction::CreateDirectory { path, mode });
    }

    for item in diff {
        let Some(after) = &item.after else {
            continue;
        };
        match after {
            TreeEntry::File { .. } => actions.push(ApplyAction::WriteFile {
                path: item.path.clone(),
                entry: after.clone(),
            }),
            TreeEntry::Symlink { target, .. } => actions.push(ApplyAction::WriteSymlink {
                path: item.path.clone(),
                target: target.clone(),
            }),
            TreeEntry::Directory { mode, .. } => {
                if item.change == DiffChange::Modified
                    && item
                        .before
                        .as_ref()
                        .is_some_and(|b| b.kind() == NodeKind::Directory)
                {
                    actions.push(ApplyAction::UpdateDirectoryMode {
                        path: item.path.clone(),
                        mode: *mode,
                    });
                }
            }
        }
    }
    actions
}

fn remove_any_host_entry(path: &Path) -> Result<(), CoreError> {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if meta.file_type().is_dir() {
        fs::remove_dir_all(path).map_err(|e| {
            CoreError::Store(StoreError::Io(format!(
                "failed to remove directory {}: {e}",
                path.display()
            )))
        })
    } else {
        fs::remove_file(path).map_err(|e| {
            CoreError::Store(StoreError::Io(format!(
                "failed to remove {}: {e}",
                path.display()
            )))
        })
    }
}

fn prepare_parent_dirs(target_root: &Path, rel: &RelPath) -> Result<(), CoreError> {
    for anc in rel.strict_ancestors() {
        let anc_full = target_root.join(anc.as_str());
        if let Ok(meta) = fs::symlink_metadata(&anc_full) {
            if !meta.file_type().is_dir() {
                remove_any_host_entry(&anc_full)?;
            }
        }
        fs::create_dir_all(&anc_full).map_err(|e| {
            CoreError::Store(StoreError::Io(format!(
                "failed to create parent directory {}: {e}",
                anc_full.display()
            )))
        })?;
    }
    Ok(())
}

fn ensure_host_directory(path: &Path, mode: u32) -> Result<(), CoreError> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.file_type().is_dir() {
            remove_any_host_entry(path)?;
        }
    }
    fs::create_dir_all(path).map_err(|e| {
        CoreError::Store(StoreError::Io(format!(
            "failed to create directory {}: {e}",
            path.display()
        )))
    })?;
    set_host_permissions(path, mode)
}

#[cfg(unix)]
fn set_host_permissions(path: &Path, mode: u32) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode & PERM_MASK)).map_err(|e| {
        CoreError::Store(StoreError::Io(format!(
            "failed to set permissions on {}: {e}",
            path.display()
        )))
    })
}

#[cfg(not(unix))]
fn set_host_permissions(_path: &Path, _mode: u32) -> Result<(), CoreError> {
    Ok(())
}

#[cfg(unix)]
fn create_tree_symlink(target: &str, link_path: &Path) -> Result<(), CoreError> {
    std::os::unix::fs::symlink(target, link_path).map_err(|e| {
        CoreError::Store(StoreError::Io(format!(
            "failed to create symlink {}: {e}",
            link_path.display()
        )))
    })
}

#[cfg(not(unix))]
fn create_tree_symlink(_target: &str, link_path: &Path) -> Result<(), CoreError> {
    Err(CoreError::UnsupportedFilesystemEntry {
        path: link_path.display().to_string(),
        reason: "host symlink projection requires platform adapter".to_owned(),
    })
}

fn create_external_view_symlink(mount_target: &Path, link_path: &Path) -> Result<(), String> {
    if let Some(parent) = link_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "failed to create parent directory for symlink {}: {e}",
                    link_path.display()
                )
            })?;
        }
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(mount_target, link_path).map_err(|e| {
            format!(
                "failed to create external symlink {} -> {}: {e}",
                link_path.display(),
                mount_target.display()
            )
        })
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(mount_target, link_path).map_err(|e| {
            format!(
                "failed to create external directory symlink {} -> {}: {e}",
                link_path.display(),
                mount_target.display()
            )
        })
    }
}

fn remove_external_view_symlink(link_path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        if fs::remove_dir(link_path).is_ok() {
            return Ok(());
        }
    }
    fs::remove_file(link_path)
}
