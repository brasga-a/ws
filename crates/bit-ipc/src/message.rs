//! Control-plane IPC request, response, status, and remote error types.

use std::fmt;
use std::path::PathBuf;

use bit_core::{
    ApplyOutput, BaseId, BaseInfo, BaseSelector, CoreError, DiffEntry, RemoveBaseOutput, TagName,
    ViewId, ViewInfo,
};

/// Request sent from `bit-cli` (or another local client) to `bit-daemon`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcRequest {
    /// Lightweight liveness check used during daemon startup readiness probing.
    Ping,
    /// Queries daemon process, mount, and store status.
    Status,
    /// Requests clean daemon shutdown and VFS unmount.
    Shutdown,
    /// Creates an immutable `Base` from `dir`, optionally attaching `tag` and excluding patterns.
    CreateBase {
        dir: PathBuf,
        tag: Option<TagName>,
        excludes: Vec<String>,
    },
    /// Lists all stored `Bases`.
    ListBases,
    /// Creates or updates mutable `tag` to point to `base`.
    SetTag { tag: TagName, base: BaseSelector },
    /// Deletes mutable `tag` without deleting its target `Base`.
    DeleteTag { tag: TagName },
    /// Removes `selector` (blocking if active `Views` reference it unless `cascade` is `true`).
    RemoveBase {
        selector: BaseSelector,
        cascade: bool,
    },
    /// Creates an isolated writable `View` from `base`, generating a portable `ViewId` if `None`
    /// and optionally creating an external symlink at `link_path`.
    CreateView {
        base: BaseSelector,
        view_id: Option<ViewId>,
        link_path: Option<PathBuf>,
    },
    /// Lists all active `Views`.
    ListViews,
    /// Queries the mounted host filesystem path `<mount>/<view-id>` for `view_id`.
    ViewPath { view_id: ViewId },
    /// Removes `view_id` and its private `Overlay` (plus any daemon-managed external symlink).
    RemoveView { view_id: ViewId },
    /// Computes the live `Diff` of `view_id` relative to its `Base`.
    DiffView { view_id: ViewId },
    /// Captures the live state of `view_id` as a new immutable `Base` (`Freeze`).
    FreezeView {
        view_id: ViewId,
        tag: Option<TagName>,
    },
    /// Projects `view_id`'s `Overlay` onto `target_dir` (`Apply`), guarded against external
    /// directory modifications unless `force` is `true`.
    ApplyView {
        view_id: ViewId,
        target_dir: PathBuf,
        force: bool,
    },
}

/// Live status summary reported by `bit-daemon`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonStatus {
    /// Operating system process ID of the running daemon.
    pub pid: u32,
    /// Root directory where all `Views` are exposed (`<mount>/<view-id>/`).
    pub mount_dir: PathBuf,
    /// Internal backing store directory.
    pub store_dir: PathBuf,
    /// Local IPC endpoint path.
    pub ipc_endpoint: PathBuf,
    /// Active VFS mount backend identifier.
    pub vfs_backend: String,
    /// Whether the VFS mount handle is currently active.
    pub vfs_mounted: bool,
    /// Number of stored `Bases`.
    pub base_count: usize,
    /// Number of active `Views`.
    pub view_count: usize,
}

/// Summary of a created or listed `View`, combining core metadata with host paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewSummary {
    /// Core `View` descriptor (`ViewId`, `BaseId`, `Overlay` entry count, creation timestamp).
    pub info: ViewInfo,
    /// Host path under the VFS mount (`<mount>/<view-id>`).
    pub mount_path: PathBuf,
    /// Optional external symlink path created via `--link`.
    pub link_path: Option<PathBuf>,
}

/// Summary of a `Freeze` operation returned over IPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreezeSummary {
    /// Newly sealed `BaseId`.
    pub base_id: BaseId,
    /// Optional `Tag` pointed at `base_id`.
    pub tag: Option<TagName>,
    /// Total number of non-root entries in the newly sealed `Base`.
    pub entry_count: usize,
}

/// Structured error returned by `bit-daemon` inside [`IpcResponse::Error`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteError {
    /// Domain or storage error from `bit-core`.
    Core(CoreError),
    /// Daemon-level operational error (e.g. symlink failure or invalid host path).
    Daemon(String),
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(err) => fmt::Display::fmt(err, f),
            Self::Daemon(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for RemoteError {}

impl From<CoreError> for RemoteError {
    fn from(err: CoreError) -> Self {
        Self::Core(err)
    }
}

/// Response sent from `bit-daemon` back to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcResponse {
    /// Reply to [`IpcRequest::Ping`].
    Pong,
    /// Reply to [`IpcRequest::Status`].
    Status(DaemonStatus),
    /// Reply to [`IpcRequest::Shutdown`].
    ShuttingDown,
    /// Reply to [`IpcRequest::CreateBase`].
    BaseCreated(BaseInfo),
    /// Reply to [`IpcRequest::ListBases`].
    BaseList(Vec<BaseInfo>),
    /// Reply to [`IpcRequest::SetTag`].
    TagSet { tag: TagName, base_id: BaseId },
    /// Reply to [`IpcRequest::DeleteTag`].
    TagDeleted,
    /// Reply to [`IpcRequest::RemoveBase`].
    BaseRemoved(RemoveBaseOutput),
    /// Reply to [`IpcRequest::CreateView`].
    ViewCreated(ViewSummary),
    /// Reply to [`IpcRequest::ListViews`].
    ViewList(Vec<ViewSummary>),
    /// Reply to [`IpcRequest::ViewPath`].
    ViewPath(PathBuf),
    /// Reply to [`IpcRequest::RemoveView`].
    ViewRemoved,
    /// Reply to [`IpcRequest::DiffView`].
    ViewDiff(Vec<DiffEntry>),
    /// Reply to [`IpcRequest::FreezeView`].
    ViewFrozen(FreezeSummary),
    /// Reply to [`IpcRequest::ApplyView`].
    ViewApplied(ApplyOutput),
    /// Error reply when an operation fails.
    Error(RemoteError),
}
