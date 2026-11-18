//! Background IPC server and VFS mount host (`DaemonServer`, `RunningDaemon`).

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bit_core::{
    BlobStore, ControlPlane, CoreEngine, InMemoryCoreEngine, MetadataStore, StoreError,
    VfsOperations,
};
use bit_ipc::{
    read_request_opt, write_response, IpcEndpoint, IpcError, IpcRequest, LocalClient,
    LocalListener, LocalStream,
};
use bit_store::{BitStore, PersistentCoreEngine, RecoverySummary};

use crate::mount::{
    build_mount_backend, MountError, NoopMountBackend, VfsBackendChoice, VfsMountBackend,
    VfsMountHandle,
};
use crate::paths::{PathLayoutError, UserPaths};
use crate::service::{
    DaemonService, EngineStoreBridge, GenericEngineBridge, PersistentStoreBridge,
};

/// Top-level error returned by [`DaemonServer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonError {
    /// Directory layout resolution or creation failed.
    Paths(PathLayoutError),
    /// Persistent backing store initialization or recovery failed.
    Store(StoreError),
    /// VFS stale cleanup, mount, or unmount failed.
    Mount(MountError),
    /// IPC listener binding or transport failed.
    Ipc(IpcError),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Paths(e) => fmt::Display::fmt(e, f),
            Self::Store(e) => fmt::Display::fmt(e, f),
            Self::Mount(e) => fmt::Display::fmt(e, f),
            Self::Ipc(e) => fmt::Display::fmt(e, f),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<PathLayoutError> for DaemonError {
    fn from(e: PathLayoutError) -> Self {
        Self::Paths(e)
    }
}

impl From<StoreError> for DaemonError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<MountError> for DaemonError {
    fn from(e: MountError) -> Self {
        Self::Mount(e)
    }
}

impl From<IpcError> for DaemonError {
    fn from(e: IpcError) -> Self {
        Self::Ipc(e)
    }
}

type PreparedRuntime = (
    LocalListener,
    Arc<DaemonService>,
    Option<Box<dyn VfsMountHandle>>,
);

/// Builder and runner for the `bit-daemon` IPC server and VFS mount lifecycle.
pub struct DaemonServer {
    paths: UserPaths,
    control: Arc<dyn ControlPlane>,
    vfs: Option<Arc<dyn VfsOperations>>,
    store_bridge: Option<Arc<dyn EngineStoreBridge>>,
    links_file: Option<PathBuf>,
    mount_backend: Box<dyn VfsMountBackend>,
}

impl DaemonServer {
    /// Creates a `DaemonServer` dispatching IPC requests to `control` with [`NoopMountBackend`].
    pub fn new(paths: UserPaths, control: Arc<dyn ControlPlane>) -> Self {
        Self {
            paths,
            control,
            vfs: None,
            store_bridge: None,
            links_file: None,
            mount_backend: Box::new(NoopMountBackend::new()),
        }
    }

    /// Opens (or initializes) a persistent `BitStore` at `paths.store_dir()`, wires
    /// `ingest_external_dir_fs` and transactional `execute_apply`, and selects the platform VFS
    /// mount backend according to `BIT_VFS_BACKEND` (defaulting to [`VfsBackendChoice::Auto`]).
    pub fn open_persistent(paths: UserPaths) -> Result<Self, DaemonError> {
        let (server, _recovery) = Self::open_persistent_with_recovery(paths)?;
        Ok(server)
    }

    /// Identical to [`Self::open_persistent`], also returning the store [`RecoverySummary`] and
    /// shared [`PersistentCoreEngine`].
    pub fn open_persistent_with_recovery(
        paths: UserPaths,
    ) -> Result<(Self, RecoverySummary), DaemonError> {
        paths.ensure_directories()?;
        let backend_choice = VfsBackendChoice::from_env()?;
        let (store, recovery) = BitStore::open(paths.store_dir())?;
        let engine = Arc::new(store.into_engine());
        let server =
            Self::from_persistent_engine(paths, engine, build_mount_backend(backend_choice));
        Ok((server, recovery))
    }

    /// Constructs a `DaemonServer` over an already-opened [`PersistentCoreEngine`] and explicit
    /// [`VfsMountBackend`].
    pub fn from_persistent_engine(
        paths: UserPaths,
        engine: Arc<PersistentCoreEngine>,
        mount_backend: Box<dyn VfsMountBackend>,
    ) -> Self {
        let links_file = paths.store_dir().join("view_links.bin");
        let bridge: Arc<dyn EngineStoreBridge> = Arc::new(PersistentStoreBridge {
            engine: Arc::clone(&engine),
        });
        let control: Arc<dyn ControlPlane> = Arc::clone(&engine) as Arc<dyn ControlPlane>;
        let vfs: Arc<dyn VfsOperations> = engine;
        Self {
            paths,
            control,
            vfs: Some(vfs),
            store_bridge: Some(bridge),
            links_file: Some(links_file),
            mount_backend,
        }
    }

    /// Creates a `DaemonServer` wired to both `ControlPlane` and `VfsOperations` of any
    /// [`CoreEngine`].
    pub fn with_engine<B, M>(paths: UserPaths, engine: Arc<CoreEngine<B, M>>) -> Self
    where
        B: BlobStore + 'static,
        M: MetadataStore + 'static,
    {
        let bridge: Arc<dyn EngineStoreBridge> = Arc::new(GenericEngineBridge {
            engine: Arc::clone(&engine),
        });
        let control: Arc<dyn ControlPlane> = Arc::clone(&engine) as Arc<dyn ControlPlane>;
        let vfs: Arc<dyn VfsOperations> = engine;
        Self {
            paths,
            control,
            vfs: Some(vfs),
            store_bridge: Some(bridge),
            links_file: None,
            mount_backend: Box::new(NoopMountBackend::new().with_os_stale_check()),
        }
    }

    /// Creates a standalone in-memory `DaemonServer` (`InMemoryCoreEngine` + `NoopMountBackend`).
    pub fn in_memory(paths: UserPaths) -> Self {
        Self::with_engine(paths, Arc::new(InMemoryCoreEngine::in_memory()))
    }

    /// Attaches a `VfsOperations` implementation to mount via `mount_backend`.
    pub fn with_vfs(mut self, vfs: Arc<dyn VfsOperations>) -> Self {
        self.vfs = Some(vfs);
        self
    }

    /// Configures a custom OS [`VfsMountBackend`] (`FuseMountBackend`, `NfsMountBackend`,
    /// `WinFspMountBackend`, `AutoMountBackend`, or `NoopMountBackend`).
    pub fn with_mount_backend(mut self, backend: Box<dyn VfsMountBackend>) -> Self {
        self.mount_backend = backend;
        self
    }

    fn prepare_runtime(self) -> Result<PreparedRuntime, DaemonError> {
        self.paths.ensure_directories()?;

        // Bind IPC listener first so a second daemon instance fails immediately with AddressInUse
        // before touching any live VFS mount owned by the primary daemon.
        let listener = LocalListener::bind(self.paths.endpoint())?;

        // Clean up any stale/orphaned VFS mount from an earlier crashed daemon before mounting.
        self.mount_backend
            .cleanup_stale_mount(self.paths.mount_dir())?;

        let backend_name = self.mount_backend.name().to_owned();
        let mut service = DaemonService::new(self.paths.clone(), self.control)
            .with_vfs_backend_name(backend_name);
        if let Some(bridge) = self.store_bridge {
            service = service.with_store_bridge(bridge);
        }
        if let Some(links_file) = self.links_file {
            service = service.with_links_file(links_file);
        }
        if let Some(vfs) = &self.vfs {
            service = service.with_vfs(Arc::clone(vfs));
        }

        let mount_handle = match self.vfs {
            Some(vfs) => {
                let handle = self.mount_backend.mount(self.paths.mount_dir(), vfs)?;
                service.set_vfs_backend_name(handle.backend_name());
                service.set_vfs_mounted(true);
                Some(handle)
            }
            None => None,
        };

        Ok((listener, Arc::new(service), mount_handle))
    }

    /// Runs the daemon synchronously on the calling thread until [`IpcRequest::Shutdown`] is
    /// processed, then unmounts the VFS and cleans up the IPC socket.
    pub fn serve_blocking(self) -> Result<(), DaemonError> {
        let (listener, service, mount_handle) = self.prepare_runtime()?;
        run_accept_loop(listener, service, mount_handle)
    }

    /// Binds the IPC listener and mounts the VFS synchronously, then spawns the accept loop on a
    /// background thread and returns a [`RunningDaemon`] handle.
    pub fn spawn_background(self) -> Result<RunningDaemon, DaemonError> {
        let (listener, service, mount_handle) = self.prepare_runtime()?;
        let endpoint = listener.endpoint().clone();
        let shared_service = Arc::clone(&service);
        let join_handle = thread::spawn(move || run_accept_loop(listener, service, mount_handle));
        Ok(RunningDaemon {
            endpoint,
            service: shared_service,
            join_handle: Some(join_handle),
        })
    }
}

/// Handle to a background [`DaemonServer`] started via [`DaemonServer::spawn_background`].
pub struct RunningDaemon {
    endpoint: IpcEndpoint,
    service: Arc<DaemonService>,
    join_handle: Option<JoinHandle<Result<(), DaemonError>>>,
}

impl RunningDaemon {
    /// Bound [`IpcEndpoint`] accepting client connections.
    pub const fn endpoint(&self) -> &IpcEndpoint {
        &self.endpoint
    }

    /// Shared [`DaemonService`].
    pub fn service(&self) -> &Arc<DaemonService> {
        &self.service
    }

    /// Signals shutdown, wakes the accept loop, and waits for clean VFS unmount and socket cleanup.
    pub fn shutdown_and_join(mut self) -> Result<(), DaemonError> {
        self.trigger_shutdown();
        if let Some(handle) = self.join_handle.take() {
            return handle.join().unwrap_or(Ok(()));
        }
        Ok(())
    }

    fn trigger_shutdown(&self) {
        self.service.shutdown_flag().store(true, Ordering::SeqCst);
        let _ = LocalClient::connect(&self.endpoint);
    }
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        if let Some(handle) = self.join_handle.take() {
            self.trigger_shutdown();
            let _ = handle.join();
        }
    }
}

fn run_accept_loop(
    mut listener: LocalListener,
    service: Arc<DaemonService>,
    mount_handle: Option<Box<dyn VfsMountHandle>>,
) -> Result<(), DaemonError> {
    let endpoint = listener.endpoint().clone();
    let mut client_workers: Vec<JoinHandle<()>> = Vec::new();

    while !service.is_shutdown_requested() {
        let stream = match listener.accept() {
            Ok(s) => s,
            Err(_) if service.is_shutdown_requested() => break,
            Err(err) => {
                if matches!(err, IpcError::ConnectionClosed) {
                    break;
                }
                continue;
            }
        };

        if service.is_shutdown_requested() {
            drop(stream);
            break;
        }

        client_workers.retain(|h| !h.is_finished());

        let svc = Arc::clone(&service);
        let wake_ep = endpoint.clone();
        client_workers.push(thread::spawn(move || {
            handle_client_connection(stream, svc, wake_ep);
        }));
    }

    listener.cleanup_socket();

    for worker in client_workers {
        let _ = worker.join();
    }

    service.set_vfs_mounted(false);
    if let Some(handle) = mount_handle {
        handle.unmount()?;
    }

    Ok(())
}

fn handle_client_connection(
    mut stream: LocalStream,
    service: Arc<DaemonService>,
    wake_endpoint: IpcEndpoint,
) {
    let _ = stream.set_timeout(Some(Duration::from_millis(50)));
    loop {
        let req = match read_request_opt(&mut stream) {
            Ok(Some(req)) => req,
            Err(IpcError::Timeout) => {
                if service.is_shutdown_requested() {
                    break;
                }
                continue;
            }
            Ok(None) | Err(_) => break,
        };
        let is_shutdown = matches!(req, IpcRequest::Shutdown);
        let resp = service.handle_request(req);
        if write_response(&mut stream, &resp).is_err() {
            break;
        }
        if is_shutdown {
            let _ = LocalClient::connect(&wake_endpoint);
            break;
        }
    }
}
