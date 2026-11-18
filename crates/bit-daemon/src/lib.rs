//! Background VFS mount host and control-plane IPC server for Bit.
#![forbid(unsafe_code)]

pub mod exclude;
pub mod id_gen;
pub mod mount;
pub mod paths;
pub mod server;
pub mod service;

pub use exclude::{scan_host_dir_with_excludes, ExcludeFilter};
pub use id_gen::ViewIdGenerator;
pub use mount::{
    build_mount_backend, cleanup_stale_os_mount, AutoMountBackend, FuseDeviceIo, FuseMountBackend,
    MountError, NfsMountBackend, NoopMountBackend, NoopMountCounters, VfsBackendChoice,
    VfsMountBackend, VfsMountHandle, WinFspMountBackend, BIT_VFS_BACKEND_VAR,
    DEFAULT_WINFSP_OWNER_SID,
};
pub use paths::{
    PathLayoutError, UserPaths, BIT_HOME_VAR, BIT_IPC_ENDPOINT_VAR, BIT_MOUNT_DIR_VAR,
};
pub use server::{DaemonError, DaemonServer, RunningDaemon};
pub use service::DaemonService;

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use bit_core::{
        BaseSelector, CoreError, DiffChange, EntryName, InMemoryCoreEngine, RelPath, TagName,
        Timestamp, VfsOperations, ViewId,
    };
    use bit_ipc::{IpcRequest, IpcResponse, LocalClient, RemoteError};
    use bit_store::BitStore;
    use bit_vfs_fuse::SystemFuseMountLifecycle;
    use bit_vfs_winfsp::OwnerSid;

    use super::*;

    fn unique_temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bit-daemon-{label}-{}-{}",
            std::process::id(),
            Timestamp::now().nanos
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn user_paths_defaults_and_overrides() {
        let defaults =
            UserPaths::from_values(None, None, None, Some(OsStr::new("/home/alice"))).unwrap();
        assert_eq!(defaults.bit_home(), PathBuf::from("/home/alice/.bit"));
        assert_eq!(
            defaults.mount_dir(),
            PathBuf::from("/home/alice/.bit/views")
        );
        assert_eq!(
            defaults.store_dir(),
            PathBuf::from("/home/alice/.bit/store")
        );
        assert_eq!(
            defaults.ipc_endpoint(),
            PathBuf::from("/home/alice/.bit/daemon.sock")
        );
        assert!(defaults.is_mount_dir_space_free());

        let overridden = UserPaths::from_values(
            Some(OsStr::new("/var/lib/bit-data")),
            Some(OsStr::new("/mnt/bit-views")),
            Some(OsStr::new("/run/user/1000/bit.sock")),
            Some(OsStr::new("/home/alice")),
        )
        .unwrap();
        assert_eq!(overridden.bit_home(), PathBuf::from("/var/lib/bit-data"));
        assert_eq!(overridden.mount_dir(), PathBuf::from("/mnt/bit-views"));
        assert_eq!(
            overridden.store_dir(),
            PathBuf::from("/var/lib/bit-data/store")
        );
        assert_eq!(
            overridden.ipc_endpoint(),
            PathBuf::from("/run/user/1000/bit.sock")
        );

        assert_eq!(
            UserPaths::from_values(None, None, None, None),
            Err(PathLayoutError::MissingHomeDir)
        );
    }

    #[test]
    fn view_id_generator_produces_unique_portable_ids() {
        let gen = ViewIdGenerator::new();
        let existing = [ViewId::new("view-0001").unwrap()];
        let first = gen.next_available(existing.iter());
        assert_eq!(first.as_str(), "view-0002");
        let second = gen.next_available(existing.iter());
        assert_eq!(second.as_str(), "view-0003");
    }

    #[test]
    fn exclude_filter_matches_component_and_nested_path_patterns() {
        let filter =
            ExcludeFilter::new(["target", "*.log", "build/cache", "crates/**/generated/*"]);
        let check = |p: &str| {
            let rel = RelPath::new(p).unwrap();
            let leaf = rel
                .file_name()
                .unwrap_or_else(|| EntryName::new("x").unwrap());
            filter.is_excluded(&rel, &leaf)
        };

        assert!(check("target"));
        assert!(check("nested/target"));
        assert!(check("app.log"));
        assert!(check("logs/server.log"));
        assert!(check("build/cache"));
        assert!(check("build/cache/obj.o"));
        assert!(check("crates/foo/generated/api.rs"));
        assert!(check("crates/generated/api.rs"));

        assert!(!check("src/main.rs"));
        assert!(!check("build/output.bin"));
        assert!(!check("crates/foo/src/lib.rs"));
    }

    #[test]
    fn vfs_mount_backend_adapters_wrap_fuse_nfs3_winfsp_and_auto_fallback() {
        let root = unique_temp_dir("vfs-adapters");
        let mount_dir = root.join("views");
        let vfs: Arc<dyn VfsOperations> = Arc::new(InMemoryCoreEngine::in_memory());

        // 1. FuseMountBackend with custom packet device cleanly starts and unmounts.
        let fuse_backend = FuseMountBackend::with_custom_device(
            Arc::new(
                SystemFuseMountLifecycle::new().with_proc_mounts_path(root.join("empty_mounts")),
            ),
            Arc::new(|_cfg| Ok(Box::new(Cursor::new(Vec::<u8>::new())))),
        );
        fs::write(root.join("empty_mounts"), b"").unwrap();
        let fuse_handle = fuse_backend.mount(&mount_dir, Arc::clone(&vfs)).unwrap();
        assert_eq!(fuse_handle.backend_name(), "fuse");
        fuse_handle.unmount().unwrap();

        // 2. NfsMountBackend in loopback server mode binds 127.0.0.1:0 and shuts down cleanly.
        let nfs_backend = NfsMountBackend::loopback_server_only();
        nfs_backend.cleanup_stale_mount(&mount_dir).unwrap();
        let nfs_handle = nfs_backend.mount(&mount_dir, Arc::clone(&vfs)).unwrap();
        assert_eq!(nfs_handle.backend_name(), "nfs3");
        nfs_handle.unmount().unwrap();

        // 3. WinFspMountBackend in in-process mode starts and stops WinFspDispatcher cleanly.
        let sid = OwnerSid::new(DEFAULT_WINFSP_OWNER_SID).unwrap();
        let winfsp_backend = WinFspMountBackend::in_process(sid);
        winfsp_backend.cleanup_stale_mount(&mount_dir).unwrap();
        let winfsp_handle = winfsp_backend.mount(&mount_dir, Arc::clone(&vfs)).unwrap();
        assert_eq!(winfsp_handle.backend_name(), "winfsp");
        winfsp_handle.unmount().unwrap();

        // 4. AutoMountBackend falls back gracefully to NoopMountBackend in sandboxed environments.
        let auto_backend = AutoMountBackend::platform_default();
        auto_backend.cleanup_stale_mount(&mount_dir).unwrap();
        let auto_handle = auto_backend.mount(&mount_dir, vfs).unwrap();
        auto_handle.unmount().unwrap();

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn remove_view_never_deletes_user_file_that_replaced_external_symlink() {
        let root = unique_temp_dir("symlink-safety");
        let paths = UserPaths::with_home(root.join(".bit"));
        let tree_dir = root.join("tree");
        fs::create_dir_all(&tree_dir).unwrap();
        fs::write(tree_dir.join("hello.txt"), b"hi\n").unwrap();

        let service = DaemonService::new(paths, Arc::new(InMemoryCoreEngine::in_memory()));
        assert!(matches!(
            service.handle_request(IpcRequest::CreateBase {
                dir: tree_dir,
                tag: Some(TagName::new("v1").unwrap()),
                excludes: Vec::new(),
            }),
            IpcResponse::BaseCreated(_)
        ));

        let link_path = root.join("ext-link");
        assert!(matches!(
            service.handle_request(IpcRequest::CreateView {
                base: BaseSelector::Tag(TagName::new("v1").unwrap()),
                view_id: Some(ViewId::new("v1").unwrap()),
                link_path: Some(link_path.clone()),
            }),
            IpcResponse::ViewCreated(_)
        ));
        assert!(fs::symlink_metadata(&link_path)
            .unwrap()
            .file_type()
            .is_symlink());

        // User manually replaces the symlink with an ordinary file; RemoveView must leave it intact.
        fs::remove_file(&link_path).unwrap();
        fs::write(&link_path, b"important user file").unwrap();

        assert_eq!(
            service.handle_request(IpcRequest::RemoveView {
                view_id: ViewId::new("v1").unwrap()
            }),
            IpcResponse::ViewRemoved
        );
        assert_eq!(fs::read(&link_path).unwrap(), b"important user file");

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_daemon_server_client_full_roundtrip_and_persistence() {
        let root = unique_temp_dir("persistent-roundtrip");
        let paths = UserPaths::with_home(root.join(".bit"));

        let project_dir = root.join("project");
        fs::create_dir_all(project_dir.join("src")).unwrap();
        fs::create_dir_all(project_dir.join("target/debug")).unwrap();
        fs::write(
            project_dir.join("src/lib.rs"),
            b"pub fn answer() -> u32 { 42 }\n",
        )
        .unwrap();
        fs::write(project_dir.join("README.md"), b"hello\n").unwrap();
        // Verify ADR-0003: `.gitignore` is ignored during ingestion unless explicitly excluded!
        fs::write(project_dir.join(".gitignore"), b"README.md\n").unwrap();
        fs::write(project_dir.join("debug.log"), b"noisy log\n").unwrap();
        fs::write(project_dir.join("target/debug/app"), b"binary\n").unwrap();

        let (store, _) = BitStore::open(paths.store_dir()).unwrap();
        let engine = Arc::new(store.into_engine());
        let mount_backend = NoopMountBackend::new();
        let counters = mount_backend.counters();

        let daemon = DaemonServer::from_persistent_engine(
            paths.clone(),
            Arc::clone(&engine),
            Box::new(mount_backend),
        )
        .spawn_background()
        .unwrap();

        assert_eq!(counters.cleanup_calls.load(Ordering::SeqCst), 1);
        assert_eq!(counters.mount_calls.load(Ordering::SeqCst), 1);

        let mut client = LocalClient::connect(daemon.endpoint()).unwrap();
        assert_eq!(client.send(&IpcRequest::Ping).unwrap(), IpcResponse::Pong);

        // CreateBase via `bit_store::ingest_external_dir_fs` (`README.md`, `.gitignore`, `src`, `src/lib.rs` = 4 entries).
        let base_info = match client
            .send(&IpcRequest::CreateBase {
                dir: project_dir.clone(),
                tag: Some(TagName::new("v1").unwrap()),
                excludes: vec!["target".to_owned(), "*.log".to_owned()],
            })
            .unwrap()
        {
            IpcResponse::BaseCreated(info) => info,
            other => panic!("unexpected CreateBase response: {other:?}"),
        };
        assert_eq!(base_info.entry_count, 4);

        fs::remove_dir_all(project_dir.join("target")).unwrap();
        fs::remove_file(project_dir.join("debug.log")).unwrap();

        let ext_link = root.join("links/active-view");
        let created_view = match client
            .send(&IpcRequest::CreateView {
                base: BaseSelector::Tag(TagName::new("v1").unwrap()),
                view_id: None,
                link_path: Some(ext_link.clone()),
            })
            .unwrap()
        {
            IpcResponse::ViewCreated(summary) => summary,
            other => panic!("unexpected CreateView response: {other:?}"),
        };
        assert_eq!(created_view.info.id.as_str(), "view-0001");

        // Mutate View via VfsOperations (`Overlay` persisted to `FsMetadataStore`).
        engine
            .write("view-0001/README.md", 0, b"updated readme\n")
            .unwrap();
        engine
            .create_file("view-0001/NEW.txt", 0o644, true)
            .unwrap();
        engine
            .write("view-0001/NEW.txt", 0, b"created in view\n")
            .unwrap();

        // Stop first daemon instance completely.
        assert_eq!(
            client.send(&IpcRequest::Shutdown).unwrap(),
            IpcResponse::ShuttingDown
        );
        daemon.shutdown_and_join().unwrap();
        drop(engine);

        // Restart a brand-new persistent daemon from disk (`DaemonServer::open_persistent`)!
        let daemon2 = DaemonServer::open_persistent(paths.clone())
            .unwrap()
            .spawn_background()
            .unwrap();
        let mut client2 = LocalClient::connect(daemon2.endpoint()).unwrap();

        // Verify Base, Tag, View, Overlay Diff, and external symlink link_path survived restart!
        match client2.send(&IpcRequest::ListViews).unwrap() {
            IpcResponse::ViewList(views) => {
                assert_eq!(views.len(), 1);
                assert_eq!(views[0].info.id.as_str(), "view-0001");
                assert_eq!(views[0].link_path.as_deref(), Some(ext_link.as_path()));
            }
            other => panic!("unexpected ListViews: {other:?}"),
        }

        match client2
            .send(&IpcRequest::DiffView {
                view_id: ViewId::new("view-0001").unwrap(),
            })
            .unwrap()
        {
            IpcResponse::ViewDiff(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].path.as_str(), "NEW.txt");
                assert_eq!(entries[0].change, DiffChange::Added);
                assert_eq!(entries[1].path.as_str(), "README.md");
                assert_eq!(entries[1].change, DiffChange::Modified);
            }
            other => panic!("unexpected DiffView: {other:?}"),
        }

        // Guarded Apply via `bit_store::execute_apply` detects conflict and leaves target untouched!
        fs::write(project_dir.join("README.md"), b"conflicting host edit\n").unwrap();
        match client2
            .send(&IpcRequest::ApplyView {
                view_id: ViewId::new("view-0001").unwrap(),
                target_dir: project_dir.clone(),
                force: false,
            })
            .unwrap()
        {
            IpcResponse::Error(RemoteError::Core(CoreError::ApplyConflicts(c))) => {
                assert_eq!(c.len(), 1);
                assert_eq!(c[0].path.as_str(), "README.md");
            }
            other => panic!("expected ApplyConflicts, got: {other:?}"),
        }
        assert!(!project_dir.join("NEW.txt").exists());
        assert_eq!(
            fs::read(project_dir.join("README.md")).unwrap(),
            b"conflicting host edit\n"
        );

        // Forced Apply succeeds via `bit_store::execute_apply(..., force = true)`.
        match client2
            .send(&IpcRequest::ApplyView {
                view_id: ViewId::new("view-0001").unwrap(),
                target_dir: project_dir.clone(),
                force: true,
            })
            .unwrap()
        {
            IpcResponse::ViewApplied(applied) => assert_eq!(applied.plan.diff.len(), 2),
            other => panic!("expected ViewApplied, got: {other:?}"),
        }
        assert_eq!(
            fs::read(project_dir.join("README.md")).unwrap(),
            b"updated readme\n"
        );
        assert_eq!(
            fs::read(project_dir.join("NEW.txt")).unwrap(),
            b"created in view\n"
        );

        daemon2.shutdown_and_join().unwrap();
        let _ = fs::remove_dir_all(&root);
    }
}
