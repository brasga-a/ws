//! Pluggable OS-specific VFS mount lifecycle traits (`VfsMountBackend`, `VfsMountHandle`) and
//! adapters wrapping `bit-vfs-fuse` (Linux), `bit-vfs-nfs` (macOS loopback NFSv3),
//! `bit-vfs-winfsp` (Windows WinFsp), and `NoopMountBackend` (headless / sandboxed fallback).

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bit_core::VfsOperations;
use bit_vfs_fuse::{
    FuseDispatcher, FuseMountConfig, FuseMountHandle, FuseMountLifecycle, MountState as FuseState,
    SystemFuseMountLifecycle,
};
use bit_vfs_nfs::{
    build_stale_umount_command, NfsLoopbackServer, NfsMountConfig, NfsRunningServer,
    MACOS_UMOUNT_BIN,
};
use bit_vfs_winfsp::{OwnerSid, WinFspDispatcher, WinFspMountConfig};

/// Optional process variable selecting the VFS mount backend (`auto`, `fuse`, `nfs3`, `winfsp`, `noop`).
pub const BIT_VFS_BACKEND_VAR: &str = "BIT_VFS_BACKEND";

/// Default Windows owner SID used when none is explicitly supplied.
pub const DEFAULT_WINFSP_OWNER_SID: &str = "S-1-5-18";

/// Requested VFS mount backend policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VfsBackendChoice {
    /// Automatically try the native OS backend (`fuse` on Linux, `nfs3` on macOS, `winfsp` on
    /// Windows) and fall back gracefully to `NoopMountBackend` if kernel mounting is unavailable
    /// (e.g. inside an unprivileged container or test sandbox).
    #[default]
    Auto,
    /// Strict Linux FUSE adapter (`bit-vfs-fuse`).
    Fuse,
    /// Strict macOS loopback NFSv3 adapter (`bit-vfs-nfs`).
    Nfs3,
    /// Strict Windows WinFsp adapter (`bit-vfs-winfsp`).
    WinFsp,
    /// Headless directory-only mode (`NoopMountBackend`).
    Noop,
}

impl VfsBackendChoice {
    /// Parses a `BIT_VFS_BACKEND` value (`auto`, `fuse`, `nfs`/`nfs3`, `winfsp`, `noop`/`none`).
    pub fn parse(raw: &str) -> Result<Self, MountError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Self::Auto),
            "fuse" => Ok(Self::Fuse),
            "nfs" | "nfs3" => Ok(Self::Nfs3),
            "winfsp" => Ok(Self::WinFsp),
            "noop" | "none" | "headless" => Ok(Self::Noop),
            other => Err(MountError::InvalidBackend(other.to_owned())),
        }
    }

    /// Resolves backend policy from `BIT_VFS_BACKEND` (defaulting to [`Self::Auto`]).
    pub fn from_env() -> Result<Self, MountError> {
        match std::env::var(BIT_VFS_BACKEND_VAR) {
            Ok(val) => Self::parse(&val),
            Err(_) => Ok(Self::Auto),
        }
    }
}

/// Builds the [`VfsMountBackend`] corresponding to `choice`.
pub fn build_mount_backend(choice: VfsBackendChoice) -> Box<dyn VfsMountBackend> {
    match choice {
        VfsBackendChoice::Auto => Box::new(AutoMountBackend::platform_default()),
        VfsBackendChoice::Fuse => Box::new(FuseMountBackend::new()),
        VfsBackendChoice::Nfs3 => Box::new(NfsMountBackend::new()),
        VfsBackendChoice::WinFsp => Box::new(WinFspMountBackend::default()),
        VfsBackendChoice::Noop => Box::new(NoopMountBackend::new()),
    }
}

/// Error returned during stale-mount cleanup, VFS mounting, or unmounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountError {
    /// Unrecognized `BIT_VFS_BACKEND` value.
    InvalidBackend(String),
    /// Cleaning up a stale mount from an earlier crashed daemon failed.
    StaleCleanupFailed { mount_dir: PathBuf, reason: String },
    /// Mounting the userspace VFS backend failed.
    MountFailed { mount_dir: PathBuf, reason: String },
    /// Unmounting the userspace VFS backend failed.
    UnmountFailed { mount_dir: PathBuf, reason: String },
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBackend(val) => write!(
                f,
                "unknown {BIT_VFS_BACKEND_VAR} value {val:?} (expected auto, fuse, nfs3, winfsp, or noop)"
            ),
            Self::StaleCleanupFailed { mount_dir, reason } => write!(
                f,
                "failed to clean up stale VFS mount at {}: {reason}",
                mount_dir.display()
            ),
            Self::MountFailed { mount_dir, reason } => write!(
                f,
                "failed to mount VFS at {}: {reason}",
                mount_dir.display()
            ),
            Self::UnmountFailed { mount_dir, reason } => write!(
                f,
                "failed to unmount VFS at {}: {reason}",
                mount_dir.display()
            ),
        }
    }
}

impl std::error::Error for MountError {}

/// Live handle to an active userspace VFS mount (`<mount>/`).
pub trait VfsMountHandle: Send + Sync {
    /// Host path where `<mount>/` is mounted.
    fn mount_dir(&self) -> &Path;

    /// Active backend name (`"fuse"`, `"nfs3"`, `"winfsp"`, or `"noop"`).
    fn backend_name(&self) -> &'static str {
        "unknown"
    }

    /// Cleanly detaches the userspace VFS mount during daemon shutdown.
    fn unmount(self: Box<Self>) -> Result<(), MountError>;
}

/// Pluggable OS VFS adapter (`FuseMountBackend`, `NfsMountBackend`, `WinFspMountBackend`,
/// `AutoMountBackend`, or `NoopMountBackend`).
pub trait VfsMountBackend: Send + Sync {
    /// Short backend identifier reported in `DaemonStatus` (`"fuse"`, `"nfs3"`, `"winfsp"`, `"noop"`).
    fn name(&self) -> &'static str;

    /// Startup hook invoked before mounting to detach any orphaned/stale mount left behind by a
    /// crashed daemon process and ensure `mount_dir` exists as a clean directory.
    fn cleanup_stale_mount(&self, mount_dir: &Path) -> Result<(), MountError>;

    /// Mounts `vfs` at `mount_dir` and returns a live [`VfsMountHandle`].
    fn mount(
        &self,
        mount_dir: &Path,
        vfs: Arc<dyn VfsOperations>,
    ) -> Result<Box<dyn VfsMountHandle>, MountError>;
}

// ---------------------------------------------------------------------------
// 1. Linux FUSE adapter (`bit-vfs-fuse`)
// ---------------------------------------------------------------------------

type FuseDeviceFactory =
    dyn Fn(&FuseMountConfig) -> std::io::Result<Box<dyn FuseDeviceIo>> + Send + Sync;

/// Trait combining `Read + Write + Send` for boxed FUSE packet devices.
pub trait FuseDeviceIo: Read + Write + Send {}
impl<T: Read + Write + Send> FuseDeviceIo for T {}

/// `VfsMountBackend` adapter wrapping `bit-vfs-fuse` (`FuseMountConfig`, `FuseDispatcher`,
/// `FuseMountLifecycle`, and `FuseMountHandle`).
pub struct FuseMountBackend {
    lifecycle: Arc<dyn FuseMountLifecycle>,
    device_factory: Option<Arc<FuseDeviceFactory>>,
}

impl Default for FuseMountBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FuseMountBackend {
    /// Creates a `FuseMountBackend` using [`SystemFuseMountLifecycle`].
    pub fn new() -> Self {
        Self {
            lifecycle: Arc::new(SystemFuseMountLifecycle::new()),
            device_factory: None,
        }
    }

    /// Creates a `FuseMountBackend` with a custom [`FuseMountLifecycle`] and packet device factory
    /// (useful for deterministic FUSE session lifecycle tests without `/dev/fuse` privileges).
    pub fn with_custom_device(
        lifecycle: Arc<dyn FuseMountLifecycle>,
        device_factory: Arc<FuseDeviceFactory>,
    ) -> Self {
        Self {
            lifecycle,
            device_factory: Some(device_factory),
        }
    }
}

struct DaemonFuseHandle {
    inner: Mutex<Option<FuseMountHandle>>,
    mount_dir: PathBuf,
}

impl VfsMountHandle for DaemonFuseHandle {
    fn mount_dir(&self) -> &Path {
        &self.mount_dir
    }

    fn backend_name(&self) -> &'static str {
        "fuse"
    }

    fn unmount(self: Box<Self>) -> Result<(), MountError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut handle) = guard.take() {
            handle.shutdown().map_err(|e| MountError::UnmountFailed {
                mount_dir: self.mount_dir.clone(),
                reason: e.to_string(),
            })?;
        }
        Ok(())
    }
}

impl VfsMountBackend for FuseMountBackend {
    fn name(&self) -> &'static str {
        "fuse"
    }

    fn cleanup_stale_mount(&self, mount_dir: &Path) -> Result<(), MountError> {
        match self.lifecycle.inspect_mount(mount_dir) {
            Ok(FuseState::NotMounted) => {}
            Ok(FuseState::StaleFuseMount { .. }) => {
                self.lifecycle.lazy_unmount(mount_dir).map_err(|e| {
                    MountError::StaleCleanupFailed {
                        mount_dir: mount_dir.to_path_buf(),
                        reason: e.to_string(),
                    }
                })?;
            }
            Ok(FuseState::ActiveFuseMount(_)) => {
                // Detach orphaned mount left behind if no live daemon owns the IPC socket.
                self.lifecycle.lazy_unmount(mount_dir).map_err(|e| {
                    MountError::StaleCleanupFailed {
                        mount_dir: mount_dir.to_path_buf(),
                        reason: e.to_string(),
                    }
                })?;
            }
            Err(err) => {
                return Err(MountError::StaleCleanupFailed {
                    mount_dir: mount_dir.to_path_buf(),
                    reason: err.to_string(),
                });
            }
        }
        fs::create_dir_all(mount_dir).map_err(|e| MountError::StaleCleanupFailed {
            mount_dir: mount_dir.to_path_buf(),
            reason: e.to_string(),
        })
    }

    fn mount(
        &self,
        mount_dir: &Path,
        vfs: Arc<dyn VfsOperations>,
    ) -> Result<Box<dyn VfsMountHandle>, MountError> {
        let (uid, gid) = detect_unix_owner_ids(mount_dir);
        let cfg = FuseMountConfig::new(mount_dir).with_owner(uid, gid);
        cfg.validate().map_err(|e| MountError::MountFailed {
            mount_dir: mount_dir.to_path_buf(),
            reason: e.to_string(),
        })?;
        self.lifecycle
            .prepare_mount_point(&cfg, false)
            .map_err(|e| MountError::MountFailed {
                mount_dir: mount_dir.to_path_buf(),
                reason: e.to_string(),
            })?;

        let dispatcher = Arc::new(FuseDispatcher::new(vfs, cfg.clone()).map_err(|e| {
            MountError::MountFailed {
                mount_dir: mount_dir.to_path_buf(),
                reason: e.to_string(),
            }
        })?);

        if let Some(factory) = &self.device_factory {
            let dev = factory(&cfg).map_err(|e| MountError::MountFailed {
                mount_dir: mount_dir.to_path_buf(),
                reason: e.to_string(),
            })?;
            let handle =
                FuseMountHandle::spawn_device(dispatcher, dev, Arc::clone(&self.lifecycle))
                    .map_err(|e| MountError::MountFailed {
                        mount_dir: mount_dir.to_path_buf(),
                        reason: e.to_string(),
                    })?;
            return Ok(Box::new(DaemonFuseHandle {
                inner: Mutex::new(Some(handle)),
                mount_dir: mount_dir.to_path_buf(),
            }));
        }

        Err(MountError::MountFailed {
            mount_dir: mount_dir.to_path_buf(),
            reason: "kernel /dev/fuse mount privilege is not available in this process".to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// 2. macOS loopback NFSv3 adapter (`bit-vfs-nfs`)
// ---------------------------------------------------------------------------

/// `VfsMountBackend` adapter wrapping `bit-vfs-nfs` (`NfsMountConfig` + `NfsLoopbackServer` bound
/// strictly to `127.0.0.1` with owner `uid` enforcement).
#[derive(Debug, Clone)]
pub struct NfsMountBackend {
    invoke_os_mount_cmd: bool,
}

impl Default for NfsMountBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NfsMountBackend {
    /// Creates an `NfsMountBackend` that invokes `/sbin/mount_nfs` on macOS.
    pub const fn new() -> Self {
        Self {
            invoke_os_mount_cmd: true,
        }
    }

    /// Creates a loopback-server-only `NfsMountBackend` (binds `127.0.0.1:0` and serves ONC-RPC
    /// `MOUNTv3` + `NFSv3` without invoking `/sbin/mount_nfs`, ideal for cross-platform tests).
    pub const fn loopback_server_only() -> Self {
        Self {
            invoke_os_mount_cmd: false,
        }
    }
}

struct DaemonNfsHandle {
    server: NfsRunningServer,
    mount_dir: PathBuf,
    os_mounted: bool,
}

impl VfsMountHandle for DaemonNfsHandle {
    fn mount_dir(&self) -> &Path {
        &self.mount_dir
    }

    fn backend_name(&self) -> &'static str {
        "nfs3"
    }

    fn unmount(self: Box<Self>) -> Result<(), MountError> {
        if self.os_mounted {
            let status = Command::new(MACOS_UMOUNT_BIN).arg(&self.mount_dir).status();
            if !status.is_ok_and(|s| s.success()) {
                let _ = build_stale_umount_command(&self.mount_dir).status();
            }
        }
        self.server.shutdown();
        Ok(())
    }
}

impl VfsMountBackend for NfsMountBackend {
    fn name(&self) -> &'static str {
        "nfs3"
    }

    fn cleanup_stale_mount(&self, mount_dir: &Path) -> Result<(), MountError> {
        if self.invoke_os_mount_cmd && cfg!(target_os = "macos") {
            if let Err(err) = fs::read_dir(mount_dir) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    let _ = build_stale_umount_command(mount_dir).status();
                }
            }
        }
        fs::create_dir_all(mount_dir).map_err(|e| MountError::StaleCleanupFailed {
            mount_dir: mount_dir.to_path_buf(),
            reason: e.to_string(),
        })
    }

    fn mount(
        &self,
        mount_dir: &Path,
        vfs: Arc<dyn VfsOperations>,
    ) -> Result<Box<dyn VfsMountHandle>, MountError> {
        fs::create_dir_all(mount_dir).map_err(|e| MountError::MountFailed {
            mount_dir: mount_dir.to_path_buf(),
            reason: e.to_string(),
        })?;
        let (uid, gid) = detect_unix_owner_ids(mount_dir);
        let cfg = NfsMountConfig::loopback(0, uid, mount_dir)
            .map_err(|e| MountError::MountFailed {
                mount_dir: mount_dir.to_path_buf(),
                reason: e.to_string(),
            })?
            .with_owner_gid(gid);

        let running = NfsLoopbackServer::bind(cfg, vfs)
            .and_then(NfsLoopbackServer::start)
            .map_err(|e| MountError::MountFailed {
                mount_dir: mount_dir.to_path_buf(),
                reason: e.to_string(),
            })?;

        if self.invoke_os_mount_cmd {
            if !cfg!(target_os = "macos") {
                running.shutdown();
                return Err(MountError::MountFailed {
                    mount_dir: mount_dir.to_path_buf(),
                    reason: format!(
                        "{MACOS_UMOUNT_BIN}/mount_nfs kernel mount is only supported on macos"
                    ),
                });
            }
            let mut cmd = running.config().mount_nfs_command(running.bound_port());
            match cmd.output() {
                Ok(out) if out.status.success() => {}
                Ok(out) => {
                    running.shutdown();
                    let detail = String::from_utf8_lossy(&out.stderr).trim().to_owned();
                    return Err(MountError::MountFailed {
                        mount_dir: mount_dir.to_path_buf(),
                        reason: if detail.is_empty() {
                            format!("mount_nfs exited with {}", out.status)
                        } else {
                            detail
                        },
                    });
                }
                Err(err) => {
                    running.shutdown();
                    return Err(MountError::MountFailed {
                        mount_dir: mount_dir.to_path_buf(),
                        reason: format!("failed to execute mount_nfs: {err}"),
                    });
                }
            }
        }

        Ok(Box::new(DaemonNfsHandle {
            server: running,
            mount_dir: mount_dir.to_path_buf(),
            os_mounted: self.invoke_os_mount_cmd,
        }))
    }
}

// ---------------------------------------------------------------------------
// 3. Windows WinFsp adapter (`bit-vfs-winfsp`)
// ---------------------------------------------------------------------------

/// `VfsMountBackend` adapter wrapping `bit-vfs-winfsp` (`WinFspMountConfig` + `WinFspDispatcher`).
#[derive(Debug, Clone)]
pub struct WinFspMountBackend {
    owner_sid: OwnerSid,
    require_kernel_driver: bool,
}

impl Default for WinFspMountBackend {
    fn default() -> Self {
        Self {
            owner_sid: OwnerSid::new(DEFAULT_WINFSP_OWNER_SID).expect("valid default SID"),
            require_kernel_driver: true,
        }
    }
}

impl WinFspMountBackend {
    /// Creates a `WinFspMountBackend` restricted to `owner_sid`.
    pub fn new(owner_sid: OwnerSid) -> Self {
        Self {
            owner_sid,
            require_kernel_driver: true,
        }
    }

    /// Creates an in-process `WinFspMountBackend` exercising `WinFspMountConfig` validation and
    /// `WinFspDispatcher::start`/`stop` without requiring the Windows `winfsp` kernel driver.
    pub fn in_process(owner_sid: OwnerSid) -> Self {
        Self {
            owner_sid,
            require_kernel_driver: false,
        }
    }
}

struct DaemonWinFspHandle {
    dispatcher: Arc<WinFspDispatcher>,
    mount_dir: PathBuf,
}

impl VfsMountHandle for DaemonWinFspHandle {
    fn mount_dir(&self) -> &Path {
        &self.mount_dir
    }

    fn backend_name(&self) -> &'static str {
        "winfsp"
    }

    fn unmount(self: Box<Self>) -> Result<(), MountError> {
        self.dispatcher
            .stop()
            .map_err(|status| MountError::UnmountFailed {
                mount_dir: self.mount_dir.clone(),
                reason: format!("WinFspDispatcher::stop failed with {status}"),
            })
    }
}

impl VfsMountBackend for WinFspMountBackend {
    fn name(&self) -> &'static str {
        "winfsp"
    }

    fn cleanup_stale_mount(&self, mount_dir: &Path) -> Result<(), MountError> {
        let raw = mount_dir.to_string_lossy();
        let is_drive_letter = raw.len() == 2 && raw.as_bytes()[1] == b':';
        if !is_drive_letter {
            fs::create_dir_all(mount_dir).map_err(|e| MountError::StaleCleanupFailed {
                mount_dir: mount_dir.to_path_buf(),
                reason: e.to_string(),
            })?;
        }
        Ok(())
    }

    fn mount(
        &self,
        mount_dir: &Path,
        vfs: Arc<dyn VfsOperations>,
    ) -> Result<Box<dyn VfsMountHandle>, MountError> {
        let cfg = WinFspMountConfig::new(
            mount_dir.to_string_lossy().into_owned(),
            self.owner_sid.as_str(),
        )
        .map_err(|e| MountError::MountFailed {
            mount_dir: mount_dir.to_path_buf(),
            reason: e.to_string(),
        })?;
        let dispatcher = Arc::new(WinFspDispatcher::new(vfs, cfg));
        dispatcher
            .start()
            .map_err(|status| MountError::MountFailed {
                mount_dir: mount_dir.to_path_buf(),
                reason: format!("WinFspDispatcher::start failed with {status}"),
            })?;

        if self.require_kernel_driver {
            let _ = dispatcher.stop();
            return Err(MountError::MountFailed {
                mount_dir: mount_dir.to_path_buf(),
                reason: "WinFsp kernel driver host is not available in this process".to_owned(),
            });
        }

        Ok(Box::new(DaemonWinFspHandle {
            dispatcher,
            mount_dir: mount_dir.to_path_buf(),
        }))
    }
}

// ---------------------------------------------------------------------------
// 4. Auto platform selector with graceful sandbox/headless fallback
// ---------------------------------------------------------------------------

/// Tries the host OS's primary [`VfsMountBackend`] (`FuseMountBackend` on Linux,
/// `NfsMountBackend` on macOS, `WinFspMountBackend` on Windows), falling back cleanly to
/// [`NoopMountBackend`] when running in a sandboxed or unprivileged headless process.
pub struct AutoMountBackend {
    primary: Box<dyn VfsMountBackend>,
    fallback: NoopMountBackend,
}

impl AutoMountBackend {
    /// Selects the native OS primary adapter paired with `NoopMountBackend` fallback.
    pub fn platform_default() -> Self {
        #[cfg(target_os = "linux")]
        let primary: Box<dyn VfsMountBackend> = Box::new(FuseMountBackend::new());
        #[cfg(target_os = "macos")]
        let primary: Box<dyn VfsMountBackend> = Box::new(NfsMountBackend::new());
        #[cfg(target_os = "windows")]
        let primary: Box<dyn VfsMountBackend> = Box::new(WinFspMountBackend::default());
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let primary: Box<dyn VfsMountBackend> = Box::new(NoopMountBackend::new());

        Self {
            primary,
            fallback: NoopMountBackend::new(),
        }
    }
}

impl VfsMountBackend for AutoMountBackend {
    fn name(&self) -> &'static str {
        self.primary.name()
    }

    fn cleanup_stale_mount(&self, mount_dir: &Path) -> Result<(), MountError> {
        if self.primary.cleanup_stale_mount(mount_dir).is_err() {
            self.fallback.cleanup_stale_mount(mount_dir)?;
        }
        Ok(())
    }

    fn mount(
        &self,
        mount_dir: &Path,
        vfs: Arc<dyn VfsOperations>,
    ) -> Result<Box<dyn VfsMountHandle>, MountError> {
        match self.primary.mount(mount_dir, Arc::clone(&vfs)) {
            Ok(handle) => Ok(handle),
            Err(_) => self.fallback.mount(mount_dir, vfs),
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Headless / test `NoopMountBackend` & OS stale-mount helper
// ---------------------------------------------------------------------------

/// Best-effort OS stale-mount cleanup helper for `mount_dir`.
pub fn cleanup_stale_os_mount(mount_dir: &Path) -> Result<(), MountError> {
    #[cfg(target_os = "linux")]
    {
        FuseMountBackend::new().cleanup_stale_mount(mount_dir)
    }
    #[cfg(target_os = "macos")]
    {
        NfsMountBackend::new().cleanup_stale_mount(mount_dir)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        fs::create_dir_all(mount_dir).map_err(|e| MountError::StaleCleanupFailed {
            mount_dir: mount_dir.to_path_buf(),
            reason: e.to_string(),
        })
    }
}

/// Telemetry counters shared with [`NoopMountBackend`] for deterministic lifecycle tests.
#[derive(Debug, Default)]
pub struct NoopMountCounters {
    pub cleanup_calls: AtomicUsize,
    pub mount_calls: AtomicUsize,
    pub unmount_calls: AtomicUsize,
    pub currently_mounted: AtomicBool,
}

/// Headless / test [`VfsMountBackend`] that ensures `mount_dir` exists on disk and tracks
/// lifecycle calls without invoking kernel mount syscalls.
#[derive(Debug, Clone, Default)]
pub struct NoopMountBackend {
    counters: Arc<NoopMountCounters>,
    run_os_stale_check: bool,
}

impl NoopMountBackend {
    /// Creates a new `NoopMountBackend`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables [`cleanup_stale_os_mount`] during `cleanup_stale_mount`.
    pub fn with_os_stale_check(mut self) -> Self {
        self.run_os_stale_check = true;
        self
    }

    /// Returns shared lifecycle counters for assertions in tests.
    pub fn counters(&self) -> Arc<NoopMountCounters> {
        Arc::clone(&self.counters)
    }
}

struct NoopMountHandle {
    mount_dir: PathBuf,
    _vfs: Arc<dyn VfsOperations>,
    counters: Arc<NoopMountCounters>,
    unmounted: bool,
}

impl VfsMountHandle for NoopMountHandle {
    fn mount_dir(&self) -> &Path {
        &self.mount_dir
    }

    fn backend_name(&self) -> &'static str {
        "noop"
    }

    fn unmount(mut self: Box<Self>) -> Result<(), MountError> {
        self.unmounted = true;
        self.counters.unmount_calls.fetch_add(1, Ordering::SeqCst);
        self.counters
            .currently_mounted
            .store(false, Ordering::SeqCst);
        Ok(())
    }
}

impl Drop for NoopMountHandle {
    fn drop(&mut self) {
        if !self.unmounted {
            self.counters.unmount_calls.fetch_add(1, Ordering::SeqCst);
            self.counters
                .currently_mounted
                .store(false, Ordering::SeqCst);
        }
    }
}

impl VfsMountBackend for NoopMountBackend {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn cleanup_stale_mount(&self, mount_dir: &Path) -> Result<(), MountError> {
        self.counters.cleanup_calls.fetch_add(1, Ordering::SeqCst);
        if self.run_os_stale_check {
            cleanup_stale_os_mount(mount_dir)
        } else {
            fs::create_dir_all(mount_dir).map_err(|e| MountError::StaleCleanupFailed {
                mount_dir: mount_dir.to_path_buf(),
                reason: e.to_string(),
            })
        }
    }

    fn mount(
        &self,
        mount_dir: &Path,
        vfs: Arc<dyn VfsOperations>,
    ) -> Result<Box<dyn VfsMountHandle>, MountError> {
        fs::create_dir_all(mount_dir).map_err(|e| MountError::MountFailed {
            mount_dir: mount_dir.to_path_buf(),
            reason: e.to_string(),
        })?;
        self.counters.mount_calls.fetch_add(1, Ordering::SeqCst);
        self.counters
            .currently_mounted
            .store(true, Ordering::SeqCst);
        Ok(Box::new(NoopMountHandle {
            mount_dir: mount_dir.to_path_buf(),
            _vfs: vfs,
            counters: Arc::clone(&self.counters),
            unmounted: false,
        }))
    }
}

#[cfg(unix)]
fn detect_unix_owner_ids(mount_dir: &Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    if let Ok(meta) = fs::metadata("/proc/self") {
        return (meta.uid(), meta.gid());
    }
    if let Ok(meta) = fs::metadata(mount_dir) {
        return (meta.uid(), meta.gid());
    }
    (0, 0)
}

#[cfg(not(unix))]
fn detect_unix_owner_ids(_mount_dir: &Path) -> (u32, u32) {
    (0, 0)
}
