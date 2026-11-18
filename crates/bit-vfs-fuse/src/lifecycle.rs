//! `/proc/mounts` stale FUSE mount inspection, unprivileged lazy-unmount command builders
//! (`fusermount3 -uz` / `fusermount -uz`), and cross-platform mount lifecycle hooks.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crate::config::{FuseConfigError, FuseMountConfig};
use crate::dispatch::{FuseDispatcher, FuseSession};
use crate::protocol::{EIO, ENOTCONN};

/// Default Linux kernel mount table path.
pub const PROC_MOUNTS_PATH: &str = "/proc/mounts";

/// Linux `/dev/fuse` character device path.
pub const DEV_FUSE_PATH: &str = "/dev/fuse";

/// Unprivileged FUSE helper binary selection (ADR-0004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FusermountBinary {
    /// Preferred FUSE 3 helper (`fusermount3`).
    Fusermount3,
    /// Fallback FUSE 2 helper (`fusermount`).
    Fusermount,
}

impl FusermountBinary {
    /// Preference order when attempting lazy unmount recovery.
    pub const CANDIDATES: [Self; 2] = [Self::Fusermount3, Self::Fusermount];

    /// Executable binary name resolved via `PATH`.
    pub const fn program_name(self) -> &'static str {
        match self {
            Self::Fusermount3 => "fusermount3",
            Self::Fusermount => "fusermount",
        }
    }
}

impl fmt::Display for FusermountBinary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.program_name())
    }
}

/// Parsed single line from `/proc/mounts` (`<fs_spec> <fs_file> <fs_vfstype> <fs_mntops> ...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcMountEntry {
    /// Mount device / `fsname` field (field 1, e.g. `"bit"` or `"/dev/fuse"`).
    pub fs_spec: String,
    /// Unescaped mount point path (field 2, e.g. `"/home/alice/.bit/views"`).
    pub mount_point: PathBuf,
    /// Filesystem type (field 3, e.g. `"fuse.bit"` or `"fuse"`).
    pub fs_type: String,
    /// Comma-separated mount options (field 4).
    pub mount_options: Vec<String>,
}

impl ProcMountEntry {
    /// Returns `true` when `fs_type` is a FUSE mount (`fuse`, `fuseblk`, or `fuse.<subtype>`).
    pub fn is_fuse(&self) -> bool {
        self.fs_type == "fuse" || self.fs_type == "fuseblk" || self.fs_type.starts_with("fuse.")
    }

    /// Returns `true` when this FUSE mount carries Bit's `fsname=bit` / `fuse.bit` identity.
    pub fn is_bit_fuse(&self) -> bool {
        self.is_fuse()
            && (self.fs_spec == "bit"
                || self.fs_type == "fuse.bit"
                || self
                    .mount_options
                    .iter()
                    .any(|opt| opt == "fsname=bit" || opt == "subtype=bit"))
    }
}

/// Observed state of `mount_path` during startup or health checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum MountState {
    /// No FUSE mount is registered at `mount_path`.
    #[default]
    NotMounted,
    /// A FUSE mount is registered at `mount_path` and responds to metadata probes.
    ActiveFuseMount(ProcMountEntry),
    /// A stale/disconnected FUSE mount is present at `mount_path` (e.g. `ENOTCONN` after an
    /// unclean daemon exit) and requires lazy unmount cleanup.
    StaleFuseMount {
        entry: Option<ProcMountEntry>,
        probe_errno: Option<i32>,
    },
}

impl MountState {
    /// Returns `true` for both [`Self::ActiveFuseMount`] and [`Self::StaleFuseMount`].
    pub const fn is_mounted(&self) -> bool {
        !matches!(self, Self::NotMounted)
    }

    /// Returns `true` when the mount is a broken/stale FUSE endpoint.
    pub const fn is_stale(&self) -> bool {
        matches!(self, Self::StaleFuseMount { .. })
    }

    /// Returns `true` if startup cleanup should run `fusermount3 -uz` on this path.
    pub const fn needs_lazy_unmount(&self, detach_active_orphan: bool) -> bool {
        match self {
            Self::NotMounted => false,
            Self::StaleFuseMount { .. } => true,
            Self::ActiveFuseMount(_) => detach_active_orphan,
        }
    }
}

/// Unprivileged lazy-unmount command specification (`fusermount3 -uz <mount_path>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LazyUnmountSpec {
    pub binary: FusermountBinary,
    pub args: Vec<OsString>,
}

impl LazyUnmountSpec {
    /// Converts this specification into a [`std::process::Command`].
    pub fn to_command(&self) -> Command {
        let mut cmd = Command::new(self.binary.program_name());
        cmd.args(&self.args);
        cmd
    }
}

/// Builds a [`LazyUnmountSpec`] (`<binary> -uz <mount_path>`).
pub fn build_lazy_unmount_spec(binary: FusermountBinary, mount_path: &Path) -> LazyUnmountSpec {
    LazyUnmountSpec {
        binary,
        args: vec![OsString::from("-uz"), mount_path.as_os_str().to_owned()],
    }
}

/// Builds an unprivileged lazy-unmount [`Command`] (`fusermount3 -uz <mount_path>` or
/// `fusermount -uz <mount_path>`).
pub fn build_lazy_unmount_command(binary: FusermountBinary, mount_path: &Path) -> Command {
    build_lazy_unmount_spec(binary, mount_path).to_command()
}

/// Builds an unprivileged mount [`Command`] (`<binary> -o fsname=bit,... <mount_path>`),
/// validating `config` first (rejecting `allow_other` and whitespace paths).
pub fn build_fusermount_mount_command(
    binary: FusermountBinary,
    config: &FuseMountConfig,
) -> Result<Command, FuseConfigError> {
    let options = config.to_mount_options_string()?;
    let mut cmd = Command::new(binary.program_name());
    cmd.arg("-o").arg(options).arg(&config.mount_path);
    Ok(cmd)
}

/// Decodes octal escape sequences (`\040`, `\011`, `\012`, `\134`, etc.) used by Linux
/// `/proc/mounts` (`seq_path`).
pub fn unescape_proc_mount_field(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let d0 = bytes[i + 1];
            let d1 = bytes[i + 2];
            let d2 = bytes[i + 3];
            if (b'0'..=b'3').contains(&d0)
                && (b'0'..=b'7').contains(&d1)
                && (b'0'..=b'7').contains(&d2)
            {
                let val = ((d0 - b'0') << 6) | ((d1 - b'0') << 3) | (d2 - b'0');
                out.push(val);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn normalize_mount_comparison_key(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if raw == "/" {
        return "/".to_owned();
    }
    raw.trim_end_matches('/').to_owned()
}

/// Parses `/proc/mounts` text into structured [`ProcMountEntry`] records.
pub fn parse_proc_mounts(contents: &str) -> Vec<ProcMountEntry> {
    let mut entries = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split_ascii_whitespace();
        let (Some(raw_spec), Some(raw_point), Some(fs_type), Some(raw_opts)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let fs_spec = unescape_proc_mount_field(raw_spec);
        let mount_point = PathBuf::from(unescape_proc_mount_field(raw_point));
        let mount_options = raw_opts
            .split(',')
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        entries.push(ProcMountEntry {
            fs_spec,
            mount_point,
            fs_type: fs_type.to_owned(),
            mount_options,
        });
    }
    entries
}

/// Finds the latest FUSE mount entry in `/proc/mounts` text matching `mount_path`.
pub fn find_fuse_mount(proc_mounts_contents: &str, mount_path: &Path) -> Option<ProcMountEntry> {
    let target_key = normalize_mount_comparison_key(mount_path);
    parse_proc_mounts(proc_mounts_contents)
        .into_iter()
        .rev()
        .find(|entry| {
            entry.is_fuse() && normalize_mount_comparison_key(&entry.mount_point) == target_key
        })
}

/// Classifies the FUSE mount state at `mount_path` from `/proc/mounts` text and an optional
/// metadata `stat` probe `errno` (`Some(ENOTCONN)` when the FUSE endpoint is dead).
pub fn classify_mount_state(
    proc_mounts_contents: &str,
    mount_path: &Path,
    probe_errno: Option<i32>,
) -> MountState {
    let found = find_fuse_mount(proc_mounts_contents, mount_path);
    if probe_errno == Some(ENOTCONN) {
        return MountState::StaleFuseMount {
            entry: found,
            probe_errno,
        };
    }
    match found {
        Some(entry) => match probe_errno {
            Some(errno) => MountState::StaleFuseMount {
                entry: Some(entry),
                probe_errno: Some(errno),
            },
            None => MountState::ActiveFuseMount(entry),
        },
        None => MountState::NotMounted,
    }
}

/// Errors emitted during FUSE mount inspection, stale-mount recovery, or unmount lifecycle hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuseLifecycleError {
    /// Invalid [`FuseMountConfig`].
    Config(FuseConfigError),
    /// Another healthy FUSE mount is already active at `mount_path`.
    MountAlreadyActive(PathBuf),
    /// Neither `fusermount3` nor `fusermount` could be found in `PATH`.
    FusermountUnavailable,
    /// `fusermount3 -uz` / `fusermount -uz` exited with a non-zero status.
    UnmountFailed {
        binary: FusermountBinary,
        mount_path: PathBuf,
        detail: String,
    },
    /// Live Linux FUSE kernel mount lifecycle was invoked on a non-Linux target OS.
    UnsupportedPlatform(&'static str),
    /// Host filesystem or `/proc/mounts` I/O failure.
    Io(String),
}

impl fmt::Display for FuseLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => fmt::Display::fmt(err, f),
            Self::MountAlreadyActive(path) => {
                write!(f, "FUSE mount is already active at {}", path.display())
            }
            Self::FusermountUnavailable => {
                f.write_str("neither 'fusermount3' nor 'fusermount' was found in PATH")
            }
            Self::UnmountFailed {
                binary,
                mount_path,
                detail,
            } => write!(f, "{binary} -uz {} failed: {detail}", mount_path.display()),
            Self::UnsupportedPlatform(os) => {
                write!(f, "Linux FUSE kernel mount is not supported on {os}")
            }
            Self::Io(msg) => write!(f, "FUSE lifecycle I/O error: {msg}"),
        }
    }
}

impl std::error::Error for FuseLifecycleError {}

impl From<FuseConfigError> for FuseLifecycleError {
    fn from(err: FuseConfigError) -> Self {
        Self::Config(err)
    }
}

/// Cross-platform FUSE mount inspection and lifecycle port (usable on all OSes in daemon code
/// and unit tests, with Linux `/proc/mounts` + `fusermount3` hooks in [`SystemFuseMountLifecycle`]).
pub trait FuseMountLifecycle: Send + Sync {
    /// Inspects whether `mount_path` is unmounted, an active FUSE mount, or a stale FUSE mount.
    fn inspect_mount(&self, mount_path: &Path) -> Result<MountState, FuseLifecycleError>;

    /// Detaches `mount_path` via unprivileged lazy unmount (`fusermount3 -uz` / `fusermount -uz`).
    fn lazy_unmount(&self, mount_path: &Path) -> Result<FusermountBinary, FuseLifecycleError>;

    /// Recovers a stale (or optionally orphaned active) FUSE mount at `mount_path`, returning
    /// `Ok(true)` if a lazy unmount was performed or `Ok(false)` if nothing was mounted.
    fn recover_stale_mount(
        &self,
        mount_path: &Path,
        detach_active_orphan: bool,
    ) -> Result<bool, FuseLifecycleError> {
        let state = self.inspect_mount(mount_path)?;
        match state {
            MountState::NotMounted => Ok(false),
            MountState::StaleFuseMount { .. } => {
                let _ = self.lazy_unmount(mount_path)?;
                Ok(true)
            }
            MountState::ActiveFuseMount(_) => {
                if detach_active_orphan {
                    let _ = self.lazy_unmount(mount_path)?;
                    Ok(true)
                } else {
                    Err(FuseLifecycleError::MountAlreadyActive(
                        mount_path.to_path_buf(),
                    ))
                }
            }
        }
    }

    /// Validates `config`, cleans up any stale mount at `config.mount_path`, and ensures the
    /// mount directory exists on disk.
    fn prepare_mount_point(
        &self,
        config: &FuseMountConfig,
        detach_active_orphan: bool,
    ) -> Result<PathBuf, FuseLifecycleError> {
        config.validate()?;
        let _ = self.recover_stale_mount(&config.mount_path, detach_active_orphan)?;
        fs::create_dir_all(&config.mount_path).map_err(|e| {
            FuseLifecycleError::Io(format!(
                "failed to create mount directory {}: {e}",
                config.mount_path.display()
            ))
        })?;
        Ok(config.mount_path.clone())
    }
}

/// Host OS implementation of [`FuseMountLifecycle`].
///
/// - On `target_os = "linux"`, reads `/proc/mounts`, probes `stat` for `ENOTCONN`, and executes
///   `fusermount3 -uz` (with fallback to `fusermount -uz`).
/// - On non-Linux targets, compiles cleanly and reports `NotMounted` / `UnsupportedPlatform`.
#[derive(Debug, Clone)]
pub struct SystemFuseMountLifecycle {
    proc_mounts_path: PathBuf,
}

impl Default for SystemFuseMountLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemFuseMountLifecycle {
    /// Constructs a `SystemFuseMountLifecycle` reading `/proc/mounts`.
    pub fn new() -> Self {
        Self {
            proc_mounts_path: PathBuf::from(PROC_MOUNTS_PATH),
        }
    }

    /// Overrides the mount-table file path (e.g. for hermetic integration tests).
    pub fn with_proc_mounts_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.proc_mounts_path = path.into();
        self
    }

    /// Inspects a mount table file on disk together with a live `fs::metadata` probe.
    pub fn inspect_from_proc_file(
        &self,
        mount_path: &Path,
    ) -> Result<MountState, FuseLifecycleError> {
        let contents = fs::read_to_string(&self.proc_mounts_path).map_err(|e| {
            FuseLifecycleError::Io(format!(
                "failed to read {}: {e}",
                self.proc_mounts_path.display()
            ))
        })?;
        let has_entry = find_fuse_mount(&contents, mount_path).is_some();
        let probe_errno = match fs::metadata(mount_path) {
            Ok(_) => None,
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound && !has_entry {
                    None
                } else {
                    Some(err.raw_os_error().unwrap_or(EIO))
                }
            }
        };
        Ok(classify_mount_state(&contents, mount_path, probe_errno))
    }

    /// Opens `/dev/fuse` with read+write permissions on Linux.
    #[cfg(target_os = "linux")]
    pub fn open_dev_fuse() -> io::Result<fs::File> {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEV_FUSE_PATH)
    }
}

#[cfg(target_os = "linux")]
impl FuseMountLifecycle for SystemFuseMountLifecycle {
    fn inspect_mount(&self, mount_path: &Path) -> Result<MountState, FuseLifecycleError> {
        self.inspect_from_proc_file(mount_path)
    }

    fn lazy_unmount(&self, mount_path: &Path) -> Result<FusermountBinary, FuseLifecycleError> {
        for candidate in FusermountBinary::CANDIDATES {
            let mut cmd = build_lazy_unmount_command(candidate, mount_path);
            match cmd.output() {
                Ok(output) if output.status.success() => return Ok(candidate),
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                    let detail = if stderr.is_empty() {
                        format!("exit status {}", output.status)
                    } else {
                        stderr
                    };
                    return Err(FuseLifecycleError::UnmountFailed {
                        binary: candidate,
                        mount_path: mount_path.to_path_buf(),
                        detail,
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(FuseLifecycleError::Io(format!(
                        "failed to spawn {candidate}: {err}"
                    )));
                }
            }
        }
        Err(FuseLifecycleError::FusermountUnavailable)
    }
}

#[cfg(not(target_os = "linux"))]
impl FuseMountLifecycle for SystemFuseMountLifecycle {
    fn inspect_mount(&self, _mount_path: &Path) -> Result<MountState, FuseLifecycleError> {
        Ok(MountState::NotMounted)
    }

    fn lazy_unmount(&self, _mount_path: &Path) -> Result<FusermountBinary, FuseLifecycleError> {
        Err(FuseLifecycleError::UnsupportedPlatform(
            std::env::consts::OS,
        ))
    }
}

/// Active mount handle coordinating a background [`FuseSession`] worker and lazy unmount on shutdown.
pub struct FuseMountHandle {
    mount_path: PathBuf,
    session: FuseSession,
    lifecycle: Arc<dyn FuseMountLifecycle>,
    worker: Option<JoinHandle<io::Result<usize>>>,
    unmounted: bool,
}

impl fmt::Debug for FuseMountHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FuseMountHandle")
            .field("mount_path", &self.mount_path)
            .field("stopped", &self.session.is_stopped())
            .field("unmounted", &self.unmounted)
            .finish_non_exhaustive()
    }
}

impl FuseMountHandle {
    /// Spawns a background packet-device session (`serve_fuse_device`) paired with `lifecycle`.
    pub fn spawn_device<D>(
        dispatcher: Arc<FuseDispatcher>,
        mut device: D,
        lifecycle: Arc<dyn FuseMountLifecycle>,
    ) -> io::Result<Self>
    where
        D: Read + Write + Send + 'static,
    {
        let mount_path = dispatcher.config().mount_path.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let session = FuseSession::with_stop_flag(dispatcher, stop_flag);
        let worker_session = session.clone();
        let worker = thread::Builder::new()
            .name("bit-vfs-fuse".to_owned())
            .spawn(move || worker_session.serve_fuse_device(&mut device))?;
        Ok(Self {
            mount_path,
            session,
            lifecycle,
            worker: Some(worker),
            unmounted: false,
        })
    }

    /// Returns the mounted host directory path.
    pub fn mount_path(&self) -> &Path {
        &self.mount_path
    }

    /// Borrows the underlying [`FuseSession`].
    pub const fn session(&self) -> &FuseSession {
        &self.session
    }

    /// Signals the session to stop, invokes lazy unmount via `lifecycle`, and joins the worker thread.
    pub fn shutdown(&mut self) -> Result<usize, FuseLifecycleError> {
        self.session.request_stop();
        if !self.unmounted {
            self.unmounted = true;
            match self.lifecycle.inspect_mount(&self.mount_path)? {
                MountState::NotMounted => {}
                MountState::ActiveFuseMount(_) | MountState::StaleFuseMount { .. } => {
                    let _ = self.lifecycle.lazy_unmount(&self.mount_path)?;
                }
            }
        }
        if let Some(handle) = self.worker.take() {
            let count = handle
                .join()
                .map_err(|_| FuseLifecycleError::Io("FUSE session worker panicked".to_owned()))?
                .map_err(|e| FuseLifecycleError::Io(e.to_string()))?;
            return Ok(count);
        }
        Ok(0)
    }
}

impl Drop for FuseMountHandle {
    fn drop(&mut self) {
        self.session.request_stop();
        if !self.unmounted {
            self.unmounted = true;
            if let Ok(state) = self.lifecycle.inspect_mount(&self.mount_path) {
                if state.is_mounted() {
                    let _ = self.lifecycle.lazy_unmount(&self.mount_path);
                }
            }
        }
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}
