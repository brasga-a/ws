//! Local IPC client with on-demand background daemon auto-start.

use std::fmt;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use bit_daemon::{UserPaths, BIT_HOME_VAR, BIT_IPC_ENDPOINT_VAR, BIT_MOUNT_DIR_VAR};
use bit_ipc::{IpcError, IpcRequest, IpcResponse, LocalClient, RemoteError};

/// Default readiness timeout when waiting for an auto-started background daemon.
pub const DEFAULT_AUTOSTART_TIMEOUT: Duration = Duration::from_secs(5);

/// Error returned while communicating with or auto-starting `bit-daemon`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// Spawning `<bit> daemon run` failed.
    AutoStartFailed(String),
    /// Auto-started daemon did not begin accepting IPC connections before timeout.
    AutoStartTimeout(Duration),
    /// IPC transport or framing error.
    Ipc(IpcError),
    /// Remote domain/daemon error returned inside `IpcResponse::Error`.
    Remote(RemoteError),
    /// Daemon returned an unexpected response variant for the sent request.
    UnexpectedResponse(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AutoStartFailed(msg) => write!(f, "failed to auto-start daemon: {msg}"),
            Self::AutoStartTimeout(dur) => {
                write!(
                    f,
                    "timed out after {dur:?} waiting for daemon to become ready"
                )
            }
            Self::Ipc(err) => fmt::Display::fmt(err, f),
            Self::Remote(err) => fmt::Display::fmt(err, f),
            Self::UnexpectedResponse(msg) => write!(f, "unexpected daemon response: {msg}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<IpcError> for ClientError {
    fn from(err: IpcError) -> Self {
        Self::Ipc(err)
    }
}

impl From<RemoteError> for ClientError {
    fn from(err: RemoteError) -> Self {
        Self::Remote(err)
    }
}

/// Pluggable launcher responsible for spawning `bit daemon run` when the daemon is not running.
pub trait DaemonLauncher: Send + Sync {
    /// Spawns a detached background daemon configured with `paths`.
    fn launch(&self, paths: &UserPaths) -> Result<(), String>;
}

/// Production [`DaemonLauncher`] invoking `<exe> daemon run` in the background.
#[derive(Debug, Clone)]
pub struct ExecutableDaemonLauncher {
    executable: Option<PathBuf>,
}

impl Default for ExecutableDaemonLauncher {
    fn default() -> Self {
        Self::current_exe()
    }
}

impl ExecutableDaemonLauncher {
    /// Uses `std::env::current_exe()` resolved at launch time.
    pub const fn current_exe() -> Self {
        Self { executable: None }
    }

    /// Uses an explicit path to the `bit` binary (convenient for integration tests).
    pub fn with_executable(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: Some(executable.into()),
        }
    }
}

impl DaemonLauncher for ExecutableDaemonLauncher {
    fn launch(&self, paths: &UserPaths) -> Result<(), String> {
        let exe = match &self.executable {
            Some(explicit) => explicit.clone(),
            None => std::env::current_exe()
                .map_err(|e| format!("failed to locate current executable: {e}"))?,
        };
        ProcessCommand::new(&exe)
            .arg("daemon")
            .arg("run")
            .env(BIT_HOME_VAR, paths.bit_home())
            .env(BIT_MOUNT_DIR_VAR, paths.mount_dir())
            .env(BIT_IPC_ENDPOINT_VAR, paths.ipc_endpoint())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|_child| ())
            .map_err(|e| format!("failed to spawn '{} daemon run': {e}", exe.display()))
    }
}

/// IPC client wrapper used by `bit-cli`.
#[derive(Clone)]
pub struct CliClient {
    paths: UserPaths,
    launcher: Arc<dyn DaemonLauncher>,
    autostart_timeout: Duration,
}

impl CliClient {
    /// Creates a `CliClient` using `ExecutableDaemonLauncher::current_exe()`.
    pub fn new(paths: UserPaths) -> Self {
        Self {
            paths,
            launcher: Arc::new(ExecutableDaemonLauncher::current_exe()),
            autostart_timeout: DEFAULT_AUTOSTART_TIMEOUT,
        }
    }

    /// Overrides the background [`DaemonLauncher`].
    pub fn with_launcher(mut self, launcher: Arc<dyn DaemonLauncher>) -> Self {
        self.launcher = launcher;
        self
    }

    /// Overrides the readiness timeout for daemon auto-start.
    pub fn with_autostart_timeout(mut self, timeout: Duration) -> Self {
        self.autostart_timeout = timeout;
        self
    }

    /// Borrows `UserPaths`.
    pub const fn paths(&self) -> &UserPaths {
        &self.paths
    }

    /// Connects to the local daemon (auto-starting it in the background if not running) and
    /// executes `req`.
    pub fn send(&self, req: &IpcRequest) -> Result<IpcResponse, ClientError> {
        let mut conn = self.connect_or_autostart()?;
        let resp = conn.send(req)?;
        match resp {
            IpcResponse::Error(err) => Err(ClientError::Remote(err)),
            ok => Ok(ok),
        }
    }

    /// Attempts to send `req` WITHOUT auto-starting the daemon, returning `Ok(None)` if no daemon
    /// is currently listening on the IPC endpoint.
    pub fn try_send_if_running(
        &self,
        req: &IpcRequest,
    ) -> Result<Option<IpcResponse>, ClientError> {
        let endpoint = self.paths.endpoint();
        let mut conn = match LocalClient::connect(&endpoint) {
            Ok(c) => c,
            Err(err) if err.is_daemon_unavailable() => return Ok(None),
            Err(err) => return Err(ClientError::Ipc(err)),
        };
        let resp = conn.send(req)?;
        match resp {
            IpcResponse::Error(err) => Err(ClientError::Remote(err)),
            ok => Ok(Some(ok)),
        }
    }

    /// Waits briefly until the daemon stops accepting connections after `Shutdown`.
    pub fn wait_until_stopped(&self, timeout: Duration) {
        let endpoint = self.paths.endpoint();
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match LocalClient::connect(&endpoint) {
                Err(err) if err.is_daemon_unavailable() => break,
                Ok(mut c) => {
                    if c.send(&IpcRequest::Ping).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn connect_or_autostart(&self) -> Result<LocalClient, ClientError> {
        let endpoint = self.paths.endpoint();
        match LocalClient::connect(&endpoint) {
            Ok(mut client) => {
                // Verify connection is alive (handles rare race where previous daemon is mid-exit).
                if matches!(client.send(&IpcRequest::Ping), Ok(IpcResponse::Pong)) {
                    return Ok(client);
                }
            }
            Err(err) if !err.is_daemon_unavailable() => return Err(ClientError::Ipc(err)),
            Err(_) => {}
        }

        self.paths
            .ensure_directories()
            .map_err(|e| ClientError::AutoStartFailed(e.to_string()))?;
        self.launcher
            .launch(&self.paths)
            .map_err(ClientError::AutoStartFailed)?;

        let deadline = Instant::now() + self.autostart_timeout;
        let mut delay = Duration::from_millis(5);
        while Instant::now() < deadline {
            if let Ok(mut client) = LocalClient::connect(&endpoint) {
                if matches!(client.send(&IpcRequest::Ping), Ok(IpcResponse::Pong)) {
                    return Ok(client);
                }
            }
            thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_millis(50));
        }

        Err(ClientError::AutoStartTimeout(self.autostart_timeout))
    }
}
