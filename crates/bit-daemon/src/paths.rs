//! Per-user directory and IPC endpoint layout (`UserPaths`).

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use bit_core::ViewId;
use bit_ipc::IpcEndpoint;

/// Process variable overriding the default `~/.bit` root directory.
pub const BIT_HOME_VAR: &str = "BIT_HOME";

/// Process variable overriding the default `<bit_home>/views` VFS mount directory.
pub const BIT_MOUNT_DIR_VAR: &str = "BIT_MOUNT_DIR";

/// Optional process variable overriding the default `<bit_home>/daemon.sock` IPC endpoint path.
pub const BIT_IPC_ENDPOINT_VAR: &str = "BIT_IPC_ENDPOINT";

/// Error returned when resolving or initializing [`UserPaths`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathLayoutError {
    /// Home directory could not be determined when `BIT_HOME` was unset.
    MissingHomeDir,
    /// Configured path variable was empty.
    EmptyPath(&'static str),
    /// Creating required directories failed.
    Io(String),
}

impl fmt::Display for PathLayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHomeDir => {
                f.write_str("could not determine user home directory (set BIT_HOME explicitly)")
            }
            Self::EmptyPath(var) => write!(f, "{var} must not be empty"),
            Self::Io(msg) => write!(f, "failed to initialize daemon directories: {msg}"),
        }
    }
}

impl std::error::Error for PathLayoutError {}

/// Per-user host filesystem layout for `bit-daemon` and `bit-cli`.
///
/// Defaults:
/// - `bit_home`: `~/.bit` (overridable via `BIT_HOME`)
/// - `mount_dir`: `~/.bit/views` (space-free default; overridable via `BIT_MOUNT_DIR`)
/// - `store_dir`: `~/.bit/store`
/// - `ipc_endpoint`: `~/.bit/daemon.sock` (overridable via `BIT_IPC_ENDPOINT`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPaths {
    bit_home: PathBuf,
    mount_dir: PathBuf,
    store_dir: PathBuf,
    ipc_endpoint: PathBuf,
}

impl UserPaths {
    /// Constructs explicit `UserPaths`.
    pub fn new(
        bit_home: PathBuf,
        mount_dir: PathBuf,
        store_dir: PathBuf,
        ipc_endpoint: PathBuf,
    ) -> Self {
        Self {
            bit_home,
            mount_dir,
            store_dir,
            ipc_endpoint,
        }
    }

    /// Derives default layout rooted at `bit_home` (`<bit_home>/views`, `<bit_home>/store`,
    /// `<bit_home>/daemon.sock`).
    pub fn with_home(bit_home: impl Into<PathBuf>) -> Self {
        let bit_home = bit_home.into();
        let mount_dir = bit_home.join("views");
        let store_dir = bit_home.join("store");
        let ipc_endpoint = bit_home.join("daemon.sock");
        Self {
            bit_home,
            mount_dir,
            store_dir,
            ipc_endpoint,
        }
    }

    /// Resolves `UserPaths` from the current process variables (`BIT_HOME`, `BIT_MOUNT_DIR`,
    /// `BIT_IPC_ENDPOINT`, falling back to `HOME` / `USERPROFILE`).
    pub fn from_env() -> Result<Self, PathLayoutError> {
        let bit_home = std::env::var_os(BIT_HOME_VAR);
        let bit_mount = std::env::var_os(BIT_MOUNT_DIR_VAR);
        let bit_ipc = std::env::var_os(BIT_IPC_ENDPOINT_VAR);
        let user_home = detect_user_home();
        Self::from_values(
            bit_home.as_deref(),
            bit_mount.as_deref(),
            bit_ipc.as_deref(),
            user_home.as_deref(),
        )
    }

    /// Pure deterministic constructor from explicit variable values for unit testing.
    pub fn from_values(
        bit_home: Option<&OsStr>,
        bit_mount_dir: Option<&OsStr>,
        bit_ipc_endpoint: Option<&OsStr>,
        user_home: Option<&OsStr>,
    ) -> Result<Self, PathLayoutError> {
        let resolved_home = match bit_home {
            Some(val) if val.is_empty() => return Err(PathLayoutError::EmptyPath(BIT_HOME_VAR)),
            Some(val) => PathBuf::from(val),
            None => {
                let Some(home) = user_home.filter(|h| !h.is_empty()) else {
                    return Err(PathLayoutError::MissingHomeDir);
                };
                PathBuf::from(home).join(".bit")
            }
        };

        let mount_dir = match bit_mount_dir {
            Some(val) if val.is_empty() => {
                return Err(PathLayoutError::EmptyPath(BIT_MOUNT_DIR_VAR))
            }
            Some(val) => PathBuf::from(val),
            None => resolved_home.join("views"),
        };

        let ipc_endpoint = match bit_ipc_endpoint {
            Some(val) if val.is_empty() => {
                return Err(PathLayoutError::EmptyPath(BIT_IPC_ENDPOINT_VAR))
            }
            Some(val) => PathBuf::from(val),
            None => resolved_home.join("daemon.sock"),
        };

        let store_dir = resolved_home.join("store");

        Ok(Self {
            bit_home: resolved_home,
            mount_dir,
            store_dir,
            ipc_endpoint,
        })
    }

    /// Root Bit directory (`~/.bit` by default).
    pub fn bit_home(&self) -> &Path {
        &self.bit_home
    }

    /// Single-mount userspace VFS directory (`~/.bit/views` by default).
    pub fn mount_dir(&self) -> &Path {
        &self.mount_dir
    }

    /// Internal content-addressed and metadata store directory (`~/.bit/store` by default).
    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    /// Local IPC endpoint path (`~/.bit/daemon.sock` by default).
    pub fn ipc_endpoint(&self) -> &Path {
        &self.ipc_endpoint
    }

    /// Returns the typed [`IpcEndpoint`] for this user layout.
    pub fn endpoint(&self) -> IpcEndpoint {
        IpcEndpoint::new(&self.ipc_endpoint)
    }

    /// Computes the mounted directory path `<mount_dir>/<view_id>` for `view_id`.
    pub fn view_mount_path(&self, view_id: &ViewId) -> PathBuf {
        self.mount_dir.join(view_id.as_str())
    }

    /// Returns `true` if `mount_dir` contains no ASCII whitespace characters (ensuring
    /// space-intolerant build scripts can operate safely under `<mount_dir>/<view-id>`).
    pub fn is_mount_dir_space_free(&self) -> bool {
        !self
            .mount_dir
            .to_string_lossy()
            .chars()
            .any(|c| c.is_ascii_whitespace())
    }

    /// Creates `bit_home`, `mount_dir`, `store_dir`, and parent directory of `ipc_endpoint`.
    pub fn ensure_directories(&self) -> Result<(), PathLayoutError> {
        for dir in [&self.bit_home, &self.mount_dir, &self.store_dir] {
            fs::create_dir_all(dir)
                .map_err(|e| PathLayoutError::Io(format!("{}: {e}", dir.display())))?;
        }
        if let Some(parent) = self.ipc_endpoint.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| PathLayoutError::Io(format!("{}: {e}", parent.display())))?;
            }
        }
        Ok(())
    }
}

fn detect_user_home() -> Option<OsString> {
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Some(home);
    }
    if let Some(profile) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        return Some(profile);
    }
    let drive = std::env::var_os("HOMEDRIVE")?;
    let path = std::env::var_os("HOMEPATH")?;
    if drive.is_empty() || path.is_empty() {
        return None;
    }
    let mut combined = drive;
    combined.push(path);
    Some(combined)
}
