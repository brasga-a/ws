//! Single-mount FUSE configuration (`FuseMountConfig`) enforcing a stable space-free mount path
//! (`~/.bit/views`), strict single-user access (`allow_other` forbidden), `fsname=bit`, and
//! configurable kernel attribute/entry cache TTLs.

use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default FUSE `fsname` mount option (`fsname=bit`).
pub const DEFAULT_FSNAME: &str = "bit";

/// Default FUSE filesystem subtype (`subtype=bit`, rendered as `fuse.bit` in `/proc/mounts`).
pub const DEFAULT_SUBTYPE: &str = "bit";

/// Default per-user directory components under `$HOME` (`~/.bit/views`).
pub const DEFAULT_HOME_SUBDIRS: [&str; 2] = [".bit", "views"];

/// Default kernel attribute cache TTL (`1s`).
pub const DEFAULT_ATTR_TTL: Duration = Duration::from_secs(1);

/// Default kernel directory-entry (`dentry`) cache TTL inside a `View` (`1s`).
pub const DEFAULT_ENTRY_TTL: Duration = Duration::from_secs(1);

/// Default kernel `dentry` cache TTL at the `<mount>/` root (`0s` so newly created or removed
/// `Views` become visible immediately without stale root dentries).
pub const DEFAULT_ROOT_ENTRY_TTL: Duration = Duration::ZERO;

/// Default maximum payload size per `FUSE_WRITE` request (`1 MiB`).
pub const DEFAULT_MAX_WRITE: u32 = 1024 * 1024;

/// Minimum allowed `max_write` size (`4 KiB`, one standard page).
pub const MIN_MAX_WRITE: u32 = 4096;

/// Validation error for [`FuseMountConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuseConfigError {
    /// Could not determine user home directory from `HOME` or `USERPROFILE`.
    HomeDirectoryUnavailable,
    /// Mount path was empty.
    EmptyMountPath,
    /// Mount path contained a NUL byte.
    MountPathContainsNul,
    /// Mount path was relative rather than an absolute path.
    RelativeMountPath(PathBuf),
    /// Mount path contained ASCII whitespace, violating the space-free path invariant.
    MountPathContainsWhitespace(PathBuf),
    /// `allow_other` or `allow_root` was requested; Bit mounts are strictly single-user.
    AllowOtherForbidden,
    /// `fsname` was empty or contained invalid characters (`,`, whitespace, or NUL).
    InvalidFsname(String),
    /// `subtype` was empty or contained invalid characters (`,`, whitespace, or NUL).
    InvalidSubtype(String),
    /// Custom mount option token was empty or malformed.
    InvalidMountOption(String),
    /// `max_write` was smaller than [`MIN_MAX_WRITE`].
    InvalidMaxWrite(u32),
}

impl fmt::Display for FuseConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HomeDirectoryUnavailable => {
                f.write_str("could not resolve user home directory for ~/.bit/views")
            }
            Self::EmptyMountPath => f.write_str("FUSE mount path must not be empty"),
            Self::MountPathContainsNul => f.write_str("FUSE mount path must not contain NUL bytes"),
            Self::RelativeMountPath(p) => {
                write!(f, "FUSE mount path must be absolute: {}", p.display())
            }
            Self::MountPathContainsWhitespace(p) => write!(
                f,
                "FUSE mount path must not contain whitespace: {}",
                p.display()
            ),
            Self::AllowOtherForbidden => f.write_str(
                "FUSE mount option 'allow_other'/'allow_root' is forbidden in strict single-user mode",
            ),
            Self::InvalidFsname(name) => write!(f, "invalid FUSE fsname {name:?}"),
            Self::InvalidSubtype(sub) => write!(f, "invalid FUSE subtype {sub:?}"),
            Self::InvalidMountOption(opt) => write!(f, "invalid FUSE mount option {opt:?}"),
            Self::InvalidMaxWrite(sz) => {
                write!(f, "FUSE max_write ({sz}) must be at least {MIN_MAX_WRITE}")
            }
        }
    }
}

impl std::error::Error for FuseConfigError {}

/// Configuration for the single userspace FUSE mount exposing `<mount>/<view-id>/` (ADR-0002, ADR-0004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseMountConfig {
    /// Absolute, space-free host directory where the single VFS mount is attached (`~/.bit/views`).
    pub mount_path: PathBuf,
    /// FUSE `fsname=<name>` identifier (`"bit"` by default).
    pub fsname: String,
    /// Optional FUSE `subtype=<name>` (`Some("bit")` by default -> `fuse.bit` in `/proc/mounts`).
    pub subtype: Option<String>,
    /// Kernel attribute (`FuseAttr`) cache TTL.
    pub attr_ttl: Duration,
    /// Kernel directory-entry (`dentry`) cache TTL for nodes inside a `View`.
    pub entry_ttl: Duration,
    /// Kernel `dentry` cache TTL for direct children of `<mount>/`.
    pub root_entry_ttl: Duration,
    /// Maximum `FUSE_WRITE` payload bytes negotiated during `FUSE_INIT`.
    pub max_write: u32,
    /// Single-user owner UID reported in `FuseAttr`.
    pub uid: u32,
    /// Single-user owner GID reported in `FuseAttr`.
    pub gid: u32,
    /// When set, `FuseDispatcher` rejects incoming FUSE requests whose `header.uid` differs (`EACCES`).
    pub strict_caller_uid: Option<u32>,
    /// Must remain `false`; setting `true` causes [`Self::validate`] to reject with
    /// [`FuseConfigError::AllowOtherForbidden`].
    pub allow_other: bool,
    /// Additional comma-free FUSE mount options (validated against `allow_other` / `allow_root`).
    pub extra_options: Vec<String>,
}

impl FuseMountConfig {
    /// Computes `~/.bit/views` for a given `home` directory path.
    pub fn default_mount_path_for_home(home: impl AsRef<Path>) -> PathBuf {
        let mut path = home.as_ref().to_path_buf();
        for segment in DEFAULT_HOME_SUBDIRS {
            path.push(segment);
        }
        path
    }

    /// Resolves the default mount path (`~/.bit/views`) from `HOME` (falling back to `USERPROFILE`).
    pub fn default_mount_path() -> Result<PathBuf, FuseConfigError> {
        let home = env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .or_else(|| env::var_os("USERPROFILE").filter(|v| !v.is_empty()))
            .ok_or(FuseConfigError::HomeDirectoryUnavailable)?;
        Ok(Self::default_mount_path_for_home(PathBuf::from(home)))
    }

    /// Creates a `FuseMountConfig` rooted at `<home>/.bit/views` and validates it.
    pub fn for_home(home: impl AsRef<Path>) -> Result<Self, FuseConfigError> {
        let cfg = Self::new(Self::default_mount_path_for_home(home));
        cfg.validate()?;
        Ok(cfg)
    }

    /// Creates a default `FuseMountConfig` using [`Self::default_mount_path`] and validates it.
    pub fn try_default() -> Result<Self, FuseConfigError> {
        let cfg = Self::new(Self::default_mount_path()?);
        cfg.validate()?;
        Ok(cfg)
    }

    /// Creates a `FuseMountConfig` at `mount_path` with standard defaults (`fsname=bit`,
    /// single-user mode, `allow_other = false`).
    pub fn new(mount_path: impl Into<PathBuf>) -> Self {
        Self {
            mount_path: mount_path.into(),
            fsname: DEFAULT_FSNAME.to_owned(),
            subtype: Some(DEFAULT_SUBTYPE.to_owned()),
            attr_ttl: DEFAULT_ATTR_TTL,
            entry_ttl: DEFAULT_ENTRY_TTL,
            root_entry_ttl: DEFAULT_ROOT_ENTRY_TTL,
            max_write: DEFAULT_MAX_WRITE,
            uid: 1000,
            gid: 1000,
            strict_caller_uid: None,
            allow_other: false,
            extra_options: Vec::new(),
        }
    }

    /// Sets the `fsname` mount option.
    pub fn with_fsname(mut self, fsname: impl Into<String>) -> Self {
        self.fsname = fsname.into();
        self
    }

    /// Sets or clears the `subtype` mount option.
    pub fn with_subtype(mut self, subtype: Option<String>) -> Self {
        self.subtype = subtype;
        self
    }

    /// Sets the kernel attribute cache TTL.
    pub const fn with_attr_ttl(mut self, ttl: Duration) -> Self {
        self.attr_ttl = ttl;
        self
    }

    /// Sets the kernel entry cache TTL inside `Views`.
    pub const fn with_entry_ttl(mut self, ttl: Duration) -> Self {
        self.entry_ttl = ttl;
        self
    }

    /// Sets the kernel entry cache TTL for direct children of `<mount>/`.
    pub const fn with_root_entry_ttl(mut self, ttl: Duration) -> Self {
        self.root_entry_ttl = ttl;
        self
    }

    /// Sets the maximum `FUSE_WRITE` payload size.
    pub const fn with_max_write(mut self, max_write: u32) -> Self {
        self.max_write = max_write;
        self
    }

    /// Sets the single-user owner `uid` and `gid` reported in `FuseAttr`.
    pub const fn with_owner(mut self, uid: u32, gid: u32) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    /// Enforces that every incoming FUSE request header carries `uid` (`EACCES` otherwise).
    pub const fn with_strict_caller_uid(mut self, uid: u32) -> Self {
        self.strict_caller_uid = Some(uid);
        self
    }

    /// Sets `allow_other` (note: passing `true` will be rejected by [`Self::validate`]).
    pub const fn with_allow_other(mut self, allow_other: bool) -> Self {
        self.allow_other = allow_other;
        self
    }

    /// Appends one or more comma-separated mount options, immediately rejecting `allow_other`
    /// and `allow_root`.
    pub fn with_mount_options(mut self, raw_options: &str) -> Result<Self, FuseConfigError> {
        for token in raw_options.split(',') {
            let trimmed = token.trim();
            validate_extra_option_token(trimmed)?;
            self.extra_options.push(trimmed.to_owned());
        }
        self.validate()?;
        Ok(self)
    }

    /// Validates all invariants of this mount configuration:
    /// - Non-empty, absolute, NUL-free, space-free `mount_path`
    /// - `allow_other == false` and no `allow_other` / `allow_root` in `extra_options`
    /// - Valid `fsname`, `subtype`, and `max_write`
    pub fn validate(&self) -> Result<(), FuseConfigError> {
        if self.allow_other {
            return Err(FuseConfigError::AllowOtherForbidden);
        }

        let path_str = self.mount_path.to_string_lossy();
        if path_str.is_empty() {
            return Err(FuseConfigError::EmptyMountPath);
        }
        if path_str.contains('\0') {
            return Err(FuseConfigError::MountPathContainsNul);
        }
        if !is_cross_platform_absolute(&self.mount_path, &path_str) {
            return Err(FuseConfigError::RelativeMountPath(self.mount_path.clone()));
        }
        if path_str.chars().any(char::is_whitespace) {
            return Err(FuseConfigError::MountPathContainsWhitespace(
                self.mount_path.clone(),
            ));
        }

        if !is_valid_token(&self.fsname) {
            return Err(FuseConfigError::InvalidFsname(self.fsname.clone()));
        }
        if let Some(sub) = &self.subtype {
            if !is_valid_token(sub) {
                return Err(FuseConfigError::InvalidSubtype(sub.clone()));
            }
        }
        if self.max_write < MIN_MAX_WRITE {
            return Err(FuseConfigError::InvalidMaxWrite(self.max_write));
        }

        for raw in &self.extra_options {
            for part in raw.split(',') {
                validate_extra_option_token(part.trim())?;
            }
        }

        Ok(())
    }

    /// Builds validated `fusermount3 -o ...` option tokens (`fsname=bit`, `subtype=bit`,
    /// `default_permissions`, plus any validated `extra_options`).
    pub fn to_mount_options(&self) -> Result<Vec<String>, FuseConfigError> {
        self.validate()?;
        let mut opts = Vec::with_capacity(3 + self.extra_options.len());
        opts.push(format!("fsname={}", self.fsname));
        if let Some(sub) = &self.subtype {
            opts.push(format!("subtype={sub}"));
        }
        opts.push("default_permissions".to_owned());
        for extra in &self.extra_options {
            for part in extra.split(',') {
                let token = part.trim();
                if !opts.iter().any(|existing| existing == token) {
                    opts.push(token.to_owned());
                }
            }
        }
        Ok(opts)
    }

    /// Formats the validated comma-joined `-o` mount options string for `fusermount3`.
    pub fn to_mount_options_string(&self) -> Result<String, FuseConfigError> {
        Ok(self.to_mount_options()?.join(","))
    }
}

fn is_cross_platform_absolute(path: &Path, lossy: &str) -> bool {
    path.is_absolute() || lossy.starts_with('/')
}

fn is_valid_token(s: &str) -> bool {
    !s.is_empty() && !s.contains(',') && !s.contains('\0') && !s.chars().any(char::is_whitespace)
}

fn validate_extra_option_token(token: &str) -> Result<(), FuseConfigError> {
    if token.is_empty() || token.contains('\0') || token.chars().any(char::is_whitespace) {
        return Err(FuseConfigError::InvalidMountOption(token.to_owned()));
    }
    let key = token.split_once('=').map_or(token, |(k, _)| k);
    if key.eq_ignore_ascii_case("allow_other") || key.eq_ignore_ascii_case("allow_root") {
        return Err(FuseConfigError::AllowOtherForbidden);
    }
    Ok(())
}
