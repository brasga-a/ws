//! Loopback NFSv3 mount configuration, security invariants, and macOS `/sbin/mount_nfs` +
//! stale-mount `/sbin/umount -f` command builders (ADR-0004 & ADR-0005).
//!
//! ## Architectural Trade-offs on macOS
//! - **Kernel-extension-free virtualization**: Bit mounts `<mount>/<view-id>/` on macOS through a
//!   userspace loopback NFSv3 server bound strictly to `127.0.0.1`, avoiding `macFUSE` third-party
//!   kernel extensions (`kext`) that would require booting Apple Silicon Macs into Recovery Mode
//!   with Reduced Security.
//! - **Local kernel advisory locks (`nolocks,locallocks`)**: Passing `nolocks,locallocks` to
//!   `/sbin/mount_nfs` instructs the macOS XNU kernel NFS client to service `flock(2)` and
//!   `fcntl(2)` advisory locks locally in-kernel without requiring `rpc.lockd` or `rpcbind`.
//! - **Mandatory `owner_uid` check**: Because loopback TCP ports on `127.0.0.1` are reachable by
//!   processes on the same host, every non-`NULL` RPC call (and any `NULL` call carrying
//!   `AUTH_UNIX`) must present `AUTH_UNIX` credentials matching `owner_uid`.
//! - **Accepted XNU `FSEvents` (`MNT_LOCAL`) limitation & future `FSKit` backend**: XNU mounts
//!   NFSv3 filesystems without the `MNT_LOCAL` mount flag, so `fseventsd` does not emit push
//!   `FSEvents` notifications for paths inside `<mount>/<view-id>/`. Tools on macOS rely on
//!   `kqueue`, polling, or Watchman until a future `FSKit` userspace filesystem backend supersedes
//!   loopback NFSv3.
//! - **VFS-only live `View` mutations (ADR-0005)**: Stateless NFSv3 has no server-to-client cache
//!   invalidation callback channel; mutating live `Views` exclusively through VFS syscalls keeps
//!   XNU buffer, attribute, and directory-entry caches coherent with each `View`'s `Overlay`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Path to the standard macOS NFS mount utility.
pub const MACOS_MOUNT_NFS_BIN: &str = "/sbin/mount_nfs";

/// Path to the standard macOS unmount utility used for stale-mount cleanup.
pub const MACOS_UMOUNT_BIN: &str = "/sbin/umount";

/// Remote share specification passed to `/sbin/mount_nfs` for the single `<mount>/` root.
pub const LOOPBACK_NFS_SHARE_SPEC: &str = "127.0.0.1:/";

/// Configuration validation error for [`NfsMountConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NfsConfigError {
    /// Bind address was not IPv4 loopback `127.0.0.1`.
    NonLoopbackBindAddress(IpAddr),
    /// Mount point path was empty.
    EmptyMountPoint,
}

impl fmt::Display for NfsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLoopbackBindAddress(ip) => write!(
                f,
                "refusing non-loopback NFSv3 bind address {ip}; must bind strictly to 127.0.0.1"
            ),
            Self::EmptyMountPoint => f.write_str("NFSv3 mount point path must not be empty"),
        }
    }
}

impl std::error::Error for NfsConfigError {}

/// Validated configuration for the macOS userspace loopback NFSv3 server and mount helper.
///
/// Enforces two mandatory host-isolation invariants (ADR-0004):
/// 1. `bind_addr` is strictly `127.0.0.1:<port>` (ephemeral port `0` is supported so the OS kernel
///    can assign an unprivileged port dynamically; all non-`127.0.0.1` IPv4 and IPv6 addresses are
///    rejected).
/// 2. Incoming RPC calls must authenticate via `AUTH_UNIX` with `uid == owner_uid`.
///
/// ### XNU `FSEvents` Trade-off & Future `FSKit` Direction
/// Because macOS XNU does not set `MNT_LOCAL` on `/sbin/mount_nfs` mounts, `FSEvents` does not
/// generate push events for mutations inside a mounted `View`; file watchers fall back to
/// `kqueue`, polling, or Watchman until a future `FSKit` adapter is introduced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfsMountConfig {
    bind_addr: SocketAddr,
    owner_uid: u32,
    owner_gid: u32,
    mount_point: PathBuf,
    mount_port_override: Option<u16>,
}

impl NfsMountConfig {
    /// Validates `bind_addr` (`127.0.0.1` only; port `0` allowed for ephemeral allocation) and
    /// `mount_point`, constructing an [`NfsMountConfig`].
    pub fn new(
        bind_addr: SocketAddr,
        owner_uid: u32,
        mount_point: impl Into<PathBuf>,
    ) -> Result<Self, NfsConfigError> {
        let mount_point = mount_point.into();
        let cfg = Self {
            bind_addr,
            owner_uid,
            owner_gid: 0,
            mount_point,
            mount_port_override: None,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Convenience constructor binding `127.0.0.1:<port>` (pass `port = 0` for an ephemeral port).
    pub fn loopback(
        port: u16,
        owner_uid: u32,
        mount_point: impl Into<PathBuf>,
    ) -> Result<Self, NfsConfigError> {
        Self::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            owner_uid,
            mount_point,
        )
    }

    /// Sets the primary `gid` reported in synthesized `fattr3` attributes (defaults to `0`).
    pub const fn with_owner_gid(mut self, owner_gid: u32) -> Self {
        self.owner_gid = owner_gid;
        self
    }

    /// Overrides `mountport` in `/sbin/mount_nfs` options when `MOUNTv3` runs on a distinct port
    /// from `NFSv3` (by default both protocols multiplex over `bound_nfs_port` on one socket).
    pub const fn with_mount_port(mut self, mount_port: u16) -> Self {
        self.mount_port_override = Some(mount_port);
        self
    }

    /// Re-verifies loopback-only bind and non-empty mount point invariants.
    pub fn validate(&self) -> Result<(), NfsConfigError> {
        if self.bind_addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(NfsConfigError::NonLoopbackBindAddress(self.bind_addr.ip()));
        }
        if self.mount_point.as_os_str().is_empty() {
            return Err(NfsConfigError::EmptyMountPoint);
        }
        Ok(())
    }

    /// Configured loopback socket address (`127.0.0.1:<port>`, where `port` may be `0` prior to bind).
    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Mandatory `uid` required on incoming `AUTH_UNIX` RPC credentials.
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// Primary `gid` reported in `fattr3` node attributes.
    pub const fn owner_gid(&self) -> u32 {
        self.owner_gid
    }

    /// Host mount point directory (`<mount>/`, e.g. `~/.bit/views`).
    pub fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    /// Formats the comma-separated `-o` option string for macOS `/sbin/mount_nfs`:
    /// `vers=3,tcp,nolocks,locallocks,port=<nfs_port>,mountport=<mount_port>`.
    pub fn mount_options(&self, bound_nfs_port: u16) -> String {
        let mount_port = self.mount_port_override.unwrap_or(bound_nfs_port);
        format!("vers=3,tcp,nolocks,locallocks,port={bound_nfs_port},mountport={mount_port}")
    }

    /// Builds the argument vector passed to `/sbin/mount_nfs` for `bound_nfs_port`.
    pub fn mount_nfs_args(&self, bound_nfs_port: u16) -> Vec<String> {
        vec![
            "-o".to_owned(),
            self.mount_options(bound_nfs_port),
            LOOPBACK_NFS_SHARE_SPEC.to_owned(),
            self.mount_point.to_string_lossy().into_owned(),
        ]
    }

    /// Builds a ready-to-spawn `/sbin/mount_nfs` [`Command`] for `bound_nfs_port`.
    pub fn mount_nfs_command(&self, bound_nfs_port: u16) -> Command {
        let mut cmd = Command::new(MACOS_MOUNT_NFS_BIN);
        cmd.args(self.mount_nfs_args(bound_nfs_port));
        cmd
    }

    /// Builds the `umount -f` argument vector to clean up a stale mount at `self.mount_point`.
    pub fn stale_umount_args(&self) -> Vec<String> {
        build_stale_umount_args(&self.mount_point)
    }

    /// Builds a ready-to-spawn `/sbin/umount -f <mount_point>` [`Command`] for stale-mount cleanup.
    pub fn stale_umount_command(&self) -> Command {
        build_stale_umount_command(&self.mount_point)
    }
}

/// Builds the argument list `["-f", "<mount_point>"]` for forced macOS stale-mount cleanup.
pub fn build_stale_umount_args(mount_point: &Path) -> Vec<String> {
    vec!["-f".to_owned(), mount_point.to_string_lossy().into_owned()]
}

/// Builds a `/sbin/umount -f <mount_point>` [`Command`] to detach a stale loopback NFSv3 mount
/// left behind after an unclean daemon exit.
pub fn build_stale_umount_command(mount_point: &Path) -> Command {
    let mut cmd = Command::new(MACOS_UMOUNT_BIN);
    cmd.args(build_stale_umount_args(mount_point));
    cmd
}
