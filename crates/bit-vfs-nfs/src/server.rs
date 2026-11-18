//! Loopback `TcpListener` server skeleton for multiplexing `MOUNTv3` and `NFSv3` on `127.0.0.1`.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use bit_core::VfsOperations;

use crate::config::{NfsConfigError, NfsMountConfig};
use crate::nfs::NfsDispatcher;
use crate::rpc::RpcError;

/// Error returned when binding or operating [`NfsLoopbackServer`].
#[derive(Debug)]
pub enum NfsServerError {
    /// Invalid [`NfsMountConfig`] (e.g. non-loopback bind IP).
    Config(NfsConfigError),
    /// Socket bind or accept I/O error.
    Io(io::Error),
    /// RPC framing or transport error.
    Rpc(RpcError),
}

impl fmt::Display for NfsServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => fmt::Display::fmt(err, f),
            Self::Io(err) => write!(f, "loopback NFSv3 server I/O error: {err}"),
            Self::Rpc(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl std::error::Error for NfsServerError {}

impl From<NfsConfigError> for NfsServerError {
    fn from(err: NfsConfigError) -> Self {
        Self::Config(err)
    }
}

impl From<io::Error> for NfsServerError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<RpcError> for NfsServerError {
    fn from(err: RpcError) -> Self {
        Self::Rpc(err)
    }
}

/// Bound loopback `TcpListener` server multiplexing `MOUNTv3` and `NFSv3` over `127.0.0.1`.
#[derive(Debug)]
pub struct NfsLoopbackServer {
    config: NfsMountConfig,
    listener: TcpListener,
    local_addr: SocketAddr,
    dispatcher: Arc<NfsDispatcher>,
}

impl NfsLoopbackServer {
    /// Validates `config`, binds a `TcpListener` strictly on `127.0.0.1` (resolving ephemeral port
    /// `0` if requested), and constructs an [`NfsLoopbackServer`].
    pub fn bind(
        config: NfsMountConfig,
        vfs: Arc<dyn VfsOperations>,
    ) -> Result<Self, NfsServerError> {
        config.validate()?;
        let listener = TcpListener::bind(config.bind_addr())?;
        let local_addr = listener.local_addr()?;
        if local_addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(NfsServerError::Config(
                NfsConfigError::NonLoopbackBindAddress(local_addr.ip()),
            ));
        }

        let dispatcher = Arc::new(
            NfsDispatcher::new(vfs, config.owner_uid()).with_owner_gid(config.owner_gid()),
        );

        Ok(Self {
            config,
            listener,
            local_addr,
            dispatcher,
        })
    }

    /// Actual bound loopback socket address (`127.0.0.1:<port>`).
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Actual TCP port assigned to `self.listener`.
    pub const fn bound_port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Borrows the validated [`NfsMountConfig`].
    pub const fn config(&self) -> &NfsMountConfig {
        &self.config
    }

    /// Borrows the underlying [`NfsDispatcher`].
    pub const fn dispatcher(&self) -> &Arc<NfsDispatcher> {
        &self.dispatcher
    }

    /// Builds `/sbin/mount_nfs` arguments populated with `self.bound_port()`.
    pub fn mount_nfs_args(&self) -> Vec<String> {
        self.config.mount_nfs_args(self.bound_port())
    }

    /// Builds a `/sbin/mount_nfs` [`Command`] populated with `self.bound_port()`.
    pub fn mount_nfs_command(&self) -> Command {
        self.config.mount_nfs_command(self.bound_port())
    }

    /// Builds `/sbin/umount -f` arguments for stale-mount cleanup at `self.config.mount_point()`.
    pub fn stale_umount_args(&self) -> Vec<String> {
        self.config.stale_umount_args()
    }

    /// Builds a `/sbin/umount -f` [`Command`] for stale-mount cleanup.
    pub fn stale_umount_command(&self) -> Command {
        self.config.stale_umount_command()
    }

    /// Accepts and serves a single loopback TCP client connection synchronously.
    pub fn accept_one(&self) -> Result<usize, NfsServerError> {
        let (mut stream, peer_addr) = self.listener.accept()?;
        if peer_addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(NfsServerError::Config(
                NfsConfigError::NonLoopbackBindAddress(peer_addr.ip()),
            ));
        }
        let _ = stream.set_nodelay(true);
        Ok(self.dispatcher.serve_connection(&mut stream)?)
    }

    /// Spawns a background accept loop serving concurrent loopback `MOUNTv3` + `NFSv3` TCP
    /// connections until [`NfsRunningServer::shutdown`] (or `Drop`) is invoked.
    pub fn start(self) -> Result<NfsRunningServer, NfsServerError> {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_for_accept = Arc::clone(&stop_flag);
        let dispatcher = Arc::clone(&self.dispatcher);
        let local_addr = self.local_addr;
        let config = self.config;
        let listener = self.listener;

        let accept_thread = thread::Builder::new()
            .name("bit-vfs-nfs-accept".to_owned())
            .spawn(move || {
                let mut workers: Vec<JoinHandle<()>> = Vec::new();
                loop {
                    let (mut stream, peer_addr) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(_) => break,
                    };
                    if stop_for_accept.load(Ordering::SeqCst) {
                        break;
                    }
                    if peer_addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
                        continue;
                    }
                    let _ = stream.set_nodelay(true);
                    let disp = Arc::clone(&dispatcher);
                    if let Ok(handle) = thread::Builder::new()
                        .name("bit-vfs-nfs-conn".to_owned())
                        .spawn(move || {
                            let _ = disp.serve_connection(&mut stream);
                        })
                    {
                        workers.push(handle);
                    }
                }
                for worker in workers {
                    let _ = worker.join();
                }
            })?;

        Ok(NfsRunningServer {
            config,
            local_addr,
            dispatcher: self.dispatcher,
            stop_flag,
            accept_thread: Mutex::new(Some(accept_thread)),
        })
    }
}

/// Handle to a running background [`NfsLoopbackServer`].
#[derive(Debug)]
pub struct NfsRunningServer {
    config: NfsMountConfig,
    local_addr: SocketAddr,
    dispatcher: Arc<NfsDispatcher>,
    stop_flag: Arc<AtomicBool>,
    accept_thread: Mutex<Option<JoinHandle<()>>>,
}

impl NfsRunningServer {
    /// Bound loopback socket address (`127.0.0.1:<port>`).
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Bound loopback TCP port.
    pub const fn bound_port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Validated [`NfsMountConfig`].
    pub const fn config(&self) -> &NfsMountConfig {
        &self.config
    }

    /// Shared [`NfsDispatcher`].
    pub const fn dispatcher(&self) -> &Arc<NfsDispatcher> {
        &self.dispatcher
    }

    /// Builds `/sbin/mount_nfs` arguments with the live bound port.
    pub fn mount_nfs_args(&self) -> Vec<String> {
        self.config.mount_nfs_args(self.bound_port())
    }

    /// Builds `/sbin/umount -f` stale-mount cleanup arguments.
    pub fn stale_umount_args(&self) -> Vec<String> {
        self.config.stale_umount_args()
    }

    /// Signals the accept loop to stop, wakes `TcpListener::accept()` via a loopback poke, and
    /// joins the accept thread.
    pub fn shutdown(&self) {
        if !self.stop_flag.swap(true, Ordering::SeqCst) {
            let _ = TcpStream::connect(self.local_addr);
        }
        let mut guard = self
            .accept_thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(handle) = guard.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for NfsRunningServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}
