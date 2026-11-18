//! Local IPC endpoint and transport abstractions:
//! - Unix domain sockets (`UnixListener` / `UnixStream`) on `#[cfg(unix)]`,
//! - Named Pipe endpoint (`\\.\pipe\...`) abstraction on `#[cfg(windows)]`,
//! - Generic `Read + Write` framing exchange helpers for deterministic testing.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use bit_core::Sha256;

use crate::codec::{read_request_opt, read_response, write_request, write_response, CodecError};
use crate::message::{IpcRequest, IpcResponse};

/// Transport and wire-framing error for IPC clients and listeners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    /// Local daemon is not running or its IPC endpoint does not exist.
    NotRunning(String),
    /// Another live daemon process is already listening on the IPC endpoint.
    AddressInUse(PathBuf),
    /// Peer closed the connection before sending an expected frame.
    ConnectionClosed,
    /// Socket read/write operation timed out.
    Timeout,
    /// Wire framing or codec validation failed.
    Codec(CodecError),
    /// Underlying operating-system I/O error.
    Io(String),
}

impl IpcError {
    /// Returns `true` if the error indicates that no daemon is listening on the endpoint.
    pub const fn is_daemon_unavailable(&self) -> bool {
        matches!(self, Self::NotRunning(_))
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRunning(msg) => write!(f, "daemon is not running: {msg}"),
            Self::AddressInUse(path) => {
                write!(f, "daemon is already listening at {}", path.display())
            }
            Self::ConnectionClosed => f.write_str("IPC connection closed unexpectedly"),
            Self::Timeout => f.write_str("IPC operation timed out"),
            Self::Codec(err) => fmt::Display::fmt(err, f),
            Self::Io(msg) => write!(f, "IPC I/O error: {msg}"),
        }
    }
}

impl std::error::Error for IpcError {}

impl From<CodecError> for IpcError {
    fn from(err: CodecError) -> Self {
        Self::Codec(err)
    }
}

impl From<io::Error> for IpcError {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                Self::NotRunning(err.to_string())
            }
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Self::Timeout,
            io::ErrorKind::UnexpectedEof => Self::ConnectionClosed,
            _ => Self::Io(err.to_string()),
        }
    }
}

/// OS-agnostic local IPC endpoint address.
///
/// On Unix, wraps a filesystem path to a Unix domain socket (e.g. `~/.bit/daemon.sock`).
/// On Windows, maps any filesystem or logical endpoint path into a deterministic Named Pipe path
/// (`\\.\pipe\bit-<digest>`) or preserves an explicit `\\.\pipe\...` pipe path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpcEndpoint {
    path: PathBuf,
}

impl IpcEndpoint {
    /// Creates an `IpcEndpoint` from `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Borrows the underlying endpoint path.
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// Consumes `self` and returns the inner `PathBuf`.
    pub fn into_path(self) -> PathBuf {
        self.path
    }

    /// Derives the deterministic Windows Named Pipe path (`\\.\pipe\...`) for this endpoint.
    ///
    /// If `self.path` already starts with `\\.\pipe\`, returns it verbatim; otherwise hashes
    /// the normalized path into `\\.\pipe\bit-<16-hex-chars>`.
    pub fn windows_pipe_name(&self) -> String {
        let raw = self.path.to_string_lossy();
        if raw.starts_with(r"\\.\pipe\") {
            return raw.into_owned();
        }
        let digest = Sha256::digest(raw.as_bytes());
        let mut hex16 = String::with_capacity(16);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &b in &digest[..8] {
            hex16.push(HEX[(b >> 4) as usize] as char);
            hex16.push(HEX[(b & 0x0f) as usize] as char);
        }
        format!(r"\\.\pipe\bit-{hex16}")
    }
}

/// Sends a single [`IpcRequest`] and reads one [`IpcResponse`] over any `Read + Write` stream.
pub fn exchange_io<RW: Read + Write>(
    stream: &mut RW,
    req: &IpcRequest,
) -> Result<IpcResponse, IpcError> {
    write_request(stream, req)?;
    read_response(stream)
}

/// Processes at most one incoming [`IpcRequest`] on `stream`, writing the handler's
/// [`IpcResponse`]. Returns `Ok(false)` if the client cleanly closed the stream without sending
/// another frame, or `Ok(true)` if a request was handled.
pub fn serve_one_io<RW, F>(stream: &mut RW, handler: F) -> Result<bool, IpcError>
where
    RW: Read + Write,
    F: FnOnce(IpcRequest) -> IpcResponse,
{
    let Some(req) = read_request_opt(stream)? else {
        return Ok(false);
    };
    let resp = handler(req);
    write_response(stream, &resp)?;
    Ok(true)
}

#[cfg(unix)]
mod imp {
    use std::fs;
    use std::io::{self, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    use super::{exchange_io, IpcEndpoint, IpcError};
    use crate::message::{IpcRequest, IpcResponse};

    /// Bidirectional local IPC connection stream backed by `UnixStream`.
    #[derive(Debug)]
    pub struct LocalStream {
        inner: UnixStream,
    }

    impl LocalStream {
        pub(crate) fn new(inner: UnixStream) -> Self {
            Self { inner }
        }

        /// Configures read and write timeouts on the underlying socket.
        pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<(), IpcError> {
            self.inner.set_read_timeout(timeout)?;
            self.inner.set_write_timeout(timeout)?;
            Ok(())
        }
    }

    impl Read for LocalStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl Write for LocalStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    /// Local IPC server listener backed by `UnixListener`.
    #[derive(Debug)]
    pub struct LocalListener {
        endpoint: IpcEndpoint,
        inner: UnixListener,
        cleanup_on_drop: bool,
    }

    impl LocalListener {
        /// Binds a `UnixListener` at `endpoint`.
        ///
        /// If a stale socket file exists from an unclean exit (where `connect` fails with
        /// `ConnectionRefused` or `NotFound`), removes the stale file before binding. If a live
        /// listener accepts connections on `endpoint`, returns [`IpcError::AddressInUse`].
        pub fn bind(endpoint: IpcEndpoint) -> Result<Self, IpcError> {
            let sock_path = endpoint.as_path();
            if let Some(parent) = sock_path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }

            if fs::symlink_metadata(sock_path).is_ok() {
                match UnixStream::connect(sock_path) {
                    Ok(_) => return Err(IpcError::AddressInUse(sock_path.to_path_buf())),
                    Err(err)
                        if matches!(
                            err.kind(),
                            io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                        ) =>
                    {
                        let _ = fs::remove_file(sock_path);
                    }
                    Err(err) => return Err(IpcError::from(err)),
                }
            }

            let inner = match UnixListener::bind(sock_path) {
                Ok(listener) => listener,
                Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                    return Err(IpcError::AddressInUse(sock_path.to_path_buf()));
                }
                Err(err) => return Err(IpcError::from(err)),
            };

            let _ = fs::set_permissions(sock_path, fs::Permissions::from_mode(0o600));

            Ok(Self {
                endpoint,
                inner,
                cleanup_on_drop: true,
            })
        }

        /// Borrows the bound `IpcEndpoint`.
        pub const fn endpoint(&self) -> &IpcEndpoint {
            &self.endpoint
        }

        /// Toggles non-blocking accept mode.
        pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), IpcError> {
            self.inner.set_nonblocking(nonblocking)?;
            Ok(())
        }

        /// Accepts the next incoming client connection.
        pub fn accept(&self) -> Result<LocalStream, IpcError> {
            let (stream, _) = self.inner.accept()?;
            Ok(LocalStream::new(stream))
        }

        /// Removes the bound Unix domain socket file immediately.
        pub fn cleanup_socket(&mut self) {
            if self.cleanup_on_drop {
                let _ = fs::remove_file(self.endpoint.as_path());
                self.cleanup_on_drop = false;
            }
        }
    }

    impl Drop for LocalListener {
        fn drop(&mut self) {
            self.cleanup_socket();
        }
    }

    /// Local IPC client backed by `UnixStream`.
    #[derive(Debug)]
    pub struct LocalClient {
        stream: LocalStream,
    }

    impl LocalClient {
        /// Connects to a running daemon at `endpoint`.
        pub fn connect(endpoint: &IpcEndpoint) -> Result<Self, IpcError> {
            let raw = UnixStream::connect(endpoint.as_path())?;
            Ok(Self {
                stream: LocalStream::new(raw),
            })
        }

        /// Configures read/write timeouts on this client connection.
        pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<(), IpcError> {
            self.stream.set_timeout(timeout)
        }

        /// Sends `req` and reads back the daemon's [`IpcResponse`].
        pub fn send(&mut self, req: &IpcRequest) -> Result<IpcResponse, IpcError> {
            exchange_io(&mut self.stream, req)
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::sync::mpsc::{self, Receiver};
    use std::time::Duration;

    use super::{exchange_io, IpcEndpoint, IpcError};
    use crate::message::{IpcRequest, IpcResponse};

    /// Bidirectional local IPC connection stream backed by a Windows Named Pipe handle (`File`).
    #[derive(Debug)]
    pub struct LocalStream {
        inner: File,
    }

    impl LocalStream {
        /// Wraps an opened Named Pipe `File` handle.
        pub fn from_pipe_file(inner: File) -> Self {
            Self { inner }
        }

        /// Configures optional stream timeouts (no-op on standard `File` pipe handles).
        pub fn set_timeout(&self, _timeout: Option<Duration>) -> Result<(), IpcError> {
            Ok(())
        }
    }

    impl Read for LocalStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl Write for LocalStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    /// Safe `std` Named Pipe listener endpoint abstraction on Windows.
    #[derive(Debug)]
    pub struct LocalListener {
        endpoint: IpcEndpoint,
        pipe_name: String,
        incoming: Receiver<LocalStream>,
    }

    impl LocalListener {
        /// Binds the Named Pipe endpoint abstraction for `endpoint`.
        pub fn bind(endpoint: IpcEndpoint) -> Result<Self, IpcError> {
            let pipe_name = endpoint.windows_pipe_name();
            let (_tx, rx) = mpsc::channel();
            Ok(Self {
                endpoint,
                pipe_name,
                incoming: rx,
            })
        }

        /// Constructs a `LocalListener` fed by an external Named Pipe acceptor channel.
        pub fn from_channel(endpoint: IpcEndpoint, incoming: Receiver<LocalStream>) -> Self {
            let pipe_name = endpoint.windows_pipe_name();
            Self {
                endpoint,
                pipe_name,
                incoming,
            }
        }

        /// Borrows the bound `IpcEndpoint`.
        pub const fn endpoint(&self) -> &IpcEndpoint {
            &self.endpoint
        }

        /// Returns the `\\.\pipe\...` pipe name associated with this listener.
        pub fn pipe_name(&self) -> &str {
            &self.pipe_name
        }

        /// Toggles non-blocking accept mode.
        pub fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), IpcError> {
            Ok(())
        }

        /// Accepts the next incoming Named Pipe stream.
        pub fn accept(&self) -> Result<LocalStream, IpcError> {
            self.incoming.recv().map_err(|_| IpcError::ConnectionClosed)
        }

        /// Cleans up listener state on shutdown.
        pub fn cleanup_socket(&mut self) {}
    }

    /// Local IPC client connecting to a `\\.\pipe\...` Windows Named Pipe via safe `OpenOptions`.
    #[derive(Debug)]
    pub struct LocalClient {
        stream: LocalStream,
    }

    impl LocalClient {
        /// Connects to a running daemon Named Pipe at `endpoint`.
        pub fn connect(endpoint: &IpcEndpoint) -> Result<Self, IpcError> {
            let pipe_name = endpoint.windows_pipe_name();
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&pipe_name)
                .map_err(|err| match err.kind() {
                    io::ErrorKind::NotFound => IpcError::NotRunning(format!(
                        "named pipe {pipe_name} is not available: {err}"
                    )),
                    _ => IpcError::from(err),
                })?;
            Ok(Self {
                stream: LocalStream::from_pipe_file(file),
            })
        }

        /// Configures stream timeouts.
        pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<(), IpcError> {
            self.stream.set_timeout(timeout)
        }

        /// Sends `req` and reads back the daemon's [`IpcResponse`].
        pub fn send(&mut self, req: &IpcRequest) -> Result<IpcResponse, IpcError> {
            exchange_io(&mut self.stream, req)
        }
    }
}

pub use imp::{LocalClient, LocalListener, LocalStream};
