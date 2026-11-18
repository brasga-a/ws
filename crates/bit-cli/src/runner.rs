//! Command execution and output formatting for `bit`.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bit_core::{CoreError, DiffChange};
use bit_daemon::{DaemonError, DaemonServer, PathLayoutError, UserPaths};
use bit_ipc::{IpcRequest, IpcResponse, RemoteError};

use crate::args::{
    parse_args, render_help, BaseCommand, CliAction, Command, DaemonCommand, ParseError,
    ViewCommand,
};
use crate::client::{CliClient, ClientError};

/// Top-level CLI execution error.
#[derive(Debug)]
pub enum CliError {
    /// Argument parsing or identifier validation error.
    Parse(ParseError),
    /// Resolving `UserPaths` failed.
    Paths(PathLayoutError),
    /// Client/IPC/remote domain error.
    Client(ClientError),
    /// Running foreground `bit daemon run` failed.
    Daemon(DaemonError),
    /// Resolving current working directory or writing output failed.
    Io(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(err) => fmt::Display::fmt(err, f),
            Self::Paths(err) => fmt::Display::fmt(err, f),
            Self::Client(ClientError::Remote(RemoteError::Core(CoreError::ApplyConflicts(
                conflicts,
            )))) => {
                writeln!(
                    f,
                    "apply aborted due to {} conflict(s) against external directory:",
                    conflicts.len()
                )?;
                for c in conflicts {
                    writeln!(f, "  - {c}")?;
                }
                f.write_str("hint: pass --force to overwrite conflicting entries")
            }
            Self::Client(err) => fmt::Display::fmt(err, f),
            Self::Daemon(err) => fmt::Display::fmt(err, f),
            Self::Io(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for CliError {}

impl From<ParseError> for CliError {
    fn from(err: ParseError) -> Self {
        Self::Parse(err)
    }
}

impl From<PathLayoutError> for CliError {
    fn from(err: PathLayoutError) -> Self {
        Self::Paths(err)
    }
}

impl From<ClientError> for CliError {
    fn from(err: ClientError) -> Self {
        Self::Client(err)
    }
}

impl From<DaemonError> for CliError {
    fn from(err: DaemonError) -> Self {
        Self::Daemon(err)
    }
}

/// Executes `bit` using process arguments (`std::env::args().skip(1)`), `std::env::current_dir()`,
/// and `UserPaths::from_env()`.
pub fn run_from_env(stdout: &mut dyn Write) -> Result<(), CliError> {
    let action = parse_args(std::env::args().skip(1))?;
    match action {
        CliAction::Help(topic) => {
            write_str_out(stdout, render_help(topic))?;
            Ok(())
        }
        CliAction::Version => {
            writeln_out(stdout, &format!("bit {}", env!("CARGO_PKG_VERSION")))?;
            Ok(())
        }
        CliAction::Command(Command::Daemon(DaemonCommand::Run)) => {
            let paths = UserPaths::from_env()?;
            DaemonServer::open_persistent(paths)?.serve_blocking()?;
            Ok(())
        }
        CliAction::Command(cmd) => {
            let paths = UserPaths::from_env()?;
            let cwd = std::env::current_dir().map_err(|e| CliError::Io(e.to_string()))?;
            let client = CliClient::new(paths);
            execute_command(cmd, &client, &cwd, stdout)
        }
    }
}

/// Executes a parsed [`CliAction`] against `client` using explicit `cwd` and `stdout` (ideal for
/// deterministic in-process testing).
pub fn execute_action(
    action: CliAction,
    client: &CliClient,
    cwd: &Path,
    stdout: &mut dyn Write,
) -> Result<(), CliError> {
    match action {
        CliAction::Help(topic) => write_str_out(stdout, render_help(topic)),
        CliAction::Version => writeln_out(stdout, &format!("bit {}", env!("CARGO_PKG_VERSION"))),
        CliAction::Command(Command::Daemon(DaemonCommand::Run)) => {
            DaemonServer::open_persistent(client.paths().clone())?.serve_blocking()?;
            Ok(())
        }
        CliAction::Command(cmd) => execute_command(cmd, client, cwd, stdout),
    }
}

/// Executes an operational [`Command`] against `client`.
pub fn execute_command(
    cmd: Command,
    client: &CliClient,
    cwd: &Path,
    stdout: &mut dyn Write,
) -> Result<(), CliError> {
    match cmd {
        Command::Base(base_cmd) => execute_base(base_cmd, client, cwd, stdout),
        Command::View(view_cmd) => execute_view(view_cmd, client, cwd, stdout),
        Command::Diff { view_id } => {
            let resp = client.send(&IpcRequest::DiffView { view_id })?;
            let IpcResponse::ViewDiff(entries) = resp else {
                return Err(unexpected(resp));
            };
            for item in entries {
                let code = match item.change {
                    DiffChange::Added => 'A',
                    DiffChange::Modified => 'M',
                    DiffChange::Deleted => 'D',
                };
                writeln_out(stdout, &format!("{code} {}", item.path))?;
            }
            Ok(())
        }
        Command::Freeze { view_id, tag } => {
            let resp = client.send(&IpcRequest::FreezeView { view_id, tag })?;
            let IpcResponse::ViewFrozen(frozen) = resp else {
                return Err(unexpected(resp));
            };
            match frozen.tag {
                Some(t) => writeln_out(stdout, &format!("{} (tag: {t})", frozen.base_id)),
                None => writeln_out(stdout, &frozen.base_id.to_string()),
            }
        }
        Command::Apply {
            view_id,
            target_dir,
            force,
        } => {
            let abs_target = resolve_against_cwd(cwd, &target_dir);
            let resp = client.send(&IpcRequest::ApplyView {
                view_id,
                target_dir: abs_target.clone(),
                force,
            })?;
            let IpcResponse::ViewApplied(applied) = resp else {
                return Err(unexpected(resp));
            };
            writeln_out(
                stdout,
                &format!(
                    "applied {} change(s) from {} to {}",
                    applied.plan.diff.len(),
                    applied.view_id,
                    abs_target.display()
                ),
            )
        }
        Command::Daemon(DaemonCommand::Run) => {
            DaemonServer::open_persistent(client.paths().clone())?.serve_blocking()?;
            Ok(())
        }
        Command::Daemon(DaemonCommand::Status) => {
            match client.try_send_if_running(&IpcRequest::Status)? {
                None => writeln_out(stdout, "status: stopped"),
                Some(IpcResponse::Status(st)) => {
                    writeln_out(stdout, "status: running")?;
                    writeln_out(stdout, &format!("pid: {}", st.pid))?;
                    writeln_out(stdout, &format!("mount_dir: {}", st.mount_dir.display()))?;
                    writeln_out(stdout, &format!("store_dir: {}", st.store_dir.display()))?;
                    writeln_out(
                        stdout,
                        &format!("ipc_endpoint: {}", st.ipc_endpoint.display()),
                    )?;
                    writeln_out(
                        stdout,
                        &format!("vfs: {} (mounted={})", st.vfs_backend, st.vfs_mounted),
                    )?;
                    writeln_out(stdout, &format!("bases: {}", st.base_count))?;
                    writeln_out(stdout, &format!("views: {}", st.view_count))
                }
                Some(other) => Err(unexpected(other)),
            }
        }
        Command::Daemon(DaemonCommand::Stop) => {
            match client.try_send_if_running(&IpcRequest::Shutdown)? {
                None => writeln_out(stdout, "daemon is not running"),
                Some(IpcResponse::ShuttingDown) => {
                    client.wait_until_stopped(Duration::from_secs(2));
                    writeln_out(stdout, "daemon stopped")
                }
                Some(other) => Err(unexpected(other)),
            }
        }
    }
}

fn execute_base(
    cmd: BaseCommand,
    client: &CliClient,
    cwd: &Path,
    stdout: &mut dyn Write,
) -> Result<(), CliError> {
    match cmd {
        BaseCommand::Create { dir, tag, excludes } => {
            let abs_dir = resolve_against_cwd(cwd, &dir);
            let resp = client.send(&IpcRequest::CreateBase {
                dir: abs_dir,
                tag,
                excludes,
            })?;
            let IpcResponse::BaseCreated(info) = resp else {
                return Err(unexpected(resp));
            };
            if info.tags.is_empty() {
                writeln_out(stdout, &info.id.to_string())
            } else {
                let tags = format_tags(&info.tags);
                writeln_out(stdout, &format!("{} (tags: {tags})", info.id))
            }
        }
        BaseCommand::List => {
            let resp = client.send(&IpcRequest::ListBases)?;
            let IpcResponse::BaseList(bases) = resp else {
                return Err(unexpected(resp));
            };
            for info in bases {
                let tags = if info.tags.is_empty() {
                    "-".to_owned()
                } else {
                    format_tags(&info.tags)
                };
                writeln_out(
                    stdout,
                    &format!(
                        "{}\tentries={}\tviews={}\ttags={tags}",
                        info.id, info.entry_count, info.view_count
                    ),
                )?;
            }
            Ok(())
        }
        BaseCommand::Tag { tag, base } => {
            let resp = client.send(&IpcRequest::SetTag { tag, base })?;
            let IpcResponse::TagSet { tag, base_id } = resp else {
                return Err(unexpected(resp));
            };
            writeln_out(stdout, &format!("{tag} -> {base_id}"))
        }
        BaseCommand::Untag { tag } => {
            let resp = client.send(&IpcRequest::DeleteTag { tag: tag.clone() })?;
            let IpcResponse::TagDeleted = resp else {
                return Err(unexpected(resp));
            };
            writeln_out(stdout, &format!("untagged {tag}"))
        }
        BaseCommand::Rm { base, cascade } => {
            let resp = client.send(&IpcRequest::RemoveBase {
                selector: base,
                cascade,
            })?;
            let IpcResponse::BaseRemoved(out) = resp else {
                return Err(unexpected(resp));
            };
            writeln_out(
                stdout,
                &format!(
                    "removed base {} (removed_views={}, removed_tags={})",
                    out.base_id,
                    out.removed_views.len(),
                    out.removed_tags.len()
                ),
            )
        }
    }
}

fn execute_view(
    cmd: ViewCommand,
    client: &CliClient,
    cwd: &Path,
    stdout: &mut dyn Write,
) -> Result<(), CliError> {
    match cmd {
        ViewCommand::Create {
            base,
            view_id,
            link,
        } => {
            let link_path = link.map(|p| resolve_against_cwd(cwd, &p));
            let resp = client.send(&IpcRequest::CreateView {
                base,
                view_id,
                link_path,
            })?;
            let IpcResponse::ViewCreated(summary) = resp else {
                return Err(unexpected(resp));
            };
            match summary.link_path {
                Some(lp) => writeln_out(
                    stdout,
                    &format!(
                        "{}\t{}\tlink={}",
                        summary.info.id,
                        summary.mount_path.display(),
                        lp.display()
                    ),
                ),
                None => writeln_out(
                    stdout,
                    &format!("{}\t{}", summary.info.id, summary.mount_path.display()),
                ),
            }
        }
        ViewCommand::List => {
            let resp = client.send(&IpcRequest::ListViews)?;
            let IpcResponse::ViewList(views) = resp else {
                return Err(unexpected(resp));
            };
            for summary in views {
                match summary.link_path {
                    Some(lp) => writeln_out(
                        stdout,
                        &format!(
                            "{}\tbase={}\toverlay={}\tpath={}\tlink={}",
                            summary.info.id,
                            summary.info.base_id,
                            summary.info.overlay_entry_count,
                            summary.mount_path.display(),
                            lp.display()
                        ),
                    )?,
                    None => writeln_out(
                        stdout,
                        &format!(
                            "{}\tbase={}\toverlay={}\tpath={}",
                            summary.info.id,
                            summary.info.base_id,
                            summary.info.overlay_entry_count,
                            summary.mount_path.display()
                        ),
                    )?,
                }
            }
            Ok(())
        }
        ViewCommand::Path { view_id } => {
            let resp = client.send(&IpcRequest::ViewPath { view_id })?;
            let IpcResponse::ViewPath(path) = resp else {
                return Err(unexpected(resp));
            };
            writeln_out(stdout, &path.display().to_string())
        }
        ViewCommand::Rm { view_id } => {
            let resp = client.send(&IpcRequest::RemoveView {
                view_id: view_id.clone(),
            })?;
            let IpcResponse::ViewRemoved = resp else {
                return Err(unexpected(resp));
            };
            writeln_out(stdout, &format!("removed view {view_id}"))
        }
    }
}

fn resolve_against_cwd(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn format_tags(tags: &[bit_core::TagName]) -> String {
    tags.iter()
        .map(bit_core::TagName::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

fn unexpected(resp: IpcResponse) -> CliError {
    CliError::Client(ClientError::UnexpectedResponse(format!("{resp:?}")))
}

fn write_str_out(out: &mut dyn Write, text: &str) -> Result<(), CliError> {
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| CliError::Io(e.to_string()))
}

fn writeln_out(out: &mut dyn Write, line: &str) -> Result<(), CliError> {
    writeln!(out, "{line}")
        .and_then(|()| out.flush())
        .map_err(|e| CliError::Io(e.to_string()))
}
