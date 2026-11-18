//! Pure deterministic command-line argument parser for the `bit` binary.
//!
//! Per ADR-0005, `bit` exposes lifecycle and whole-`View` commands (`base`, `view`, `diff`,
//! `freeze`, `apply`, `daemon`) and intentionally exposes NO per-file restore or checkout
//! commands.

use std::fmt;
use std::path::PathBuf;

use bit_core::{BaseSelector, IdError, TagName, ViewId};

/// Parsed top-level CLI invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliAction {
    /// Print help text for a topic and exit `0`.
    Help(HelpTopic),
    /// Print version string and exit `0`.
    Version,
    /// Execute an operational command.
    Command(Command),
}

/// Help topic requested via `-h`, `--help`, or `help`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpTopic {
    Root,
    Base,
    View,
    Diff,
    Freeze,
    Apply,
    Daemon,
}

/// Validated `bit` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `bit base ...` subcommands.
    Base(BaseCommand),
    /// `bit view ...` subcommands.
    View(ViewCommand),
    /// `bit diff <view-id>`
    Diff { view_id: ViewId },
    /// `bit freeze <view-id> [--tag <tag>]`
    Freeze {
        view_id: ViewId,
        tag: Option<TagName>,
    },
    /// `bit apply <view-id> <target-dir> [--force]`
    Apply {
        view_id: ViewId,
        target_dir: PathBuf,
        force: bool,
    },
    /// `bit daemon ...` subcommands.
    Daemon(DaemonCommand),
}

/// Subcommands under `bit base`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseCommand {
    /// `bit base create <dir> [--tag <tag>] [--exclude <pattern>...]`
    Create {
        dir: PathBuf,
        tag: Option<TagName>,
        excludes: Vec<String>,
    },
    /// `bit base list`
    List,
    /// `bit base tag <tag> <base>`
    Tag { tag: TagName, base: BaseSelector },
    /// `bit base untag <tag>`
    Untag { tag: TagName },
    /// `bit base rm <base> [--cascade]`
    Rm { base: BaseSelector, cascade: bool },
}

/// Subcommands under `bit view`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewCommand {
    /// `bit view create <base> [<view-id>] [--link <path>]`
    Create {
        base: BaseSelector,
        view_id: Option<ViewId>,
        link: Option<PathBuf>,
    },
    /// `bit view list`
    List,
    /// `bit view path <view-id>`
    Path { view_id: ViewId },
    /// `bit view rm <view-id>`
    Rm { view_id: ViewId },
}

/// Subcommands under `bit daemon`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonCommand {
    /// `bit daemon run`
    Run,
    /// `bit daemon status`
    Status,
    /// `bit daemon stop`
    Stop,
}

/// Argument parsing or identifier validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Unknown top-level command or subcommand.
    UnknownCommand(String),
    /// Unknown flag.
    UnknownFlag(String),
    /// Flag required a value that was missing.
    MissingFlagValue(String),
    /// Required positional argument was omitted.
    MissingArgument(&'static str),
    /// Too many positional arguments were supplied.
    UnexpectedArgument(String),
    /// Flag was specified more than once when at most one value is allowed.
    DuplicateFlag(&'static str),
    /// Domain identifier (`TagName`, `ViewId`, `BaseSelector`) failed validation.
    InvalidIdentifier { field: &'static str, error: IdError },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand(cmd) => {
                write!(f, "unknown command {cmd:?} (run 'bit --help' for usage)")
            }
            Self::UnknownFlag(flag) => write!(f, "unknown option {flag:?}"),
            Self::MissingFlagValue(flag) => write!(f, "option {flag} requires a value"),
            Self::MissingArgument(arg) => write!(f, "missing required argument <{arg}>"),
            Self::UnexpectedArgument(arg) => write!(f, "unexpected argument {arg:?}"),
            Self::DuplicateFlag(flag) => {
                write!(f, "option {flag} cannot be specified multiple times")
            }
            Self::InvalidIdentifier { field, error } => write!(f, "invalid <{field}>: {error}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Renders human-readable CLI usage text for `topic`.
pub const fn render_help(topic: HelpTopic) -> &'static str {
    match topic {
        HelpTopic::Root => concat!(
            "bit - isolated, writable Views backed by shared immutable Bases\n\n",
            "USAGE:\n",
            "  bit <command> [arguments]\n\n",
            "COMMANDS:\n",
            "  base     Manage sealed immutable Bases and mutable Tags\n",
            "  view     Manage isolated writable Views under the VFS mount\n",
            "  diff     Show net changes in a View relative to its Base\n",
            "  freeze   Capture a View's current state as a new immutable Base\n",
            "  apply    Project a View's Overlay onto an external directory\n",
            "  daemon   Run, inspect, or stop the local background daemon\n\n",
            "OPTIONS:\n",
            "  -h, --help     Show help information\n",
            "  -V, --version  Show version information\n"
        ),
        HelpTopic::Base => concat!(
            "Manage sealed immutable Bases and mutable Tags\n\n",
            "USAGE:\n",
            "  bit base create <dir> [--tag <tag>] [--exclude <pattern>...]\n",
            "  bit base list\n",
            "  bit base tag <tag> <base>\n",
            "  bit base untag <tag>\n",
            "  bit base rm <base> [--cascade]\n"
        ),
        HelpTopic::View => concat!(
            "Manage isolated writable Views\n\n",
            "USAGE:\n",
            "  bit view create <base> [<view-id>] [--link <path>]\n",
            "  bit view list\n",
            "  bit view path <view-id>\n",
            "  bit view rm <view-id>\n"
        ),
        HelpTopic::Diff => concat!(
            "Compute the live Diff of a View against its Base\n\n",
            "USAGE:\n",
            "  bit diff <view-id>\n"
        ),
        HelpTopic::Freeze => concat!(
            "Capture a View's current state as a new immutable Base\n\n",
            "USAGE:\n",
            "  bit freeze <view-id> [--tag <tag>]\n"
        ),
        HelpTopic::Apply => concat!(
            "All-or-nothing guarded projection of a View's Overlay onto an external directory\n\n",
            "USAGE:\n",
            "  bit apply <view-id> <target-dir> [--force]\n"
        ),
        HelpTopic::Daemon => concat!(
            "Manage the local VFS and control-plane background daemon\n\n",
            "USAGE:\n",
            "  bit daemon run\n",
            "  bit daemon status\n",
            "  bit daemon stop\n"
        ),
    }
}

/// Parses arguments excluding the binary name (`argv[1..]`).
pub fn parse_args<I, S>(args: I) -> Result<CliAction, ParseError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let tokens: Vec<String> = args.into_iter().map(Into::into).collect();
    let Some(first) = tokens.first() else {
        return Ok(CliAction::Help(HelpTopic::Root));
    };

    match first.as_str() {
        "-h" | "--help" | "help" => {
            if let Some(sub) = tokens.get(1) {
                return match sub.as_str() {
                    "base" => Ok(CliAction::Help(HelpTopic::Base)),
                    "view" => Ok(CliAction::Help(HelpTopic::View)),
                    "diff" => Ok(CliAction::Help(HelpTopic::Diff)),
                    "freeze" => Ok(CliAction::Help(HelpTopic::Freeze)),
                    "apply" => Ok(CliAction::Help(HelpTopic::Apply)),
                    "daemon" => Ok(CliAction::Help(HelpTopic::Daemon)),
                    _ => Err(ParseError::UnknownCommand(sub.clone())),
                };
            }
            Ok(CliAction::Help(HelpTopic::Root))
        }
        "-V" | "--version" => {
            if let Some(extra) = tokens.get(1) {
                return Err(ParseError::UnexpectedArgument(extra.clone()));
            }
            Ok(CliAction::Version)
        }
        "base" => parse_base(&tokens[1..]),
        "view" => parse_view(&tokens[1..]),
        "diff" => parse_diff(&tokens[1..]),
        "freeze" => parse_freeze(&tokens[1..]),
        "apply" => parse_apply(&tokens[1..]),
        "daemon" => parse_daemon(&tokens[1..]),
        other if other.starts_with('-') => Err(ParseError::UnknownFlag(other.to_owned())),
        other => Err(ParseError::UnknownCommand(other.to_owned())),
    }
}

fn has_help_flag(tokens: &[String]) -> bool {
    let mut after_dd = false;
    for tok in tokens {
        if after_dd {
            break;
        }
        if tok == "--" {
            after_dd = true;
            continue;
        }
        if tok == "-h" || tok == "--help" {
            return true;
        }
    }
    false
}

fn parse_base(tokens: &[String]) -> Result<CliAction, ParseError> {
    let Some(sub) = tokens.first() else {
        return Ok(CliAction::Help(HelpTopic::Base));
    };
    if sub == "-h" || sub == "--help" || sub == "help" {
        return Ok(CliAction::Help(HelpTopic::Base));
    }
    let rest = &tokens[1..];
    if has_help_flag(rest) {
        return Ok(CliAction::Help(HelpTopic::Base));
    }

    let cmd = match sub.as_str() {
        "create" => parse_base_create(rest)?,
        "list" => {
            ensure_no_extra_tokens(rest)?;
            BaseCommand::List
        }
        "tag" => parse_base_tag(rest)?,
        "untag" => parse_base_untag(rest)?,
        "rm" => parse_base_rm(rest)?,
        other if other.starts_with('-') => return Err(ParseError::UnknownFlag(other.to_owned())),
        other => return Err(ParseError::UnknownCommand(format!("base {other}"))),
    };
    Ok(CliAction::Command(Command::Base(cmd)))
}

fn parse_base_create(tokens: &[String]) -> Result<BaseCommand, ParseError> {
    let mut dir: Option<PathBuf> = None;
    let mut tag: Option<TagName> = None;
    let mut excludes: Vec<String> = Vec::new();
    let mut positional_only = false;
    let mut idx = 0;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        if !positional_only && tok == "--" {
            positional_only = true;
            idx += 1;
            continue;
        }
        if !positional_only && tok == "--tag" {
            let val = tokens
                .get(idx + 1)
                .ok_or_else(|| ParseError::MissingFlagValue("--tag".to_owned()))?;
            set_unique_tag(&mut tag, val)?;
            idx += 2;
            continue;
        }
        if !positional_only {
            if let Some(val) = tok.strip_prefix("--tag=") {
                if val.is_empty() {
                    return Err(ParseError::MissingFlagValue("--tag".to_owned()));
                }
                set_unique_tag(&mut tag, val)?;
                idx += 1;
                continue;
            }
        }
        if !positional_only && tok == "--exclude" {
            let val = tokens
                .get(idx + 1)
                .ok_or_else(|| ParseError::MissingFlagValue("--exclude".to_owned()))?;
            if val.is_empty() {
                return Err(ParseError::MissingFlagValue("--exclude".to_owned()));
            }
            excludes.push(val.clone());
            idx += 2;
            continue;
        }
        if !positional_only {
            if let Some(val) = tok.strip_prefix("--exclude=") {
                if val.is_empty() {
                    return Err(ParseError::MissingFlagValue("--exclude".to_owned()));
                }
                excludes.push(val.to_owned());
                idx += 1;
                continue;
            }
            if tok.starts_with('-') {
                return Err(ParseError::UnknownFlag(tok.clone()));
            }
        }

        if dir.is_none() {
            dir = Some(PathBuf::from(tok));
        } else {
            return Err(ParseError::UnexpectedArgument(tok.clone()));
        }
        idx += 1;
    }

    let dir = dir.ok_or(ParseError::MissingArgument("dir"))?;
    Ok(BaseCommand::Create { dir, tag, excludes })
}

fn parse_base_tag(tokens: &[String]) -> Result<BaseCommand, ParseError> {
    let pos = collect_positionals_no_flags(tokens)?;
    let raw_tag = pos.first().ok_or(ParseError::MissingArgument("tag"))?;
    let raw_base = pos.get(1).ok_or(ParseError::MissingArgument("base"))?;
    if let Some(extra) = pos.get(2) {
        return Err(ParseError::UnexpectedArgument((*extra).clone()));
    }
    let tag = parse_tag_field(raw_tag)?;
    let base = parse_base_field(raw_base)?;
    Ok(BaseCommand::Tag { tag, base })
}

fn parse_base_untag(tokens: &[String]) -> Result<BaseCommand, ParseError> {
    let pos = collect_positionals_no_flags(tokens)?;
    let raw_tag = pos.first().ok_or(ParseError::MissingArgument("tag"))?;
    if let Some(extra) = pos.get(1) {
        return Err(ParseError::UnexpectedArgument((*extra).clone()));
    }
    let tag = parse_tag_field(raw_tag)?;
    Ok(BaseCommand::Untag { tag })
}

fn parse_base_rm(tokens: &[String]) -> Result<BaseCommand, ParseError> {
    let mut cascade = false;
    let mut raw_base: Option<&String> = None;
    let mut positional_only = false;

    for tok in tokens {
        if !positional_only && tok == "--" {
            positional_only = true;
            continue;
        }
        if !positional_only && tok == "--cascade" {
            cascade = true;
            continue;
        }
        if !positional_only && tok.starts_with('-') {
            return Err(ParseError::UnknownFlag(tok.clone()));
        }
        if raw_base.is_none() {
            raw_base = Some(tok);
        } else {
            return Err(ParseError::UnexpectedArgument(tok.clone()));
        }
    }

    let raw_base = raw_base.ok_or(ParseError::MissingArgument("base"))?;
    let base = parse_base_field(raw_base)?;
    Ok(BaseCommand::Rm { base, cascade })
}

fn parse_view(tokens: &[String]) -> Result<CliAction, ParseError> {
    let Some(sub) = tokens.first() else {
        return Ok(CliAction::Help(HelpTopic::View));
    };
    if sub == "-h" || sub == "--help" || sub == "help" {
        return Ok(CliAction::Help(HelpTopic::View));
    }
    let rest = &tokens[1..];
    if has_help_flag(rest) {
        return Ok(CliAction::Help(HelpTopic::View));
    }

    let cmd = match sub.as_str() {
        "create" => parse_view_create(rest)?,
        "list" => {
            ensure_no_extra_tokens(rest)?;
            ViewCommand::List
        }
        "path" => {
            let view_id = parse_single_view_id(rest)?;
            ViewCommand::Path { view_id }
        }
        "rm" => {
            let view_id = parse_single_view_id(rest)?;
            ViewCommand::Rm { view_id }
        }
        other if other.starts_with('-') => return Err(ParseError::UnknownFlag(other.to_owned())),
        other => return Err(ParseError::UnknownCommand(format!("view {other}"))),
    };
    Ok(CliAction::Command(Command::View(cmd)))
}

fn parse_view_create(tokens: &[String]) -> Result<ViewCommand, ParseError> {
    let mut raw_base: Option<&String> = None;
    let mut raw_view_id: Option<&String> = None;
    let mut link: Option<PathBuf> = None;
    let mut positional_only = false;
    let mut idx = 0;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        if !positional_only && tok == "--" {
            positional_only = true;
            idx += 1;
            continue;
        }
        if !positional_only && tok == "--link" {
            let val = tokens
                .get(idx + 1)
                .ok_or_else(|| ParseError::MissingFlagValue("--link".to_owned()))?;
            if val.is_empty() {
                return Err(ParseError::MissingFlagValue("--link".to_owned()));
            }
            if link.is_some() {
                return Err(ParseError::DuplicateFlag("--link"));
            }
            link = Some(PathBuf::from(val));
            idx += 2;
            continue;
        }
        if !positional_only {
            if let Some(val) = tok.strip_prefix("--link=") {
                if val.is_empty() {
                    return Err(ParseError::MissingFlagValue("--link".to_owned()));
                }
                if link.is_some() {
                    return Err(ParseError::DuplicateFlag("--link"));
                }
                link = Some(PathBuf::from(val));
                idx += 1;
                continue;
            }
            if tok.starts_with('-') {
                return Err(ParseError::UnknownFlag(tok.clone()));
            }
        }

        if raw_base.is_none() {
            raw_base = Some(tok);
        } else if raw_view_id.is_none() {
            raw_view_id = Some(tok);
        } else {
            return Err(ParseError::UnexpectedArgument(tok.clone()));
        }
        idx += 1;
    }

    let raw_base = raw_base.ok_or(ParseError::MissingArgument("base"))?;
    let base = parse_base_field(raw_base)?;
    let view_id = match raw_view_id {
        Some(raw) => Some(parse_view_id_field(raw)?),
        None => None,
    };
    Ok(ViewCommand::Create {
        base,
        view_id,
        link,
    })
}

fn parse_diff(tokens: &[String]) -> Result<CliAction, ParseError> {
    if has_help_flag(tokens) {
        return Ok(CliAction::Help(HelpTopic::Diff));
    }
    let view_id = parse_single_view_id(tokens)?;
    Ok(CliAction::Command(Command::Diff { view_id }))
}

fn parse_freeze(tokens: &[String]) -> Result<CliAction, ParseError> {
    if has_help_flag(tokens) {
        return Ok(CliAction::Help(HelpTopic::Freeze));
    }
    let mut raw_view_id: Option<&String> = None;
    let mut tag: Option<TagName> = None;
    let mut positional_only = false;
    let mut idx = 0;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        if !positional_only && tok == "--" {
            positional_only = true;
            idx += 1;
            continue;
        }
        if !positional_only && tok == "--tag" {
            let val = tokens
                .get(idx + 1)
                .ok_or_else(|| ParseError::MissingFlagValue("--tag".to_owned()))?;
            set_unique_tag(&mut tag, val)?;
            idx += 2;
            continue;
        }
        if !positional_only {
            if let Some(val) = tok.strip_prefix("--tag=") {
                if val.is_empty() {
                    return Err(ParseError::MissingFlagValue("--tag".to_owned()));
                }
                set_unique_tag(&mut tag, val)?;
                idx += 1;
                continue;
            }
            if tok.starts_with('-') {
                return Err(ParseError::UnknownFlag(tok.clone()));
            }
        }

        if raw_view_id.is_none() {
            raw_view_id = Some(tok);
        } else {
            return Err(ParseError::UnexpectedArgument(tok.clone()));
        }
        idx += 1;
    }

    let raw_view_id = raw_view_id.ok_or(ParseError::MissingArgument("view-id"))?;
    let view_id = parse_view_id_field(raw_view_id)?;
    Ok(CliAction::Command(Command::Freeze { view_id, tag }))
}

fn parse_apply(tokens: &[String]) -> Result<CliAction, ParseError> {
    if has_help_flag(tokens) {
        return Ok(CliAction::Help(HelpTopic::Apply));
    }
    let mut force = false;
    let mut raw_view_id: Option<&String> = None;
    let mut target_dir: Option<PathBuf> = None;
    let mut positional_only = false;

    for tok in tokens {
        if !positional_only && tok == "--" {
            positional_only = true;
            continue;
        }
        if !positional_only && tok == "--force" {
            force = true;
            continue;
        }
        if !positional_only && tok.starts_with('-') {
            return Err(ParseError::UnknownFlag(tok.clone()));
        }

        if raw_view_id.is_none() {
            raw_view_id = Some(tok);
        } else if target_dir.is_none() {
            target_dir = Some(PathBuf::from(tok));
        } else {
            return Err(ParseError::UnexpectedArgument(tok.clone()));
        }
    }

    let raw_view_id = raw_view_id.ok_or(ParseError::MissingArgument("view-id"))?;
    let target_dir = target_dir.ok_or(ParseError::MissingArgument("target-dir"))?;
    let view_id = parse_view_id_field(raw_view_id)?;
    Ok(CliAction::Command(Command::Apply {
        view_id,
        target_dir,
        force,
    }))
}

fn parse_daemon(tokens: &[String]) -> Result<CliAction, ParseError> {
    let Some(sub) = tokens.first() else {
        return Ok(CliAction::Help(HelpTopic::Daemon));
    };
    if sub == "-h" || sub == "--help" || sub == "help" {
        return Ok(CliAction::Help(HelpTopic::Daemon));
    }
    let rest = &tokens[1..];
    if has_help_flag(rest) {
        return Ok(CliAction::Help(HelpTopic::Daemon));
    }
    ensure_no_extra_tokens(rest)?;

    let cmd = match sub.as_str() {
        "run" => DaemonCommand::Run,
        "status" => DaemonCommand::Status,
        "stop" => DaemonCommand::Stop,
        other if other.starts_with('-') => return Err(ParseError::UnknownFlag(other.to_owned())),
        other => return Err(ParseError::UnknownCommand(format!("daemon {other}"))),
    };
    Ok(CliAction::Command(Command::Daemon(cmd)))
}

fn parse_single_view_id(tokens: &[String]) -> Result<ViewId, ParseError> {
    let pos = collect_positionals_no_flags(tokens)?;
    let raw = pos.first().ok_or(ParseError::MissingArgument("view-id"))?;
    if let Some(extra) = pos.get(1) {
        return Err(ParseError::UnexpectedArgument((*extra).clone()));
    }
    parse_view_id_field(raw)
}

fn ensure_no_extra_tokens(tokens: &[String]) -> Result<(), ParseError> {
    if let Some(tok) = tokens.first() {
        if tok.starts_with('-') {
            return Err(ParseError::UnknownFlag(tok.clone()));
        }
        return Err(ParseError::UnexpectedArgument(tok.clone()));
    }
    Ok(())
}

fn collect_positionals_no_flags(tokens: &[String]) -> Result<Vec<&String>, ParseError> {
    let mut out = Vec::new();
    let mut positional_only = false;
    for tok in tokens {
        if !positional_only && tok == "--" {
            positional_only = true;
            continue;
        }
        if !positional_only && tok.starts_with('-') {
            return Err(ParseError::UnknownFlag(tok.clone()));
        }
        out.push(tok);
    }
    Ok(out)
}

fn set_unique_tag(slot: &mut Option<TagName>, raw: &str) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError::DuplicateFlag("--tag"));
    }
    *slot = Some(parse_tag_field(raw)?);
    Ok(())
}

fn parse_tag_field(raw: &str) -> Result<TagName, ParseError> {
    TagName::new(raw).map_err(|error| ParseError::InvalidIdentifier {
        field: "tag",
        error,
    })
}

fn parse_base_field(raw: &str) -> Result<BaseSelector, ParseError> {
    BaseSelector::parse(raw).map_err(|error| ParseError::InvalidIdentifier {
        field: "base",
        error,
    })
}

fn parse_view_id_field(raw: &str) -> Result<ViewId, ParseError> {
    ViewId::new(raw).map_err(|error| ParseError::InvalidIdentifier {
        field: "view-id",
        error,
    })
}
