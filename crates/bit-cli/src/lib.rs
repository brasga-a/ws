//! Command-line interface and on-demand daemon client for Bit.
#![forbid(unsafe_code)]

pub mod args;
pub mod client;
pub mod runner;

pub use args::{
    parse_args, render_help, BaseCommand, CliAction, Command, DaemonCommand, HelpTopic, ParseError,
    ViewCommand,
};
pub use client::{
    CliClient, ClientError, DaemonLauncher, ExecutableDaemonLauncher, DEFAULT_AUTOSTART_TIMEOUT,
};
pub use runner::{execute_action, execute_command, run_from_env, CliError};

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use bit_core::{BaseId, BaseSelector, TagName, ViewId};

    use super::*;

    #[test]
    fn parses_all_base_subcommands() {
        assert_eq!(
            parse_args([
                "base",
                "create",
                "./app",
                "--tag",
                "v1",
                "--exclude",
                "target",
                "--exclude=*.log"
            ])
            .unwrap(),
            CliAction::Command(Command::Base(BaseCommand::Create {
                dir: PathBuf::from("./app"),
                tag: Some(TagName::new("v1").unwrap()),
                excludes: vec!["target".to_owned(), "*.log".to_owned()],
            }))
        );

        assert_eq!(
            parse_args(["base", "list"]).unwrap(),
            CliAction::Command(Command::Base(BaseCommand::List))
        );

        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(
            parse_args(["base", "tag", "latest", hex]).unwrap(),
            CliAction::Command(Command::Base(BaseCommand::Tag {
                tag: TagName::new("latest").unwrap(),
                base: BaseSelector::Id(BaseId::from_hex(hex).unwrap()),
            }))
        );

        assert_eq!(
            parse_args(["base", "untag", "latest"]).unwrap(),
            CliAction::Command(Command::Base(BaseCommand::Untag {
                tag: TagName::new("latest").unwrap(),
            }))
        );

        assert_eq!(
            parse_args(["base", "rm", "latest", "--cascade"]).unwrap(),
            CliAction::Command(Command::Base(BaseCommand::Rm {
                base: BaseSelector::Tag(TagName::new("latest").unwrap()),
                cascade: true,
            }))
        );
    }

    #[test]
    fn parses_all_view_and_top_level_lifecycle_commands() {
        assert_eq!(
            parse_args(["view", "create", "v1", "agent-1", "--link", "./work"]).unwrap(),
            CliAction::Command(Command::View(ViewCommand::Create {
                base: BaseSelector::Tag(TagName::new("v1").unwrap()),
                view_id: Some(ViewId::new("agent-1").unwrap()),
                link: Some(PathBuf::from("./work")),
            }))
        );

        // Unnamed View creation (`<view-id>` omitted) with `--link` before positional `<base>`.
        assert_eq!(
            parse_args(["view", "create", "--link=./auto", "v1"]).unwrap(),
            CliAction::Command(Command::View(ViewCommand::Create {
                base: BaseSelector::Tag(TagName::new("v1").unwrap()),
                view_id: None,
                link: Some(PathBuf::from("./auto")),
            }))
        );

        assert_eq!(
            parse_args(["view", "list"]).unwrap(),
            CliAction::Command(Command::View(ViewCommand::List))
        );
        assert_eq!(
            parse_args(["view", "path", "agent-1"]).unwrap(),
            CliAction::Command(Command::View(ViewCommand::Path {
                view_id: ViewId::new("agent-1").unwrap(),
            }))
        );
        assert_eq!(
            parse_args(["view", "rm", "agent-1"]).unwrap(),
            CliAction::Command(Command::View(ViewCommand::Rm {
                view_id: ViewId::new("agent-1").unwrap(),
            }))
        );

        assert_eq!(
            parse_args(["diff", "agent-1"]).unwrap(),
            CliAction::Command(Command::Diff {
                view_id: ViewId::new("agent-1").unwrap(),
            })
        );
        assert_eq!(
            parse_args(["freeze", "agent-1", "--tag", "v2"]).unwrap(),
            CliAction::Command(Command::Freeze {
                view_id: ViewId::new("agent-1").unwrap(),
                tag: Some(TagName::new("v2").unwrap()),
            })
        );
        assert_eq!(
            parse_args(["apply", "agent-1", "./out", "--force"]).unwrap(),
            CliAction::Command(Command::Apply {
                view_id: ViewId::new("agent-1").unwrap(),
                target_dir: PathBuf::from("./out"),
                force: true,
            })
        );

        assert_eq!(
            parse_args(["daemon", "run"]).unwrap(),
            CliAction::Command(Command::Daemon(DaemonCommand::Run))
        );
        assert_eq!(
            parse_args(["daemon", "status"]).unwrap(),
            CliAction::Command(Command::Daemon(DaemonCommand::Status))
        );
        assert_eq!(
            parse_args(["daemon", "stop"]).unwrap(),
            CliAction::Command(Command::Daemon(DaemonCommand::Stop))
        );
    }

    #[test]
    fn adr_0005_rejects_per_file_restore_and_checkout_commands() {
        for forbidden in [
            vec!["restore", "agent-1", "src/lib.rs"],
            vec!["checkout", "agent-1", "src/lib.rs"],
            vec!["view", "restore", "agent-1", "src/lib.rs"],
            vec!["view", "checkout", "agent-1", "src/lib.rs"],
        ] {
            assert!(
                matches!(parse_args(forbidden), Err(ParseError::UnknownCommand(_))),
                "per-file mutation commands must not exist on CLI (ADR-0005)"
            );
        }
    }

    #[test]
    fn rejects_invalid_identifiers_and_flags() {
        assert!(matches!(
            parse_args(["view", "create", "v1", "CON"]),
            Err(ParseError::InvalidIdentifier {
                field: "view-id",
                ..
            })
        ));
        assert!(matches!(
            parse_args(["base", "create", "./dir", "--unknown"]),
            Err(ParseError::UnknownFlag(_))
        ));
        assert!(matches!(
            parse_args(["apply", "agent-1"]),
            Err(ParseError::MissingArgument("target-dir"))
        ));
    }
}
