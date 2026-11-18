//! Deterministic wire framing and local IPC transport for Bit control-plane communication.
#![forbid(unsafe_code)]

pub mod codec;
pub mod message;
pub mod transport;

pub use codec::{
    decode_request, decode_response, encode_request, encode_response, read_frame, read_frame_opt,
    read_request, read_request_opt, read_response, write_frame, write_request, write_response,
    CodecError, FRAME_MAGIC, MAX_FRAME_LEN,
};
pub use message::{DaemonStatus, FreezeSummary, IpcRequest, IpcResponse, RemoteError, ViewSummary};
pub use transport::{
    exchange_io, serve_one_io, IpcEndpoint, IpcError, LocalClient, LocalListener, LocalStream,
};

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::thread;

    use bit_core::{
        AmbiguousCaseError, ApplyAction, ApplyConflict, ApplyConflictKind, ApplyOutput, ApplyPlan,
        BaseId, BaseInfo, BaseSelector, ContentHash, CoreError, DiffChange, DiffEntry, EntryName,
        HexDigestError, IdError, ModelError, PathError, RelPath, RemoveBaseOutput, StoreError,
        TagName, Timestamp, TreeEntry, ViewId, ViewInfo,
    };

    use super::*;

    fn sample_base_id(seed: u8) -> BaseId {
        BaseId::from_bytes([seed; 32])
    }

    fn sample_hash(seed: u8) -> ContentHash {
        ContentHash::from_bytes([seed; 32])
    }

    #[test]
    fn all_ipc_requests_roundtrip_deterministically() {
        let requests = vec![
            IpcRequest::Ping,
            IpcRequest::Status,
            IpcRequest::Shutdown,
            IpcRequest::CreateBase {
                dir: PathBuf::from("/tmp/project"),
                tag: Some(TagName::new("initial-v1").unwrap()),
                excludes: vec!["target".to_owned(), "*.log".to_owned()],
            },
            IpcRequest::CreateBase {
                dir: PathBuf::from("/tmp/plain"),
                tag: None,
                excludes: Vec::new(),
            },
            IpcRequest::ListBases,
            IpcRequest::SetTag {
                tag: TagName::new("stable").unwrap(),
                base: BaseSelector::Id(sample_base_id(0x11)),
            },
            IpcRequest::DeleteTag {
                tag: TagName::new("stable").unwrap(),
            },
            IpcRequest::RemoveBase {
                selector: BaseSelector::Tag(TagName::new("old-tag").unwrap()),
                cascade: true,
            },
            IpcRequest::CreateView {
                base: BaseSelector::Tag(TagName::new("stable").unwrap()),
                view_id: Some(ViewId::new("agent-42").unwrap()),
                link_path: Some(PathBuf::from("/tmp/external-link")),
            },
            IpcRequest::CreateView {
                base: BaseSelector::Id(sample_base_id(0x22)),
                view_id: None,
                link_path: None,
            },
            IpcRequest::ListViews,
            IpcRequest::ViewPath {
                view_id: ViewId::new("agent-42").unwrap(),
            },
            IpcRequest::RemoveView {
                view_id: ViewId::new("agent-42").unwrap(),
            },
            IpcRequest::DiffView {
                view_id: ViewId::new("agent-42").unwrap(),
            },
            IpcRequest::FreezeView {
                view_id: ViewId::new("agent-42").unwrap(),
                tag: Some(TagName::new("frozen-1").unwrap()),
            },
            IpcRequest::ApplyView {
                view_id: ViewId::new("agent-42").unwrap(),
                target_dir: PathBuf::from("/tmp/project"),
                force: true,
            },
        ];

        let mut stream_buf = Vec::new();
        for req in &requests {
            let encoded_a = encode_request(req);
            let encoded_b = encode_request(req);
            assert_eq!(encoded_a, encoded_b);
            assert_eq!(&decode_request(&encoded_a).unwrap(), req);
            write_request(&mut stream_buf, req).unwrap();
        }

        let mut cursor = Cursor::new(stream_buf);
        for expected in &requests {
            let actual = read_request_opt(&mut cursor).unwrap().unwrap();
            assert_eq!(&actual, expected);
        }
        assert_eq!(read_request_opt(&mut cursor).unwrap(), None);
    }

    #[test]
    fn all_ipc_responses_and_errors_roundtrip_deterministically() {
        let file_entry = TreeEntry::file(sample_hash(0xaa), 128, 0o755, Timestamp::new(1700, 42));
        let dir_entry = TreeEntry::directory(0o755, Timestamp::new(1700, 0));
        let sym_entry = TreeEntry::symlink("../shared/bin", Timestamp::new(1700, 9)).unwrap();

        let diff_entries = vec![
            DiffEntry {
                path: RelPath::new("src/main.rs").unwrap(),
                change: DiffChange::Added,
                before: None,
                after: Some(file_entry.clone()),
            },
            DiffEntry {
                path: RelPath::new("bin/run").unwrap(),
                change: DiffChange::Modified,
                before: Some(dir_entry.clone()),
                after: Some(sym_entry.clone()),
            },
            DiffEntry {
                path: RelPath::new("obsolete.txt").unwrap(),
                change: DiffChange::Deleted,
                before: Some(file_entry.clone()),
                after: None,
            },
        ];

        let responses = vec![
            IpcResponse::Pong,
            IpcResponse::Status(DaemonStatus {
                pid: 12345,
                mount_dir: PathBuf::from("/home/user/.bit/views"),
                store_dir: PathBuf::from("/home/user/.bit/store"),
                ipc_endpoint: PathBuf::from("/home/user/.bit/daemon.sock"),
                vfs_backend: "fuse".to_owned(),
                vfs_mounted: true,
                base_count: 3,
                view_count: 12,
            }),
            IpcResponse::ShuttingDown,
            IpcResponse::BaseCreated(BaseInfo {
                id: sample_base_id(0x01),
                tags: vec![TagName::new("v1").unwrap()],
                entry_count: 42,
                view_count: 0,
            }),
            IpcResponse::BaseList(vec![BaseInfo {
                id: sample_base_id(0x02),
                tags: Vec::new(),
                entry_count: 5,
                view_count: 2,
            }]),
            IpcResponse::TagSet {
                tag: TagName::new("latest").unwrap(),
                base_id: sample_base_id(0x02),
            },
            IpcResponse::TagDeleted,
            IpcResponse::BaseRemoved(RemoveBaseOutput {
                base_id: sample_base_id(0x02),
                removed_views: vec![ViewId::new("v1").unwrap()],
                removed_tags: vec![TagName::new("latest").unwrap()],
            }),
            IpcResponse::ViewCreated(ViewSummary {
                info: ViewInfo {
                    id: ViewId::new("v1").unwrap(),
                    base_id: sample_base_id(0x01),
                    overlay_entry_count: 0,
                    created_at: Timestamp::new(100, 200),
                },
                mount_path: PathBuf::from("/home/user/.bit/views/v1"),
                link_path: Some(PathBuf::from("/tmp/v1-link")),
            }),
            IpcResponse::ViewList(Vec::new()),
            IpcResponse::ViewPath(PathBuf::from("/home/user/.bit/views/v1")),
            IpcResponse::ViewRemoved,
            IpcResponse::ViewDiff(diff_entries.clone()),
            IpcResponse::ViewFrozen(FreezeSummary {
                base_id: sample_base_id(0x09),
                tag: Some(TagName::new("frozen").unwrap()),
                entry_count: 99,
            }),
            IpcResponse::ViewApplied(ApplyOutput {
                view_id: ViewId::new("v1").unwrap(),
                base_id: sample_base_id(0x01),
                plan: ApplyPlan {
                    diff: diff_entries,
                    actions: vec![
                        ApplyAction::RemoveLeaf {
                            path: RelPath::new("obsolete.txt").unwrap(),
                        },
                        ApplyAction::RemoveDirectory {
                            path: RelPath::new("old_dir").unwrap(),
                        },
                        ApplyAction::CreateDirectory {
                            path: RelPath::new("src").unwrap(),
                            mode: 0o755,
                        },
                        ApplyAction::UpdateDirectoryMode {
                            path: RelPath::new("bin").unwrap(),
                            mode: 0o700,
                        },
                        ApplyAction::WriteFile {
                            path: RelPath::new("src/main.rs").unwrap(),
                            entry: file_entry.clone(),
                        },
                        ApplyAction::WriteSymlink {
                            path: RelPath::new("bin/run").unwrap(),
                            target: "../shared/bin".to_owned(),
                        },
                    ],
                },
            }),
            IpcResponse::Error(RemoteError::Daemon("custom daemon error".to_owned())),
            IpcResponse::Error(RemoteError::Core(CoreError::BaseInUse {
                base_id: sample_base_id(0x33),
                views: vec![ViewId::new("active-1").unwrap()],
            })),
            IpcResponse::Error(RemoteError::Core(CoreError::ApplyConflicts(vec![
                ApplyConflict {
                    path: RelPath::new("README.md").unwrap(),
                    kind: ApplyConflictKind::ExternalModified,
                    expected: Some(file_entry),
                    actual: Some(dir_entry),
                },
            ]))),
            IpcResponse::Error(RemoteError::Core(CoreError::InvalidId(
                IdError::InvalidHex(HexDigestError::InvalidHexByte {
                    index: 3,
                    byte: b'g',
                }),
            ))),
            IpcResponse::Error(RemoteError::Core(CoreError::Model(
                ModelError::AmbiguousCase(AmbiguousCaseError {
                    requested: EntryName::new("readme").unwrap(),
                    candidates: vec![
                        EntryName::new("README").unwrap(),
                        EntryName::new("Readme").unwrap(),
                    ],
                }),
            ))),
            IpcResponse::Error(RemoteError::Core(CoreError::InvalidPath(
                PathError::DotTraversal("..".to_owned()),
            ))),
            IpcResponse::Error(RemoteError::Core(CoreError::Store(
                StoreError::BlobNotFound(sample_hash(0x77)),
            ))),
        ];

        for resp in &responses {
            let mut framed = Vec::new();
            write_response(&mut framed, resp).unwrap();
            let mut reader = Cursor::new(framed);
            let decoded = read_response(&mut reader).unwrap();
            assert_eq!(&decoded, resp);
        }
    }

    #[test]
    fn corrupt_magic_and_truncated_frames_are_rejected() {
        let mut bad = Vec::new();
        bad.extend_from_slice(b"NOPE\x00\x00\x00\x01\x01");
        let err = read_request(&mut Cursor::new(bad)).unwrap_err();
        assert_eq!(err, IpcError::Codec(CodecError::InvalidMagic(*b"NOPE")));

        let truncated = b"BIT1\x00\x00\x00\x05\x01\x02".to_vec();
        let err = read_request(&mut Cursor::new(truncated)).unwrap_err();
        assert_eq!(err, IpcError::Codec(CodecError::UnexpectedEof));
    }

    #[test]
    fn windows_pipe_name_derivation_is_deterministic() {
        let ep = IpcEndpoint::new("/home/alice/.bit/daemon.sock");
        let p1 = ep.windows_pipe_name();
        let p2 = ep.windows_pipe_name();
        assert_eq!(p1, p2);
        assert!(p1.starts_with(r"\\.\pipe\bit-"));

        let explicit = IpcEndpoint::new(r"\\.\pipe\bit-custom");
        assert_eq!(explicit.windows_pipe_name(), r"\\.\pipe\bit-custom");
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_listener_and_client_roundtrip_and_address_in_use_guard() {
        let tmp = std::env::temp_dir().join(format!(
            "bit-ipc-test-{}-{}",
            std::process::id(),
            Timestamp::now().nanos
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let endpoint = IpcEndpoint::new(tmp.join("daemon.sock"));

        // Before binding, client reports daemon unavailable.
        let missing = LocalClient::connect(&endpoint).unwrap_err();
        assert!(missing.is_daemon_unavailable());

        let listener = LocalListener::bind(endpoint.clone()).unwrap();

        // Second bind while listener is alive must fail with AddressInUse without unlinking socket.
        let second = LocalListener::bind(endpoint.clone()).unwrap_err();
        assert_eq!(
            second,
            IpcError::AddressInUse(endpoint.as_path().to_path_buf())
        );

        let server_thread = thread::spawn(move || loop {
            let mut stream = listener.accept().unwrap();
            let handled = serve_one_io(&mut stream, |req| match req {
                IpcRequest::Ping => IpcResponse::Pong,
                other => panic!("unexpected request: {other:?}"),
            })
            .unwrap();
            if handled {
                break;
            }
        });

        let mut client = LocalClient::connect(&endpoint).unwrap();
        let resp = client.send(&IpcRequest::Ping).unwrap();
        assert_eq!(resp, IpcResponse::Pong);

        server_thread.join().unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
