//! Linux FUSE single-mount userspace VFS adapter for Bit `Views` (ADR-0002, ADR-0004, ADR-0005).
//!
//! Exposes all active `Views` as subdirectories under a single space-free, single-user FUSE mount
//! (`~/.bit/views/<view-id>/`) backed by `Arc<dyn VfsOperations>`.
//!
//! - `<mount>/` is strictly read-only (`EROFS`).
//! - Cross-`View` `RENAME` returns `EXDEV`.
//! - Hard `LINK` returns `EOPNOTSUPP`.
//! - `allow_other` / `allow_root` mount options are explicitly rejected.
//! - `/proc/mounts` inspection and `fusermount3 -uz` / `fusermount -uz` helpers recover stale mounts.

#![forbid(unsafe_code)]

pub mod config;
pub mod dispatch;
pub mod lifecycle;
pub mod protocol;

pub use config::{
    FuseConfigError, FuseMountConfig, DEFAULT_ATTR_TTL, DEFAULT_ENTRY_TTL, DEFAULT_FSNAME,
    DEFAULT_HOME_SUBDIRS, DEFAULT_MAX_WRITE, DEFAULT_ROOT_ENTRY_TTL, DEFAULT_SUBTYPE,
    MIN_MAX_WRITE,
};
pub use dispatch::{FuseDispatcher, FuseSession};
pub use lifecycle::{
    build_fusermount_mount_command, build_lazy_unmount_command, build_lazy_unmount_spec,
    classify_mount_state, find_fuse_mount, parse_proc_mounts, unescape_proc_mount_field,
    FuseLifecycleError, FuseMountHandle, FuseMountLifecycle, FusermountBinary, LazyUnmountSpec,
    MountState, ProcMountEntry, SystemFuseMountLifecycle, DEV_FUSE_PATH, PROC_MOUNTS_PATH,
};
pub use protocol::{
    build_request_frame, decode_dirents, node_kind_to_dirent_type, parse_response_frame,
    FuseAccessIn, FuseAttr, FuseAttrOut, FuseCreateIn, FuseCreateOut, FuseDirent, FuseEntryOut,
    FuseFlushIn, FuseFsyncIn, FuseInHeader, FuseInitIn, FuseInitOut, FuseLinkIn, FuseMkdirIn,
    FuseOpcode, FuseOpenIn, FuseOpenOut, FuseOutHeader, FuseProtocolError, FuseReadIn,
    FuseReleaseIn, FuseRename2In, FuseRenameIn, FuseSetAttrIn, FuseStatfsOut, FuseSymlinkIn,
    FuseWriteIn, FuseWriteOut, WireReader, WireWriter, FUSE_KERNEL_MINOR_VERSION,
    FUSE_KERNEL_VERSION, FUSE_ROOT_ID,
};

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::io::{self, Cursor, Read, Write};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use bit_core::{
        BaseInput, BaseSelector, ControlPlane, CoreEngine, DiffChange, InMemoryCoreEngine,
        InputEntry, TagName, VfsOperations, ViewId, ROOT_INO, S_IFDIR, S_IFLNK, S_IFREG,
    };

    use super::*;
    use crate::protocol::{
        DT_DIR, DT_REG, EACCES, EBADF, EEXIST, EISDIR, ENODEV, ENOENT, ENOTCONN, ENOTEMPTY,
        EOPNOTSUPP, EROFS, EXDEV, FATTR_MODE, FATTR_SIZE, LINUX_O_CREAT, LINUX_O_EXCL,
        LINUX_O_RDONLY, LINUX_O_RDWR, LINUX_O_TRUNC, LINUX_O_WRONLY,
    };

    fn make_engine_and_dispatcher() -> (Arc<InMemoryCoreEngine>, FuseDispatcher) {
        let engine = Arc::new(CoreEngine::in_memory());
        let base_info = engine
            .create_base(
                BaseInput::Entries(vec![
                    InputEntry::file("README.md", b"hello from base\n".to_vec())
                        .expect("valid file"),
                    InputEntry::file(
                        "dir/nested/app.rs",
                        b"pub fn value() -> u32 { 42 }\n".to_vec(),
                    )
                    .expect("valid file"),
                    InputEntry::symlink("dir/doc-link", "../README.md").expect("valid symlink"),
                ]),
                Some(TagName::new("v1").expect("valid tag")),
            )
            .expect("base created");

        engine
            .create_view(
                ViewId::new("view-a").expect("valid view id"),
                BaseSelector::Id(base_info.id),
            )
            .expect("view-a created");
        engine
            .create_view(
                ViewId::new("view-b").expect("valid view id"),
                BaseSelector::Id(base_info.id),
            )
            .expect("view-b created");

        let cfg = FuseMountConfig::for_home("/home/tester")
            .expect("valid default config")
            .with_attr_ttl(Duration::from_secs(2))
            .with_entry_ttl(Duration::from_secs(5))
            .with_root_entry_ttl(Duration::ZERO)
            .with_owner(1000, 1000);

        let vfs: Arc<dyn VfsOperations> = engine.clone();
        let dispatcher = FuseDispatcher::new(vfs, cfg).expect("valid dispatcher");
        (engine, dispatcher)
    }

    fn cstr_payload(s: &str) -> Vec<u8> {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        v
    }

    fn send_wire(
        dispatcher: &FuseDispatcher,
        unique: u64,
        opcode: FuseOpcode,
        nodeid: u64,
        body: &[u8],
    ) -> (FuseOutHeader, Vec<u8>) {
        let req = build_request_frame(unique, opcode, nodeid, 1000, 1000, 99, body);
        let resp = dispatcher
            .dispatch_packet(&req)
            .expect("expected response frame");
        let (hdr, out_body) = parse_response_frame(&resp).expect("valid response frame");
        assert_eq!(hdr.unique, unique);
        (hdr, out_body.to_vec())
    }

    #[test]
    fn config_defaults_and_allow_other_rejection() {
        let cfg = FuseMountConfig::for_home("/home/alice").expect("valid home config");
        assert_eq!(cfg.mount_path, PathBuf::from("/home/alice/.bit/views"));
        assert_eq!(cfg.fsname, "bit");
        assert!(!cfg.allow_other);
        let opts = cfg.to_mount_options_string().expect("valid options");
        assert_eq!(opts, "fsname=bit,subtype=bit,default_permissions");

        // Reject allow_other boolean flag.
        let bad_flag = FuseMountConfig::new("/home/alice/.bit/views").with_allow_other(true);
        assert_eq!(
            bad_flag.validate(),
            Err(FuseConfigError::AllowOtherForbidden)
        );
        assert!(FuseDispatcher::new(Arc::new(CoreEngine::in_memory()), bad_flag.clone()).is_err());
        assert_eq!(
            build_fusermount_mount_command(FusermountBinary::Fusermount3, &bad_flag).unwrap_err(),
            FuseConfigError::AllowOtherForbidden
        );

        // Reject allow_other and allow_root in option strings.
        for forbidden in [
            "allow_other",
            "default_permissions,allow_other",
            "allow_other=1",
            "allow_root",
        ] {
            let err = FuseMountConfig::new("/home/alice/.bit/views")
                .with_mount_options(forbidden)
                .unwrap_err();
            assert_eq!(err, FuseConfigError::AllowOtherForbidden);
        }

        // Reject spaces in mount path to preserve space-free path invariant.
        let spaced = FuseMountConfig::new("/home/alice/my views");
        assert!(matches!(
            spaced.validate(),
            Err(FuseConfigError::MountPathContainsWhitespace(_))
        ));

        // Reject relative mount path.
        let rel = FuseMountConfig::new(".bit/views");
        assert!(matches!(
            rel.validate(),
            Err(FuseConfigError::RelativeMountPath(_))
        ));
    }

    #[test]
    fn wire_lookup_getattr_readdir_and_read_from_shared_base() {
        let (engine, dispatcher) = make_engine_and_dispatcher();

        // FUSE_INIT handshake
        let init_req = FuseInitIn {
            major: 7,
            minor: 39,
            max_readahead: 65536,
            flags: 0,
        };
        let (hdr, body) = send_wire(
            &dispatcher,
            1,
            FuseOpcode::Init,
            ROOT_INO,
            &init_req.encode(),
        );
        assert_eq!(hdr.error, 0);
        let init_out = FuseInitOut::decode(&body).expect("decode init_out");
        assert_eq!(init_out.major, FUSE_KERNEL_VERSION);
        assert_eq!(init_out.minor, FUSE_KERNEL_MINOR_VERSION);
        assert!(dispatcher.is_initialized());

        // GETATTR on mount root `<mount>/`
        let (hdr, body) = send_wire(&dispatcher, 2, FuseOpcode::GetAttr, ROOT_INO, &[]);
        assert_eq!(hdr.error, 0);
        let root_attr = FuseAttrOut::decode(&body).expect("decode root attr");
        assert_eq!(root_attr.attr.ino, ROOT_INO);
        assert_eq!(root_attr.attr.mode, S_IFDIR | 0o555);

        // OPENDIR + paginated READDIR on `<mount>/`
        let (hdr, body) = send_wire(
            &dispatcher,
            3,
            FuseOpcode::OpenDir,
            ROOT_INO,
            &FuseOpenIn {
                flags: LINUX_O_RDONLY,
                open_flags: 0,
            }
            .encode(),
        );
        assert_eq!(hdr.error, 0);
        let dir_open = FuseOpenOut::decode(&body).expect("decode opendir");

        // Read one entry at a time using a 40-byte buffer to exercise pagination cookies.
        let mut collected_names = Vec::new();
        let mut cursor_off = 0u64;
        loop {
            let rd = FuseReadIn {
                fh: dir_open.fh,
                offset: cursor_off,
                size: 40,
                ..FuseReadIn::default()
            };
            let (hdr, body) =
                send_wire(&dispatcher, 4, FuseOpcode::ReadDir, ROOT_INO, &rd.encode());
            assert_eq!(hdr.error, 0);
            if body.is_empty() {
                break;
            }
            let batch = decode_dirents(&body).expect("decode dirents");
            assert!(!batch.is_empty());
            for d in batch {
                assert_eq!(d.typ, DT_DIR);
                cursor_off = d.off;
                collected_names.push(d.name);
            }
        }
        assert_eq!(collected_names, vec![".", "..", "view-a", "view-b"]);

        let (hdr, _) = send_wire(
            &dispatcher,
            5,
            FuseOpcode::ReleaseDir,
            ROOT_INO,
            &FuseReleaseIn {
                fh: dir_open.fh,
                ..FuseReleaseIn::default()
            }
            .encode(),
        );
        assert_eq!(hdr.error, 0);

        // LOOKUP `<mount>/view-a` -> root_entry_ttl == 0, attr_ttl == 2
        let (hdr, body) = send_wire(
            &dispatcher,
            6,
            FuseOpcode::Lookup,
            ROOT_INO,
            &cstr_payload("view-a"),
        );
        assert_eq!(hdr.error, 0);
        let view_a_entry = FuseEntryOut::decode(&body).expect("decode view-a entry");
        assert_eq!(view_a_entry.entry_valid, 0);
        assert_eq!(view_a_entry.attr_valid, 2);
        let view_a_ino = view_a_entry.nodeid;

        // LOOKUP invalid root child -> ENOENT (not EROFS)
        let (hdr, _) = send_wire(
            &dispatcher,
            7,
            FuseOpcode::Lookup,
            ROOT_INO,
            &cstr_payload("invalid view!"),
        );
        assert_eq!(hdr.posix_errno(), Some(ENOENT));

        // LOOKUP `view-a/README.md` -> entry_ttl == 5
        let (hdr, body) = send_wire(
            &dispatcher,
            8,
            FuseOpcode::Lookup,
            view_a_ino,
            &cstr_payload("README.md"),
        );
        assert_eq!(hdr.error, 0);
        let readme_entry = FuseEntryOut::decode(&body).expect("decode readme");
        assert_eq!(readme_entry.entry_valid, 5);
        assert_eq!(readme_entry.attr.mode & S_IFREG, S_IFREG);

        // OPEN + READ `view-a/README.md`
        let (hdr, body) = send_wire(
            &dispatcher,
            9,
            FuseOpcode::Open,
            readme_entry.nodeid,
            &FuseOpenIn {
                flags: LINUX_O_RDONLY,
                open_flags: 0,
            }
            .encode(),
        );
        assert_eq!(hdr.error, 0);
        let open_out = FuseOpenOut::decode(&body).expect("decode open");

        let (hdr, data) = send_wire(
            &dispatcher,
            10,
            FuseOpcode::Read,
            readme_entry.nodeid,
            &FuseReadIn {
                fh: open_out.fh,
                offset: 0,
                size: 4096,
                ..FuseReadIn::default()
            }
            .encode(),
        );
        assert_eq!(hdr.error, 0);
        assert_eq!(data, b"hello from base\n");

        // Writing to a read-only file handle fails with EBADF.
        let (hdr, _) = send_wire(
            &dispatcher,
            11,
            FuseOpcode::Write,
            readme_entry.nodeid,
            &FuseWriteIn::encode_payload(open_out.fh, 0, 0, b"nope"),
        );
        assert_eq!(hdr.posix_errno(), Some(EBADF));

        let (hdr, _) = send_wire(
            &dispatcher,
            12,
            FuseOpcode::Release,
            readme_entry.nodeid,
            &FuseReleaseIn {
                fh: open_out.fh,
                ..FuseReleaseIn::default()
            }
            .encode(),
        );
        assert_eq!(hdr.error, 0);

        // Reading from Base must not materialize any Overlay entries.
        let diff_a = engine
            .diff_view(&ViewId::new("view-a").expect("valid id"))
            .expect("diff view-a");
        assert!(diff_a.is_empty());
    }

    #[test]
    fn whole_file_cow_write_create_flush_fsync_isolates_views() {
        let (engine, dispatcher) = make_engine_and_dispatcher();

        let view_a_ino = dispatcher
            .lookup(ROOT_INO, "view-a")
            .expect("lookup view-a")
            .nodeid;
        let view_b_ino = dispatcher
            .lookup(ROOT_INO, "view-b")
            .expect("lookup view-b")
            .nodeid;
        let readme_a_ino = dispatcher
            .lookup(view_a_ino, "README.md")
            .expect("lookup view-a/README.md")
            .nodeid;
        let readme_b_ino = dispatcher
            .lookup(view_b_ino, "README.md")
            .expect("lookup view-b/README.md")
            .nodeid;

        // 1. Partial overwrite at offset on Base-backed file triggers whole-file CoW in view-a's Overlay.
        let rw_handle = dispatcher
            .open(readme_a_ino, LINUX_O_RDWR)
            .expect("open O_RDWR");
        let write_payload = FuseWriteIn::encode_payload(rw_handle.fh, 6, 0, b"from view-a!\n");
        let (hdr, body) = send_wire(
            &dispatcher,
            20,
            FuseOpcode::Write,
            readme_a_ino,
            &write_payload,
        );
        assert_eq!(hdr.error, 0);
        let write_out = FuseWriteOut::decode(&body).expect("decode write_out");
        assert_eq!(write_out.size, 13);

        // FLUSH + FSYNC + RELEASE on the handle
        let (hdr, _) = send_wire(
            &dispatcher,
            21,
            FuseOpcode::Flush,
            readme_a_ino,
            &FuseFlushIn {
                fh: rw_handle.fh,
                ..FuseFlushIn::default()
            }
            .encode(),
        );
        assert_eq!(hdr.error, 0);
        let (hdr, _) = send_wire(
            &dispatcher,
            22,
            FuseOpcode::Fsync,
            readme_a_ino,
            &FuseFsyncIn {
                fh: rw_handle.fh,
                fsync_flags: 1,
                padding: 0,
            }
            .encode(),
        );
        assert_eq!(hdr.error, 0);
        dispatcher.release(rw_handle.fh).expect("release");

        // Verify view-a sees CoW bytes while view-b still reads untouched Base bytes.
        assert_eq!(
            dispatcher
                .read(readme_a_ino, 0, 0, 4096)
                .expect("read view-a"),
            b"hello from view-a!\n"
        );
        assert_eq!(
            dispatcher
                .read(readme_b_ino, 0, 0, 4096)
                .expect("read view-b"),
            b"hello from base\n"
        );

        // Whole-file rewrite via O_WRONLY | O_TRUNC on README.md in view-a also isolates cleanly.
        let trunc_handle = dispatcher
            .open(readme_a_ino, LINUX_O_WRONLY | LINUX_O_TRUNC)
            .expect("open O_WRONLY | O_TRUNC");
        dispatcher
            .write(readme_a_ino, trunc_handle.fh, 0, b"rewritten\n")
            .expect("write truncated");
        dispatcher
            .release(trunc_handle.fh)
            .expect("release trunc_handle");
        assert_eq!(
            dispatcher
                .read(readme_a_ino, 0, 0, 4096)
                .expect("read rewritten"),
            b"rewritten\n"
        );
        assert_eq!(
            dispatcher
                .read(readme_b_ino, 0, 0, 4096)
                .expect("view-b still intact"),
            b"hello from base\n"
        );

        // 2. CREATE + WRITE new file in view-a via wire frames, plus O_EXCL EEXIST check.
        let create_in = FuseCreateIn {
            flags: LINUX_O_CREAT | LINUX_O_EXCL | LINUX_O_RDWR,
            mode: S_IFREG | 0o664,
            umask: 0o022,
            padding: 0,
            name: "created.txt".to_owned(),
        };
        let (hdr, body) = send_wire(
            &dispatcher,
            23,
            FuseOpcode::Create,
            view_a_ino,
            &create_in.encode(),
        );
        assert_eq!(hdr.error, 0);
        let created = FuseCreateOut::decode(&body).expect("decode create_out");
        assert_eq!(created.entry.attr.mode, S_IFREG | 0o644);

        // Duplicate O_EXCL create fails with EEXIST.
        let (hdr, _) = send_wire(
            &dispatcher,
            24,
            FuseOpcode::Create,
            view_a_ino,
            &create_in.encode(),
        );
        assert_eq!(hdr.posix_errno(), Some(EEXIST));

        dispatcher
            .write(
                created.entry.nodeid,
                created.open.fh,
                0,
                b"new overlay file",
            )
            .expect("write created.txt");
        dispatcher
            .release(created.open.fh)
            .expect("release created");

        // SETATTR chmod + truncate
        let setattr_out = dispatcher
            .setattr(
                created.entry.nodeid,
                FuseSetAttrIn {
                    valid: FATTR_MODE | FATTR_SIZE,
                    mode: 0o755,
                    size: 11,
                    ..FuseSetAttrIn::default()
                },
            )
            .expect("setattr");
        assert_eq!(setattr_out.attr.mode, S_IFREG | 0o755);
        assert_eq!(setattr_out.attr.size, 11);
        assert_eq!(
            dispatcher
                .read(created.entry.nodeid, 0, 0, 100)
                .expect("read truncated"),
            b"new overlay"
        );

        // Diff confirms view-a has Added + Modified while view-b has empty Overlay.
        let diff_a = engine
            .diff_view(&ViewId::new("view-a").expect("id"))
            .expect("diff a");
        assert_eq!(diff_a.len(), 2);
        assert!(diff_a
            .iter()
            .any(|d| d.path.as_str() == "README.md" && d.change == DiffChange::Modified));
        assert!(diff_a
            .iter()
            .any(|d| d.path.as_str() == "created.txt" && d.change == DiffChange::Added));
        assert!(engine
            .diff_view(&ViewId::new("view-b").expect("id"))
            .expect("diff b")
            .is_empty());
    }

    #[test]
    fn directory_rename_symlink_mkdir_unlink_rmdir_and_inode_preservation() {
        let (_engine, dispatcher) = make_engine_and_dispatcher();

        let view_a_ino = dispatcher
            .lookup(ROOT_INO, "view-a")
            .expect("lookup view-a")
            .nodeid;
        let view_b_ino = dispatcher
            .lookup(ROOT_INO, "view-b")
            .expect("lookup view-b")
            .nodeid;

        // Pre-lookup `view-a/dir`, `view-a/dir/nested`, and `view-a/dir/nested/app.rs`
        let dir_ino = dispatcher
            .lookup(view_a_ino, "dir")
            .expect("lookup dir")
            .nodeid;
        let nested_ino = dispatcher
            .lookup(dir_ino, "nested")
            .expect("lookup nested")
            .nodeid;
        let app_ino = dispatcher
            .lookup(nested_ino, "app.rs")
            .expect("lookup app.rs")
            .nodeid;

        // Rename `view-a/dir` -> `view-a/renamed_dir` via wire FUSE_RENAME
        let rename_req = FuseRenameIn {
            newdir: view_a_ino,
            oldname: "dir".to_owned(),
            newname: "renamed_dir".to_owned(),
        };
        let (hdr, _) = send_wire(
            &dispatcher,
            30,
            FuseOpcode::Rename,
            view_a_ino,
            &rename_req.encode(),
        );
        assert_eq!(hdr.error, 0);

        // Old name is gone in view-a, new name preserves exact `dir_ino` and nested `app_ino`!
        assert_eq!(dispatcher.lookup(view_a_ino, "dir").unwrap_err(), ENOENT);
        let moved_dir = dispatcher
            .lookup(view_a_ino, "renamed_dir")
            .expect("lookup renamed_dir");
        assert_eq!(moved_dir.nodeid, dir_ino);

        // Reading using the pre-rename `app_ino` still resolves to `view-a/renamed_dir/nested/app.rs`!
        let app_bytes = dispatcher
            .read(app_ino, 0, 0, 4096)
            .expect("read via preserved app_ino");
        assert_eq!(app_bytes, b"pub fn value() -> u32 { 42 }\n");

        // Sibling `view-b/dir/nested/app.rs` is unaffected.
        let b_dir_ino = dispatcher
            .lookup(view_b_ino, "dir")
            .expect("view-b/dir still exists")
            .nodeid;
        let b_nested_ino = dispatcher
            .lookup(b_dir_ino, "nested")
            .expect("view-b/dir/nested")
            .nodeid;
        let b_app_ino = dispatcher
            .lookup(b_nested_ino, "app.rs")
            .expect("view-b/dir/nested/app.rs")
            .nodeid;
        assert_eq!(
            dispatcher.read(b_app_ino, 0, 0, 4096).expect("read view-b"),
            b"pub fn value() -> u32 { 42 }\n"
        );

        // SYMLINK (`name\0target\0`) + READLINK (including external target)
        let sym_req = FuseSymlinkIn {
            name: "ext-tool".to_owned(),
            target: "/opt/toolchains/bin/tool".to_owned(),
        };
        let (hdr, body) = send_wire(
            &dispatcher,
            31,
            FuseOpcode::Symlink,
            view_a_ino,
            &sym_req.encode(),
        );
        assert_eq!(hdr.error, 0);
        let sym_entry = FuseEntryOut::decode(&body).expect("decode symlink entry");
        assert_eq!(sym_entry.attr.mode & S_IFLNK, S_IFLNK);

        let (hdr, target_bytes) =
            send_wire(&dispatcher, 32, FuseOpcode::ReadLink, sym_entry.nodeid, &[]);
        assert_eq!(hdr.error, 0);
        assert_eq!(target_bytes, b"/opt/toolchains/bin/tool");

        // MKDIR + UNLINK + RMDIR
        let mkdir_req = FuseMkdirIn {
            mode: 0o775,
            umask: 0o022,
            name: "sub".to_owned(),
        };
        let (hdr, body) = send_wire(
            &dispatcher,
            33,
            FuseOpcode::Mkdir,
            view_a_ino,
            &mkdir_req.encode(),
        );
        assert_eq!(hdr.error, 0);
        let sub_entry = FuseEntryOut::decode(&body).expect("decode mkdir");
        assert_eq!(sub_entry.attr.mode, S_IFDIR | 0o755);

        let child_file = dispatcher
            .create(
                sub_entry.nodeid,
                &FuseCreateIn {
                    flags: LINUX_O_CREAT | LINUX_O_WRONLY,
                    mode: 0o644,
                    umask: 0,
                    padding: 0,
                    name: "temp.txt".to_owned(),
                },
            )
            .expect("create temp.txt");
        dispatcher.release(child_file.open.fh).expect("release");

        // RMDIR on non-empty directory returns ENOTEMPTY
        let (hdr, _) = send_wire(
            &dispatcher,
            34,
            FuseOpcode::Rmdir,
            view_a_ino,
            &cstr_payload("sub"),
        );
        assert_eq!(hdr.posix_errno(), Some(ENOTEMPTY));

        // UNLINK child then RMDIR succeeds
        let (hdr, _) = send_wire(
            &dispatcher,
            35,
            FuseOpcode::Unlink,
            sub_entry.nodeid,
            &cstr_payload("temp.txt"),
        );
        assert_eq!(hdr.error, 0);
        let (hdr, _) = send_wire(
            &dispatcher,
            36,
            FuseOpcode::Rmdir,
            view_a_ino,
            &cstr_payload("sub"),
        );
        assert_eq!(hdr.error, 0);
        assert_eq!(dispatcher.lookup(view_a_ino, "sub").unwrap_err(), ENOENT);
    }

    #[test]
    fn enforces_erofs_on_mount_root_exdev_across_views_and_eopnotsupp_on_link() {
        let (_engine, dispatcher) = make_engine_and_dispatcher();

        let view_a_ino = dispatcher
            .lookup(ROOT_INO, "view-a")
            .expect("lookup view-a")
            .nodeid;
        let view_b_ino = dispatcher
            .lookup(ROOT_INO, "view-b")
            .expect("lookup view-b")
            .nodeid;
        let readme_a_ino = dispatcher
            .lookup(view_a_ino, "README.md")
            .expect("lookup view-a/README.md")
            .nodeid;

        // 1. Every mutating opcode at `<mount>/` (`ROOT_INO`) must return `EROFS` (30).
        let (hdr, _) = send_wire(
            &dispatcher,
            40,
            FuseOpcode::Mkdir,
            ROOT_INO,
            &FuseMkdirIn {
                mode: 0o755,
                umask: 0,
                name: "view-c".to_owned(),
            }
            .encode(),
        );
        assert_eq!(hdr.posix_errno(), Some(EROFS));

        let (hdr, _) = send_wire(
            &dispatcher,
            41,
            FuseOpcode::Create,
            ROOT_INO,
            &FuseCreateIn {
                flags: LINUX_O_CREAT | LINUX_O_WRONLY,
                mode: 0o644,
                umask: 0,
                padding: 0,
                name: "root-file.txt".to_owned(),
            }
            .encode(),
        );
        assert_eq!(hdr.posix_errno(), Some(EROFS));

        let (hdr, _) = send_wire(
            &dispatcher,
            42,
            FuseOpcode::Unlink,
            ROOT_INO,
            &cstr_payload("view-a"),
        );
        assert_eq!(hdr.posix_errno(), Some(EROFS));

        let (hdr, _) = send_wire(
            &dispatcher,
            43,
            FuseOpcode::Rmdir,
            ROOT_INO,
            &cstr_payload("view-a"),
        );
        assert_eq!(hdr.posix_errno(), Some(EROFS));

        let (hdr, _) = send_wire(
            &dispatcher,
            44,
            FuseOpcode::Symlink,
            ROOT_INO,
            &FuseSymlinkIn {
                name: "root-link".to_owned(),
                target: "view-a".to_owned(),
            }
            .encode(),
        );
        assert_eq!(hdr.posix_errno(), Some(EROFS));

        let (hdr, _) = send_wire(
            &dispatcher,
            45,
            FuseOpcode::SetAttr,
            ROOT_INO,
            &FuseSetAttrIn {
                valid: FATTR_MODE,
                mode: 0o777,
                ..FuseSetAttrIn::default()
            }
            .encode(),
        );
        assert_eq!(hdr.posix_errno(), Some(EROFS));

        let (hdr, _) = send_wire(
            &dispatcher,
            46,
            FuseOpcode::Rename,
            ROOT_INO,
            &FuseRenameIn {
                newdir: ROOT_INO,
                oldname: "view-a".to_owned(),
                newname: "view-renamed".to_owned(),
            }
            .encode(),
        );
        assert_eq!(hdr.posix_errno(), Some(EROFS));

        // Moving a file from inside a View up into `<mount>/` also returns `EROFS`.
        let (hdr, _) = send_wire(
            &dispatcher,
            47,
            FuseOpcode::Rename,
            view_a_ino,
            &FuseRenameIn {
                newdir: ROOT_INO,
                oldname: "README.md".to_owned(),
                newname: "escaped.md".to_owned(),
            }
            .encode(),
        );
        assert_eq!(hdr.posix_errno(), Some(EROFS));

        //Read-only OPEN on directory returns EISDIR, write OPEN on `<mount>/` returns EROFS.
        assert_eq!(
            dispatcher.open(ROOT_INO, LINUX_O_RDONLY).unwrap_err(),
            EISDIR
        );
        assert_eq!(dispatcher.open(ROOT_INO, LINUX_O_RDWR).unwrap_err(), EROFS);

        // 2. Cross-View RENAME (`view-a/README.md` -> `view-b/README.md`) must return `EXDEV` (18).
        let (hdr, _) = send_wire(
            &dispatcher,
            48,
            FuseOpcode::Rename,
            view_a_ino,
            &FuseRenameIn {
                newdir: view_b_ino,
                oldname: "README.md".to_owned(),
                newname: "moved.md".to_owned(),
            }
            .encode(),
        );
        assert_eq!(hdr.posix_errno(), Some(EXDEV));

        // 3. Hard LINK (`FUSE_LINK`) must return `EOPNOTSUPP` (95).
        let (hdr, _) = send_wire(
            &dispatcher,
            49,
            FuseOpcode::Link,
            view_a_ino,
            &FuseLinkIn {
                oldnodeid: readme_a_ino,
                newname: "hardlink.md".to_owned(),
            }
            .encode(),
        );
        assert_eq!(hdr.posix_errno(), Some(EOPNOTSUPP));
    }

    #[test]
    fn strict_caller_uid_rejects_foreign_users_and_session_streams_frames() {
        let engine = Arc::new(CoreEngine::in_memory());
        let cfg = FuseMountConfig::new("/home/tester/.bit/views")
            .with_owner(1000, 1000)
            .with_strict_caller_uid(1000);
        let dispatcher = Arc::new(FuseDispatcher::new(engine, cfg).expect("dispatcher"));

        // Foreign UID 2000 is rejected with EACCES.
        let foreign_req = build_request_frame(1, FuseOpcode::GetAttr, ROOT_INO, 2000, 2000, 1, &[]);
        let foreign_resp = dispatcher.dispatch_packet(&foreign_req).expect("response");
        let (hdr, _) = parse_response_frame(&foreign_resp).expect("parse");
        assert_eq!(hdr.posix_errno(), Some(EACCES));

        // Stream multiple frames (INIT -> GETATTR -> FORGET [no reply] -> DESTROY) through FuseSession.
        let mut input = Vec::new();
        input.extend_from_slice(&build_request_frame(
            10,
            FuseOpcode::Init,
            ROOT_INO,
            1000,
            1000,
            1,
            &FuseInitIn {
                major: 7,
                minor: 31,
                max_readahead: 4096,
                flags: 0,
            }
            .encode(),
        ));
        input.extend_from_slice(&build_request_frame(
            11,
            FuseOpcode::Forget,
            ROOT_INO,
            1000,
            1000,
            1,
            &[0u8; 8],
        ));
        input.extend_from_slice(&build_request_frame(
            12,
            FuseOpcode::GetAttr,
            ROOT_INO,
            1000,
            1000,
            1,
            &[],
        ));
        input.extend_from_slice(&build_request_frame(
            13,
            FuseOpcode::Destroy,
            ROOT_INO,
            1000,
            1000,
            1,
            &[],
        ));

        let session = FuseSession::new(dispatcher.clone());
        let mut reader = Cursor::new(input);
        let mut output = Vec::new();
        let processed = session
            .serve_frames(&mut reader, &mut output)
            .expect("serve_frames succeeds");
        assert_eq!(processed, 4);
        assert!(session.is_stopped());
        assert!(dispatcher.is_destroyed());

        // Exactly 3 responses emitted (FORGET produces no reply).
        let mut slice = output.as_slice();
        let mut uniques = Vec::new();
        while !slice.is_empty() {
            let hdr = FuseOutHeader::decode(slice).expect("out hdr");
            assert_eq!(hdr.error, 0);
            uniques.push(hdr.unique);
            slice = &slice[hdr.len as usize..];
        }
        assert_eq!(uniques, vec![10, 12, 13]);
        let _ = DT_REG;
    }

    struct MockFuseDevice {
        steps: Vec<io::Result<Vec<u8>>>,
        idx: usize,
        replies: Vec<Vec<u8>>,
    }

    impl Read for MockFuseDevice {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.idx >= self.steps.len() {
                return Err(io::Error::from_raw_os_error(ENODEV));
            }
            let step = self.steps[self.idx].as_ref();
            self.idx += 1;
            match step {
                Ok(pkt) => {
                    buf[..pkt.len()].copy_from_slice(pkt);
                    Ok(pkt.len())
                }
                Err(e) => Err(match e.raw_os_error() {
                    Some(code) => io::Error::from_raw_os_error(code),
                    None => io::Error::new(e.kind(), e.to_string()),
                }),
            }
        }
    }

    impl Write for MockFuseDevice {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.replies.push(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn fuse_device_loop_handles_eintr_enoent_and_enodev_unmount() {
        let (_engine, dispatcher) = make_engine_and_dispatcher();
        let session = FuseSession::new(Arc::new(dispatcher));

        let getattr_pkt =
            build_request_frame(99, FuseOpcode::GetAttr, ROOT_INO, 1000, 1000, 1, &[]);
        let mut dev = MockFuseDevice {
            steps: vec![
                Err(io::Error::new(io::ErrorKind::Interrupted, "eintr")),
                Err(io::Error::from_raw_os_error(ENOENT)),
                Ok(getattr_pkt),
                Err(io::Error::from_raw_os_error(ENODEV)),
            ],
            idx: 0,
            replies: Vec::new(),
        };

        let count = session
            .serve_fuse_device(&mut dev)
            .expect("clean ENODEV exit");
        assert_eq!(count, 1);
        assert_eq!(dev.replies.len(), 1);
        let (hdr, _) = parse_response_frame(&dev.replies[0]).expect("reply");
        assert_eq!(hdr.unique, 99);
        assert_eq!(hdr.error, 0);
    }

    #[derive(Default)]
    struct MockLifecycle {
        state: Mutex<MountState>,
        unmounted_paths: Mutex<Vec<PathBuf>>,
    }

    impl FuseMountLifecycle for MockLifecycle {
        fn inspect_mount(&self, _mount_path: &Path) -> Result<MountState, FuseLifecycleError> {
            Ok(self.state.lock().expect("lock").clone())
        }

        fn lazy_unmount(&self, mount_path: &Path) -> Result<FusermountBinary, FuseLifecycleError> {
            self.unmounted_paths
                .lock()
                .expect("lock")
                .push(mount_path.to_path_buf());
            *self.state.lock().expect("lock") = MountState::NotMounted;
            Ok(FusermountBinary::Fusermount3)
        }
    }

    #[test]
    fn proc_mounts_stale_detection_and_lazy_unmount_commands() {
        let sample_proc_mounts = "\
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/nvme0n1p2 / ext4 rw,relatime 0 0
bit /home/alice/.bit/views fuse.bit rw,nosuid,nodev,relatime,user_id=1000,group_id=1000,default_permissions 0 0
fusectl /sys/fs/fuse/connections fusectl rw,relatime 0 0
custom /tmp/escaped\\040mount fuse rw,nosuid,nodev 0 0
";

        let entries = parse_proc_mounts(sample_proc_mounts);
        assert_eq!(entries.len(), 5);

        let found = find_fuse_mount(sample_proc_mounts, Path::new("/home/alice/.bit/views/"))
            .expect("found bit fuse mount");
        assert!(found.is_fuse());
        assert!(found.is_bit_fuse());
        assert_eq!(found.fs_type, "fuse.bit");
        assert_eq!(found.mount_point, PathBuf::from("/home/alice/.bit/views"));

        // Escaped octal space `\040` in `/proc/mounts` is decoded properly.
        let escaped = find_fuse_mount(sample_proc_mounts, Path::new("/tmp/escaped mount"))
            .expect("found escaped mount");
        assert_eq!(escaped.mount_point, PathBuf::from("/tmp/escaped mount"));

        // Active when stat probe succeeds (`None`), Stale when stat probe returns `ENOTCONN` (107).
        let active = classify_mount_state(
            sample_proc_mounts,
            Path::new("/home/alice/.bit/views"),
            None,
        );
        assert!(matches!(active, MountState::ActiveFuseMount(_)));
        assert!(!active.is_stale());

        let stale = classify_mount_state(
            sample_proc_mounts,
            Path::new("/home/alice/.bit/views"),
            Some(ENOTCONN),
        );
        assert!(stale.is_stale());
        assert!(stale.needs_lazy_unmount(false));

        let unmounted =
            classify_mount_state(sample_proc_mounts, Path::new("/home/bob/.bit/views"), None);
        assert_eq!(unmounted, MountState::NotMounted);

        // Verify unprivileged lazy-unmount command builders (`fusermount3 -uz` and `fusermount -uz`).
        let mount_target = Path::new("/home/alice/.bit/views");
        let cmd3 = build_lazy_unmount_command(FusermountBinary::Fusermount3, mount_target);
        assert_eq!(cmd3.get_program(), OsStr::new("fusermount3"));
        let args3: Vec<&OsStr> = cmd3.get_args().collect();
        assert_eq!(
            args3,
            vec![OsStr::new("-uz"), OsStr::new("/home/alice/.bit/views")]
        );

        let cmd2 = build_lazy_unmount_command(FusermountBinary::Fusermount, mount_target);
        assert_eq!(cmd2.get_program(), OsStr::new("fusermount"));
        let args2: Vec<&OsStr> = cmd2.get_args().collect();
        assert_eq!(
            args2,
            vec![OsStr::new("-uz"), OsStr::new("/home/alice/.bit/views")]
        );

        // Verify recovery state machine via FuseMountLifecycle trait.
        let mock = Arc::new(MockLifecycle {
            state: Mutex::new(stale),
            unmounted_paths: Mutex::new(Vec::new()),
        });
        let recovered = mock
            .recover_stale_mount(mount_target, false)
            .expect("recover stale");
        assert!(recovered);
        assert_eq!(
            mock.unmounted_paths.lock().expect("lock").as_slice(),
            &[PathBuf::from("/home/alice/.bit/views")]
        );
        assert!(!mock
            .recover_stale_mount(mount_target, false)
            .expect("already clean"));

        // Verify FuseMountHandle worker + shutdown lifecycle.
        let (_engine, dispatcher) = make_engine_and_dispatcher();
        let active_entry = found;
        *mock.state.lock().expect("lock") = MountState::ActiveFuseMount(active_entry);
        let dev = MockFuseDevice {
            steps: vec![Err(io::Error::from_raw_os_error(ENODEV))],
            idx: 0,
            replies: Vec::new(),
        };
        let mut handle = FuseMountHandle::spawn_device(Arc::new(dispatcher), dev, mock.clone())
            .expect("spawn handle");
        let _ = handle.shutdown().expect("clean shutdown");
        assert_eq!(mock.unmounted_paths.lock().expect("lock").len(), 2);
    }

    #[test]
    fn inspect_from_proc_file_detects_missing_mount_dir_with_mounted_entry_as_stale() {
        let temp_dir =
            std::env::temp_dir().join(format!("bit-vfs-fuse-proc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        let fake_proc = temp_dir.join("mounts");
        let missing_mount_target = temp_dir.join("stale-views");
        let line = format!(
            "bit {} fuse.bit rw,nosuid,nodev,user_id=1000,group_id=1000 0 0\n",
            missing_mount_target.display()
        );
        std::fs::write(&fake_proc, line).expect("write fake proc mounts");

        let lifecycle = SystemFuseMountLifecycle::new().with_proc_mounts_path(&fake_proc);
        let state = lifecycle
            .inspect_from_proc_file(&missing_mount_target)
            .expect("inspect");
        assert!(state.is_stale());

        let clean_target = temp_dir.join("unmounted-views");
        let clean_state = lifecycle
            .inspect_from_proc_file(&clean_target)
            .expect("inspect clean");
        assert_eq!(clean_state, MountState::NotMounted);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
