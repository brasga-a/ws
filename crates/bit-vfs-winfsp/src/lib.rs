//! `bit-vfs-winfsp`: Windows WinFsp userspace VFS adapter over [`bit_core::vfs::VfsOperations`]
//! (ADR-0002, ADR-0004, ADR-0005).
//!
//! Provides pure-`std`, OS-independent WinFsp protocol types, mount configuration, bidirectional
//! Windows/POSIX attribute and `NTSTATUS` mappings, `IO_REPARSE_TAG_SYMLINK` reparse buffer codecs,
//! `ReadDirectoryChangesW` notification hooks, stateful handle callback handling
//! ([`WinFspFileSystem`]), and host request dispatching ([`WinFspDispatcher`]).
#![deny(unsafe_code)]

pub mod attrs;
pub mod config;
pub mod dispatcher;
pub mod fs;
pub mod notify;
pub mod reparse;
pub mod status;

pub use attrs::{
    apply_file_attributes_to_mode, file_attributes_to_posix_mode, filetime_to_timestamp,
    posix_to_file_attributes, timestamp_to_filetime, vfs_attr_to_file_attributes, BasicInfoUpdate,
    FileAttributes, WinFspFileInfo, ALLOCATION_UNIT_BYTES, FILE_ATTRIBUTE_ARCHIVE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM,
    INVALID_FILE_ATTRIBUTES, WINDOWS_TICKS_PER_SEC, WINDOWS_TO_UNIX_EPOCH_SECS,
};
pub use config::{
    OwnerSid, SecurityByNameResult, WinFspConfigError, WinFspMountConfig, WinFspSecurityDescriptor,
    WinFspVolumeInfo, WinFspVolumeParams, DEFAULT_FS_NAME, DEFAULT_VIRTUAL_FREE_BYTES,
    DEFAULT_VIRTUAL_TOTAL_BYTES, DEFAULT_VOLUME_LABEL, MAX_VOLUME_LABEL_CHARS,
};
pub use dispatcher::{MountState, WinFspDispatcher, WinFspRequest, WinFspResponse};
pub use fs::{
    CleanupFlags, CreateParams, FileHandleId, OpenFileContext, OpenOptions, WinFspDirEntry,
    WinFspFileSystem,
};
pub use notify::{
    DirectoryChangeAction, DirectoryChangeEvent, DirectoryChangeListener, DirectoryChangeNotifier,
    NotifyFilter, WatchId,
};
pub use reparse::{
    ReparsePointData, IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK, REPARSE_DATA_HEADER_LEN,
    SYMLINK_FLAG_RELATIVE, SYMLINK_REPARSE_HEADER_LEN,
};
pub use status::{
    vfs_error_to_ntstatus, NtStatus, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW,
    STATUS_BUFFER_TOO_SMALL, STATUS_CANNOT_DELETE, STATUS_DELETE_PENDING,
    STATUS_DIRECTORY_NOT_EMPTY, STATUS_END_OF_FILE, STATUS_FILE_IS_A_DIRECTORY,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_IO_DEVICE_ERROR, STATUS_IO_REPARSE_DATA_INVALID, STATUS_IO_REPARSE_TAG_NOT_HANDLED,
    STATUS_MEDIA_WRITE_PROTECTED, STATUS_NAME_TOO_LONG, STATUS_NOT_A_DIRECTORY,
    STATUS_NOT_A_REPARSE_POINT, STATUS_NOT_SAME_DEVICE, STATUS_NOT_SUPPORTED, STATUS_NO_MORE_FILES,
    STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_PENDING, STATUS_SUCCESS,
};

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use bit_core::{
        BaseInput, BaseSelector, CaseSensitivity, ControlPlane, CoreEngine, InMemoryCoreEngine,
        InputEntry, NodeKind, RelPath, TagName, Timestamp, VfsOperations, ViewId,
        DEFAULT_EXEC_MODE, DEFAULT_FILE_MODE,
    };

    use super::*;

    const OWNER_SID: &str = "S-1-5-21-3623811015-3361044348-30300820-1013";
    const OTHER_SID: &str = "S-1-5-21-3623811015-3361044348-30300820-9999";

    fn seed_engine() -> Arc<InMemoryCoreEngine> {
        let engine = Arc::new(CoreEngine::in_memory());
        let ts = Timestamp::new(1_700_000_000, 500_000_000);

        engine
            .create_base(
                BaseInput::Entries(vec![
                    InputEntry::File {
                        path: RelPath::new("README.md").unwrap(),
                        bytes: b"# Bit Project\n".to_vec(),
                        mode: DEFAULT_FILE_MODE,
                        mtime: ts,
                    },
                    InputEntry::File {
                        path: RelPath::new("scripts/build.sh").unwrap(),
                        bytes: b"#!/bin/sh\necho ok\n".to_vec(),
                        mode: DEFAULT_EXEC_MODE,
                        mtime: ts,
                    },
                    InputEntry::File {
                        path: RelPath::new("locked/secret.txt").unwrap(),
                        bytes: b"immutable".to_vec(),
                        mode: 0o444,
                        mtime: ts,
                    },
                    InputEntry::File {
                        path: RelPath::new("case_dir/Foo").unwrap(),
                        bytes: b"upper-first".to_vec(),
                        mode: DEFAULT_FILE_MODE,
                        mtime: ts,
                    },
                    InputEntry::File {
                        path: RelPath::new("case_dir/FOO").unwrap(),
                        bytes: b"all-caps".to_vec(),
                        mode: DEFAULT_FILE_MODE,
                        mtime: ts,
                    },
                    InputEntry::Symlink {
                        path: RelPath::new("links/readme_link").unwrap(),
                        target: "../README.md".to_owned(),
                        mtime: ts,
                    },
                ]),
                Some(TagName::new("initial").unwrap()),
            )
            .unwrap();

        engine
            .create_view(
                ViewId::new("view-a").unwrap(),
                BaseSelector::parse("initial").unwrap(),
            )
            .unwrap();
        engine
            .create_view(
                ViewId::new("view-b").unwrap(),
                BaseSelector::parse("initial").unwrap(),
            )
            .unwrap();

        engine
    }

    fn make_fs(engine: &Arc<InMemoryCoreEngine>, policy: CaseSensitivity) -> WinFspFileSystem {
        let vfs: Arc<dyn VfsOperations> = engine.clone();
        let cfg = WinFspMountConfig::new(r"C:\bit\mnt", OWNER_SID)
            .unwrap()
            .with_case_sensitivity(policy);
        WinFspFileSystem::new(vfs, cfg)
    }

    #[test]
    fn config_validates_space_free_mount_point_owner_sid_and_volume_params() {
        assert_eq!(
            WinFspMountConfig::new("", OWNER_SID),
            Err(WinFspConfigError::EmptyMountPoint)
        );
        assert!(matches!(
            WinFspMountConfig::new(r"C:\Program Files\bit", OWNER_SID),
            Err(WinFspConfigError::MountPointContainsWhitespace(_))
        ));
        assert!(matches!(
            WinFspMountConfig::new("M:\tbad", OWNER_SID),
            Err(WinFspConfigError::MountPointContainsWhitespace(_))
        ));
        assert_eq!(
            WinFspMountConfig::new("M:\0bad", OWNER_SID),
            Err(WinFspConfigError::MountPointContainsNul)
        );
        assert!(matches!(
            WinFspMountConfig::new("M:", "not-a-sid"),
            Err(WinFspConfigError::InvalidOwnerSid(_))
        ));

        let cfg = WinFspMountConfig::new("M:", OWNER_SID).unwrap();
        assert_eq!(cfg.mount_point(), "M:");
        assert_eq!(cfg.owner_sid().as_str(), OWNER_SID);
        assert_eq!(
            cfg.case_sensitivity(),
            CaseSensitivity::CaseInsensitiveUnambiguous
        );

        let params_ci = cfg.volume_params();
        assert!(params_ci.case_preserved_names);
        assert!(!params_ci.case_sensitive_search);
        assert!(!params_ci.read_path_hydration);
        assert!(params_ci.reparse_points);
        assert!(!params_ci.hard_links);
        assert!(!params_ci.read_only_volume);

        let params_cs = cfg
            .clone()
            .with_case_sensitivity(CaseSensitivity::CaseSensitive)
            .volume_params();
        assert!(params_cs.case_preserved_names);
        assert!(params_cs.case_sensitive_search);

        assert_eq!(cfg.check_caller_sid(Some(OWNER_SID)), Ok(()));
        assert_eq!(
            cfg.check_caller_sid(Some(OTHER_SID)),
            Err(STATUS_ACCESS_DENIED)
        );
    }

    #[test]
    fn bidirectional_file_attributes_and_filetime_round_trip() {
        assert_eq!(
            posix_to_file_attributes(NodeKind::File, 0o644, false),
            FILE_ATTRIBUTE_NORMAL
        );
        assert_eq!(
            posix_to_file_attributes(NodeKind::File, 0o444, false),
            FILE_ATTRIBUTE_READONLY
        );
        assert_eq!(
            posix_to_file_attributes(NodeKind::Directory, 0o755, false),
            FILE_ATTRIBUTE_DIRECTORY
        );
        assert_eq!(
            posix_to_file_attributes(NodeKind::Directory, 0o555, true),
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY
        );
        assert_eq!(
            posix_to_file_attributes(NodeKind::Symlink, 0o777, false),
            FILE_ATTRIBUTE_REPARSE_POINT
        );

        // Executable bits survive +READONLY -> -READONLY toggling on Windows.
        let ro_exec =
            apply_file_attributes_to_mode(FILE_ATTRIBUTE_READONLY, NodeKind::File, 0o755).unwrap();
        assert_eq!(ro_exec, 0o555);
        let rw_exec =
            apply_file_attributes_to_mode(FILE_ATTRIBUTE_NORMAL, NodeKind::File, ro_exec).unwrap();
        assert_eq!(rw_exec, 0o755);

        let ts = Timestamp::new(1_731_900_123, 456_789_100);
        let ft = timestamp_to_filetime(ts);
        let round_trip = filetime_to_timestamp(ft);
        assert_eq!(round_trip, ts);
    }

    #[test]
    fn backslash_routing_and_true_read_path_virtualization_without_hydration() {
        let engine = seed_engine();
        let fs = make_fs(&engine, CaseSensitivity::CaseSensitive);

        let puts_before = engine.blob_store().put_count();
        let blobs_before = engine.blob_store().blob_count();

        // Enumerate `<mount>\` root.
        let (root_h, root_info) = fs.open(r"\", OpenOptions::directory()).unwrap();
        assert_eq!(
            root_info.file_attributes,
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY
        );
        let root_entries = fs.read_directory(root_h, None, None).unwrap();
        let root_names: Vec<&str> = root_entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(root_names, vec!["view-a", "view-b"]);
        fs.close(root_h).unwrap();

        // Read the same Base file from both `view-a` and `view-b` via backslash paths.
        for path in [r"\view-a\scripts\build.sh", r"\view-b\scripts\build.sh"] {
            let sec = fs.get_security_by_name(path).unwrap();
            assert_eq!(sec.file_attributes, FILE_ATTRIBUTE_NORMAL);
            assert!(sec.security_descriptor.sddl.contains(OWNER_SID));

            let (h, info) = fs.open(path, OpenOptions::read_only()).unwrap();
            assert_eq!(info.file_size, 18);
            let mut buf = [0u8; 64];
            let n = fs.read(h, 0, &mut buf).unwrap();
            assert_eq!(&buf[..n], b"#!/bin/sh\necho ok\n");
            fs.cleanup(h, CleanupFlags::NONE).unwrap();
            fs.close(h).unwrap();
        }

        // Zero blobs duplicated or written during virtualized reads across multiple Views.
        assert_eq!(engine.blob_store().put_count(), puts_before);
        assert_eq!(engine.blob_store().blob_count(), blobs_before);
    }

    #[test]
    fn case_insensitive_unambiguous_lookup_vs_collision_refusal() {
        let engine = seed_engine();
        let fs_cs = make_fs(&engine, CaseSensitivity::CaseSensitive);
        let fs_ci = make_fs(&engine, CaseSensitivity::CaseInsensitiveUnambiguous);

        // Unambiguous folded lookup fails in CaseSensitive mode, succeeds in CaseInsensitiveUnambiguous.
        assert_eq!(
            fs_cs.open(r"\VIEW-A\readme.md", OpenOptions::read_only()),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        let (h, _) = fs_ci
            .open(r"\VIEW-A\readme.md", OpenOptions::read_only())
            .unwrap();
        let ctx = fs_ci.handle_context(h).unwrap();
        assert_eq!(ctx.mount_path, "view-a/README.md");
        fs_ci.close(h).unwrap();

        // Multi-way case collision (`Foo` and `FOO` both exist in `case_dir`):
        // 1. Exact matches succeed even in CaseInsensitiveUnambiguous mode!
        let (h_foo, _) = fs_ci
            .open(r"\view-a\case_dir\Foo", OpenOptions::read_only())
            .unwrap();
        let mut buf = [0u8; 32];
        let n = fs_ci.read(h_foo, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"upper-first");
        fs_ci.close(h_foo).unwrap();

        // 2. Non-exact query `"foo"` matching both `"Foo"` and `"FOO"` is refused as collision!
        assert_eq!(
            fs_ci.open(r"\view-a\case_dir\foo", OpenOptions::read_only()),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            fs_ci.get_security_by_name(r"\view-a\case_dir\fOo"),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );

        // 3. Exclusive `create` with case-colliding leaf is refused in CaseInsensitiveUnambiguous,
        //    while new files preserve their exact case (`CasePreservedNames = true`).
        assert_eq!(
            fs_ci.create(r"\view-a\readme.md", CreateParams::regular_file()),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        let (h_new, _) = fs_ci
            .create(r"\view-a\MixedCaseFile.RS", CreateParams::regular_file())
            .unwrap();
        fs_ci.close(h_new).unwrap();

        let (dir_h, _) = fs_ci.open(r"\view-a", OpenOptions::directory()).unwrap();
        let names: Vec<String> = fs_ci
            .read_directory(dir_h, Some("*.rs"), None)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["MixedCaseFile.RS".to_owned()]);
        fs_ci.close(dir_h).unwrap();
    }

    #[test]
    fn cow_write_overwrite_set_basic_info_and_view_isolation() {
        let engine = seed_engine();
        let fs = make_fs(&engine, CaseSensitivity::CaseInsensitiveUnambiguous);

        // Open shared Base file in `view-a` for write and perform CoW mutation.
        let (h_a, _) = fs
            .open(r"\view-a\README.md", OpenOptions::read_write())
            .unwrap();
        let (written, info_after_write) = fs.write(h_a, 14, b"Updated in view-a\n").unwrap();
        assert_eq!(written, 18);
        assert_eq!(info_after_write.file_size, 32);

        // Append with `write_to_end_of_file = true`.
        let (_, info_appended) = fs.write_ex(h_a, 0, b"END", true, false).unwrap();
        assert_eq!(info_appended.file_size, 35);
        fs.close(h_a).unwrap();

        // Sibling `view-b` still sees untouched Base content!
        let (h_b, info_b) = fs
            .open(r"\view-b\README.md", OpenOptions::read_only())
            .unwrap();
        assert_eq!(info_b.file_size, 14);
        let mut buf = [0u8; 64];
        let n_b = fs.read(h_b, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n_b], b"# Bit Project\n");
        fs.close(h_b).unwrap();

        // `overwrite` truncates to 0 bytes and updates attributes.
        let (h_ov, _) = fs
            .open(r"\view-a\README.md", OpenOptions::read_write())
            .unwrap();
        let ov_info = fs.overwrite(h_ov, FILE_ATTRIBUTE_NORMAL, true, 0).unwrap();
        assert_eq!(ov_info.file_size, 0);
        assert_eq!(fs.read(h_ov, 0, &mut buf).unwrap(), 0);

        // `set_basic_info` toggles `FILE_ATTRIBUTE_READONLY` on executable script while preserving exec bit.
        let (h_sh, _) = fs
            .open(r"\view-a\scripts\build.sh", OpenOptions::read_write())
            .unwrap();
        let ro_info = fs
            .set_basic_info(
                h_sh,
                BasicInfoUpdate::attributes_only(FILE_ATTRIBUTE_READONLY),
            )
            .unwrap();
        assert_eq!(ro_info.file_attributes, FILE_ATTRIBUTE_READONLY);
        assert_eq!(
            engine.getattr("view-a/scripts/build.sh").unwrap().mode,
            0o555
        );
        fs.close(h_sh).unwrap();
        fs.close(h_ov).unwrap();
    }

    #[test]
    fn delete_on_close_cleanup_and_readonly_protection() {
        let engine = seed_engine();
        let fs = make_fs(&engine, CaseSensitivity::CaseInsensitiveUnambiguous);

        // Read-only file refuses delete-on-close with `STATUS_CANNOT_DELETE`.
        assert_eq!(
            fs.open(r"\view-a\locked\secret.txt", OpenOptions::delete_on_close()),
            Err(STATUS_CANNOT_DELETE)
        );

        // Non-empty directory refuses `set_delete_on_close(true)` with `STATUS_DIRECTORY_NOT_EMPTY`.
        let (dir_h, _) = fs
            .open(r"\view-a\scripts", OpenOptions::read_write())
            .unwrap();
        assert_eq!(
            fs.set_delete_on_close(dir_h, true),
            Err(STATUS_DIRECTORY_NOT_EMPTY)
        );
        fs.close(dir_h).unwrap();

        // Regular file opened with `delete_on_close` remains readable until `cleanup`, then vanishes.
        let (h_del, _) = fs
            .open(r"\view-a\README.md", OpenOptions::delete_on_close())
            .unwrap();
        assert!(fs.get_file_info(h_del).is_ok());
        fs.cleanup(h_del, CleanupFlags::NONE).unwrap();
        assert_eq!(fs.get_file_info(h_del), Err(STATUS_DELETE_PENDING));
        fs.close(h_del).unwrap();

        assert_eq!(
            fs.open(r"\view-a\README.md", OpenOptions::read_only()),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        // Still present in `view-b`!
        let (h_b, _) = fs
            .open(r"\view-b\README.md", OpenOptions::read_only())
            .unwrap();
        fs.close(h_b).unwrap();
    }

    #[test]
    fn symlink_reparse_point_get_set_and_wire_codec() {
        let engine = seed_engine();
        let fs = make_fs(&engine, CaseSensitivity::CaseInsensitiveUnambiguous);

        // 1. Existing symlink from Base reports `FILE_ATTRIBUTE_REPARSE_POINT` + `IO_REPARSE_TAG_SYMLINK`.
        let sec = fs
            .get_security_by_name(r"\view-a\links\readme_link")
            .unwrap();
        assert_eq!(sec.file_attributes, FILE_ATTRIBUTE_REPARSE_POINT);
        assert_eq!(sec.reparse_tag, Some(IO_REPARSE_TAG_SYMLINK));

        let (sym_h, sym_info) = fs
            .open(
                r"\view-a\links\readme_link",
                OpenOptions::reparse_point(false),
            )
            .unwrap();
        assert_eq!(sym_info.file_attributes, FILE_ATTRIBUTE_REPARSE_POINT);
        assert_eq!(sym_info.reparse_tag, IO_REPARSE_TAG_SYMLINK);

        let reparse = fs.get_reparse_point(sym_h).unwrap();
        assert_eq!(reparse.target, "../README.md");
        assert!(reparse.is_relative());
        fs.close(sym_h).unwrap();

        // 2. Wire `REPARSE_DATA_BUFFER` round-trip for both relative and drive-absolute symlinks.
        for raw_target in ["../README.md", r"C:\tools\clang.exe"] {
            let orig = ReparsePointData::symlink(raw_target).unwrap();
            let wire = orig.encode_reparse_buffer().unwrap();
            let decoded = ReparsePointData::decode_reparse_buffer(&wire).unwrap();
            assert_eq!(decoded.target, raw_target);
            assert_eq!(decoded.reparse_tag, IO_REPARSE_TAG_SYMLINK);
        }

        // 3. Atomic symlink creation via `CreateParams::symlink`.
        let link_payload = ReparsePointData::symlink("../scripts/build.sh").unwrap();
        let (h_created, created_info) = fs
            .create(
                r"\view-a\links\build_sym",
                CreateParams::symlink(link_payload),
            )
            .unwrap();
        assert_eq!(created_info.file_attributes, FILE_ATTRIBUTE_REPARSE_POINT);
        assert_eq!(
            fs.get_reparse_point(h_created).unwrap().target,
            "../scripts/build.sh"
        );
        fs.close(h_created).unwrap();

        // 4. Two-step Win32 symlink creation: empty file `create` followed by `set_reparse_point`.
        let (h_two, _) = fs
            .create(r"\view-a\links\two_step_sym", CreateParams::regular_file())
            .unwrap();
        assert_eq!(fs.get_reparse_point(h_two), Err(STATUS_NOT_A_REPARSE_POINT));

        // Non-symlink reparse tag is rejected with `STATUS_IO_REPARSE_TAG_NOT_HANDLED`.
        let mut bad_tag = ReparsePointData::symlink("target.txt").unwrap();
        bad_tag.reparse_tag = IO_REPARSE_TAG_MOUNT_POINT;
        assert_eq!(
            fs.set_reparse_point(h_two, bad_tag),
            Err(STATUS_IO_REPARSE_TAG_NOT_HANDLED)
        );

        let good_data = ReparsePointData::symlink("../README.md").unwrap();
        let sym_after = fs.set_reparse_point(h_two, good_data).unwrap();
        assert_eq!(sym_after.file_attributes, FILE_ATTRIBUTE_REPARSE_POINT);
        assert_eq!(sym_after.reparse_tag, IO_REPARSE_TAG_SYMLINK);
        assert_eq!(
            fs.get_reparse_point_by_name(r"\view-a\links\two_step_sym")
                .unwrap()
                .target,
            "../README.md"
        );
        fs.close(h_two).unwrap();
    }

    #[test]
    fn read_only_mount_root_cross_view_rename_and_hard_link_refusal() {
        let engine = seed_engine();
        let fs = make_fs(&engine, CaseSensitivity::CaseInsensitiveUnambiguous);

        // 1. `<mount>\` root is strictly read-only (`STATUS_MEDIA_WRITE_PROTECTED`).
        assert_eq!(
            fs.create(r"\rogue_file.txt", CreateParams::regular_file()),
            Err(STATUS_MEDIA_WRITE_PROTECTED)
        );
        assert_eq!(
            fs.create(r"\rogue-view", CreateParams::directory()),
            Err(STATUS_MEDIA_WRITE_PROTECTED)
        );
        assert_eq!(
            fs.open(r"\", OpenOptions::delete_on_close()),
            Err(STATUS_MEDIA_WRITE_PROTECTED)
        );
        assert_eq!(
            fs.open(r"\view-a", OpenOptions::delete_on_close()),
            Err(STATUS_MEDIA_WRITE_PROTECTED)
        );
        let (root_h, _) = fs.open(r"\", OpenOptions::directory()).unwrap();
        assert_eq!(
            fs.set_basic_info(
                root_h,
                BasicInfoUpdate::attributes_only(FILE_ATTRIBUTE_DIRECTORY)
            ),
            Err(STATUS_MEDIA_WRITE_PROTECTED)
        );
        fs.close(root_h).unwrap();

        // 2. Cross-`View` rename returns `STATUS_NOT_SAME_DEVICE`.
        let (h_a, _) = fs
            .open(r"\view-a\README.md", OpenOptions::read_write())
            .unwrap();
        assert_eq!(
            fs.rename(h_a, r"\view-b\README_MOVED.md", false),
            Err(STATUS_NOT_SAME_DEVICE)
        );
        assert_eq!(
            fs.rename_by_path(r"\VIEW-A\README.md", r"\VIEW-B\README.md", true),
            Err(STATUS_NOT_SAME_DEVICE)
        );

        // Intra-`View` rename (including case-only rename) succeeds without blob copies and updates open handles!
        let gets_before = engine.blob_store().get_count();
        let puts_before = engine.blob_store().put_count();
        fs.rename(h_a, r"\view-a\Readme.md", false).unwrap();
        assert_eq!(
            fs.handle_context(h_a).unwrap().mount_path,
            "view-a/Readme.md"
        );
        assert_eq!(engine.blob_store().get_count(), gets_before);
        assert_eq!(engine.blob_store().put_count(), puts_before);
        fs.close(h_a).unwrap();

        // 3. Hard links return `STATUS_NOT_SUPPORTED`.
        assert_eq!(
            fs.create_hard_link(r"\view-a\Readme.md", r"\view-a\hardlink.md"),
            Err(STATUS_NOT_SUPPORTED)
        );
    }

    #[test]
    fn directory_change_notifier_and_dispatcher_end_to_end() {
        let engine = seed_engine();
        let vfs: Arc<dyn VfsOperations> = engine;
        let cfg = WinFspMountConfig::new("B:", OWNER_SID).unwrap();
        let dispatcher = WinFspDispatcher::new(vfs, cfg);

        // Dispatches prior to `start()` fail with `STATUS_INVALID_DEVICE_REQUEST`.
        assert!(!dispatcher.is_mounted());
        assert_eq!(
            dispatcher.dispatch(WinFspRequest::GetVolumeInfo),
            Err(STATUS_INVALID_DEVICE_REQUEST)
        );

        let vol_params = dispatcher.start().unwrap();
        assert!(dispatcher.is_mounted());
        assert!(!vol_params.read_path_hydration);

        // Non-owner SID is rejected with `STATUS_ACCESS_DENIED`.
        assert_eq!(
            dispatcher.dispatch_with_sid(Some(OTHER_SID), WinFspRequest::GetVolumeInfo),
            Err(STATUS_ACCESS_DENIED)
        );

        // Subscribe to recursive changes under `\view-a`.
        let fs = dispatcher.filesystem();
        let watch = fs
            .watch_directory(r"\view-a", true, NotifyFilter::ALL)
            .unwrap();

        let pushed: Arc<Mutex<Vec<DirectoryChangeAction>>> = Arc::new(Mutex::new(Vec::new()));
        let pushed_clone = pushed.clone();
        fs.notifier().add_listener(Arc::new(move |ev| {
            pushed_clone.lock().unwrap().push(ev.action);
        }));

        // Create, write, rename, and delete-on-close through `WinFspDispatcher`.
        let WinFspResponse::Opened { handle, .. } = dispatcher
            .dispatch_with_sid(
                Some(OWNER_SID),
                WinFspRequest::Create {
                    path: r"\view-a\scripts\new_tool.ps1".to_owned(),
                    params: CreateParams::regular_file(),
                },
            )
            .unwrap()
        else {
            panic!("expected Opened");
        };

        dispatcher
            .dispatch(WinFspRequest::Write {
                handle,
                offset: 0,
                data: b"Write-Host 'hi'".to_vec(),
                write_to_end_of_file: false,
                constrained_io: false,
            })
            .unwrap();

        dispatcher
            .dispatch(WinFspRequest::Rename {
                handle,
                new_path: r"\view-a\scripts\renamed_tool.ps1".to_owned(),
                replace_if_exists: false,
            })
            .unwrap();

        dispatcher
            .dispatch(WinFspRequest::Cleanup {
                handle,
                flags: CleanupFlags::DELETE,
            })
            .unwrap();
        dispatcher
            .dispatch(WinFspRequest::Close { handle })
            .unwrap();

        // Hardlink through dispatcher returns `STATUS_NOT_SUPPORTED`.
        assert_eq!(
            dispatcher.dispatch(WinFspRequest::CreateHardLink {
                existing_path: r"\view-a\README.md".to_owned(),
                new_link_path: r"\view-a\README_HL.md".to_owned(),
            }),
            Err(STATUS_NOT_SUPPORTED)
        );

        let events = fs
            .notifier()
            .wait_for_events(watch, Duration::from_millis(50))
            .unwrap();
        let actions: Vec<(DirectoryChangeAction, String)> = events
            .into_iter()
            .map(|e| (e.action, e.relative_win_path))
            .collect();
        assert_eq!(
            actions,
            vec![
                (
                    DirectoryChangeAction::Added,
                    r"scripts\new_tool.ps1".to_owned()
                ),
                (
                    DirectoryChangeAction::Modified,
                    r"scripts\new_tool.ps1".to_owned()
                ),
                (
                    DirectoryChangeAction::RenamedOldName,
                    r"scripts\new_tool.ps1".to_owned()
                ),
                (
                    DirectoryChangeAction::RenamedNewName,
                    r"scripts\renamed_tool.ps1".to_owned()
                ),
                (
                    DirectoryChangeAction::Removed,
                    r"scripts\renamed_tool.ps1".to_owned()
                ),
            ]
        );
        assert_eq!(pushed.lock().unwrap().len(), 5);

        assert!(fs.notifier().unsubscribe(watch));
        dispatcher.stop().unwrap();
        assert!(!dispatcher.is_mounted());
        assert_eq!(fs.open_handle_count(), 0);
    }

    #[test]
    fn exhaustive_vfs_error_to_ntstatus_mapping() {
        use bit_core::VfsError;

        let cases = [
            (VfsError::NotFound, STATUS_OBJECT_NAME_NOT_FOUND),
            (VfsError::AlreadyExists, STATUS_OBJECT_NAME_COLLISION),
            (VfsError::NotADirectory, STATUS_NOT_A_DIRECTORY),
            (VfsError::IsADirectory, STATUS_FILE_IS_A_DIRECTORY),
            (VfsError::DirectoryNotEmpty, STATUS_DIRECTORY_NOT_EMPTY),
            (VfsError::ReadOnly, STATUS_MEDIA_WRITE_PROTECTED),
            (VfsError::CrossDevice, STATUS_NOT_SAME_DEVICE),
            (VfsError::NotSupported, STATUS_NOT_SUPPORTED),
            (VfsError::PermissionDenied, STATUS_ACCESS_DENIED),
            (VfsError::NameTooLong, STATUS_NAME_TOO_LONG),
            (
                VfsError::InvalidInput("bad".to_owned()),
                STATUS_INVALID_PARAMETER,
            ),
            (
                VfsError::AmbiguousCase("dup".to_owned()),
                STATUS_OBJECT_NAME_COLLISION,
            ),
            (VfsError::Io("disk".to_owned()), STATUS_IO_DEVICE_ERROR),
        ];

        for (vfs_err, expected_nt) in cases {
            assert_eq!(vfs_error_to_ntstatus(&vfs_err), expected_nt);
            assert!(expected_nt.is_error());
            assert!(!expected_nt.is_success());
        }
        assert!(STATUS_SUCCESS.is_success());
        assert!(!STATUS_SUCCESS.is_error());
    }

    #[test]
    fn directory_pagination_subtree_rename_and_constrained_io() {
        let engine = seed_engine();
        let fs = make_fs(&engine, CaseSensitivity::CaseInsensitiveUnambiguous);

        // Subdirectory `read_directory` includes `.` and `..` and honours `marker` continuation.
        let (dir_h, _) = fs.open(r"\view-a", OpenOptions::directory()).unwrap();
        let page1 = fs.read_directory(dir_h, None, None).unwrap();
        assert_eq!(page1[0].name, ".");
        assert_eq!(page1[1].name, "..");
        assert!(page1.len() >= 5);

        let resume_marker = page1[2].name.clone();
        let page2 = fs
            .read_directory(dir_h, None, Some(&resume_marker))
            .unwrap();
        assert_eq!(page2.len(), page1.len() - 3);
        fs.close(dir_h).unwrap();

        // `constrained_io` never extends past current `file_size`, while `set_file_size` resizes.
        let (file_h, _) = fs
            .open(r"\view-a\README.md", OpenOptions::read_write())
            .unwrap();
        let (written, info) = fs.write_ex(file_h, 10, b"0123456789", false, true).unwrap();
        assert_eq!(written, 4);
        assert_eq!(info.file_size, 14);

        let resized = fs.set_file_size(file_h, 6, false).unwrap();
        assert_eq!(resized.file_size, 6);
        fs.close(file_h).unwrap();

        // Directory subtree rename updates open descendant file handles transparently.
        let (script_h, _) = fs
            .open(r"\view-a\scripts\build.sh", OpenOptions::read_only())
            .unwrap();
        fs.rename_by_path(r"\view-a\scripts", r"\view-a\bin", false)
            .unwrap();
        assert_eq!(
            fs.handle_context(script_h).unwrap().win_path,
            r"\view-a\bin\build.sh"
        );
        let mut buf = [0u8; 32];
        let n = fs.read(script_h, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"#!/bin/sh\necho ok\n");
        fs.close(script_h).unwrap();

        // `replace_if_exists = false` refuses overwrite; `replace_if_exists = true` refuses READONLY target.
        assert_eq!(
            fs.rename_by_path(r"\view-a\README.md", r"\view-a\locked\secret.txt", false),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            fs.rename_by_path(r"\view-a\README.md", r"\view-a\locked\secret.txt", true),
            Err(STATUS_ACCESS_DENIED)
        );
    }
}
