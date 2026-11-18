//! Comprehensive persistence, ingestion, conflict-checking, rollback journal, and crash-recovery
//! tests for `bit-store`.

use std::fs::{self, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bit_core::{
    ApplyConflictKind, BaseInput, BaseSelector, BlobStore, ControlPlane, MetadataStore, StoreError,
    TagName, VfsOperations, ViewId,
};
use bit_store::{
    execute_apply, execute_apply_with_fault_hook, ingest_external_dir, ingest_external_dir_fs,
    ApplyStoreError, BitStore, FsBlobStore, FsMetadataStore, RecoverySummary, ReflinkCloner,
    ReflinkPolicy,
};

static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("bit-store-test-{label}-{pid}-{seq}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn persistence_across_reopen_sharded_blobs_and_checksum_verification() {
    let dir = TempDir::new("persist");
    let base_id;
    let frozen_id;

    {
        let (store, recovery) = BitStore::open(dir.path()).unwrap();
        assert_eq!(recovery, RecoverySummary::default());

        // Verify 2-hex / 62-hex sharded blob layout and positional `read_blob_at`.
        let h = store.blobs().put_blob(b"0123456789abcdef").unwrap();
        let hex = h.to_hex();
        let expected_path = store.blobs().blobs_dir().join(&hex[..2]).join(&hex[2..]);
        assert!(expected_path.is_file());
        assert_eq!(store.blobs().blob_len(&h).unwrap(), 16);
        assert_eq!(store.blobs().read_blob_at(&h, 4, 6).unwrap(), b"456789");

        let engine = store.into_engine();
        let tag = TagName::new("baseline").unwrap();
        let info = engine
            .create_base(
                BaseInput::from_files([
                    ("README.md", &b"hello persistence\n"[..]),
                    ("dir/keep.txt", &b"keep\n"[..]),
                    ("dir/remove_me.txt", &b"gone\n"[..]),
                    ("recreate/old.txt", &b"old\n"[..]),
                ])
                .unwrap(),
                Some(tag.clone()),
            )
            .unwrap();
        base_id = info.id;

        let v1 = ViewId::new("persisted-view").unwrap();
        engine
            .create_view(v1.clone(), BaseSelector::Tag(tag))
            .unwrap();

        // Exercise file edit, whiteout, external symlink, and opaque directory (`rm -rf && mkdir`).
        engine
            .write("persisted-view/README.md", 0, b"edited across restart\n")
            .unwrap();
        engine.unlink("persisted-view/dir/remove_me.txt").unwrap();
        engine.unlink("persisted-view/recreate/old.txt").unwrap();
        engine.rmdir("persisted-view/recreate").unwrap();
        engine.mkdir("persisted-view/recreate", 0o755).unwrap();
        engine
            .create_file("persisted-view/recreate/fresh.txt", 0o644, true)
            .unwrap();
        engine
            .write("persisted-view/recreate/fresh.txt", 0, b"fresh\n")
            .unwrap();
        engine
            .symlink("/usr/local/bin/tool", "persisted-view/ext_sym")
            .unwrap();

        frozen_id = engine
            .freeze_view(&v1, Some(TagName::new("frozen-v2").unwrap()))
            .unwrap()
            .base_id;
    }

    // Reopen completely from disk and verify every Base, Tag, View, Whiteout, and Opaque marker.
    let (reopened, _) = BitStore::open(dir.path()).unwrap();
    let engine = reopened.into_engine();

    assert_eq!(engine.list_bases().unwrap().len(), 2);
    assert_eq!(
        engine
            .metadata_store()
            .get_tag(&TagName::new("baseline").unwrap())
            .unwrap(),
        Some(base_id)
    );
    assert_eq!(
        engine
            .metadata_store()
            .get_tag(&TagName::new("frozen-v2").unwrap())
            .unwrap(),
        Some(frozen_id)
    );

    assert_eq!(
        engine.read("persisted-view/README.md", 0, 128).unwrap(),
        b"edited across restart\n"
    );
    assert_eq!(
        engine.read("persisted-view/dir/keep.txt", 0, 64).unwrap(),
        b"keep\n"
    );
    assert!(engine.getattr("persisted-view/dir/remove_me.txt").is_err());
    // Opaque marker survived serialization: `recreate/old.txt` stays hidden!
    assert!(engine.getattr("persisted-view/recreate/old.txt").is_err());
    assert_eq!(
        engine
            .read("persisted-view/recreate/fresh.txt", 0, 64)
            .unwrap(),
        b"fresh\n"
    );
    assert_eq!(
        engine.readlink("persisted-view/ext_sym").unwrap(),
        "/usr/local/bin/tool"
    );

    // Corrupting a persisted frame on disk must be caught by SHA-256 frame verification.
    let view_frame_path = engine
        .metadata_store()
        .meta_dir()
        .join("views")
        .join("persisted-view.view");
    let mut raw = fs::read(&view_frame_path).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0xff;
    fs::write(&view_frame_path, &raw).unwrap();
    assert!(matches!(
        engine
            .metadata_store()
            .get_view(&ViewId::new("persisted-view").unwrap()),
        Err(StoreError::CorruptData(_))
    ));
}

/// Misbehaving cloner attempting to hardlink external files; `FsBlobStore` must refuse hardlinks
/// and fall back to an independent physical copy so external edits never corrupt a `Base`.
struct HardlinkAttemptingCloner;

impl ReflinkCloner for HardlinkAttemptingCloner {
    fn try_reflink(&self, from_file: &Path, to_staging_file: &Path) -> io::Result<()> {
        fs::hard_link(from_file, to_staging_file)
    }
}

#[test]
fn external_ingestion_decouples_hardlinks_ignores_gitignore_and_skips_special_files() {
    let ext = TempDir::new("ext-ingest");
    let store_dir = TempDir::new("ext-store");

    // Populate `.gitignore` + a file that `.gitignore` would ignore + `.git/`.
    fs::create_dir_all(ext.path().join(".git")).unwrap();
    fs::write(
        ext.path().join(".gitignore"),
        b"ignored_by_git.txt\n*.secret\n",
    )
    .unwrap();
    fs::write(
        ext.path().join("ignored_by_git.txt"),
        b"must be captured verbatim!",
    )
    .unwrap();
    fs::write(ext.path().join(".git/HEAD"), b"deadbeef\n").unwrap();

    // Populate paths matching explicit `--exclude` patterns.
    fs::create_dir_all(ext.path().join("build_out/sub")).unwrap();
    fs::write(ext.path().join("build_out/sub/artifact.bin"), b"skip me").unwrap();
    fs::write(ext.path().join("debug.log"), b"skip log").unwrap();

    // Create external hardlinked files and an external symlink.
    fs::write(ext.path().join("hard_a.txt"), b"immutable-payload").unwrap();
    fs::hard_link(ext.path().join("hard_a.txt"), ext.path().join("hard_b.txt")).unwrap();

    #[cfg(unix)]
    let _sock_listener = {
        std::os::unix::fs::symlink("../outside/tool", ext.path().join("rel_sym")).unwrap();
        // Bind a real Unix domain socket inside `ext` to verify special OS files are skipped!
        Some(std::os::unix::net::UnixListener::bind(ext.path().join("daemon.sock")).unwrap())
    };

    let blob_store = FsBlobStore::open_with_policy(
        store_dir.path(),
        ReflinkPolicy::Custom(Arc::new(HardlinkAttemptingCloner)),
    )
    .unwrap();

    let excludes = ["build_out", "*.log"];
    let ingested = ingest_external_dir_fs(ext.path(), &excludes, &blob_store).unwrap();

    // `.gitignore`, `ignored_by_git.txt`, and `.git/HEAD` are all present (strictly Git-agnostic).
    let entries = ingested.base.entries();
    assert!(entries.contains_key("ignored_by_git.txt"));
    assert!(entries.contains_key(".gitignore"));
    assert!(entries.contains_key(".git/HEAD"));

    // Explicit `--exclude` patterns were honored.
    assert!(!entries.contains_key("build_out"));
    assert!(!entries.contains_key("build_out/sub/artifact.bin"));
    assert!(!entries.contains_key("debug.log"));

    // Hardlinked external files share the same `ContentHash` in `BlobStore`...
    let hash_a = entries.get("hard_a.txt").unwrap().content_hash().unwrap();
    let hash_b = entries.get("hard_b.txt").unwrap().content_hash().unwrap();
    assert_eq!(hash_a, hash_b);

    #[cfg(unix)]
    {
        assert_eq!(
            entries.get("rel_sym").unwrap().symlink_target(),
            Some("../outside/tool")
        );
        assert_eq!(ingested.skipped_special_files.len(), 1);
        assert_eq!(ingested.skipped_special_files[0].as_str(), "daemon.sock");
        assert!(!entries.contains_key("daemon.sock"));
    }

    // Mutate `hard_a.txt` IN-PLACE in the external directory (same external inode!) and delete `ignored_by_git.txt`:
    // the sealed `Base` blob MUST remain 100% unchanged!
    let mut in_place = OpenOptions::new()
        .write(true)
        .open(ext.path().join("hard_a.txt"))
        .unwrap();
    in_place.seek(SeekFrom::Start(0)).unwrap();
    in_place.write_all(b"MUTATED_EXTERNALLY").unwrap();
    drop(in_place);
    fs::remove_file(ext.path().join("ignored_by_git.txt")).unwrap();

    assert_eq!(blob_store.get_blob(&hash_a).unwrap(), b"immutable-payload");
}

#[test]
fn apply_refuses_conflicts_unless_forced_and_rolls_back_all_or_nothing_on_mid_flight_error() {
    let target = TempDir::new("apply-target");
    let store_dir = TempDir::new("apply-store");

    fs::create_dir_all(target.path().join("old_dir")).unwrap();
    fs::write(target.path().join("README.md"), b"original readme\n").unwrap();
    fs::write(
        target.path().join("old_dir/script.sh"),
        b"#!/bin/sh\necho v1\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            target.path().join("old_dir/script.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    let (store, _) = BitStore::open(store_dir.path()).unwrap();
    let empty_excludes: [&str; 0] = [];
    let ingested = ingest_external_dir(target.path(), &empty_excludes, store.blobs()).unwrap();
    store.metadata().put_base(&ingested.base).unwrap();

    let engine = store.into_engine();
    let view_id = ViewId::new("apply-view").unwrap();
    engine
        .create_view(view_id.clone(), BaseSelector::Id(ingested.base.id()))
        .unwrap();

    // Mutate `apply-view`: remove `old_dir/script.sh` & `old_dir`, edit `README.md`,
    // create `nested/sub/added.txt`, and create a symlink `bin_link` (on Unix).
    engine.unlink("apply-view/old_dir/script.sh").unwrap();
    engine.rmdir("apply-view/old_dir").unwrap();
    engine
        .write("apply-view/README.md", 0, b"updated from view\n")
        .unwrap();
    engine.mkdir("apply-view/nested", 0o755).unwrap();
    engine.mkdir("apply-view/nested/sub", 0o755).unwrap();
    engine
        .create_file("apply-view/nested/sub/added.txt", 0o644, true)
        .unwrap();
    engine
        .write("apply-view/nested/sub/added.txt", 0, b"brand new payload\n")
        .unwrap();
    #[cfg(unix)]
    engine
        .symlink("nested/sub/added.txt", "apply-view/shortcut")
        .unwrap();

    let base = engine
        .metadata_store()
        .get_base(&ingested.base.id())
        .unwrap()
        .unwrap();
    let view = engine.metadata_store().get_view(&view_id).unwrap().unwrap();

    // --- Part A: Pre-flight conflict refusal (`force == false`) ---
    fs::write(
        target.path().join("README.md"),
        b"external concurrent edit\n",
    )
    .unwrap();
    let conflict_err = execute_apply(
        &base,
        view.overlay(),
        target.path(),
        engine.blob_store(),
        false,
    )
    .unwrap_err();
    assert!(matches!(
        conflict_err,
        ApplyStoreError::Conflicts(ref list)
            if list.iter().any(|c| c.path.as_str() == "README.md" && c.kind == ApplyConflictKind::ExternalModified)
    ));
    // External directory was NOT partially modified!
    assert!(target.path().join("old_dir/script.sh").is_file());
    assert!(!target.path().join("nested").exists());

    // Restore `README.md` to Base content so pre-flight passes, and test mid-flight rollback!
    fs::write(target.path().join("README.md"), b"original readme\n").unwrap();

    // --- Part B: Simulated mid-flight I/O error triggers full LIFO journal rollback ---
    // Note action order:
    //   step 0: RemoveLeaf("old_dir/script.sh")
    //   step 1: RemoveDirectory("old_dir")
    //   step 2: CreateDirectory("nested")
    //   step 3: CreateDirectory("nested/sub")
    //   step 4: WriteFile("README.md") -> FAIL HERE after 0..=3 already mutated disk!
    let rb_err = execute_apply_with_fault_hook(
        &base,
        view.overlay(),
        target.path(),
        engine.blob_store(),
        false,
        |step_idx, _action| {
            if step_idx == 4 {
                Err(io::Error::other("simulated disk write failure at step 4"))
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();

    assert!(
        matches!(rb_err, ApplyStoreError::RolledBack { step_index: 4, .. }),
        "unexpected error: {rb_err:?}"
    );

    // Verify `target` was 100% restored all-or-nothing!
    assert_eq!(
        fs::read(target.path().join("README.md")).unwrap(),
        b"original readme\n"
    );
    assert_eq!(
        fs::read(target.path().join("old_dir/script.sh")).unwrap(),
        b"#!/bin/sh\necho v1\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(target.path().join("old_dir/script.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }
    assert!(!target.path().join("nested").exists());
    assert!(!target.path().join("shortcut").exists());

    // --- Part C: Clean execution succeeds, and `force == true` overrides subsequent conflict ---
    execute_apply(
        &base,
        view.overlay(),
        target.path(),
        engine.blob_store(),
        false,
    )
    .unwrap();
    assert_eq!(
        fs::read(target.path().join("README.md")).unwrap(),
        b"updated from view\n"
    );
    assert_eq!(
        fs::read(target.path().join("nested/sub/added.txt")).unwrap(),
        b"brand new payload\n"
    );
    assert!(!target.path().join("old_dir").exists());
    #[cfg(unix)]
    assert_eq!(
        fs::read_link(target.path().join("shortcut"))
            .unwrap()
            .to_str()
            .unwrap(),
        "nested/sub/added.txt"
    );

    // Diverge `target` (`README.md` edited + `old_dir` recreated with untracked child) and run `force = true`.
    fs::write(target.path().join("README.md"), b"diverged").unwrap();
    fs::create_dir_all(target.path().join("old_dir")).unwrap();
    fs::write(target.path().join("old_dir/extra.txt"), b"untracked").unwrap();
    fs::write(target.path().join("unrelated_keep.txt"), b"preserve").unwrap();

    execute_apply(
        &base,
        view.overlay(),
        target.path(),
        engine.blob_store(),
        true,
    )
    .unwrap();
    assert_eq!(
        fs::read(target.path().join("README.md")).unwrap(),
        b"updated from view\n"
    );
    assert!(!target.path().join("old_dir").exists());
    assert_eq!(
        fs::read(target.path().join("unrelated_keep.txt")).unwrap(),
        b"preserve"
    );

    // `View` itself remained unchanged throughout all `Apply` runs.
    assert_eq!(
        engine.read("apply-view/README.md", 0, 64).unwrap(),
        b"updated from view\n"
    );
}

#[test]
fn startup_recovery_sweeps_orphan_blob_and_metadata_staging_temps() {
    let dir = TempDir::new("recovery");
    let blobs = FsBlobStore::open(dir.path().join("blobs")).unwrap();
    let meta = FsMetadataStore::open(dir.path().join("meta")).unwrap();

    let kept_hash = blobs.put_blob(b"committed blob").unwrap();

    // Plant simulated crash leftovers inside both `.staging/` directories.
    fs::write(blobs.staging_dir().join("blob-999-1.tmp"), b"half written").unwrap();
    fs::write(blobs.staging_dir().join("blob-999-2.tmp"), b"interrupted").unwrap();
    fs::write(meta.staging_dir().join("meta-999-1.tmp"), b"partial frame").unwrap();
    fs::create_dir_all(meta.staging_dir().join("stale-dir")).unwrap();

    let (_, summary) = BitStore::open(dir.path()).unwrap();
    assert_eq!(
        summary,
        RecoverySummary {
            swept_blob_temps: 2,
            swept_metadata_temps: 2,
        }
    );

    assert_eq!(fs::read_dir(blobs.staging_dir()).unwrap().count(), 0);
    assert_eq!(fs::read_dir(meta.staging_dir()).unwrap().count(), 0);
    assert_eq!(blobs.get_blob(&kept_hash).unwrap(), b"committed blob");
}
