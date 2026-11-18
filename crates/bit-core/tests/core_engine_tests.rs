//! Comprehensive end-to-end deterministic tests for `bit-core`.

use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use bit_core::{
    ApplyConflictKind, ApplyTarget, BaseInput, BaseSelector, BlobStore, CaseSensitivity,
    ControlPlane, CoreEngine, CoreError, DiffChange, InputEntry, MetadataStore, NodeKind, RelPath,
    TagName, VfsError, VfsOperations, VfsSetAttr, ViewId, ROOT_INO,
};

fn sample_base_input() -> BaseInput {
    BaseInput::Entries(vec![
        InputEntry::file("README.md", b"# Bit\n").unwrap(),
        InputEntry::file("pkg/lib.rs", b"pub fn answer() -> u32 { 42 }\n").unwrap(),
        InputEntry::file("pkg/sub/helper.rs", b"pub const K: usize = 7;\n").unwrap(),
        InputEntry::executable("scripts/run.sh", b"#!/bin/sh\necho ok\n").unwrap(),
        InputEntry::symlink("bin_env", "/usr/bin/env").unwrap(),
        InputEntry::file(".git/HEAD", b"0123456789abcdef\n").unwrap(),
    ])
}

#[test]
fn flat_base_overlay_isolation_and_git_agnostic_entries() {
    let engine = CoreEngine::in_memory();
    let tag = TagName::new("clean").unwrap();
    let base_info = engine
        .create_base(sample_base_input(), Some(tag.clone()))
        .unwrap();

    let v1 = ViewId::new("agent-1").unwrap();
    let v2 = ViewId::new("agent-2").unwrap();
    engine
        .create_view(v1.clone(), BaseSelector::Tag(tag))
        .unwrap();
    engine
        .create_view(v2.clone(), BaseSelector::Id(base_info.id))
        .unwrap();

    // External symlink target and `.git/HEAD` resolve identically in both views (ADR-0001 & ADR-0003).
    assert_eq!(engine.readlink("agent-1/bin_env").unwrap(), "/usr/bin/env");
    assert_eq!(
        engine.read("agent-1/.git/HEAD", 0, 64).unwrap(),
        b"0123456789abcdef\n"
    );

    // Mutate `agent-1` via VFS: overwrite README, delete helper.rs, create new file.
    engine
        .write("agent-1/README.md", 0, b"# Modified in agent-1\n")
        .unwrap();
    engine.unlink("agent-1/pkg/sub/helper.rs").unwrap();
    engine
        .create_file("agent-1/notes.txt", 0o644, true)
        .unwrap();
    engine.write("agent-1/notes.txt", 0, b"private").unwrap();

    // `agent-1` sees all private Overlay mutations.
    assert_eq!(
        engine.read("agent-1/README.md", 0, 128).unwrap(),
        b"# Modified in agent-1\n"
    );
    assert_eq!(
        engine.getattr("agent-1/pkg/sub/helper.rs"),
        Err(VfsError::NotFound)
    );
    assert_eq!(engine.read("agent-1/notes.txt", 0, 64).unwrap(), b"private");

    // `agent-2` remains completely isolated on the shared immutable Base.
    assert_eq!(
        engine.read("agent-2/README.md", 0, 128).unwrap(),
        b"# Bit\n"
    );
    assert_eq!(
        engine.read("agent-2/pkg/sub/helper.rs", 0, 128).unwrap(),
        b"pub const K: usize = 7;\n"
    );
    assert_eq!(engine.getattr("agent-2/notes.txt"), Err(VfsError::NotFound));

    // Removing `agent-1` does not affect `agent-2` or the shared Base.
    engine.remove_view(&v1).unwrap();
    assert_eq!(engine.getattr("agent-1"), Err(VfsError::NotFound));
    assert_eq!(
        engine.read("agent-2/README.md", 0, 128).unwrap(),
        b"# Bit\n"
    );
}

#[test]
fn remove_base_enforces_referential_integrity_unless_cascade() {
    let engine = CoreEngine::in_memory();
    let tag_a = TagName::new("v1.0").unwrap();
    let tag_b = TagName::new("latest").unwrap();
    let base = engine
        .create_base(sample_base_input(), Some(tag_a.clone()))
        .unwrap();
    engine
        .set_tag(tag_b.clone(), BaseSelector::Id(base.id))
        .unwrap();

    let v1 = ViewId::new("view-1").unwrap();
    let v2 = ViewId::new("view-2").unwrap();
    engine
        .create_view(v1.clone(), BaseSelector::Tag(tag_a.clone()))
        .unwrap();
    engine
        .create_view(v2.clone(), BaseSelector::Tag(tag_b.clone()))
        .unwrap();

    // Blocked when `cascade == false`.
    let err = engine
        .remove_base(BaseSelector::Id(base.id), false)
        .unwrap_err();
    assert_eq!(
        err,
        CoreError::BaseInUse {
            base_id: base.id,
            views: vec![v1.clone(), v2.clone()],
        }
    );

    // Deleting one tag keeps the Base and other tag intact.
    engine.delete_tag(&tag_a).unwrap();
    assert_eq!(engine.list_bases().unwrap()[0].tags, vec![tag_b.clone()]);

    // Cascade removal cleans up dependent Views, remaining Tags, and the Base.
    let removed = engine
        .remove_base(BaseSelector::Tag(tag_b.clone()), true)
        .unwrap();
    assert_eq!(removed.base_id, base.id);
    assert_eq!(removed.removed_views, vec![v1, v2]);
    assert_eq!(removed.removed_tags, vec![tag_b]);
    assert!(engine.list_bases().unwrap().is_empty());
    assert!(engine.list_views().unwrap().is_empty());
}

#[test]
fn metadata_only_directory_rename_chmod_and_opaque_directories() {
    let engine = CoreEngine::in_memory();
    let base = engine.create_base(sample_base_input(), None).unwrap();
    let v1 = ViewId::new("v1").unwrap();
    engine
        .create_view(v1.clone(), BaseSelector::Id(base.id))
        .unwrap();

    let lib_ino_before = engine.getattr("v1/pkg/lib.rs").unwrap().ino;
    let puts_before = engine.blob_store().put_count();
    let gets_before = engine.blob_store().get_count();

    // Metadata-only directory rename and chmod must copy ZERO file bytes.
    engine.rename("v1/pkg", "v1/pkg_moved").unwrap();
    engine
        .setattr(
            "v1/README.md",
            VfsSetAttr {
                mode: Some(0o755),
                size: None,
                mtime: None,
            },
        )
        .unwrap();

    assert_eq!(engine.blob_store().put_count(), puts_before);
    assert_eq!(engine.blob_store().get_count(), gets_before);

    // Inode identity is preserved across intra-view rename, old path is hidden, new path works.
    let lib_ino_after = engine.getattr("v1/pkg_moved/lib.rs").unwrap().ino;
    assert_eq!(lib_ino_before, lib_ino_after);
    assert_eq!(engine.getattr("v1/pkg"), Err(VfsError::NotFound));
    assert_eq!(engine.getattr("v1/pkg/lib.rs"), Err(VfsError::NotFound));
    assert_eq!(
        engine.read("v1/pkg_moved/sub/helper.rs", 0, 128).unwrap(),
        b"pub const K: usize = 7;\n"
    );
    assert_eq!(engine.getattr("v1/README.md").unwrap().mode, 0o755);

    // Now recreate `"v1/pkg"` (`rm -rf pkg && mkdir pkg` / after moving `pkg` away):
    // `"v1/pkg"` must be an opaque directory so `pkg/lib.rs` and `pkg/sub` from Base do NOT leak back!
    engine.mkdir("v1/pkg", 0o755).unwrap();
    assert!(engine.readdir("v1/pkg").unwrap().is_empty());
    assert_eq!(engine.getattr("v1/pkg/lib.rs"), Err(VfsError::NotFound));
    assert_eq!(engine.getattr("v1/pkg/sub"), Err(VfsError::NotFound));

    engine
        .create_file("v1/pkg/brand_new.rs", 0o644, true)
        .unwrap();
    engine
        .write("v1/pkg/brand_new.rs", 0, b"pub const NEW: bool = true;\n")
        .unwrap();

    let pkg_entries = engine.readdir("v1/pkg").unwrap();
    assert_eq!(pkg_entries.len(), 1);
    assert_eq!(pkg_entries[0].name, "brand_new.rs");

    // Verify `rm -rf scripts && mkdir scripts` explicitly via unlink + rmdir + mkdir.
    engine.unlink("v1/scripts/run.sh").unwrap();
    engine.rmdir("v1/scripts").unwrap();
    assert_eq!(engine.getattr("v1/scripts"), Err(VfsError::NotFound));
    engine.mkdir("v1/scripts", 0o700).unwrap();
    assert!(engine.readdir("v1/scripts").unwrap().is_empty());
    assert_eq!(engine.getattr("v1/scripts/run.sh"), Err(VfsError::NotFound));

    let diff = engine.diff_view(&v1).unwrap();
    assert!(diff
        .iter()
        .any(|d| d.path.as_str() == "scripts/run.sh" && d.change == DiffChange::Deleted));
    assert!(diff
        .iter()
        .any(|d| d.path.as_str() == "scripts" && d.change == DiffChange::Modified));
    assert!(diff
        .iter()
        .any(|d| d.path.as_str() == "pkg/lib.rs" && d.change == DiffChange::Deleted));
    assert!(diff
        .iter()
        .any(|d| d.path.as_str() == "pkg/brand_new.rs" && d.change == DiffChange::Added));
    assert!(diff
        .iter()
        .any(|d| d.path.as_str() == "pkg_moved/lib.rs" && d.change == DiffChange::Added));
}

#[test]
fn diff_cancels_created_then_deleted_temp_files_and_runs_proportional_to_overlay() {
    let mut many_files = Vec::with_capacity(500);
    for idx in 0..500 {
        many_files.push(
            InputEntry::file(
                format!("bulk/mod_{idx:03}/file_{idx:03}.txt"),
                format!("payload-{idx}").into_bytes(),
            )
            .unwrap(),
        );
    }
    let engine = CoreEngine::in_memory();
    let base = engine
        .create_base(BaseInput::Entries(many_files), None)
        .unwrap();
    let v1 = ViewId::new("scratch").unwrap();
    engine
        .create_view(v1.clone(), BaseSelector::Id(base.id))
        .unwrap();

    // Create and remove temporary files & directories both at View root and inside a Base dir.
    engine.mkdir("scratch/tmp_build", 0o755).unwrap();
    engine
        .create_file("scratch/tmp_build/part.o", 0o644, true)
        .unwrap();
    engine
        .write("scratch/tmp_build/part.o", 0, b"ephemeral")
        .unwrap();
    engine.unlink("scratch/tmp_build/part.o").unwrap();
    engine.rmdir("scratch/tmp_build").unwrap();

    engine
        .create_file("scratch/bulk/mod_001/.lock", 0o644, true)
        .unwrap();
    engine
        .write("scratch/bulk/mod_001/.lock", 0, b"1234")
        .unwrap();
    engine.unlink("scratch/bulk/mod_001/.lock").unwrap();

    // Net Diff must be completely empty even though `bulk/mod_001` directory mtime was updated.
    let empty_diff = engine.diff_view(&v1).unwrap();
    assert!(
        empty_diff.is_empty(),
        "expected empty diff, got {empty_diff:?}"
    );

    // Freezing a View with zero net semantic mutations reproduces the exact deterministic BaseId.
    let frozen_same = engine.freeze_view(&v1, None).unwrap();
    assert_eq!(frozen_same.base_id, base.id);

    // Edit 1 file out of 500 and verify Diff reads 0 blobs and reports only that 1 entry.
    engine
        .write("scratch/bulk/mod_042/file_042.txt", 0, b"updated-42")
        .unwrap();
    let gets_before_diff = engine.blob_store().get_count();
    let diff = engine.diff_view(&v1).unwrap();
    assert_eq!(engine.blob_store().get_count(), gets_before_diff);
    assert_eq!(diff.len(), 1);
    assert_eq!(diff[0].path.as_str(), "bulk/mod_042/file_042.txt");
    assert_eq!(diff[0].change, DiffChange::Modified);
}

#[test]
fn freeze_captures_new_base_for_flat_composition() {
    let engine = CoreEngine::in_memory();
    let base1 = engine.create_base(sample_base_input(), None).unwrap();
    let v1 = ViewId::new("parent-view").unwrap();
    engine
        .create_view(v1.clone(), BaseSelector::Id(base1.id))
        .unwrap();

    engine
        .create_file("parent-view/feature.rs", 0o644, true)
        .unwrap();
    engine
        .write("parent-view/feature.rs", 0, b"pub fn feature() {}\n")
        .unwrap();
    engine.unlink("parent-view/README.md").unwrap();

    let frozen_tag = TagName::new("frozen-step").unwrap();
    let frozen = engine.freeze_view(&v1, Some(frozen_tag.clone())).unwrap();
    assert_ne!(frozen.base_id, base1.id);

    // Child View created from the frozen Base starts with an empty Overlay (ADR-0001 flat model).
    let v_child = ViewId::new("child-view").unwrap();
    let child_info = engine
        .create_view(v_child.clone(), BaseSelector::Tag(frozen_tag))
        .unwrap();
    assert_eq!(child_info.base_id, frozen.base_id);
    assert_eq!(child_info.overlay_entry_count, 0);
    assert!(engine.diff_view(&v_child).unwrap().is_empty());

    assert_eq!(
        engine.read("child-view/feature.rs", 0, 128).unwrap(),
        b"pub fn feature() {}\n"
    );
    assert_eq!(
        engine.getattr("child-view/README.md"),
        Err(VfsError::NotFound)
    );
}

#[test]
fn apply_detects_edits_deletes_and_colliding_creates_and_leaves_view_unchanged() {
    let engine = CoreEngine::in_memory();
    let base_info = engine.create_base(sample_base_input(), None).unwrap();
    let base = engine
        .metadata_store()
        .get_base(&base_info.id)
        .unwrap()
        .unwrap();

    let v1 = ViewId::new("work").unwrap();
    engine
        .create_view(v1.clone(), BaseSelector::Id(base.id()))
        .unwrap();

    // Mutate `work`: edit README.md, delete scripts/run.sh + scripts, add created.txt.
    engine
        .write("work/README.md", 0, b"# Updated via View\n")
        .unwrap();
    engine.unlink("work/scripts/run.sh").unwrap();
    engine.rmdir("work/scripts").unwrap();
    engine.create_file("work/created.txt", 0o644, true).unwrap();
    engine.write("work/created.txt", 0, b"new content").unwrap();

    // 1. External edit conflict on README.md.
    let mut ext_edited = base.tree().clone();
    let edited_hash = engine
        .blob_store()
        .put_blob(b"concurrent host edit")
        .unwrap();
    ext_edited
        .insert_entry(
            RelPath::new("README.md").unwrap(),
            bit_core::TreeEntry::file(edited_hash, 20, 0o644, bit_core::Timestamp::EPOCH),
        )
        .unwrap();
    let err = engine
        .apply_view(&v1, ApplyTarget::Tree(ext_edited))
        .unwrap_err();
    assert!(matches!(
        err,
        CoreError::ApplyConflicts(ref c)
            if c.iter().any(|x| x.path.as_str() == "README.md" && x.kind == ApplyConflictKind::ExternalModified)
    ));

    // 2. External delete conflict on scripts/run.sh.
    let mut ext_deleted = base.tree().clone();
    ext_deleted.remove_subtree(&RelPath::new("scripts/run.sh").unwrap());
    let err = engine
        .apply_view(&v1, ApplyTarget::Tree(ext_deleted))
        .unwrap_err();
    assert!(matches!(
        err,
        CoreError::ApplyConflicts(ref c)
            if c.iter().any(|x| x.path.as_str() == "scripts/run.sh" && x.kind == ApplyConflictKind::ExternalDeleted)
    ));

    // 3. Colliding create on created.txt.
    let mut ext_collide = base.tree().clone();
    ext_collide
        .insert_entry(
            RelPath::new("created.txt").unwrap(),
            bit_core::TreeEntry::file(edited_hash, 20, 0o644, bit_core::Timestamp::EPOCH),
        )
        .unwrap();
    let err = engine
        .apply_view(&v1, ApplyTarget::Tree(ext_collide))
        .unwrap_err();
    assert!(matches!(
        err,
        CoreError::ApplyConflicts(ref c)
            if c.iter().any(|x| x.path.as_str() == "created.txt" && x.kind == ApplyConflictKind::CollidingCreate)
    ));

    // 4. Untracked file inside a directory removed by the View (`DirectoryNotEmpty`).
    let mut ext_untracked_in_removed = base.tree().clone();
    ext_untracked_in_removed
        .insert_entry(
            RelPath::new("scripts/keep_me.sh").unwrap(),
            bit_core::TreeEntry::file(edited_hash, 20, 0o644, bit_core::Timestamp::EPOCH),
        )
        .unwrap();
    let err = engine
        .apply_view(&v1, ApplyTarget::Tree(ext_untracked_in_removed))
        .unwrap_err();
    assert!(matches!(
        err,
        CoreError::ApplyConflicts(ref c)
            if c.iter().any(|x| x.path.as_str() == "scripts/keep_me.sh" && x.kind == ApplyConflictKind::DirectoryNotEmpty)
    ));

    // 5. End-to-end host directory `create_base(ExternalDir)` + VFS edits + `apply_view(ExternalDir)`.
    let temp_dir = std::env::temp_dir().join(format!("bit-core-apply-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("pkg/sub")).unwrap();
    fs::create_dir_all(temp_dir.join("scripts")).unwrap();
    fs::create_dir_all(temp_dir.join(".git")).unwrap();
    fs::write(temp_dir.join("README.md"), b"# Bit\n").unwrap();
    fs::write(
        temp_dir.join("pkg/lib.rs"),
        b"pub fn answer() -> u32 { 42 }\n",
    )
    .unwrap();
    fs::write(
        temp_dir.join("pkg/sub/helper.rs"),
        b"pub const K: usize = 7;\n",
    )
    .unwrap();
    fs::write(temp_dir.join("scripts/run.sh"), b"#!/bin/sh\necho ok\n").unwrap();
    fs::write(temp_dir.join(".git/HEAD"), b"0123456789abcdef\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            temp_dir.join("scripts/run.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink("/usr/bin/env", temp_dir.join("bin_env")).unwrap();
    }

    let disk_base = engine
        .create_base(
            BaseInput::ExternalDir(temp_dir.clone()),
            Some(TagName::new("disk-base").unwrap()),
        )
        .unwrap();
    let disk_view = ViewId::new("disk-work").unwrap();
    engine
        .create_view(disk_view.clone(), BaseSelector::Id(disk_base.id))
        .unwrap();

    engine
        .write("disk-work/README.md", 0, b"# Updated via View\n")
        .unwrap();
    engine.unlink("disk-work/scripts/run.sh").unwrap();
    engine.rmdir("disk-work/scripts").unwrap();
    engine
        .create_file("disk-work/created.txt", 0o644, true)
        .unwrap();
    engine
        .write("disk-work/created.txt", 0, b"new content")
        .unwrap();

    // Add an unrelated untracked file in the external directory: guarded Apply should allow & keep it!
    fs::write(temp_dir.join("LOCAL_NOTES.md"), b"keep untouched").unwrap();

    let output = engine
        .apply_view(&disk_view, ApplyTarget::ExternalDir(temp_dir.clone()))
        .unwrap();
    assert!(!output.plan.is_noop());

    assert_eq!(
        fs::read(temp_dir.join("README.md")).unwrap(),
        b"# Updated via View\n"
    );
    assert_eq!(
        fs::read(temp_dir.join("created.txt")).unwrap(),
        b"new content"
    );
    assert!(!temp_dir.join("scripts").exists());
    assert_eq!(
        fs::read(temp_dir.join("LOCAL_NOTES.md")).unwrap(),
        b"keep untouched"
    );

    // View itself remains completely unchanged after Apply.
    assert_eq!(
        engine.diff_view(&disk_view).unwrap().len(),
        output.plan.diff.len()
    );

    // Re-applying onto the already-mutated external directory now conflicts (since external != Base).
    assert!(matches!(
        engine.apply_view(&disk_view, ApplyTarget::ExternalDir(temp_dir.clone())),
        Err(CoreError::ApplyConflicts(_))
    ));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn mount_root_read_only_cross_view_exdev_and_link_eopnotsupp() {
    let engine = CoreEngine::in_memory();
    let base = engine.create_base(sample_base_input(), None).unwrap();
    let v1 = ViewId::new("alpha").unwrap();
    let v2 = ViewId::new("beta").unwrap();
    engine
        .create_view(v1.clone(), BaseSelector::Id(base.id))
        .unwrap();
    engine
        .create_view(v2.clone(), BaseSelector::Id(base.id))
        .unwrap();

    // `<mount>/` root inspection.
    let root_attr = engine.getattr("/").unwrap();
    assert_eq!(root_attr.ino, ROOT_INO);
    assert_eq!(root_attr.kind, NodeKind::Directory);
    assert!(root_attr.read_only);

    let root_entries = engine.readdir("/").unwrap();
    let names: Vec<&str> = root_entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "beta"]);
    assert_eq!(engine.getattr("/nonexistent"), Err(VfsError::NotFound));
    assert_eq!(engine.getattr("/invalid space"), Err(VfsError::NotFound));

    // All mutations targeting `<mount>/` or direct `<mount>/<child>` fail with `VfsError::ReadOnly` (`EROFS`).
    assert_eq!(engine.mkdir("/gamma", 0o755), Err(VfsError::ReadOnly));
    assert_eq!(
        engine.create_file("/root_file.txt", 0o644, false),
        Err(VfsError::ReadOnly)
    );
    assert_eq!(engine.unlink("/alpha"), Err(VfsError::ReadOnly));
    assert_eq!(engine.rmdir("/alpha"), Err(VfsError::ReadOnly));
    assert_eq!(engine.symlink("alpha", "/link"), Err(VfsError::ReadOnly));
    assert_eq!(engine.rename("/alpha", "/gamma"), Err(VfsError::ReadOnly));
    assert_eq!(
        engine.setattr(
            "/",
            VfsSetAttr {
                mode: Some(0o777),
                size: None,
                mtime: None,
            }
        ),
        Err(VfsError::ReadOnly)
    );
    assert_eq!(VfsError::ReadOnly.to_posix_errno(), 30);

    // Cross-View `rename` fails with `VfsError::CrossDevice` (`EXDEV = 18`).
    let cross_err = engine
        .rename("alpha/README.md", "beta/README_moved.md")
        .unwrap_err();
    assert_eq!(cross_err, VfsError::CrossDevice);
    assert_eq!(cross_err.to_posix_errno(), 18);
    assert_eq!(cross_err.to_nfs3_stat(), 18);

    // Hard `link()` fails with `VfsError::NotSupported` (`EOPNOTSUPP`).
    let link_err = engine
        .link("alpha/README.md", "alpha/README_hardlink.md")
        .unwrap_err();
    assert_eq!(link_err, VfsError::NotSupported);
    assert_eq!(link_err.to_posix_errno(), 95);
    assert_eq!(link_err.to_nfs3_stat(), 10004);
}

#[test]
fn case_insensitive_unambiguous_adapter_mode() {
    let engine =
        CoreEngine::in_memory().with_case_sensitivity(CaseSensitivity::CaseInsensitiveUnambiguous);
    let base = engine
        .create_base(
            BaseInput::from_files([
                ("Docs/Guide.md", &b"guide"[..]),
                ("Docs/Makefile", &b"upper"[..]),
                ("Docs/makefile", &b"lower"[..]),
            ])
            .unwrap(),
            None,
        )
        .unwrap();
    engine
        .create_view(ViewId::new("mac").unwrap(), BaseSelector::Id(base.id))
        .unwrap();

    // Unambiguous case-folded path succeeds.
    assert_eq!(engine.read("mac/docs/GUIDE.MD", 0, 32).unwrap(), b"guide");
    // Exact canonical match wins even when case-colliding sibling exists.
    assert_eq!(engine.read("mac/Docs/Makefile", 0, 32).unwrap(), b"upper");
    assert_eq!(engine.read("mac/Docs/makefile", 0, 32).unwrap(), b"lower");
    // Non-exact query matching two siblings fails with `AmbiguousCase`.
    assert!(matches!(
        engine.read("mac/Docs/MAKEFILE", 0, 32),
        Err(VfsError::AmbiguousCase(_))
    ));

    // Non-exclusive `create_file` with different casing truncates the canonical entry (`Docs/Guide.md`)
    // rather than inserting a colliding sibling.
    let guide_ino = engine.getattr("mac/Docs/Guide.md").unwrap().ino;
    let truncated_attr = engine
        .create_file("mac/docs/guide.md", 0o644, false)
        .unwrap();
    assert_eq!(truncated_attr.ino, guide_ino);
    assert_eq!(truncated_attr.size, 0);
    engine.write("mac/DOCS/GUIDE.MD", 0, b"rewritten").unwrap();
    assert_eq!(
        engine.read("mac/Docs/Guide.md", 0, 32).unwrap(),
        b"rewritten"
    );
    let docs_names: Vec<String> = engine
        .readdir("mac/Docs")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(docs_names, vec!["Guide.md", "Makefile", "makefile"]);

    // Case-only `rename` updates canonical entry casing (both for files and non-empty directories).
    engine
        .rename("mac/Docs/Guide.md", "mac/docs/guide.md")
        .unwrap();
    let docs_names_after: Vec<String> = engine
        .readdir("mac/Docs")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(docs_names_after, vec!["Makefile", "guide.md", "makefile"]);
    assert_eq!(engine.getattr("mac/Docs/guide.md").unwrap().ino, guide_ino);
    assert_eq!(
        engine.read("mac/Docs/GUIDE.MD", 0, 32).unwrap(),
        b"rewritten"
    );

    engine.rename("mac/Docs", "mac/docs").unwrap();
    let root_names: Vec<String> = engine
        .readdir("mac")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(root_names, vec!["docs"]);
    assert_eq!(
        engine.read("mac/docs/guide.md", 0, 32).unwrap(),
        b"rewritten"
    );
}

#[test]
fn per_view_write_quiescence_barrier_isolates_views_and_drains_writers() {
    let engine = Arc::new(CoreEngine::in_memory());
    let base = engine.create_base(sample_base_input(), None).unwrap();
    let v1 = ViewId::new("v1").unwrap();
    let v2 = ViewId::new("v2").unwrap();
    engine
        .create_view(v1.clone(), BaseSelector::Id(base.id))
        .unwrap();
    engine
        .create_view(v2.clone(), BaseSelector::Id(base.id))
        .unwrap();

    // Hold an in-flight write guard on `v1`.
    let writer_guard = engine.quiescence().begin_write(&v1);
    let quiesced_flag = Arc::new(AtomicBool::new(false));
    let writer_entered_barrier = Arc::new(Barrier::new(2));

    let eng_q = Arc::clone(&engine);
    let v1_q = v1.clone();
    let flag_q = Arc::clone(&quiesced_flag);
    let barrier_q = Arc::clone(&writer_entered_barrier);

    let quiescer = thread::spawn(move || {
        barrier_q.wait();
        let _q_guard = eng_q.quiesce_view(&v1_q).unwrap();
        flag_q.store(true, Ordering::SeqCst);
        // While `v1` is quiesced, VFS reads on `v1` still work without deadlocking.
        assert_eq!(eng_q.read("v1/README.md", 0, 16).unwrap(), b"# Bit\n");
    });

    writer_entered_barrier.wait();
    thread::sleep(Duration::from_millis(20));
    // `quiesce_view` on `v1` must still be waiting while `writer_guard` is active.
    assert!(!quiesced_flag.load(Ordering::SeqCst));

    // Meanwhile, VFS writes on `v2` proceed immediately without blocking!
    engine
        .write("v2/README.md", 0, b"# v2 unblocked\n")
        .unwrap();

    // Releasing `writer_guard` unblocks `quiesce_view(&v1)`.
    drop(writer_guard);
    quiescer.join().unwrap();
    assert!(quiesced_flag.load(Ordering::SeqCst));
}
