//! End-to-end integration tests exercising the compiled `bit` binary, on-demand background
//! `bit daemon run` auto-start, persistent `BitStore` survival across `daemon stop` + restart,
//! and transactional `bit apply` with 3-way conflict protection.
#![forbid(unsafe_code)]

#[cfg(unix)]
mod unix_e2e {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    use bit_core::{Timestamp, VfsOperations};
    use bit_daemon::{BIT_HOME_VAR, BIT_MOUNT_DIR_VAR};
    use bit_store::BitStore;

    fn run_bit(cwd: &Path, bit_home: &Path, mount_dir: &Path, args: &[&str]) -> Output {
        let bin = env!("CARGO_BIN_EXE_bit");
        Command::new(bin)
            .current_dir(cwd)
            .env(BIT_HOME_VAR, bit_home)
            .env(BIT_MOUNT_DIR_VAR, mount_dir)
            .args(args)
            .output()
            .expect("failed to execute bit binary")
    }

    fn stdout_str(out: &Output) -> String {
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn stderr_str(out: &Output) -> String {
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    #[test]
    fn cli_persists_state_across_daemon_restarts_and_guards_apply_conflicts() {
        let root: PathBuf = std::env::temp_dir().join(format!(
            "bit-cli-persist-e2e-{}-{}",
            std::process::id(),
            Timestamp::now().nanos
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let bit_home = root.join("home/.bit");
        let mount_dir = root.join("home/.bit/views");
        let store_dir = bit_home.join("store");
        let work_cwd = root.join("caller-cwd");
        fs::create_dir_all(&work_cwd).unwrap();

        let sample_dir = work_cwd.join("sample-tree");
        fs::create_dir_all(sample_dir.join("src")).unwrap();
        fs::create_dir_all(sample_dir.join("target")).unwrap();
        fs::write(sample_dir.join("src/main.rs"), b"fn main() {}\n").unwrap();
        fs::write(sample_dir.join("README.md"), b"initial readme\n").unwrap();
        std::os::unix::fs::symlink("../README.md", sample_dir.join("src/readme_link")).unwrap();
        fs::write(sample_dir.join("notes.tmp"), b"scratch\n").unwrap();
        fs::write(sample_dir.join("target/out"), b"artifact\n").unwrap();

        // 1. `daemon status` before any command reports stopped without auto-starting.
        let st0 = run_bit(&work_cwd, &bit_home, &mount_dir, &["daemon", "status"]);
        assert!(st0.status.success(), "stderr: {}", stderr_str(&st0));
        assert_eq!(stdout_str(&st0).trim(), "status: stopped");

        // 2. `base create` auto-starts persistent `bit daemon run` and ingests `sample-tree`.
        let create_base = run_bit(
            &work_cwd,
            &bit_home,
            &mount_dir,
            &[
                "base",
                "create",
                "sample-tree",
                "--tag",
                "v1",
                "--exclude",
                "target",
                "--exclude",
                "*.tmp",
            ],
        );
        assert!(
            create_base.status.success(),
            "stderr: {}",
            stderr_str(&create_base)
        );
        assert!(stdout_str(&create_base).contains("(tags: v1)"));

        // 3. Create named View with `--link` and unnamed View.
        let create_v1 = run_bit(
            &work_cwd,
            &bit_home,
            &mount_dir,
            &["view", "create", "v1", "dev-1", "--link", "./dev-link"],
        );
        assert!(
            create_v1.status.success(),
            "stderr: {}",
            stderr_str(&create_v1)
        );
        let link_file = work_cwd.join("dev-link");
        assert!(fs::symlink_metadata(&link_file)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_link(&link_file).unwrap(), mount_dir.join("dev-1"));

        let create_auto = run_bit(&work_cwd, &bit_home, &mount_dir, &["view", "create", "v1"]);
        assert!(create_auto.status.success());
        assert!(stdout_str(&create_auto).starts_with("view-0001\t"));

        // 4. Stop the running daemon cleanly via `bit daemon stop`!
        let stop1 = run_bit(&work_cwd, &bit_home, &mount_dir, &["daemon", "stop"]);
        assert!(stop1.status.success());
        assert_eq!(stdout_str(&stop1).trim(), "daemon stopped");

        let st_stopped = run_bit(&work_cwd, &bit_home, &mount_dir, &["daemon", "status"]);
        assert_eq!(stdout_str(&st_stopped).trim(), "status: stopped");

        // Perform VFS mutations on `dev-1` in the persisted `BitStore` while daemon is offline
        // (simulating mutations written through the VFS mount before restart).
        {
            let (store, _) = BitStore::open(&store_dir).unwrap();
            let engine = store.into_engine();
            engine
                .write("dev-1/src/main.rs", 0, b"fn main() { println!(\"v2\"); }\n")
                .unwrap();
            engine
                .create_file("dev-1/CHANGELOG.md", 0o644, true)
                .unwrap();
            engine
                .write("dev-1/CHANGELOG.md", 0, b"## 0.2.0\n")
                .unwrap();
        }

        // 5. Run `bit base list` and `bit view list` — auto-starts a NEW daemon process and loads
        //    all persisted Bases, Tags, Views, Overlays, and external symlink paths from disk!
        let list_bases = run_bit(&work_cwd, &bit_home, &mount_dir, &["base", "list"]);
        assert!(
            list_bases.status.success(),
            "stderr: {}",
            stderr_str(&list_bases)
        );
        assert!(stdout_str(&list_bases).contains("entries=4\tviews=2\ttags=v1"));

        let list_views = run_bit(&work_cwd, &bit_home, &mount_dir, &["view", "list"]);
        assert!(list_views.status.success());
        let vlist_out = stdout_str(&list_views);
        assert!(vlist_out.contains("dev-1\t"));
        assert!(vlist_out.contains("view-0001\t"));
        assert!(vlist_out.contains("link="));

        // 6. `bit diff dev-1` shows the persisted Overlay mutations (`A CHANGELOG.md`, `M src/main.rs`).
        let diff_out = run_bit(&work_cwd, &bit_home, &mount_dir, &["diff", "dev-1"]);
        assert!(diff_out.status.success());
        let diff_text = stdout_str(&diff_out);
        assert!(diff_text.contains("A CHANGELOG.md"), "got: {diff_text}");
        assert!(diff_text.contains("M src/main.rs"), "got: {diff_text}");

        // 7. Prepare a clean external target directory matching Base `v1` and verify `bit apply`!
        let clean_target = work_cwd.join("clean-target");
        fs::create_dir_all(clean_target.join("src")).unwrap();
        fs::write(clean_target.join("src/main.rs"), b"fn main() {}\n").unwrap();
        fs::write(clean_target.join("README.md"), b"initial readme\n").unwrap();
        std::os::unix::fs::symlink("../README.md", clean_target.join("src/readme_link")).unwrap();

        let apply_clean = run_bit(
            &work_cwd,
            &bit_home,
            &mount_dir,
            &["apply", "dev-1", "clean-target"],
        );
        assert!(
            apply_clean.status.success(),
            "stderr: {}",
            stderr_str(&apply_clean)
        );
        assert_eq!(
            fs::read(clean_target.join("src/main.rs")).unwrap(),
            b"fn main() { println!(\"v2\"); }\n"
        );
        assert_eq!(
            fs::read(clean_target.join("CHANGELOG.md")).unwrap(),
            b"## 0.2.0\n"
        );

        // 8. Prepare a diverged external target directory (`src/main.rs` modified externally since Base)
        //    and verify guarded `bit apply` refuses all-or-nothing without writing `CHANGELOG.md`!
        let diverged_target = work_cwd.join("diverged-target");
        fs::create_dir_all(diverged_target.join("src")).unwrap();
        fs::write(
            diverged_target.join("src/main.rs"),
            b"fn main() { /* concurrent host edit */ }\n",
        )
        .unwrap();
        fs::write(diverged_target.join("README.md"), b"initial readme\n").unwrap();
        std::os::unix::fs::symlink("../README.md", diverged_target.join("src/readme_link"))
            .unwrap();

        let apply_conflict = run_bit(
            &work_cwd,
            &bit_home,
            &mount_dir,
            &["apply", "dev-1", "diverged-target"],
        );
        assert!(!apply_conflict.status.success());
        assert!(stderr_str(&apply_conflict).contains("conflict"));
        assert!(!diverged_target.join("CHANGELOG.md").exists());
        assert_eq!(
            fs::read(diverged_target.join("src/main.rs")).unwrap(),
            b"fn main() { /* concurrent host edit */ }\n"
        );

        // Passing `--force` overrides the conflict cleanly while leaving `dev-1` unchanged.
        let apply_forced = run_bit(
            &work_cwd,
            &bit_home,
            &mount_dir,
            &["apply", "dev-1", "diverged-target", "--force"],
        );
        assert!(
            apply_forced.status.success(),
            "stderr: {}",
            stderr_str(&apply_forced)
        );
        assert_eq!(
            fs::read(diverged_target.join("src/main.rs")).unwrap(),
            b"fn main() { println!(\"v2\"); }\n"
        );
        assert_eq!(
            fs::read(diverged_target.join("CHANGELOG.md")).unwrap(),
            b"## 0.2.0\n"
        );

        // 9. `bit freeze dev-1 --tag v2` captures a new Base that also survives restart!
        let freeze_out = run_bit(
            &work_cwd,
            &bit_home,
            &mount_dir,
            &["freeze", "dev-1", "--tag", "v2"],
        );
        assert!(freeze_out.status.success());
        assert!(stdout_str(&freeze_out).contains("(tag: v2)"));

        // 10. Cascade remove `v1` cleans up dependent Views + external symlink; stop daemon cleanly.
        let cascade_rm = run_bit(
            &work_cwd,
            &bit_home,
            &mount_dir,
            &["base", "rm", "v1", "--cascade"],
        );
        assert!(cascade_rm.status.success());
        assert!(fs::symlink_metadata(&link_file).is_err());

        let stop2 = run_bit(&work_cwd, &bit_home, &mount_dir, &["daemon", "stop"]);
        assert!(stop2.status.success());

        // Restart once more via `base list` and confirm frozen `v2` Base is still stored!
        let bases_after = run_bit(&work_cwd, &bit_home, &mount_dir, &["base", "list"]);
        assert!(bases_after.status.success());
        assert!(stdout_str(&bases_after).contains("tags=v2"));

        let _ = run_bit(&work_cwd, &bit_home, &mount_dir, &["daemon", "stop"]);
        let _ = fs::remove_dir_all(&root);
    }
}
