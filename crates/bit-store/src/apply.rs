//! Transactional `Apply` execution (`execute_apply`) with pre-flight 3-way conflict detection,
//! local blob staging, persistent rollback journal, and LIFO restoration on mid-flight error.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bit_core::{
    compute_diff, plan_apply, ApplyAction, ApplyConflict, ApplyPlan, Base, BlobStore, DiffChange,
    DiffEntry, DirectoryTree, NodeKind, Overlay, RelPath, StoreError, Timestamp, TreeEntry, View,
    ViewId, PERM_MASK,
};

use crate::blob::clear_readonly_if_needed;
use crate::ingest::{host_mode, observe_external_dir};

static JOURNAL_SEQ: AtomicU64 = AtomicU64::new(1);

/// Error returned by `execute_apply`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyStoreError {
    /// Pre-flight 3-way conflict check detected external edits, deletes, or colliding creates
    /// (returned when `force == false`; zero external mutations were performed).
    Conflicts(Vec<ApplyConflict>),
    /// Mid-flight I/O failure occurred at `step_index`; all prior mutations were rolled back
    /// from the transaction journal so `target_root` was restored all-or-nothing.
    RolledBack {
        step_index: usize,
        reason: String,
        restored_records: usize,
    },
    /// Mid-flight I/O failure occurred AND rollback also encountered an error.
    RollbackFailed {
        step_index: usize,
        apply_reason: String,
        rollback_reason: String,
    },
    /// Backing store or pre-flight directory inspection error.
    Store(StoreError),
}

impl fmt::Display for ApplyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflicts(list) => write!(
                f,
                "apply refused: {} pre-flight conflict(s) detected in target directory",
                list.len()
            ),
            Self::RolledBack {
                step_index,
                reason,
                restored_records,
            } => write!(
                f,
                "apply failed at step {step_index} ({reason}); cleanly rolled back {restored_records} journal record(s)"
            ),
            Self::RollbackFailed {
                step_index,
                apply_reason,
                rollback_reason,
            } => write!(
                f,
                "apply failed at step {step_index} ({apply_reason}) and rollback failed ({rollback_reason})"
            ),
            Self::Store(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl std::error::Error for ApplyStoreError {}

impl From<StoreError> for ApplyStoreError {
    fn from(err: StoreError) -> Self {
        Self::Store(err)
    }
}

#[derive(Debug, Clone)]
enum UndoRecord {
    /// Path did not exist prior to this step; remove it on rollback.
    RemoveCreated { rel: RelPath },
    /// Path existed as a directory with `mode`.
    RestoreDirectory { rel: RelPath, mode: u32 },
    /// Path existed as a regular file backed up at `backup_file` with `mode`.
    RestoreFile {
        rel: RelPath,
        backup_file: PathBuf,
        mode: u32,
    },
    /// Path existed as a symbolic link pointing to `target`.
    RestoreSymlink { rel: RelPath, target: String },
}

/// Projects `overlay` (backed by `base`) onto `target_root` all-or-nothing, leaving the `View`
/// and `Overlay` unchanged.
///
/// - When `force == false`, runs a pre-flight 3-way conflict check against `base` (refusing modified,
///   deleted, and colliding created paths before touching `target_root`).
/// - Stages all required file blobs ahead of time and records an on-disk rollback journal + backups
///   so any mid-flight error restores `target_root` to its exact pre-`Apply` state.
pub fn execute_apply(
    base: &Base,
    overlay: &Overlay,
    target_root: impl AsRef<Path>,
    blob_store: &dyn BlobStore,
    force: bool,
) -> Result<ApplyPlan, ApplyStoreError> {
    execute_apply_with_fault_hook(base, overlay, target_root, blob_store, force, |_, _| Ok(()))
}

/// Identical to `execute_apply`, invoking `fault_hook(step_index, action)` right before each
/// host filesystem mutation step (after recording that step's rollback journal entry) so tests
/// can deterministically inject mid-flight I/O failures and verify rollback.
pub fn execute_apply_with_fault_hook<F>(
    base: &Base,
    overlay: &Overlay,
    target_root: impl AsRef<Path>,
    blob_store: &dyn BlobStore,
    force: bool,
    mut fault_hook: F,
) -> Result<ApplyPlan, ApplyStoreError>
where
    F: FnMut(usize, &ApplyAction) -> io::Result<()>,
{
    let root = target_root.as_ref();
    let observed = observe_external_dir(root)?;

    let temp_view = View::from_parts(
        ViewId::new("apply-check").expect("valid constant ViewId"),
        base.id(),
        overlay.clone(),
        Timestamp::EPOCH,
    );

    let plan = if !force {
        plan_apply(base, &temp_view, &observed).map_err(ApplyStoreError::Conflicts)?
    } else {
        build_forced_plan(base, &temp_view, &observed)
    };

    if plan.is_noop() {
        return Ok(plan);
    }

    let seq = JOURNAL_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let journal_dir = std::env::temp_dir().join(format!("bit-apply-journal-{pid}-{seq}"));
    let staged_dir = journal_dir.join("staged");
    let backups_dir = journal_dir.join("backups");
    fs::create_dir_all(&staged_dir).map_err(StoreError::from)?;
    fs::create_dir_all(&backups_dir).map_err(StoreError::from)?;

    // Phase 1: Pre-stage every `WriteFile` blob into `staged/` and sync before touching `target_root`.
    let prestage_res = (|| -> Result<Vec<Option<PathBuf>>, StoreError> {
        let mut staged_paths = Vec::with_capacity(plan.actions.len());
        for (idx, action) in plan.actions.iter().enumerate() {
            if let ApplyAction::WriteFile {
                entry: TreeEntry::File { content, .. },
                ..
            } = action
            {
                let bytes = blob_store.get_blob(content)?;
                let staged_file = staged_dir.join(format!("{idx}.blob"));
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&staged_file)?;
                f.write_all(&bytes)?;
                f.sync_all()?;
                staged_paths.push(Some(staged_file));
            } else {
                staged_paths.push(None);
            }
        }
        Ok(staged_paths)
    })();

    let staged_files = match prestage_res {
        Ok(list) => list,
        Err(err) => {
            let _ = fs::remove_dir_all(&journal_dir);
            return Err(ApplyStoreError::Store(err));
        }
    };

    let mut journal_log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(journal_dir.join("rollback.log"))
        .map_err(StoreError::from)?;

    // Phase 2: Execute actions while logging & syncing pre-images into `backups/` + `rollback.log`.
    let mut undo_stack: Vec<UndoRecord> = Vec::new();
    let mut backup_counter: usize = 0;

    for (step_idx, action) in plan.actions.iter().enumerate() {
        let capture_res = capture_undo_for_action(
            root,
            action,
            &backups_dir,
            &mut backup_counter,
            &mut journal_log,
            &mut undo_stack,
        );

        let step_outcome: io::Result<()> = match capture_res {
            Err(io_err) => Err(io_err),
            Ok(()) => fault_hook(step_idx, action).and_then(|()| {
                execute_single_action(root, action, staged_files[step_idx].as_deref())
            }),
        };

        if let Err(apply_err) = step_outcome {
            let restored_count = undo_stack.len();
            let rb_res = rollback_all(root, &undo_stack);
            let _ = fs::remove_dir_all(&journal_dir);
            return match rb_res {
                Ok(()) => Err(ApplyStoreError::RolledBack {
                    step_index: step_idx,
                    reason: apply_err.to_string(),
                    restored_records: restored_count,
                }),
                Err(rb_err) => Err(ApplyStoreError::RollbackFailed {
                    step_index: step_idx,
                    apply_reason: apply_err.to_string(),
                    rollback_reason: rb_err.to_string(),
                }),
            };
        }
    }

    drop(journal_log);
    let _ = fs::remove_dir_all(&journal_dir);
    Ok(plan)
}

/// Builds a conflict-overriding `ApplyPlan` when `force == true`.
fn build_forced_plan(base: &Base, view: &View, observed: &DirectoryTree) -> ApplyPlan {
    let diff = compute_diff(base, view);
    if diff.is_empty() {
        return ApplyPlan {
            diff,
            actions: Vec::new(),
        };
    }

    let mut to_remove: BTreeSet<(usize, RelPath, NodeKind)> = BTreeSet::new();
    let mut to_mkdir: BTreeSet<(usize, RelPath, u32)> = BTreeSet::new();

    // Ensure every required parent directory exists as a directory (removing colliding non-dirs).
    for item in &diff {
        if item.after.is_some() {
            for anc in item.path.strict_ancestors() {
                match observed.get(&anc) {
                    Some(ext) if ext.kind() != NodeKind::Directory => {
                        to_remove.insert((anc.depth(), anc.clone(), ext.kind()));
                        let mode = view
                            .resolve(base, &anc)
                            .map_or(0o755, |e| e.metadata().mode);
                        to_mkdir.insert((anc.depth(), anc, mode));
                    }
                    None => {
                        let mode = view
                            .resolve(base, &anc)
                            .map_or(0o755, |e| e.metadata().mode);
                        to_mkdir.insert((anc.depth(), anc, mode));
                    }
                    Some(_) => {}
                }
            }
        }
    }

    for item in &diff {
        match (&item.after, observed.get(&item.path)) {
            (None, Some(ext_entry)) => {
                schedule_observed_removal(observed, &item.path, ext_entry.kind(), &mut to_remove);
            }
            (None, None) => {}
            (Some(desired), Some(ext_entry)) => {
                if ext_entry.kind() != desired.kind() {
                    schedule_observed_removal(
                        observed,
                        &item.path,
                        ext_entry.kind(),
                        &mut to_remove,
                    );
                    if let TreeEntry::Directory { mode, .. } = desired {
                        to_mkdir.insert((item.path.depth(), item.path.clone(), *mode));
                    }
                }
            }
            (Some(TreeEntry::Directory { mode, .. }), None) => {
                to_mkdir.insert((item.path.depth(), item.path.clone(), *mode));
            }
            (Some(_), None) => {}
        }
    }

    let mut sorted_removals: Vec<(usize, RelPath, NodeKind)> = to_remove.into_iter().collect();
    sorted_removals.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| {
                let a_dir = a.2 == NodeKind::Directory;
                let b_dir = b.2 == NodeKind::Directory;
                a_dir.cmp(&b_dir)
            })
            .then_with(|| a.1.cmp(&b.1))
    });

    let mut actions = Vec::new();
    for (_, path, kind) in sorted_removals {
        if kind == NodeKind::Directory {
            actions.push(ApplyAction::RemoveDirectory { path });
        } else {
            actions.push(ApplyAction::RemoveLeaf { path });
        }
    }

    for (_, path, mode) in to_mkdir {
        actions.push(ApplyAction::CreateDirectory { path, mode });
    }

    for item in &diff {
        let Some(after) = &item.after else {
            continue;
        };
        match after {
            TreeEntry::File { .. } => actions.push(ApplyAction::WriteFile {
                path: item.path.clone(),
                entry: after.clone(),
            }),
            TreeEntry::Symlink { target, .. } => actions.push(ApplyAction::WriteSymlink {
                path: item.path.clone(),
                target: target.clone(),
            }),
            TreeEntry::Directory { mode, .. } => {
                if item.change == DiffChange::Modified
                    && observed
                        .get(&item.path)
                        .is_some_and(|e| e.kind() == NodeKind::Directory)
                {
                    actions.push(ApplyAction::UpdateDirectoryMode {
                        path: item.path.clone(),
                        mode: *mode,
                    });
                }
            }
        }
    }

    let _ = DiffEntry {
        path: RelPath::root(),
        change: DiffChange::Added,
        before: None,
        after: None,
    };

    ApplyPlan { diff, actions }
}

fn schedule_observed_removal(
    observed: &DirectoryTree,
    path: &RelPath,
    kind: NodeKind,
    to_remove: &mut BTreeSet<(usize, RelPath, NodeKind)>,
) {
    to_remove.insert((path.depth(), path.clone(), kind));
    if kind == NodeKind::Directory {
        for (desc_path, desc_entry) in observed.descendants_of(path) {
            to_remove.insert((desc_path.depth(), desc_path.clone(), desc_entry.kind()));
        }
    }
}

fn capture_undo_for_action(
    root: &Path,
    action: &ApplyAction,
    backups_dir: &Path,
    backup_counter: &mut usize,
    journal_log: &mut fs::File,
    undo_stack: &mut Vec<UndoRecord>,
) -> io::Result<()> {
    match action {
        ApplyAction::CreateDirectory { path, .. } => {
            // Record any missing intermediate ancestors shallowest-first so `create_dir_all`
            // cleanly unwinds deepest-first.
            for anc in path.strict_ancestors() {
                if fs::symlink_metadata(root.join(anc.as_str())).is_err() {
                    push_and_log_undo(
                        UndoRecord::RemoveCreated { rel: anc },
                        journal_log,
                        undo_stack,
                    )?;
                }
            }
            capture_single_path(
                root,
                path,
                backups_dir,
                backup_counter,
                journal_log,
                undo_stack,
            )
        }
        ApplyAction::RemoveLeaf { path }
        | ApplyAction::RemoveDirectory { path }
        | ApplyAction::UpdateDirectoryMode { path, .. }
        | ApplyAction::WriteFile { path, .. }
        | ApplyAction::WriteSymlink { path, .. } => capture_single_path(
            root,
            path,
            backups_dir,
            backup_counter,
            journal_log,
            undo_stack,
        ),
    }
}

fn capture_single_path(
    root: &Path,
    rel: &RelPath,
    backups_dir: &Path,
    backup_counter: &mut usize,
    journal_log: &mut fs::File,
    undo_stack: &mut Vec<UndoRecord>,
) -> io::Result<()> {
    let full = root.join(rel.as_str());
    let meta = match fs::symlink_metadata(&full) {
        Ok(m) => m,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return push_and_log_undo(
                UndoRecord::RemoveCreated { rel: rel.clone() },
                journal_log,
                undo_stack,
            );
        }
        Err(err) => return Err(err),
    };

    let ft = meta.file_type();
    if ft.is_symlink() {
        let link = fs::read_link(&full)?;
        let target = link.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "existing symlink target is not valid UTF-8",
            )
        })?;
        push_and_log_undo(
            UndoRecord::RestoreSymlink {
                rel: rel.clone(),
                target: target.to_owned(),
            },
            journal_log,
            undo_stack,
        )
    } else if ft.is_dir() {
        let mode = host_mode(&meta, true);
        push_and_log_undo(
            UndoRecord::RestoreDirectory {
                rel: rel.clone(),
                mode,
            },
            journal_log,
            undo_stack,
        )
    } else {
        let idx = *backup_counter;
        *backup_counter += 1;
        let backup_file = backups_dir.join(format!("{idx}.bak"));
        fs::copy(&full, &backup_file)?;
        fs::File::open(&backup_file)?.sync_all()?;
        let mode = host_mode(&meta, false);
        push_and_log_undo(
            UndoRecord::RestoreFile {
                rel: rel.clone(),
                backup_file,
                mode,
            },
            journal_log,
            undo_stack,
        )
    }
}

fn push_and_log_undo(
    record: UndoRecord,
    journal_log: &mut fs::File,
    undo_stack: &mut Vec<UndoRecord>,
) -> io::Result<()> {
    // Persist structured line + fsync to rollback journal before performing host syscall.
    let line = match &record {
        UndoRecord::RemoveCreated { rel } => format!("ABSENT\t{}\n", rel.as_str()),
        UndoRecord::RestoreDirectory { rel, mode } => {
            format!("DIR\t{mode:o}\t{}\n", rel.as_str())
        }
        UndoRecord::RestoreFile {
            rel,
            backup_file,
            mode,
        } => format!(
            "FILE\t{mode:o}\t{}\t{}\n",
            rel.as_str(),
            backup_file.display()
        ),
        UndoRecord::RestoreSymlink { rel, target } => {
            format!("SYMLINK\t{}\t{target:?}\n", rel.as_str())
        }
    };
    journal_log.write_all(line.as_bytes())?;
    journal_log.sync_all()?;
    undo_stack.push(record);
    Ok(())
}

fn execute_single_action(
    root: &Path,
    action: &ApplyAction,
    staged_blob: Option<&Path>,
) -> io::Result<()> {
    match action {
        ApplyAction::RemoveLeaf { path } => {
            let full = root.join(path.as_str());
            if fs::symlink_metadata(&full).is_ok() {
                clear_readonly_if_needed(&full);
                fs::remove_file(&full)?;
            }
            Ok(())
        }
        ApplyAction::RemoveDirectory { path } => {
            let full = root.join(path.as_str());
            if fs::symlink_metadata(&full).is_ok() {
                fs::remove_dir(&full)?;
            }
            Ok(())
        }
        ApplyAction::CreateDirectory { path, mode } => {
            let full = root.join(path.as_str());
            fs::create_dir_all(&full)?;
            set_host_permissions(&full, *mode)
        }
        ApplyAction::UpdateDirectoryMode { path, mode } => {
            let full = root.join(path.as_str());
            set_host_permissions(&full, *mode)
        }
        ApplyAction::WriteFile { path, entry } => {
            let TreeEntry::File { mode, .. } = entry else {
                return Ok(());
            };
            let staged = staged_blob.ok_or_else(|| {
                io::Error::other("missing pre-staged blob file for WriteFile action")
            })?;
            let full = root.join(path.as_str());
            if let Ok(meta) = fs::symlink_metadata(&full) {
                if meta.file_type().is_symlink() {
                    fs::remove_file(&full)?;
                } else {
                    clear_readonly_if_needed(&full);
                }
            }
            fs::copy(staged, &full)?;
            set_host_permissions(&full, *mode)
        }
        ApplyAction::WriteSymlink { path, target } => {
            let full = root.join(path.as_str());
            if fs::symlink_metadata(&full).is_ok() {
                clear_readonly_if_needed(&full);
                fs::remove_file(&full)?;
            }
            create_symlink_host(target, &full)
        }
    }
}

fn rollback_all(root: &Path, undo_stack: &[UndoRecord]) -> io::Result<()> {
    for record in undo_stack.iter().rev() {
        match record {
            UndoRecord::RemoveCreated { rel } => {
                let full = root.join(rel.as_str());
                if let Ok(meta) = fs::symlink_metadata(&full) {
                    if meta.file_type().is_dir() {
                        let _ = fs::remove_dir(&full);
                    } else {
                        clear_readonly_if_needed(&full);
                        fs::remove_file(&full)?;
                    }
                }
            }
            UndoRecord::RestoreDirectory { rel, mode } => {
                let full = root.join(rel.as_str());
                if let Ok(meta) = fs::symlink_metadata(&full) {
                    if !meta.file_type().is_dir() {
                        clear_readonly_if_needed(&full);
                        fs::remove_file(&full)?;
                    }
                }
                fs::create_dir_all(&full)?;
                set_host_permissions(&full, *mode)?;
            }
            UndoRecord::RestoreFile {
                rel,
                backup_file,
                mode,
            } => {
                let full = root.join(rel.as_str());
                if let Ok(meta) = fs::symlink_metadata(&full) {
                    if meta.file_type().is_dir() {
                        fs::remove_dir_all(&full)?;
                    } else {
                        clear_readonly_if_needed(&full);
                        fs::remove_file(&full)?;
                    }
                }
                if let Some(parent) = full.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(backup_file, &full)?;
                set_host_permissions(&full, *mode)?;
            }
            UndoRecord::RestoreSymlink { rel, target } => {
                let full = root.join(rel.as_str());
                if let Ok(meta) = fs::symlink_metadata(&full) {
                    if meta.file_type().is_dir() {
                        fs::remove_dir_all(&full)?;
                    } else {
                        clear_readonly_if_needed(&full);
                        fs::remove_file(&full)?;
                    }
                }
                if let Some(parent) = full.parent() {
                    fs::create_dir_all(parent)?;
                }
                create_symlink_host(target, &full)?;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_host_permissions(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode & PERM_MASK))
}

#[cfg(not(unix))]
fn set_host_permissions(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn create_symlink_host(target: &str, link_path: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link_path)
}

#[cfg(not(unix))]
fn create_symlink_host(_target: &str, _link_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symlink creation requires platform adapter",
    ))
}
