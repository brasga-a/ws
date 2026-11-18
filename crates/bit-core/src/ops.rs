//! Whole-`View` operations: `Diff` (`O(|Overlay|)`), `Freeze`, and guarded `Apply`.

use std::collections::BTreeSet;
use std::fmt;

use crate::hash::BaseId;
use crate::ids::{TagName, ViewId};
use crate::model::{Base, DirectoryTree, ModelError, NodeKind, TreeEntry, View};
use crate::path::RelPath;

/// Classification of a net path change between a `View` and its `Base`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiffChange {
    /// Entry was created in the `View` and did not exist in the `Base`.
    Added,
    /// Entry existed in the `Base` and was modified (content, mode, kind, or symlink target).
    Modified,
    /// Entry existed in the `Base` and was removed in the `View`.
    Deleted,
}

impl fmt::Display for DiffChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added => f.write_str("added"),
            Self::Modified => f.write_str("modified"),
            Self::Deleted => f.write_str("deleted"),
        }
    }
}

/// Net difference record for a single `RelPath` between a `View`'s `Base` and current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    /// Canonical relative path within the `View`.
    pub path: RelPath,
    /// Net kind of change (`Added`, `Modified`, or `Deleted`).
    pub change: DiffChange,
    /// Previous entry in the `Base` (`Some` for `Modified` and `Deleted`).
    pub before: Option<TreeEntry>,
    /// Current entry in the `View` (`Some` for `Added` and `Modified`).
    pub after: Option<TreeEntry>,
}

/// Computes the canonical sorted `Diff` of `view` relative to `base` in `O(|Overlay|)` time
/// (visiting only keys present in `Overlay` plus bounded `Base` subtrees explicitly removed or
/// shadowed by opaque/non-directory `Overlay` nodes, never scanning untouched `Base` entries).
pub fn compute_diff(base: &Base, view: &View) -> Vec<DiffEntry> {
    let mut candidates = BTreeSet::new();
    for (path, node) in view.overlay().entries() {
        candidates.insert(path.clone());
        if node.blocks_base_descendants()
            && matches!(base.get(path), Some(TreeEntry::Directory { .. }))
        {
            for (desc_path, _) in base.descendants_of(path) {
                candidates.insert(desc_path.clone());
            }
        }
    }

    let mut out = Vec::new();
    for path in candidates {
        let before = base.get(&path).cloned();
        let after = view.resolve(base, &path);
        match (before, after) {
            (None, None) => {}
            (None, Some(new_entry)) => out.push(DiffEntry {
                path,
                change: DiffChange::Added,
                before: None,
                after: Some(new_entry),
            }),
            (Some(old_entry), None) => out.push(DiffEntry {
                path,
                change: DiffChange::Deleted,
                before: Some(old_entry),
                after: None,
            }),
            (Some(old_entry), Some(new_entry)) => {
                if !old_entry.semantically_equal(&new_entry) {
                    out.push(DiffEntry {
                        path,
                        change: DiffChange::Modified,
                        before: Some(old_entry),
                        after: Some(new_entry),
                    });
                }
            }
        }
    }
    out
}

/// Result of a `Freeze` operation capturing a `View`'s current state as a new immutable `Base`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreezeOutput {
    /// Deterministic `BaseId` of the newly sealed `Base`.
    pub base_id: BaseId,
    /// Sealed `Base` manifest.
    pub base: Base,
    /// Optional `Tag` pointed at `base_id` during `Freeze`.
    pub tag: Option<TagName>,
}

/// Captures the combined state of `(base, view)` into a new immutable `Base` without mutating `view`.
pub fn freeze_to_base(base: &Base, view: &View, tag: Option<TagName>) -> FreezeOutput {
    let tree = view.materialize_tree(base);
    let frozen_base = Base::from_tree(tree);
    FreezeOutput {
        base_id: frozen_base.id(),
        base: frozen_base,
        tag,
    }
}

/// Reason why guarded `Apply` rejected projecting a `View`'s `Overlay` onto an external directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApplyConflictKind {
    /// Target path was modified in the external directory since the `View`'s `Base` was created.
    ExternalModified,
    /// Target path (or required `Base` parent directory) was deleted in the external directory
    /// since the `View`'s `Base` was created.
    ExternalDeleted,
    /// Path added by the `View` (or needed as a parent directory) already exists in the external directory.
    CollidingCreate,
    /// Directory deleted or replaced by the `View` contains untracked entries in the external directory.
    DirectoryNotEmpty,
}

impl fmt::Display for ApplyConflictKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExternalModified => {
                f.write_str("external entry was modified since Base was created")
            }
            Self::ExternalDeleted => {
                f.write_str("external entry was deleted since Base was created")
            }
            Self::CollidingCreate => {
                f.write_str("external entry already exists at newly added path")
            }
            Self::DirectoryNotEmpty => {
                f.write_str("external directory contains untracked entries and cannot be removed")
            }
        }
    }
}

/// Single conflict detected while validating an external directory against a `View`'s `Base`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyConflict {
    /// Conflicting relative path.
    pub path: RelPath,
    /// Classification of the conflict.
    pub kind: ApplyConflictKind,
    /// Entry expected from the `View`'s `Base` (`None` for newly added paths).
    pub expected: Option<TreeEntry>,
    /// Actual entry observed in the external directory (`None` if missing).
    pub actual: Option<TreeEntry>,
}

impl fmt::Display for ApplyConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.kind)
    }
}

/// Ordered atomic step in a validated `ApplyPlan`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyAction {
    /// Remove an existing leaf file or symlink (ordered deepest-first before directory removals).
    RemoveLeaf { path: RelPath },
    /// Remove an empty directory (ordered deepest-first after its children are removed).
    RemoveDirectory { path: RelPath },
    /// Create a directory (ordered shallowest-first before children are written).
    CreateDirectory { path: RelPath, mode: u32 },
    /// Update permissions on an existing directory.
    UpdateDirectoryMode { path: RelPath, mode: u32 },
    /// Write or replace a regular file from content-addressed bytes.
    WriteFile { path: RelPath, entry: TreeEntry },
    /// Write or replace a symbolic link.
    WriteSymlink { path: RelPath, target: String },
}

/// Validated, conflict-free execution plan projecting a `View`'s `Overlay` onto an external directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPlan {
    /// Canonical `Diff` entries from which this plan was derived.
    pub diff: Vec<DiffEntry>,
    /// Ordered filesystem actions that transform the external directory without partial failure.
    pub actions: Vec<ApplyAction>,
}

impl ApplyPlan {
    /// Returns `true` if the `View` has no net changes to project.
    pub fn is_noop(&self) -> bool {
        self.actions.is_empty()
    }

    /// Applies this validated plan to an in-memory `DirectoryTree` (useful for deterministic
    /// tests and dry-run verification).
    pub fn apply_to_tree(&self, external: &mut DirectoryTree) -> Result<(), ModelError> {
        for action in &self.actions {
            match action {
                ApplyAction::RemoveLeaf { path } | ApplyAction::RemoveDirectory { path } => {
                    external.remove_subtree(path);
                }
                ApplyAction::CreateDirectory { path, mode }
                | ApplyAction::UpdateDirectoryMode { path, mode } => {
                    let mtime = external
                        .get(path)
                        .map_or_else(|| external.root_mtime(), |e| e.metadata().mtime);
                    external.insert_entry(path.clone(), TreeEntry::directory(*mode, mtime))?;
                }
                ApplyAction::WriteFile { path, entry } => {
                    external.insert_entry(path.clone(), entry.clone())?;
                }
                ApplyAction::WriteSymlink { path, target } => {
                    let mtime = external.root_mtime();
                    external.insert_entry(path.clone(), TreeEntry::symlink(target, mtime)?)?;
                }
            }
        }
        Ok(())
    }
}

/// Summary returned by `ControlPlane::apply_view`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutput {
    /// `ViewId` whose `Overlay` was projected (the `View` itself remains unchanged).
    pub view_id: ViewId,
    /// `BaseId` against which external conflicts were guarded.
    pub base_id: BaseId,
    /// Validated `ApplyPlan` that was computed (and executed if targeting a host directory).
    pub plan: ApplyPlan,
}

/// Validates `external` against `base` for every path touched by `view`'s `Overlay`, returning
/// either a conflict-free `ApplyPlan` or the complete sorted list of `ApplyConflict`s.
pub fn plan_apply(
    base: &Base,
    view: &View,
    external: &DirectoryTree,
) -> Result<ApplyPlan, Vec<ApplyConflict>> {
    let diff = compute_diff(base, view);
    if diff.is_empty() {
        return Ok(ApplyPlan {
            diff,
            actions: Vec::new(),
        });
    }

    let mut conflicts = Vec::new();
    let mut seen_conflict_paths = BTreeSet::new();
    let mut record_conflict = |conflict: ApplyConflict| {
        if seen_conflict_paths.insert((conflict.path.clone(), conflict.kind)) {
            conflicts.push(conflict);
        }
    };

    // Track paths scheduled for deletion in this Apply so we can verify external directories
    // have no untracked extra children inside removed/replaced directories.
    let deleted_or_replaced: BTreeSet<RelPath> = diff
        .iter()
        .filter(|d| {
            d.change == DiffChange::Deleted
                || matches!(
                    (&d.before, &d.after),
                    (Some(b), Some(a)) if b.kind() != a.kind()
                )
        })
        .map(|d| d.path.clone())
        .collect();

    for item in &diff {
        match item.change {
            DiffChange::Added => {
                if let Some(actual) = external.get(&item.path) {
                    // Only skip if `item.path` is an implicit directory already matching Base,
                    // which cannot happen for `Added` because `base.get(path)` was `None`.
                    record_conflict(ApplyConflict {
                        path: item.path.clone(),
                        kind: ApplyConflictKind::CollidingCreate,
                        expected: None,
                        actual: Some(actual.clone()),
                    });
                }

                // Verify ancestor chain in `external`: any ancestor that existed in `Base` as a
                // directory must still exist as a directory in `external` (unless replaced within
                // `View` itself), and any newly created ancestor must not collide with a non-dir.
                for anc in item.path.strict_ancestors() {
                    match (base.get(&anc), external.get(&anc)) {
                        (Some(b_anc), None)
                            if b_anc.kind() == NodeKind::Directory
                                && !deleted_or_replaced.contains(&anc) =>
                        {
                            record_conflict(ApplyConflict {
                                path: anc,
                                kind: ApplyConflictKind::ExternalDeleted,
                                expected: Some(b_anc.clone()),
                                actual: None,
                            });
                        }
                        (Some(b_anc), Some(e_anc))
                            if e_anc.kind() != NodeKind::Directory
                                && !deleted_or_replaced.contains(&anc) =>
                        {
                            record_conflict(ApplyConflict {
                                path: anc,
                                kind: ApplyConflictKind::ExternalModified,
                                expected: Some(b_anc.clone()),
                                actual: Some(e_anc.clone()),
                            });
                        }
                        (None, Some(e_anc)) if e_anc.kind() != NodeKind::Directory => {
                            record_conflict(ApplyConflict {
                                path: anc,
                                kind: ApplyConflictKind::CollidingCreate,
                                expected: None,
                                actual: Some(e_anc.clone()),
                            });
                        }
                        _ => {}
                    }
                }
            }
            DiffChange::Modified | DiffChange::Deleted => {
                let expected = item
                    .before
                    .as_ref()
                    .expect("Modified/Deleted must have Base entry");
                match external.get(&item.path) {
                    None => {
                        record_conflict(ApplyConflict {
                            path: item.path.clone(),
                            kind: ApplyConflictKind::ExternalDeleted,
                            expected: Some(expected.clone()),
                            actual: None,
                        });
                    }
                    Some(actual) => {
                        if !actual.semantically_equal(expected) {
                            record_conflict(ApplyConflict {
                                path: item.path.clone(),
                                kind: ApplyConflictKind::ExternalModified,
                                expected: Some(expected.clone()),
                                actual: Some(actual.clone()),
                            });
                        }
                    }
                }

                // If `expected` was a `Directory` and is being deleted or replaced by a non-dir,
                // ensure `external` has no untracked descendants under `item.path` that aren't
                // themselves accounted for in `deleted_or_replaced`.
                let removing_dir = expected.kind() == NodeKind::Directory
                    && (item.change == DiffChange::Deleted
                        || item
                            .after
                            .as_ref()
                            .is_some_and(|a| a.kind() != NodeKind::Directory));
                if removing_dir {
                    for (ext_desc, ext_entry) in external.descendants_of(&item.path) {
                        if !deleted_or_replaced.contains(ext_desc) {
                            let conflict_kind = if base.get(ext_desc).is_none() {
                                ApplyConflictKind::DirectoryNotEmpty
                            } else {
                                ApplyConflictKind::ExternalModified
                            };
                            record_conflict(ApplyConflict {
                                path: ext_desc.clone(),
                                kind: conflict_kind,
                                expected: base.get(ext_desc).cloned(),
                                actual: Some(ext_entry.clone()),
                            });
                        }
                    }
                }
            }
        }
    }

    if !conflicts.is_empty() {
        conflicts.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.kind.cmp(&b.kind)));
        return Err(conflicts);
    }

    // Build deterministic, properly ordered execution actions:
    // 1. Remove deleted entries and entries whose `NodeKind` changed, deepest-path-first.
    let mut removals: Vec<(usize, RelPath, NodeKind)> = Vec::new();
    for item in &diff {
        match (&item.before, &item.after) {
            (Some(old), None) => {
                removals.push((item.path.depth(), item.path.clone(), old.kind()));
            }
            (Some(old), Some(new)) if old.kind() != new.kind() => {
                removals.push((item.path.depth(), item.path.clone(), old.kind()));
            }
            _ => {}
        }
    }
    // Sort deepest first; at equal depth, leaves before directories.
    removals.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| {
                let a_is_dir = a.2 == NodeKind::Directory;
                let b_is_dir = b.2 == NodeKind::Directory;
                a_is_dir.cmp(&b_is_dir)
            })
            .then_with(|| a.1.cmp(&b.1))
    });

    let mut actions = Vec::new();
    for (_, path, kind) in removals {
        if kind == NodeKind::Directory {
            actions.push(ApplyAction::RemoveDirectory { path });
        } else {
            actions.push(ApplyAction::RemoveLeaf { path });
        }
    }

    // 2. Create added (or kind-replaced) directories shallowest-first.
    let mut dir_creates: Vec<(usize, RelPath, u32)> = Vec::new();
    for item in &diff {
        if let Some(TreeEntry::Directory { mode, .. }) = &item.after {
            let needs_create = item.change == DiffChange::Added
                || item
                    .before
                    .as_ref()
                    .is_some_and(|b| b.kind() != NodeKind::Directory);
            if needs_create {
                // Only create if not already an existing untouched external directory.
                if external.get(&item.path).is_none()
                    || item
                        .before
                        .as_ref()
                        .is_some_and(|b| b.kind() != NodeKind::Directory)
                {
                    dir_creates.push((item.path.depth(), item.path.clone(), *mode));
                }
            }
        }
    }
    dir_creates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    for (_, path, mode) in dir_creates {
        actions.push(ApplyAction::CreateDirectory { path, mode });
    }

    // 3. Write added/modified files & symlinks, and update modified directory modes.
    for item in &diff {
        let Some(after) = &item.after else {
            continue;
        };
        match after {
            TreeEntry::File { .. } => {
                actions.push(ApplyAction::WriteFile {
                    path: item.path.clone(),
                    entry: after.clone(),
                });
            }
            TreeEntry::Symlink { target, .. } => {
                actions.push(ApplyAction::WriteSymlink {
                    path: item.path.clone(),
                    target: target.clone(),
                });
            }
            TreeEntry::Directory { mode, .. } => {
                let mode_update_only = item.change == DiffChange::Modified
                    && item
                        .before
                        .as_ref()
                        .is_some_and(|b| b.kind() == NodeKind::Directory);
                if mode_update_only {
                    actions.push(ApplyAction::UpdateDirectoryMode {
                        path: item.path.clone(),
                        mode: *mode,
                    });
                }
            }
        }
    }

    Ok(ApplyPlan { diff, actions })
}
