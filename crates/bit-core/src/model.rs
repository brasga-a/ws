//! Core domain structures (`NodeKind`, `EntryMetadata`, `TreeEntry`, `DirectoryTree`, `Base`,
//! `Overlay`, and `View`) implementing flat `Base + Overlay` composition (ADR-0001).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::hash::{BaseId, ContentHash, Sha256};
use crate::ids::ViewId;
use crate::path::{
    lookup_entry_in_map, AmbiguousCaseError, CaseSensitivity, EntryName, PathError, RelPath,
};

/// Default POSIX permission bits for regular files (`rw-r--r--`).
pub const DEFAULT_FILE_MODE: u32 = 0o644;
/// Default POSIX permission bits for executable regular files (`rwxr-xr-x`).
pub const DEFAULT_EXEC_MODE: u32 = 0o755;
/// Default POSIX permission bits for directories (`rwxr-xr-x`).
pub const DEFAULT_DIR_MODE: u32 = 0o755;
/// Default POSIX permission bits for symbolic links (`rwxrwxrwx`).
pub const DEFAULT_SYMLINK_MODE: u32 = 0o777;
/// Mask for POSIX permission and special mode bits (`0o7777`).
pub const PERM_MASK: u32 = 0o7777;

/// POSIX `S_IFREG` file type mask.
pub const S_IFREG: u32 = 0o100_000;
/// POSIX `S_IFDIR` file type mask.
pub const S_IFDIR: u32 = 0o040_000;
/// POSIX `S_IFLNK` file type mask.
pub const S_IFLNK: u32 = 0o120_000;

/// Portable nanosecond-precision UNIX timestamp (`mtime`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    /// Seconds relative to `1970-01-01T00:00:00Z`.
    pub secs: i64,
    /// Sub-second nanoseconds in `0..1_000_000_000`.
    pub nanos: u32,
}

impl Timestamp {
    /// `1970-01-01T00:00:00Z`.
    pub const EPOCH: Self = Self { secs: 0, nanos: 0 };

    /// Constructs a normalized `Timestamp`, carrying excess nanoseconds into `secs`.
    pub const fn new(secs: i64, nanos: u32) -> Self {
        let extra_secs = (nanos / 1_000_000_000) as i64;
        let rem_nanos = nanos % 1_000_000_000;
        Self {
            secs: secs.saturating_add(extra_secs),
            nanos: rem_nanos,
        }
    }

    /// Captures the current wall-clock `SystemTime` as a `Timestamp`.
    pub fn now() -> Self {
        Self::from(SystemTime::now())
    }

    /// Converts to `SystemTime`, clamping pre-epoch negative timestamps only if unsupported.
    pub fn to_system_time(self) -> SystemTime {
        if self.secs >= 0 {
            UNIX_EPOCH + Duration::new(self.secs as u64, self.nanos)
        } else {
            let abs_secs = self.secs.unsigned_abs();
            if self.nanos == 0 {
                UNIX_EPOCH
                    .checked_sub(Duration::from_secs(abs_secs))
                    .unwrap_or(UNIX_EPOCH)
            } else {
                let sub = Duration::new(abs_secs.saturating_sub(1), 1_000_000_000 - self.nanos);
                UNIX_EPOCH.checked_sub(sub).unwrap_or(UNIX_EPOCH)
            }
        }
    }
}

impl From<SystemTime> for Timestamp {
    fn from(time: SystemTime) -> Self {
        match time.duration_since(UNIX_EPOCH) {
            Ok(dur) => Self::new(dur.as_secs() as i64, dur.subsec_nanos()),
            Err(err) => {
                let dur = err.duration();
                if dur.subsec_nanos() == 0 {
                    Self {
                        secs: -(dur.as_secs() as i64),
                        nanos: 0,
                    }
                } else {
                    Self {
                        secs: -(dur.as_secs() as i64) - 1,
                        nanos: 1_000_000_000 - dur.subsec_nanos(),
                    }
                }
            }
        }
    }
}

/// Supported filesystem node kinds in Bit.
///
/// Special OS files (FIFOs, sockets, block/character devices) are intentionally excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeKind {
    /// Regular content-addressed file.
    File,
    /// Directory node.
    Directory,
    /// Symbolic link storing a verbatim UTF-8 target string (relative or external).
    Symlink,
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File => f.write_str("file"),
            Self::Directory => f.write_str("directory"),
            Self::Symlink => f.write_str("symlink"),
        }
    }
}

/// Portable node attributes exposed across `Base`, `Overlay`, and VFS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryMetadata {
    /// Kind of filesystem entry.
    pub kind: NodeKind,
    /// POSIX permission bits (`0..=0o7777`).
    pub mode: u32,
    /// Logical byte size (`File` byte length, `Symlink` UTF-8 target byte length, `0` for `Directory`).
    pub size: u64,
    /// Modification timestamp.
    pub mtime: Timestamp,
}

impl EntryMetadata {
    /// Returns full POSIX `st_mode` combining `S_IFREG`/`S_IFDIR`/`S_IFLNK` with `self.mode`.
    pub const fn posix_mode(&self) -> u32 {
        let kind_bits = match self.kind {
            NodeKind::File => S_IFREG,
            NodeKind::Directory => S_IFDIR,
            NodeKind::Symlink => S_IFLNK,
        };
        kind_bits | (self.mode & PERM_MASK)
    }
}

/// Validation or structural error for `TreeEntry`, `DirectoryTree`, `Base`, and `View`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    /// Symlink target was empty or contained a NUL byte.
    InvalidSymlinkTarget(String),
    /// Root path `""` cannot be inserted as a named child entry in a `DirectoryTree`.
    RootEntryNotAllowed,
    /// Entry had an ancestor in the tree that was not a `Directory`.
    ParentNotDirectory {
        path: RelPath,
        ancestor: RelPath,
        actual: NodeKind,
    },
    /// Supplied `BaseId` did not match the canonical digest of the `Base` manifest.
    BaseIdMismatch { expected: BaseId, actual: BaseId },
    /// Path parsing error.
    InvalidPath(PathError),
    /// Ambiguous case-insensitive lookup.
    AmbiguousCase(AmbiguousCaseError),
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSymlinkTarget(reason) => write!(f, "invalid symlink target: {reason}"),
            Self::RootEntryNotAllowed => {
                f.write_str("root path '' cannot appear as a child entry in DirectoryTree")
            }
            Self::ParentNotDirectory {
                path,
                ancestor,
                actual,
            } => write!(
                f,
                "cannot place {path:?} under {ancestor:?} because {ancestor:?} is a {actual}"
            ),
            Self::BaseIdMismatch { expected, actual } => {
                write!(
                    f,
                    "base manifest digest mismatch: expected {expected}, computed {actual}"
                )
            }
            Self::InvalidPath(err) => fmt::Display::fmt(err, f),
            Self::AmbiguousCase(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl std::error::Error for ModelError {}

impl From<PathError> for ModelError {
    fn from(err: PathError) -> Self {
        Self::InvalidPath(err)
    }
}

impl From<AmbiguousCaseError> for ModelError {
    fn from(err: AmbiguousCaseError) -> Self {
        Self::AmbiguousCase(err)
    }
}

/// Validates a verbatim UTF-8 symlink target (allows relative and external targets; rejects empty and NUL).
pub fn validate_symlink_target(target: &str) -> Result<(), ModelError> {
    if target.is_empty() {
        return Err(ModelError::InvalidSymlinkTarget(
            "symlink target must not be empty".to_owned(),
        ));
    }
    if target.contains('\0') {
        return Err(ModelError::InvalidSymlinkTarget(
            "symlink target must not contain NUL bytes".to_owned(),
        ));
    }
    Ok(())
}

/// Complete manifest entry for a single `RelPath` in a `DirectoryTree`, `Base`, or `Overlay`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TreeEntry {
    /// Regular file referencing content-addressed bytes via `ContentHash`.
    File {
        content: ContentHash,
        size: u64,
        mode: u32,
        mtime: Timestamp,
    },
    /// Directory node.
    Directory { mode: u32, mtime: Timestamp },
    /// Symbolic link storing its verbatim UTF-8 target string.
    Symlink {
        target: String,
        mode: u32,
        mtime: Timestamp,
    },
}

impl TreeEntry {
    /// Constructs a normalized `File` entry.
    pub const fn file(content: ContentHash, size: u64, mode: u32, mtime: Timestamp) -> Self {
        let clean_mode = mode & PERM_MASK;
        Self::File {
            content,
            size,
            mode: if clean_mode == 0 {
                DEFAULT_FILE_MODE
            } else {
                clean_mode
            },
            mtime,
        }
    }

    /// Constructs a normalized `Directory` entry.
    pub const fn directory(mode: u32, mtime: Timestamp) -> Self {
        let clean_mode = mode & PERM_MASK;
        Self::Directory {
            mode: if clean_mode == 0 {
                DEFAULT_DIR_MODE
            } else {
                clean_mode
            },
            mtime,
        }
    }

    /// Validates `target` and constructs a `Symlink` entry.
    pub fn symlink(target: impl Into<String>, mtime: Timestamp) -> Result<Self, ModelError> {
        let target = target.into();
        validate_symlink_target(&target)?;
        Ok(Self::Symlink {
            target,
            mode: DEFAULT_SYMLINK_MODE,
            mtime,
        })
    }

    /// Validates internal invariants and returns a mode-normalized copy.
    pub fn validated(self) -> Result<Self, ModelError> {
        match self {
            Self::File {
                content,
                size,
                mode,
                mtime,
            } => Ok(Self::File {
                content,
                size,
                mode: mode & PERM_MASK,
                mtime,
            }),
            Self::Directory { mode, mtime } => Ok(Self::Directory {
                mode: mode & PERM_MASK,
                mtime,
            }),
            Self::Symlink {
                target,
                mode,
                mtime,
            } => {
                validate_symlink_target(&target)?;
                let clean = mode & PERM_MASK;
                Ok(Self::Symlink {
                    target,
                    mode: if clean == 0 {
                        DEFAULT_SYMLINK_MODE
                    } else {
                        clean
                    },
                    mtime,
                })
            }
        }
    }

    /// Returns the `NodeKind` of this entry.
    pub const fn kind(&self) -> NodeKind {
        match self {
            Self::File { .. } => NodeKind::File,
            Self::Directory { .. } => NodeKind::Directory,
            Self::Symlink { .. } => NodeKind::Symlink,
        }
    }

    /// Projects portable `EntryMetadata` for `stat` / `getattr`.
    pub fn metadata(&self) -> EntryMetadata {
        match self {
            Self::File {
                size, mode, mtime, ..
            } => EntryMetadata {
                kind: NodeKind::File,
                mode: *mode & PERM_MASK,
                size: *size,
                mtime: *mtime,
            },
            Self::Directory { mode, mtime } => EntryMetadata {
                kind: NodeKind::Directory,
                mode: *mode & PERM_MASK,
                size: 0,
                mtime: *mtime,
            },
            Self::Symlink {
                target,
                mode,
                mtime,
            } => EntryMetadata {
                kind: NodeKind::Symlink,
                mode: *mode & PERM_MASK,
                size: target.len() as u64,
                mtime: *mtime,
            },
        }
    }

    /// Returns the `ContentHash` if this entry is a `File`.
    pub const fn content_hash(&self) -> Option<ContentHash> {
        match self {
            Self::File { content, .. } => Some(*content),
            _ => None,
        }
    }

    /// Returns the symlink target string if this entry is a `Symlink`.
    pub fn symlink_target(&self) -> Option<&str> {
        match self {
            Self::Symlink { target, .. } => Some(target.as_str()),
            _ => None,
        }
    }

    /// Compares semantic tree state (`kind`, `mode`, `ContentHash`/`size`, or `Symlink` target),
    /// ignoring `mtime`-only differences so transient directory timestamp updates do not pollute `Diff` or `Apply`.
    pub fn semantically_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::File {
                    content: c1,
                    size: s1,
                    mode: m1,
                    ..
                },
                Self::File {
                    content: c2,
                    size: s2,
                    mode: m2,
                    ..
                },
            ) => c1 == c2 && s1 == s2 && (m1 & PERM_MASK) == (m2 & PERM_MASK),
            (Self::Directory { mode: m1, .. }, Self::Directory { mode: m2, .. }) => {
                (m1 & PERM_MASK) == (m2 & PERM_MASK)
            }
            (Self::Symlink { target: t1, .. }, Self::Symlink { target: t2, .. }) => t1 == t2,
            _ => false,
        }
    }

    /// Returns a copy with updated `mode` and/or `mtime`.
    pub fn with_attrs(&self, mode: Option<u32>, mtime: Option<Timestamp>) -> Self {
        match self {
            Self::File {
                content,
                size,
                mode: old_m,
                mtime: old_t,
            } => Self::File {
                content: *content,
                size: *size,
                mode: mode.map_or(*old_m, |m| m & PERM_MASK),
                mtime: mtime.unwrap_or(*old_t),
            },
            Self::Directory {
                mode: old_m,
                mtime: old_t,
            } => Self::Directory {
                mode: mode.map_or(*old_m, |m| m & PERM_MASK),
                mtime: mtime.unwrap_or(*old_t),
            },
            Self::Symlink {
                target,
                mode: old_m,
                mtime: old_t,
            } => Self::Symlink {
                target: target.clone(),
                mode: mode.map_or(*old_m, |m| m & PERM_MASK),
                mtime: mtime.unwrap_or(*old_t),
            },
        }
    }
}

/// Fast `O(k * log N)` iteration over direct children of `dir_path` in any `BTreeMap<RelPath, V>`,
/// skipping nested grandchild subtrees using `'/'` (`0x2F`) -> `'0'` (`0x30`) range jumps.
pub(crate) fn collect_direct_children<'a, V>(
    map: &'a BTreeMap<RelPath, V>,
    dir_path: &RelPath,
) -> Vec<(EntryName, &'a V)> {
    let mut out = Vec::new();
    if dir_path.is_root() {
        let mut cursor: Option<String> = None;
        loop {
            let next_item = match &cursor {
                None => map.iter().next(),
                Some(bound) => map
                    .range::<str, _>((Included(bound.as_str()), Unbounded))
                    .next(),
            };
            let Some((path, val)) = next_item else {
                break;
            };
            let s = path.as_str();
            match s.find('/') {
                None => {
                    out.push((EntryName::new(s).expect("validated component"), val));
                    // Advance immediately past `s`; siblings like `s-2` (0x2D) or `s.txt` (0x2E)
                    // sort before `s/` (0x2F), so step with `Excluded(s)` first.
                    let after_exact = map
                        .range::<str, _>((Excluded(s), Unbounded))
                        .next()
                        .map(|(k, _)| k.as_str().to_owned());
                    match after_exact {
                        None => break,
                        Some(next_key) => cursor = Some(next_key),
                    }
                }
                Some(slash_idx) => {
                    // `s` is `top/...`; jump straight to `top0` (`0x30`), skipping all `top/*`!
                    let mut jump = String::with_capacity(slash_idx + 1);
                    jump.push_str(&s[..slash_idx]);
                    jump.push('0');
                    cursor = Some(jump);
                }
            }
        }
    } else {
        let prefix_slash = format!("{}/", dir_path.as_str());
        let upper_bound = format!("{}0", dir_path.as_str());
        let base_offset = prefix_slash.len();
        let mut cursor = prefix_slash;

        loop {
            if cursor >= upper_bound {
                break;
            }
            let next_item = map
                .range::<str, _>((Included(cursor.as_str()), Excluded(upper_bound.as_str())))
                .next();
            let Some((path, val)) = next_item else {
                break;
            };
            let s = path.as_str();
            let rel_tail = &s[base_offset..];
            match rel_tail.find('/') {
                None => {
                    out.push((EntryName::new(rel_tail).expect("validated component"), val));
                    let after_exact = map
                        .range::<str, _>((Excluded(s), Excluded(upper_bound.as_str())))
                        .next()
                        .map(|(k, _)| k.as_str().to_owned());
                    match after_exact {
                        None => break,
                        Some(next_key) => cursor = next_key,
                    }
                }
                Some(slash_idx) => {
                    let child_full_len = base_offset + slash_idx;
                    let mut jump = String::with_capacity(child_full_len + 1);
                    jump.push_str(&s[..child_full_len]);
                    jump.push('0');
                    cursor = jump;
                }
            }
        }
    }
    out
}

/// Bounded range iterator over all strict descendants of `dir_path` in `map`.
pub(crate) fn iter_descendants<'a, V>(
    map: &'a BTreeMap<RelPath, V>,
    dir_path: &RelPath,
) -> Vec<(&'a RelPath, &'a V)> {
    if dir_path.is_root() {
        map.iter().collect()
    } else {
        let lower = format!("{}/", dir_path.as_str());
        let upper = format!("{}0", dir_path.as_str());
        map.range::<str, _>((Included(lower.as_str()), Excluded(upper.as_str())))
            .collect()
    }
}

/// Self-consistent hierarchical map of `RelPath -> TreeEntry` with root directory attributes.
///
/// Used both as the inner manifest of a sealed `Base` and to represent an observed external
/// directory state during `create_base` and `Apply`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryTree {
    root_mode: u32,
    root_mtime: Timestamp,
    entries: BTreeMap<RelPath, TreeEntry>,
}

impl Default for DirectoryTree {
    fn default() -> Self {
        Self::empty()
    }
}

impl DirectoryTree {
    /// Creates an empty `DirectoryTree` containing only the root directory (`0o755`).
    pub const fn empty() -> Self {
        Self {
            root_mode: DEFAULT_DIR_MODE,
            root_mtime: Timestamp::EPOCH,
            entries: BTreeMap::new(),
        }
    }

    /// Validates `entries`, synthesizes any missing intermediate parent directories with
    /// `DEFAULT_DIR_MODE`, and ensures every ancestor of every entry is a `Directory`.
    pub fn from_entries(
        entries: impl IntoIterator<Item = (RelPath, TreeEntry)>,
    ) -> Result<Self, ModelError> {
        Self::with_root_and_entries(DEFAULT_DIR_MODE, Timestamp::EPOCH, entries)
    }

    /// Validates `entries` with explicit root directory `mode` and `mtime`.
    pub fn with_root_and_entries(
        root_mode: u32,
        root_mtime: Timestamp,
        entries: impl IntoIterator<Item = (RelPath, TreeEntry)>,
    ) -> Result<Self, ModelError> {
        let mut map = BTreeMap::new();
        for (path, entry) in entries {
            if path.is_root() {
                return Err(ModelError::RootEntryNotAllowed);
            }
            let clean = entry.validated()?;
            map.insert(path, clean);
        }

        // Synthesize missing parent directories and check that all ancestors are directories.
        let keys: Vec<RelPath> = map.keys().cloned().collect();
        for path in keys {
            for anc in path.strict_ancestors() {
                match map.get(&anc) {
                    Some(existing) if existing.kind() != NodeKind::Directory => {
                        return Err(ModelError::ParentNotDirectory {
                            path,
                            ancestor: anc,
                            actual: existing.kind(),
                        });
                    }
                    Some(_) => {}
                    None => {
                        map.insert(
                            anc,
                            TreeEntry::Directory {
                                mode: DEFAULT_DIR_MODE,
                                mtime: Timestamp::EPOCH,
                            },
                        );
                    }
                }
            }
        }

        let clean_root_mode = root_mode & PERM_MASK;
        Ok(Self {
            root_mode: if clean_root_mode == 0 {
                DEFAULT_DIR_MODE
            } else {
                clean_root_mode
            },
            root_mtime,
            entries: map,
        })
    }

    /// Root directory POSIX permission bits (`0..=0o7777`).
    pub const fn root_mode(&self) -> u32 {
        self.root_mode
    }

    /// Root directory modification timestamp.
    pub const fn root_mtime(&self) -> Timestamp {
        self.root_mtime
    }

    /// Root directory `EntryMetadata`.
    pub const fn root_metadata(&self) -> EntryMetadata {
        EntryMetadata {
            kind: NodeKind::Directory,
            mode: self.root_mode,
            size: 0,
            mtime: self.root_mtime,
        }
    }

    /// Number of non-root entries in this tree.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if there are no non-root entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Borrows the canonical `BTreeMap<RelPath, TreeEntry>`.
    pub const fn entries(&self) -> &BTreeMap<RelPath, TreeEntry> {
        &self.entries
    }

    /// Looks up a non-root `RelPath` (for `RelPath::root()`, use `root_metadata()`).
    pub fn get(&self, path: &RelPath) -> Option<&TreeEntry> {
        self.entries.get(path)
    }

    /// Returns direct children `(EntryName, &TreeEntry)` of `dir_path` in `O(k * log N)` time.
    pub fn direct_children(&self, dir_path: &RelPath) -> BTreeMap<EntryName, TreeEntry> {
        collect_direct_children(&self.entries, dir_path)
            .into_iter()
            .map(|(name, entry)| (name, entry.clone()))
            .collect()
    }

    /// Returns all strict descendants `(&RelPath, &TreeEntry)` of `dir_path`.
    pub fn descendants_of(&self, dir_path: &RelPath) -> Vec<(&RelPath, &TreeEntry)> {
        iter_descendants(&self.entries, dir_path)
    }

    /// Mutably inserts or replaces a single validated entry (synthesizing missing parent dirs).
    pub fn insert_entry(&mut self, path: RelPath, entry: TreeEntry) -> Result<(), ModelError> {
        if path.is_root() {
            return Err(ModelError::RootEntryNotAllowed);
        }
        let clean = entry.validated()?;
        for anc in path.strict_ancestors() {
            match self.entries.get(&anc) {
                Some(existing) if existing.kind() != NodeKind::Directory => {
                    return Err(ModelError::ParentNotDirectory {
                        path,
                        ancestor: anc,
                        actual: existing.kind(),
                    });
                }
                Some(_) => {}
                None => {
                    self.entries.insert(
                        anc,
                        TreeEntry::Directory {
                            mode: DEFAULT_DIR_MODE,
                            mtime: Timestamp::EPOCH,
                        },
                    );
                }
            }
        }
        self.entries.insert(path, clean);
        Ok(())
    }

    /// Removes `path` and any strict descendants under `path`.
    pub fn remove_subtree(&mut self, path: &RelPath) -> bool {
        if path.is_root() {
            let had = !self.entries.is_empty();
            self.entries.clear();
            return had;
        }
        let desc_keys: Vec<RelPath> = iter_descendants(&self.entries, path)
            .into_iter()
            .map(|(k, _)| k.clone())
            .collect();
        let mut removed = self.entries.remove(path).is_some();
        for k in desc_keys {
            removed |= self.entries.remove(&k).is_some();
        }
        removed
    }

    /// Computes the canonical, deterministic `BaseId` for this directory manifest.
    pub fn compute_base_id(&self) -> BaseId {
        let mut hasher = Sha256::new();
        hasher.update(b"bit-base-manifest-v1\0");
        hasher.update(&(self.root_mode & PERM_MASK).to_be_bytes());
        hasher.update(&(self.entries.len() as u64).to_be_bytes());

        for (path, entry) in &self.entries {
            hasher.update_len_prefixed(path.as_str().as_bytes());
            match entry {
                TreeEntry::File {
                    content,
                    size,
                    mode,
                    ..
                } => {
                    hasher.update(&[0x01]);
                    hasher.update(&(mode & PERM_MASK).to_be_bytes());
                    hasher.update(&size.to_be_bytes());
                    hasher.update(content.as_bytes());
                }
                TreeEntry::Directory { mode, .. } => {
                    hasher.update(&[0x02]);
                    hasher.update(&(mode & PERM_MASK).to_be_bytes());
                }
                TreeEntry::Symlink { target, .. } => {
                    hasher.update(&[0x03]);
                    hasher.update_len_prefixed(target.as_bytes());
                }
            }
        }

        BaseId::from_bytes(hasher.finalize())
    }
}

/// Sealed, immutable directory tree owned by Bit and identified by its canonical `BaseId`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base {
    id: BaseId,
    tree: DirectoryTree,
}

impl Base {
    /// Seals a `DirectoryTree` into an immutable `Base` with a deterministically computed `BaseId`.
    pub fn from_tree(tree: DirectoryTree) -> Self {
        let id = tree.compute_base_id();
        Self { id, tree }
    }

    /// Builds a `Base` directly from `(RelPath, TreeEntry)` pairs.
    pub fn from_entries(
        entries: impl IntoIterator<Item = (RelPath, TreeEntry)>,
    ) -> Result<Self, ModelError> {
        Ok(Self::from_tree(DirectoryTree::from_entries(entries)?))
    }

    /// Reconstructs a `Base` from persistent storage, verifying that `id` matches `tree`.
    pub fn with_verified_id(id: BaseId, tree: DirectoryTree) -> Result<Self, ModelError> {
        let computed = tree.compute_base_id();
        if computed != id {
            return Err(ModelError::BaseIdMismatch {
                expected: id,
                actual: computed,
            });
        }
        Ok(Self { id, tree })
    }

    /// Returns the immutable `BaseId`.
    pub const fn id(&self) -> BaseId {
        self.id
    }

    /// Borrows the underlying `DirectoryTree`.
    pub const fn tree(&self) -> &DirectoryTree {
        &self.tree
    }

    /// Root directory `EntryMetadata`.
    pub const fn root_metadata(&self) -> EntryMetadata {
        self.tree.root_metadata()
    }

    /// Number of non-root entries in this `Base`.
    pub fn entry_count(&self) -> usize {
        self.tree.len()
    }

    /// Borrows the canonical map of non-root entries.
    pub const fn entries(&self) -> &BTreeMap<RelPath, TreeEntry> {
        self.tree.entries()
    }

    /// Point lookup of a non-root `RelPath` in `O(log |Base|)`.
    pub fn get(&self, path: &RelPath) -> Option<&TreeEntry> {
        self.tree.get(path)
    }

    /// Direct children of `dir_path` in `O(k * log |Base|)`.
    pub fn direct_children(&self, dir_path: &RelPath) -> BTreeMap<EntryName, TreeEntry> {
        self.tree.direct_children(dir_path)
    }

    /// Strict descendants of `dir_path` via bounded range scan.
    pub fn descendants_of(&self, dir_path: &RelPath) -> Vec<(&RelPath, &TreeEntry)> {
        self.tree.descendants_of(dir_path)
    }
}

/// Private mutation record for a single `RelPath` inside a `View`'s `Overlay`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayNode {
    /// Added or modified entry.
    ///
    /// When `opaque == true` (for example after `rm -rf dir && mkdir dir` or directory `rename`),
    /// any `Base` descendants strictly beneath this path are hidden and not inherited.
    Upsert { entry: TreeEntry, opaque: bool },
    /// Tombstone hiding an entry (and any `Base` subtree beneath it) inherited from `Base`.
    Whiteout,
}

impl OverlayNode {
    /// Returns `true` if this node blocks inheritance of strict descendants from `Base`.
    pub const fn blocks_base_descendants(&self) -> bool {
        match self {
            Self::Whiteout => true,
            Self::Upsert { entry, opaque } => {
                *opaque || !matches!(entry.kind(), NodeKind::Directory)
            }
        }
    }
}

/// Private set of file and directory additions, modifications, whiteouts, and opaque markers
/// belonging to a single `View`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overlay {
    root_mode: Option<u32>,
    root_mtime: Option<Timestamp>,
    entries: BTreeMap<RelPath, OverlayNode>,
}

impl Overlay {
    /// Creates an empty `Overlay`.
    pub const fn new() -> Self {
        Self {
            root_mode: None,
            root_mtime: None,
            entries: BTreeMap::new(),
        }
    }

    /// Reconstructs an `Overlay` from persisted parts.
    pub fn from_parts(
        root_mode: Option<u32>,
        root_mtime: Option<Timestamp>,
        entries: BTreeMap<RelPath, OverlayNode>,
    ) -> Self {
        Self {
            root_mode: root_mode.map(|m| m & PERM_MASK),
            root_mtime,
            entries,
        }
    }

    /// Optional overridden root directory mode.
    pub const fn root_mode(&self) -> Option<u32> {
        self.root_mode
    }

    /// Optional overridden root directory mtime.
    pub const fn root_mtime(&self) -> Option<Timestamp> {
        self.root_mtime
    }

    /// Number of mutation records currently held in this `Overlay`.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no path mutations are recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.root_mode.is_none()
    }

    /// Borrows all recorded `Overlay` entries.
    pub const fn entries(&self) -> &BTreeMap<RelPath, OverlayNode> {
        &self.entries
    }

    /// Looks up the raw `OverlayNode` at `path`.
    pub fn get(&self, path: &RelPath) -> Option<&OverlayNode> {
        self.entries.get(path)
    }

    /// Direct children recorded in this `Overlay` under `dir_path`.
    pub fn direct_children(&self, dir_path: &RelPath) -> Vec<(EntryName, &OverlayNode)> {
        collect_direct_children(&self.entries, dir_path)
    }

    /// Strict descendants recorded in this `Overlay` under `dir_path`.
    pub fn descendants_of(&self, dir_path: &RelPath) -> Vec<(&RelPath, &OverlayNode)> {
        iter_descendants(&self.entries, dir_path)
    }
}

/// Isolated, writable directory tree composed of exactly one immutable `Base` and one private
/// `Overlay` (ADR-0001).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    id: ViewId,
    base_id: BaseId,
    overlay: Overlay,
    created_at: Timestamp,
}

impl View {
    /// Creates a fresh `View` backed by `base_id` with an empty `Overlay`.
    pub const fn new(id: ViewId, base_id: BaseId, created_at: Timestamp) -> Self {
        Self {
            id,
            base_id,
            overlay: Overlay::new(),
            created_at,
        }
    }

    /// Reconstructs a `View` from persisted state.
    pub const fn from_parts(
        id: ViewId,
        base_id: BaseId,
        overlay: Overlay,
        created_at: Timestamp,
    ) -> Self {
        Self {
            id,
            base_id,
            overlay,
            created_at,
        }
    }

    /// Borrows the `ViewId`.
    pub const fn id(&self) -> &ViewId {
        &self.id
    }

    /// Returns the immutable `BaseId` backing this `View`.
    pub const fn base_id(&self) -> BaseId {
        self.base_id
    }

    /// Borrows the private `Overlay` of this `View`.
    pub const fn overlay(&self) -> &Overlay {
        &self.overlay
    }

    /// Mutably borrows the `Overlay`.
    pub fn overlay_mut(&mut self) -> &mut Overlay {
        &mut self.overlay
    }

    /// Creation timestamp of this `View`.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns effective root directory `EntryMetadata` combining `Base` and `Overlay`.
    pub fn root_metadata(&self, base: &Base) -> EntryMetadata {
        let base_root = base.root_metadata();
        EntryMetadata {
            kind: NodeKind::Directory,
            mode: self.overlay.root_mode.unwrap_or(base_root.mode),
            size: 0,
            mtime: self.overlay.root_mtime.unwrap_or(base_root.mtime),
        }
    }

    /// Updates root directory attributes in `Overlay`.
    pub fn set_root_attrs(&mut self, mode: Option<u32>, mtime: Option<Timestamp>) {
        if let Some(m) = mode {
            self.overlay.root_mode = Some(m & PERM_MASK);
        }
        if let Some(t) = mtime {
            self.overlay.root_mtime = Some(t);
        }
    }

    /// Returns `true` if any strict ancestor of `path` in `Overlay` blocks `Base` inheritance.
    pub fn has_blocking_ancestor(&self, path: &RelPath) -> bool {
        for anc in path.strict_ancestors() {
            if let Some(node) = self.overlay.entries.get(&anc) {
                if node.blocks_base_descendants() {
                    return true;
                }
            }
        }
        false
    }

    /// Returns `true` if `Base` has an entry at `path` that is NOT shadowed by any strict
    /// ancestor in `Overlay` (meaning removing `path` requires a `Whiteout` rather than deletion
    /// of the `Overlay` entry alone).
    pub fn base_exposed_at(&self, base: &Base, path: &RelPath) -> bool {
        !self.has_blocking_ancestor(path) && base.get(path).is_some()
    }

    /// Resolves `path` against `(Base, Overlay)` in `O(depth)` time (`O(1)` in tree history).
    pub fn resolve(&self, base: &Base, path: &RelPath) -> Option<TreeEntry> {
        if path.is_root() {
            let meta = self.root_metadata(base);
            return Some(TreeEntry::Directory {
                mode: meta.mode,
                mtime: meta.mtime,
            });
        }

        // Walk ancestors top-down to check for Whiteout or opaque/non-directory replacement.
        let mut base_blocked = false;
        for anc in path.strict_ancestors() {
            if let Some(node) = self.overlay.entries.get(&anc) {
                match node {
                    OverlayNode::Whiteout => return None,
                    OverlayNode::Upsert { entry, opaque } => {
                        if entry.kind() != NodeKind::Directory {
                            return None;
                        }
                        if *opaque {
                            base_blocked = true;
                        }
                    }
                }
            }
        }

        match self.overlay.entries.get(path) {
            Some(OverlayNode::Whiteout) => None,
            Some(OverlayNode::Upsert { entry, .. }) => Some(entry.clone()),
            None if base_blocked => None,
            None => base.get(path).cloned(),
        }
    }

    /// Lists merged direct children of `dir_path` in `(Base, Overlay)` in `O(k * log N)` time.
    ///
    /// Returns `None` if `dir_path` does not exist or is not a `Directory`.
    pub fn list_dir(
        &self,
        base: &Base,
        dir_path: &RelPath,
    ) -> Option<BTreeMap<EntryName, TreeEntry>> {
        if !dir_path.is_root() {
            let dir_entry = self.resolve(base, dir_path)?;
            if dir_entry.kind() != NodeKind::Directory {
                return None;
            }
        }

        let inherits_base = if dir_path.is_root() {
            true
        } else {
            !self.has_blocking_ancestor(dir_path)
                && !matches!(
                    self.overlay.entries.get(dir_path),
                    Some(OverlayNode::Upsert { opaque: true, .. } | OverlayNode::Whiteout)
                )
        };

        let mut merged = if inherits_base {
            base.direct_children(dir_path)
        } else {
            BTreeMap::new()
        };

        for (name, node) in self.overlay.direct_children(dir_path) {
            match node {
                OverlayNode::Whiteout => {
                    merged.remove(&name);
                }
                OverlayNode::Upsert { entry, .. } => {
                    merged.insert(name, entry.clone());
                }
            }
        }

        Some(merged)
    }

    /// Resolves a relative path component-by-component using `policy` (`CaseSensitive` or
    /// `CaseInsensitiveUnambiguous`), returning the canonical `RelPath` and resolved `TreeEntry`.
    pub fn resolve_with_case(
        &self,
        base: &Base,
        query: &RelPath,
        policy: CaseSensitivity,
    ) -> Result<Option<(RelPath, TreeEntry)>, AmbiguousCaseError> {
        if policy == CaseSensitivity::CaseSensitive || query.is_root() {
            return Ok(self
                .resolve(base, query)
                .map(|entry| (query.clone(), entry)));
        }

        let mut canonical = RelPath::root();
        let comps: Vec<EntryName> = query.components().collect();
        for (idx, comp) in comps.iter().enumerate() {
            let Some(children) = self.list_dir(base, &canonical) else {
                return Ok(None);
            };
            let Some((matched_name, matched_entry)) =
                lookup_entry_in_map(&children, comp, policy).into_result(comp)?
            else {
                return Ok(None);
            };
            canonical = canonical.join(matched_name);
            if idx + 1 == comps.len() {
                return Ok(Some((canonical, matched_entry.clone())));
            }
        }
        Ok(None)
    }

    /// Collects all live strict descendants `(relative_suffix, TreeEntry)` under `dir_path`.
    pub fn collect_live_subtree(
        &self,
        base: &Base,
        dir_path: &RelPath,
    ) -> Vec<(RelPath, TreeEntry)> {
        let mut candidate_paths = BTreeSet::new();
        if !self.has_blocking_ancestor(dir_path)
            && !matches!(
                self.overlay.entries.get(dir_path),
                Some(OverlayNode::Upsert { opaque: true, .. } | OverlayNode::Whiteout)
            )
        {
            for (k, _) in base.descendants_of(dir_path) {
                candidate_paths.insert(k.clone());
            }
        }
        for (k, _) in self.overlay.descendants_of(dir_path) {
            candidate_paths.insert(k.clone());
        }

        let mut live = Vec::new();
        for full_path in candidate_paths {
            if let Some(entry) = self.resolve(base, &full_path) {
                let suffix = full_path
                    .strip_prefix(dir_path)
                    .expect("descendant must strip dir_path");
                live.push((suffix, entry));
            }
        }
        live
    }

    /// Touches `mtime` on an existing directory `dir_path` in `Overlay`.
    pub fn touch_dir_mtime(&mut self, base: &Base, dir_path: &RelPath, now: Timestamp) {
        if dir_path.is_root() {
            self.overlay.root_mtime = Some(now);
            return;
        }
        if let Some(OverlayNode::Upsert { entry, opaque }) =
            self.overlay.entries.get(dir_path).cloned()
        {
            if entry.kind() == NodeKind::Directory {
                self.overlay.entries.insert(
                    dir_path.clone(),
                    OverlayNode::Upsert {
                        entry: entry.with_attrs(None, Some(now)),
                        opaque,
                    },
                );
            }
            return;
        }
        if let Some(entry) = self.resolve(base, dir_path) {
            if entry.kind() == NodeKind::Directory {
                self.overlay.entries.insert(
                    dir_path.clone(),
                    OverlayNode::Upsert {
                        entry: entry.with_attrs(None, Some(now)),
                        opaque: false,
                    },
                );
            }
        }
    }

    /// Places a `File` or `Symlink` at `path` inside `Overlay` (caller verifies parent directory
    /// and target collisions). Cleans up any stale `Overlay` entries under `path/`.
    pub fn put_non_dir(
        &mut self,
        base: &Base,
        path: RelPath,
        entry: TreeEntry,
        now: Timestamp,
    ) -> Result<(), ModelError> {
        if path.is_root() {
            return Err(ModelError::RootEntryNotAllowed);
        }
        let clean = entry.validated()?;
        debug_assert_ne!(clean.kind(), NodeKind::Directory);

        let desc_keys: Vec<RelPath> = self
            .overlay
            .descendants_of(&path)
            .into_iter()
            .map(|(k, _)| k.clone())
            .collect();
        for k in desc_keys {
            self.overlay.entries.remove(&k);
        }

        let opaque = self.base_exposed_at(base, &path)
            && matches!(base.get(&path), Some(TreeEntry::Directory { .. }));
        let parent = path.parent();
        self.overlay.entries.insert(
            path,
            OverlayNode::Upsert {
                entry: clean,
                opaque,
            },
        );
        if let Some(p) = parent {
            self.touch_dir_mtime(base, &p, now);
        }
        Ok(())
    }

    /// Creates a brand-new `Directory` at `path` (which must not currently exist in `View`).
    ///
    /// Automatically marks `opaque: true` if `Base` had a `Directory` at `path` that was previously
    /// removed (`rm -rf dir && mkdir dir`), preventing stale `Base` children from reappearing.
    pub fn put_new_dir(
        &mut self,
        base: &Base,
        path: RelPath,
        mode: u32,
        now: Timestamp,
    ) -> Result<TreeEntry, ModelError> {
        if path.is_root() {
            return Err(ModelError::RootEntryNotAllowed);
        }
        let desc_keys: Vec<RelPath> = self
            .overlay
            .descendants_of(&path)
            .into_iter()
            .map(|(k, _)| k.clone())
            .collect();
        for k in desc_keys {
            self.overlay.entries.remove(&k);
        }

        let opaque = !self.has_blocking_ancestor(&path)
            && matches!(base.get(&path), Some(TreeEntry::Directory { .. }));
        let entry = TreeEntry::directory(mode, now);
        let parent = path.parent();
        self.overlay.entries.insert(
            path,
            OverlayNode::Upsert {
                entry: entry.clone(),
                opaque,
            },
        );
        if let Some(p) = parent {
            self.touch_dir_mtime(base, &p, now);
        }
        Ok(entry)
    }

    /// Updates `mode` and/or `mtime` on an existing live entry at `path` without copying file bytes.
    pub fn update_attrs(
        &mut self,
        base: &Base,
        path: &RelPath,
        mode: Option<u32>,
        mtime: Option<Timestamp>,
    ) -> Option<TreeEntry> {
        if path.is_root() {
            self.set_root_attrs(mode, mtime);
            let meta = self.root_metadata(base);
            return Some(TreeEntry::Directory {
                mode: meta.mode,
                mtime: meta.mtime,
            });
        }
        let current = self.resolve(base, path)?;
        let updated = current.with_attrs(mode, mtime);
        let preserve_opaque = match self.overlay.entries.get(path) {
            Some(OverlayNode::Upsert { opaque, .. }) => *opaque,
            _ => false,
        };
        self.overlay.entries.insert(
            path.clone(),
            OverlayNode::Upsert {
                entry: updated.clone(),
                opaque: preserve_opaque,
            },
        );
        Some(updated)
    }

    /// Removes a live entry (or empty directory) at `path`:
    /// - Inserts `OverlayNode::Whiteout` if `Base` would otherwise expose `path`.
    /// - Deletes `path` from `Overlay` completely if `path` existed only in `Overlay`, ensuring
    ///   created-then-deleted temporary files leave zero residual `Overlay` state.
    pub fn remove_entry(&mut self, base: &Base, path: &RelPath, now: Timestamp) {
        if path.is_root() {
            return;
        }
        let desc_keys: Vec<RelPath> = self
            .overlay
            .descendants_of(path)
            .into_iter()
            .map(|(k, _)| k.clone())
            .collect();
        for k in desc_keys {
            self.overlay.entries.remove(&k);
        }

        if self.base_exposed_at(base, path) {
            self.overlay
                .entries
                .insert(path.clone(), OverlayNode::Whiteout);
        } else {
            self.overlay.entries.remove(path);
        }

        if let Some(parent) = path.parent() {
            self.touch_dir_mtime(base, &parent, now);
        }
    }

    /// Performs a metadata-only move of `from` (and its live subtree if a `Directory`) to `to`
    /// inside this `View`, reusing existing `ContentHash` digests without copying file bytes.
    ///
    /// Caller validates POSIX preconditions (`from`/`to` existence, `DirectoryNotEmpty`, etc.).
    pub fn move_subtree(&mut self, base: &Base, from: &RelPath, to: &RelPath, now: Timestamp) {
        if from == to || from.is_root() || to.is_root() {
            return;
        }
        let Some(from_entry) = self.resolve(base, from) else {
            return;
        };
        let descendants = if from_entry.kind() == NodeKind::Directory {
            self.collect_live_subtree(base, from)
        } else {
            Vec::new()
        };

        // Remove `from` and any overlay descendants under `from`.
        self.remove_entry(base, from, now);

        // Clear any stale overlay entries under `to`.
        let to_desc_keys: Vec<RelPath> = self
            .overlay
            .descendants_of(to)
            .into_iter()
            .map(|(k, _)| k.clone())
            .collect();
        for k in to_desc_keys {
            self.overlay.entries.remove(&k);
        }

        let top_opaque = from_entry.kind() == NodeKind::Directory
            || (self.base_exposed_at(base, to)
                && matches!(base.get(to), Some(TreeEntry::Directory { .. })));

        self.overlay.entries.insert(
            to.clone(),
            OverlayNode::Upsert {
                entry: from_entry,
                opaque: top_opaque,
            },
        );

        for (suffix, child_entry) in descendants {
            let dest_path = to.join_rel(&suffix);
            let child_opaque = child_entry.kind() == NodeKind::Directory;
            self.overlay.entries.insert(
                dest_path,
                OverlayNode::Upsert {
                    entry: child_entry,
                    opaque: child_opaque,
                },
            );
        }

        if let Some(to_parent) = to.parent() {
            self.touch_dir_mtime(base, &to_parent, now);
        }
    }

    /// Materializes the combined flat `Base + Overlay` state into a standalone `DirectoryTree`.
    pub fn materialize_tree(&self, base: &Base) -> DirectoryTree {
        let root_meta = self.root_metadata(base);
        let mut out = BTreeMap::new();

        for (path, entry) in base.entries() {
            if !self.has_blocking_ancestor(path) {
                match self.overlay.entries.get(path) {
                    None => {
                        out.insert(path.clone(), entry.clone());
                    }
                    Some(OverlayNode::Whiteout) => {}
                    Some(OverlayNode::Upsert { entry: ov, .. }) => {
                        out.insert(path.clone(), ov.clone());
                    }
                }
            }
        }

        for (path, node) in self.overlay.entries() {
            if let OverlayNode::Upsert { entry, .. } = node {
                if self.resolve(base, path).is_some() {
                    out.insert(path.clone(), entry.clone());
                }
            }
        }

        DirectoryTree {
            root_mode: root_meta.mode,
            root_mtime: root_meta.mtime,
            entries: out,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_children_skips_grandchildren_around_tricky_ascii_siblings() {
        let h = ContentHash::hash_bytes(b"x");
        let t = Timestamp::EPOCH;
        let tree = DirectoryTree::from_entries([
            (
                RelPath::new("dir/sub-dash").unwrap(),
                TreeEntry::file(h, 1, 0o644, t),
            ),
            (
                RelPath::new("dir/sub.dot").unwrap(),
                TreeEntry::file(h, 1, 0o644, t),
            ),
            (
                RelPath::new("dir/sub/nested/deep.txt").unwrap(),
                TreeEntry::file(h, 1, 0o644, t),
            ),
            (
                RelPath::new("dir/sub0").unwrap(),
                TreeEntry::file(h, 1, 0o644, t),
            ),
            (
                RelPath::new("dir/sub_under").unwrap(),
                TreeEntry::file(h, 1, 0o644, t),
            ),
        ])
        .unwrap();

        let children = tree.direct_children(&RelPath::new("dir").unwrap());
        let names: Vec<&str> = children.keys().map(EntryName::as_str).collect();
        assert_eq!(
            names,
            vec!["sub", "sub-dash", "sub.dot", "sub0", "sub_under"]
        );
    }
}
