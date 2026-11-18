//! Control-plane port (`ControlPlane` trait, request/response types, and `CoreError`) for
//! `bit-ipc`, `bit-daemon`, and `bit-cli`.

use std::fmt;
use std::path::PathBuf;

use crate::hash::BaseId;
use crate::ids::{BaseSelector, IdError, TagName, ViewId};
use crate::model::{
    DirectoryTree, ModelError, NodeKind, Timestamp, DEFAULT_DIR_MODE, DEFAULT_FILE_MODE,
};
use crate::ops::{ApplyConflict, ApplyOutput, DiffEntry, FreezeOutput};
use crate::path::{PathError, RelPath};
use crate::store::StoreError;

/// Single in-memory entry descriptor for `BaseInput::Entries` (convenient for deterministic
/// tests and programmatic `Base` construction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputEntry {
    /// Regular file with raw byte contents.
    File {
        path: RelPath,
        bytes: Vec<u8>,
        mode: u32,
        mtime: Timestamp,
    },
    /// Explicit directory entry.
    Directory {
        path: RelPath,
        mode: u32,
        mtime: Timestamp,
    },
    /// Symbolic link with verbatim UTF-8 target.
    Symlink {
        path: RelPath,
        target: String,
        mtime: Timestamp,
    },
}

impl InputEntry {
    /// Creates a `File` input entry with `0o644` permissions and `Timestamp::EPOCH`.
    pub fn file(path: impl AsRef<str>, bytes: impl Into<Vec<u8>>) -> Result<Self, PathError> {
        Ok(Self::File {
            path: RelPath::new(path.as_ref())?,
            bytes: bytes.into(),
            mode: DEFAULT_FILE_MODE,
            mtime: Timestamp::EPOCH,
        })
    }

    /// Creates an executable `File` input entry (`0o755`).
    pub fn executable(path: impl AsRef<str>, bytes: impl Into<Vec<u8>>) -> Result<Self, PathError> {
        Ok(Self::File {
            path: RelPath::new(path.as_ref())?,
            bytes: bytes.into(),
            mode: 0o755,
            mtime: Timestamp::EPOCH,
        })
    }

    /// Creates an explicit `Directory` input entry (`0o755`).
    pub fn directory(path: impl AsRef<str>) -> Result<Self, PathError> {
        Ok(Self::Directory {
            path: RelPath::new(path.as_ref())?,
            mode: DEFAULT_DIR_MODE,
            mtime: Timestamp::EPOCH,
        })
    }

    /// Creates a `Symlink` input entry.
    pub fn symlink(path: impl AsRef<str>, target: impl Into<String>) -> Result<Self, PathError> {
        Ok(Self::Symlink {
            path: RelPath::new(path.as_ref())?,
            target: target.into(),
            mtime: Timestamp::EPOCH,
        })
    }
}

/// Input specification for `ControlPlane::create_base`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseInput {
    /// Raw in-memory entries whose file payloads will be content-hashed into `BlobStore`.
    Entries(Vec<InputEntry>),
    /// Pre-built `DirectoryTree` whose referenced `ContentHash` blobs already exist in `BlobStore`.
    Tree(DirectoryTree),
    /// Host filesystem directory path to ingest into a sealed `Base`.
    ExternalDir(PathBuf),
}

impl BaseInput {
    /// Convenience constructor building `BaseInput::Entries` from `(path, bytes)` file tuples.
    pub fn from_files<'a, I, B>(files: I) -> Result<Self, PathError>
    where
        I: IntoIterator<Item = (&'a str, B)>,
        B: AsRef<[u8]>,
    {
        let mut out = Vec::new();
        for (raw_path, data) in files {
            out.push(InputEntry::file(raw_path, data.as_ref().to_vec())?);
        }
        Ok(Self::Entries(out))
    }
}

/// Target specification for `ControlPlane::apply_view`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyTarget {
    /// Validate and plan against an observed in-memory `DirectoryTree`.
    Tree(DirectoryTree),
    /// Validate and atomically project the `View`'s `Overlay` onto an external host directory.
    ExternalDir(PathBuf),
}

/// Summary descriptor of a stored `Base` returned by `create_base` and `list_bases`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseInfo {
    /// Immutable `BaseId`.
    pub id: BaseId,
    /// Sorted human-readable `Tags` currently pointing to this `Base`.
    pub tags: Vec<TagName>,
    /// Number of non-root entries in the `Base` manifest.
    pub entry_count: usize,
    /// Number of live `Views` currently referencing this `Base`.
    pub view_count: usize,
}

/// Summary descriptor of a live `View` returned by `create_view` and `list_views`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewInfo {
    /// Unique `ViewId` (`<mount>/<view-id>/`).
    pub id: ViewId,
    /// `BaseId` backing this `View`.
    pub base_id: BaseId,
    /// Number of private mutation records currently in this `View`'s `Overlay`.
    pub overlay_entry_count: usize,
    /// Creation timestamp.
    pub created_at: Timestamp,
}

/// Result returned by `ControlPlane::remove_base`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveBaseOutput {
    /// Removed `BaseId`.
    pub base_id: BaseId,
    /// Dependent `Views` that were removed when `cascade == true`.
    pub removed_views: Vec<ViewId>,
    /// `Tags` pointing to `base_id` that were cleaned up.
    pub removed_tags: Vec<TagName>,
}

/// Control-plane domain error returned by `ControlPlane` operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// `Base` with the given `BaseId` does not exist.
    BaseNotFound(BaseId),
    /// `Tag` with the given `TagName` does not exist.
    TagNotFound(TagName),
    /// `View` with the given `ViewId` does not exist.
    ViewNotFound(ViewId),
    /// `View` with the given `ViewId` already exists.
    ViewAlreadyExists(ViewId),
    /// `remove_base` with `cascade == false` was blocked because live `Views` still reference `base_id`.
    BaseInUse { base_id: BaseId, views: Vec<ViewId> },
    /// Guarded `Apply` detected external directory modifications, deletions, or collisions since `Base` creation.
    ApplyConflicts(Vec<ApplyConflict>),
    /// Host directory contained a special OS file (FIFO, socket, block/char device) or non-UTF-8 name/target.
    UnsupportedFilesystemEntry { path: String, reason: String },
    /// Identifier validation failed.
    InvalidId(IdError),
    /// Path validation failed.
    InvalidPath(PathError),
    /// Manifest / node validation failed.
    Model(ModelError),
    /// Backing store error.
    Store(StoreError),
    /// Unexpected node kind encountered during an operation.
    UnexpectedNodeKind {
        path: RelPath,
        expected: NodeKind,
        actual: NodeKind,
    },
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaseNotFound(id) => write!(f, "base not found: {id}"),
            Self::TagNotFound(tag) => write!(f, "tag not found: {tag}"),
            Self::ViewNotFound(id) => write!(f, "view not found: {id}"),
            Self::ViewAlreadyExists(id) => write!(f, "view already exists: {id}"),
            Self::BaseInUse { base_id, views } => {
                let names: Vec<&str> = views.iter().map(ViewId::as_str).collect();
                write!(
                    f,
                    "cannot remove base {base_id} while referenced by active views {:?} (pass cascade: true to remove them)",
                    names
                )
            }
            Self::ApplyConflicts(conflicts) => {
                write!(
                    f,
                    "apply aborted due to {} conflict(s) against external directory",
                    conflicts.len()
                )
            }
            Self::UnsupportedFilesystemEntry { path, reason } => {
                write!(f, "unsupported filesystem entry at {path:?}: {reason}")
            }
            Self::InvalidId(err) => fmt::Display::fmt(err, f),
            Self::InvalidPath(err) => fmt::Display::fmt(err, f),
            Self::Model(err) => fmt::Display::fmt(err, f),
            Self::Store(err) => fmt::Display::fmt(err, f),
            Self::UnexpectedNodeKind {
                path,
                expected,
                actual,
            } => write!(f, "at {path:?}: expected {expected}, found {actual}"),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<IdError> for CoreError {
    fn from(err: IdError) -> Self {
        Self::InvalidId(err)
    }
}

impl From<PathError> for CoreError {
    fn from(err: PathError) -> Self {
        Self::InvalidPath(err)
    }
}

impl From<ModelError> for CoreError {
    fn from(err: ModelError) -> Self {
        Self::Model(err)
    }
}

impl From<StoreError> for CoreError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::BaseNotFound(id) => Self::BaseNotFound(id),
            StoreError::TagNotFound(tag) => Self::TagNotFound(tag),
            StoreError::ViewNotFound(id) => Self::ViewNotFound(id),
            other => Self::Store(other),
        }
    }
}

/// Control-plane port exposed over IPC by `bit-daemon` and invoked by `bit-cli` (ADR-0005).
///
/// Object-safe (`dyn ControlPlane`) and `Send + Sync`.
pub trait ControlPlane: Send + Sync {
    /// Creates a sealed immutable `Base` from `input`, optionally pointing `tag` at it.
    fn create_base(&self, input: BaseInput, tag: Option<TagName>) -> Result<BaseInfo, CoreError>;

    /// Creates or updates mutable `tag` to point to `base`.
    fn set_tag(&self, tag: TagName, base: BaseSelector) -> Result<BaseId, CoreError>;

    /// Removes mutable `tag` without removing the underlying `Base`.
    fn delete_tag(&self, tag: &TagName) -> Result<(), CoreError>;

    /// Removes `base` and any `Tags` pointing to it; blocks with `CoreError::BaseInUse` if any
    /// `Views` reference `base` unless `cascade == true` (which removes those `Views` as well).
    fn remove_base(&self, base: BaseSelector, cascade: bool)
        -> Result<RemoveBaseOutput, CoreError>;

    /// Lists all stored `Bases` along with their attached `Tags` and active `View` counts.
    fn list_bases(&self) -> Result<Vec<BaseInfo>, CoreError>;

    /// Creates a new isolated writable `View` backed by `base` with an empty `Overlay`.
    fn create_view(&self, view_id: ViewId, base: BaseSelector) -> Result<ViewInfo, CoreError>;

    /// Removes `view_id` and its private `Overlay` without affecting its `Base` or sibling `Views`.
    fn remove_view(&self, view_id: &ViewId) -> Result<(), CoreError>;

    /// Lists all active `Views`.
    fn list_views(&self) -> Result<Vec<ViewInfo>, CoreError>;

    /// Computes the live `O(|Overlay|)` `Diff` of `view_id` against its `Base` under write quiescence.
    fn diff_view(&self, view_id: &ViewId) -> Result<Vec<DiffEntry>, CoreError>;

    /// Captures the live state of `view_id` into a new immutable `Base` (`Freeze`) under write quiescence.
    fn freeze_view(
        &self,
        view_id: &ViewId,
        tag: Option<TagName>,
    ) -> Result<FreezeOutput, CoreError>;

    /// All-or-nothing guarded projection (`Apply`) of `view_id`'s `Overlay` onto `target` under
    /// write quiescence, leaving `view_id` unchanged.
    fn apply_view(&self, view_id: &ViewId, target: ApplyTarget) -> Result<ApplyOutput, CoreError>;
}
