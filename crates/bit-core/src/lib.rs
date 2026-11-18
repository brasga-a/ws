//! `bit-core`: OS-independent, Git-agnostic deterministic domain model, port traits, and
//! in-memory reference engine for Bit.
//!
//! ## Core Vocabulary (`GLOSSARY.md` & ADR-0001..0005)
//! - [`Base`]: A sealed, immutable directory tree owned by Bit and identified by [`BaseId`].
//! - [`TagName`]: A mutable human-readable `Tag` pointing to a [`Base`].
//! - [`View`]: An isolated, writable directory tree composed of exactly one [`Base`] and one
//!   private [`Overlay`], exposed under `<mount>/<view-id>/`.
//! - [`Overlay`]: The private set of file/directory additions, modifications, whiteouts, and
//!   opaque directory markers belonging to a single [`View`].
//! - [`FreezeOutput`] (`Freeze`): Capturing a [`View`]'s current state into a new immutable [`Base`].
//! - [`ApplyPlan`] / [`ApplyOutput`] (`Apply`): All-or-nothing guarded projection of a [`View`]'s
//!   [`Overlay`] onto an external directory while leaving the [`View`] unchanged.

pub mod control;
pub mod engine;
pub mod hash;
pub mod ids;
pub mod model;
pub mod ops;
pub mod path;
pub mod store;
pub mod vfs;

pub use control::{
    ApplyTarget, BaseInfo, BaseInput, ControlPlane, CoreError, InputEntry, RemoveBaseOutput,
    ViewInfo,
};
pub use engine::{CoreEngine, InMemoryCoreEngine};
pub use hash::{BaseId, ContentHash, HexDigestError, Sha256};
pub use ids::{
    is_windows_reserved_name, BaseSelector, IdError, TagName, ViewId, MAX_IDENTIFIER_LEN,
};
pub use model::{
    validate_symlink_target, Base, DirectoryTree, EntryMetadata, ModelError, NodeKind, Overlay,
    OverlayNode, Timestamp, TreeEntry, View, DEFAULT_DIR_MODE, DEFAULT_EXEC_MODE,
    DEFAULT_FILE_MODE, DEFAULT_SYMLINK_MODE, PERM_MASK, S_IFDIR, S_IFLNK, S_IFREG,
};
pub use ops::{
    compute_diff, freeze_to_base, plan_apply, ApplyAction, ApplyConflict, ApplyConflictKind,
    ApplyOutput, ApplyPlan, DiffChange, DiffEntry, FreezeOutput,
};
pub use path::{
    lookup_entry_in_map, AmbiguousCaseError, CaseLookup, CaseSensitivity, EntryName, PathError,
    RelPath,
};
pub use store::{BlobStore, InMemoryBlobStore, InMemoryMetadataStore, MetadataStore, StoreError};
pub use vfs::{
    InodeTable, MountPath, QuiescenceManager, VfsAttr, VfsDirEntry, VfsError, VfsOperations,
    VfsSetAttr, ViewQuiesceGuard, ViewWriteGuard, MOUNT_ROOT_MODE, ROOT_INO,
};

// Compile-time verification that all sister-crate port traits are `dyn`-compatible (`Send + Sync`).
fn _assert_port_traits_dyn_compatible(
    _: &dyn BlobStore,
    _: &dyn MetadataStore,
    _: &dyn VfsOperations,
    _: &dyn ControlPlane,
) {
}
