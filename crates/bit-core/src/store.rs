//! Storage port traits (`BlobStore` and `MetadataStore`) for `bit-store`, plus deterministic
//! thread-safe in-memory implementations.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

use crate::hash::{BaseId, ContentHash};
use crate::ids::{TagName, ViewId};
use crate::model::{Base, View};

/// Error returned by `BlobStore` and `MetadataStore` implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Requested content-addressed blob was not found.
    BlobNotFound(ContentHash),
    /// Requested `Base` manifest was not found.
    BaseNotFound(BaseId),
    /// Requested `Tag` was not found.
    TagNotFound(TagName),
    /// Requested `View` was not found.
    ViewNotFound(ViewId),
    /// Stored bytes or manifest failed integrity or format validation.
    CorruptData(String),
    /// Underlying I/O error message.
    Io(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlobNotFound(hash) => write!(f, "blob not found: {hash}"),
            Self::BaseNotFound(id) => write!(f, "base not found: {id}"),
            Self::TagNotFound(tag) => write!(f, "tag not found: {tag}"),
            Self::ViewNotFound(id) => write!(f, "view not found: {id}"),
            Self::CorruptData(msg) => write!(f, "corrupt store data: {msg}"),
            Self::Io(msg) => write!(f, "store I/O error: {msg}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(err: io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

/// Content-addressed immutable file byte storage port (implemented by `bit-store`).
///
/// Object-safe (`dyn BlobStore`) and `Send + Sync` for concurrent VFS read/write access.
pub trait BlobStore: Send + Sync {
    /// Computes `ContentHash::hash_bytes(bytes)`, stores `bytes` idempotently, and returns the digest.
    fn put_blob(&self, bytes: &[u8]) -> Result<ContentHash, StoreError>;

    /// Retrieves the full byte payload for `hash`, or `Err(StoreError::BlobNotFound(*hash))`.
    fn get_blob(&self, hash: &ContentHash) -> Result<Vec<u8>, StoreError>;

    /// Returns `true` if `hash` exists in the store.
    fn has_blob(&self, hash: &ContentHash) -> Result<bool, StoreError>;

    /// Removes `hash` if present, returning `true` if a blob was deleted.
    fn delete_blob(&self, hash: &ContentHash) -> Result<bool, StoreError>;

    /// Reads at most `len` bytes starting at `offset` from `hash`.
    ///
    /// Disk-backed stores can override this with positional `pread` / `seek_read` so VFS reads
    /// on large `Base` files avoid loading entire blobs into memory.
    fn read_blob_at(
        &self,
        hash: &ContentHash,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, StoreError> {
        let full = self.get_blob(hash)?;
        if len == 0 || offset >= full.len() as u64 {
            return Ok(Vec::new());
        }
        let start = offset as usize;
        let end = start.saturating_add(len).min(full.len());
        Ok(full[start..end].to_vec())
    }

    /// Returns the byte length of `hash`.
    fn blob_len(&self, hash: &ContentHash) -> Result<u64, StoreError> {
        Ok(self.get_blob(hash)?.len() as u64)
    }
}

/// Metadata persistence port for `Base` manifests, `Tag` pointers, and `View` state
/// (implemented by `bit-store`).
///
/// Object-safe (`dyn MetadataStore`) and `Send + Sync`.
pub trait MetadataStore: Send + Sync {
    /// Persists an immutable `Base` manifest idempotently.
    fn put_base(&self, base: &Base) -> Result<(), StoreError>;

    /// Loads a `Base` manifest by `BaseId`, returning `Ok(None)` if absent.
    fn get_base(&self, id: &BaseId) -> Result<Option<Base>, StoreError>;

    /// Deletes a `Base` manifest by `BaseId`, returning `true` if it existed.
    fn delete_base(&self, id: &BaseId) -> Result<bool, StoreError>;

    /// Lists all stored `BaseId`s in canonical sorted order.
    fn list_base_ids(&self) -> Result<Vec<BaseId>, StoreError>;

    /// Points mutable `tag` at `base_id` (creating or updating the `Tag`).
    fn set_tag(&self, tag: &TagName, base_id: &BaseId) -> Result<(), StoreError>;

    /// Resolves `tag` to its target `BaseId`, returning `Ok(None)` if absent.
    fn get_tag(&self, tag: &TagName) -> Result<Option<BaseId>, StoreError>;

    /// Deletes `tag`, returning `true` if it existed.
    fn delete_tag(&self, tag: &TagName) -> Result<bool, StoreError>;

    /// Lists all `(TagName, BaseId)` mappings in canonical sorted order.
    fn list_tags(&self) -> Result<BTreeMap<TagName, BaseId>, StoreError>;

    /// Persists a `View` (its `ViewId`, `BaseId`, and `Overlay`), creating or replacing it.
    fn put_view(&self, view: &View) -> Result<(), StoreError>;

    /// Loads a `View` by `ViewId`, returning `Ok(None)` if absent.
    fn get_view(&self, id: &ViewId) -> Result<Option<View>, StoreError>;

    /// Deletes a `View` by `ViewId`, returning `true` if it existed.
    fn delete_view(&self, id: &ViewId) -> Result<bool, StoreError>;

    /// Lists all persisted `Views` sorted by `ViewId`.
    fn list_views(&self) -> Result<Vec<View>, StoreError>;
}

/// Deterministic in-memory `BlobStore` with operation counters for unit-test verification
/// (e.g. asserting zero blob reads/writes on metadata-only `rename` and `chmod`).
#[derive(Debug, Default)]
pub struct InMemoryBlobStore {
    blobs: RwLock<BTreeMap<ContentHash, Vec<u8>>>,
    puts: AtomicUsize,
    gets: AtomicUsize,
}

impl InMemoryBlobStore {
    /// Creates an empty `InMemoryBlobStore`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of `put_blob` calls executed on this store.
    pub fn put_count(&self) -> usize {
        self.puts.load(Ordering::SeqCst)
    }

    /// Total number of `get_blob` / `read_blob_at` calls executed on this store.
    pub fn get_count(&self) -> usize {
        self.gets.load(Ordering::SeqCst)
    }

    /// Number of distinct content-addressed blobs currently stored.
    pub fn blob_count(&self) -> usize {
        self.blobs.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl BlobStore for InMemoryBlobStore {
    fn put_blob(&self, bytes: &[u8]) -> Result<ContentHash, StoreError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        let hash = ContentHash::hash_bytes(bytes);
        let mut guard = self.blobs.write().unwrap_or_else(|e| e.into_inner());
        guard.entry(hash).or_insert_with(|| bytes.to_vec());
        Ok(hash)
    }

    fn get_blob(&self, hash: &ContentHash) -> Result<Vec<u8>, StoreError> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        let guard = self.blobs.read().unwrap_or_else(|e| e.into_inner());
        guard
            .get(hash)
            .cloned()
            .ok_or(StoreError::BlobNotFound(*hash))
    }

    fn has_blob(&self, hash: &ContentHash) -> Result<bool, StoreError> {
        let guard = self.blobs.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard.contains_key(hash))
    }

    fn delete_blob(&self, hash: &ContentHash) -> Result<bool, StoreError> {
        let mut guard = self.blobs.write().unwrap_or_else(|e| e.into_inner());
        Ok(guard.remove(hash).is_some())
    }
}

#[derive(Debug, Default)]
struct MetadataInner {
    bases: BTreeMap<BaseId, Base>,
    tags: BTreeMap<TagName, BaseId>,
    views: BTreeMap<ViewId, View>,
}

/// Deterministic in-memory `MetadataStore` for `CoreEngine::in_memory()` and tests.
#[derive(Debug, Default)]
pub struct InMemoryMetadataStore {
    inner: RwLock<MetadataInner>,
}

impl InMemoryMetadataStore {
    /// Creates an empty `InMemoryMetadataStore`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl MetadataStore for InMemoryMetadataStore {
    fn put_base(&self, base: &Base) -> Result<(), StoreError> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard.bases.insert(base.id(), base.clone());
        Ok(())
    }

    fn get_base(&self, id: &BaseId) -> Result<Option<Base>, StoreError> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard.bases.get(id).cloned())
    }

    fn delete_base(&self, id: &BaseId) -> Result<bool, StoreError> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        Ok(guard.bases.remove(id).is_some())
    }

    fn list_base_ids(&self) -> Result<Vec<BaseId>, StoreError> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard.bases.keys().copied().collect())
    }

    fn set_tag(&self, tag: &TagName, base_id: &BaseId) -> Result<(), StoreError> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard.tags.insert(tag.clone(), *base_id);
        Ok(())
    }

    fn get_tag(&self, tag: &TagName) -> Result<Option<BaseId>, StoreError> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard.tags.get(tag).copied())
    }

    fn delete_tag(&self, tag: &TagName) -> Result<bool, StoreError> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        Ok(guard.tags.remove(tag).is_some())
    }

    fn list_tags(&self) -> Result<BTreeMap<TagName, BaseId>, StoreError> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard.tags.clone())
    }

    fn put_view(&self, view: &View) -> Result<(), StoreError> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard.views.insert(view.id().clone(), view.clone());
        Ok(())
    }

    fn get_view(&self, id: &ViewId) -> Result<Option<View>, StoreError> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard.views.get(id).cloned())
    }

    fn delete_view(&self, id: &ViewId) -> Result<bool, StoreError> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        Ok(guard.views.remove(id).is_some())
    }

    fn list_views(&self) -> Result<Vec<View>, StoreError> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard.views.values().cloned().collect())
    }
}
