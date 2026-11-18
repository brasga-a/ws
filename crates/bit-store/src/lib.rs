//! `bit-store`: Crash-safe content-addressed `FsBlobStore`, ACID `FsMetadataStore`, verbatim
//! external directory ingestion, and transactional `Apply` execution with rollback journal.

pub mod apply;
pub mod blob;
pub mod codec;
pub mod ingest;
pub mod meta;

use std::path::{Path, PathBuf};

use bit_core::{CoreEngine, StoreError};

pub use apply::{execute_apply, execute_apply_with_fault_hook, ApplyStoreError};
pub use blob::{FsBlobStore, ReflinkCloner, ReflinkPolicy};
pub use codec::{decode_base, decode_tag, decode_view, encode_base, encode_tag, encode_view};
pub use ingest::{ingest_external_dir, ingest_external_dir_fs, ExcludeMatcher, IngestOutput};
pub use meta::FsMetadataStore;

/// Startup recovery counts returned by [`BitStore::open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecoverySummary {
    /// Orphaned temporary blob files swept from `<store>/blobs/.staging`.
    pub swept_blob_temps: usize,
    /// Orphaned temporary metadata frames swept from `<store>/meta/.staging`.
    pub swept_metadata_temps: usize,
}

/// Persistent `CoreEngine` backed by `FsBlobStore` and `FsMetadataStore`.
pub type PersistentCoreEngine = CoreEngine<FsBlobStore, FsMetadataStore>;

/// Combined on-disk store root managing `<store_dir>/blobs` and `<store_dir>/meta`.
#[derive(Debug)]
pub struct BitStore {
    root: PathBuf,
    blobs: FsBlobStore,
    metadata: FsMetadataStore,
}

impl BitStore {
    /// Opens `<store_dir>/blobs` and `<store_dir>/meta`, automatically sweeping incomplete
    /// staging artifacts from any prior interrupted run.
    pub fn open(store_dir: impl AsRef<Path>) -> Result<(Self, RecoverySummary), StoreError> {
        let root = store_dir.as_ref().to_path_buf();
        let blobs = FsBlobStore::open(root.join("blobs"))?;
        let metadata = FsMetadataStore::open(root.join("meta"))?;
        let swept_blob_temps = blobs.sweep_orphan_temps()?;
        let swept_metadata_temps = metadata.recover()?;
        Ok((
            Self {
                root,
                blobs,
                metadata,
            },
            RecoverySummary {
                swept_blob_temps,
                swept_metadata_temps,
            },
        ))
    }

    /// Root directory of this store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Borrows the `FsBlobStore`.
    pub const fn blobs(&self) -> &FsBlobStore {
        &self.blobs
    }

    /// Borrows the `FsMetadataStore`.
    pub const fn metadata(&self) -> &FsMetadataStore {
        &self.metadata
    }

    /// Consumes `self` into `(FsBlobStore, FsMetadataStore)`.
    pub fn into_parts(self) -> (FsBlobStore, FsMetadataStore) {
        (self.blobs, self.metadata)
    }

    /// Consumes `self` into a ready-to-serve `CoreEngine<FsBlobStore, FsMetadataStore>`.
    pub fn into_engine(self) -> PersistentCoreEngine {
        CoreEngine::new(self.blobs, self.metadata)
    }
}
