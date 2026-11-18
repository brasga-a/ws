//! Crash-safe content-addressed on-disk `FsBlobStore` (`blobs/<2-hex>/<62-hex>`).

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bit_core::{BlobStore, ContentHash, Sha256, StoreError};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Optional OS-level copy-on-write file cloner (`FICLONE` on Linux Btrfs/XFS, `clonefile` on APFS).
///
/// Implementations MUST create an independent copy-on-write inode at `dest` and MUST NEVER create
/// an OS hardlink (`link()`), because in-place writes to an external hardlinked file would mutate
/// sealed `Base` blobs.
pub trait ReflinkCloner: Send + Sync {
    /// Attempts to clone `from_file` to `to_staging_file` using a copy-on-write reflink.
    fn try_reflink(&self, from_file: &Path, to_staging_file: &Path) -> io::Result<()>;
}

/// Strategy for ingesting external files into `FsBlobStore`.
#[derive(Clone, Default)]
pub enum ReflinkPolicy {
    /// Attempt copy-on-write reflink via an optional `ReflinkCloner`, falling back transparently
    /// to a physical byte copy into a new staging inode (never hardlinking).
    #[default]
    Auto,
    /// Use a custom `ReflinkCloner` hook with automatic fallback to physical byte copy.
    Custom(Arc<dyn ReflinkCloner>),
    /// Always perform a physical streaming byte copy into a fresh staging inode.
    PhysicalCopyOnly,
}

impl fmt::Debug for ReflinkPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str("ReflinkPolicy::Auto"),
            Self::Custom(_) => f.write_str("ReflinkPolicy::Custom(..)"),
            Self::PhysicalCopyOnly => f.write_str("ReflinkPolicy::PhysicalCopyOnly"),
        }
    }
}

/// Whole-file content-addressed `BlobStore` persisted under `<root>/blobs/<2-hex>/<62-hex>`.
///
/// Writes stage into `<root>/blobs/.staging/`, call `File::sync_all()`, and atomically `rename`
/// into the final sharded path so readers never observe torn or partially written blobs.
#[derive(Debug, Clone)]
pub struct FsBlobStore {
    blobs_dir: PathBuf,
    staging_dir: PathBuf,
    reflink_policy: ReflinkPolicy,
}

impl FsBlobStore {
    /// Opens or initializes an `FsBlobStore` rooted at `root` (creating `<root>/blobs` and
    /// `<root>/blobs/.staging` if absent).
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_policy(root, ReflinkPolicy::Auto)
    }

    /// Opens or initializes an `FsBlobStore` with an explicit `ReflinkPolicy`.
    pub fn open_with_policy(
        root: impl AsRef<Path>,
        reflink_policy: ReflinkPolicy,
    ) -> Result<Self, StoreError> {
        let root_ref = root.as_ref();
        let blobs_dir = if root_ref.file_name().is_some_and(|n| n == "blobs") {
            root_ref.to_path_buf()
        } else {
            root_ref.join("blobs")
        };
        let staging_dir = blobs_dir.join(".staging");
        fs::create_dir_all(&staging_dir)?;
        Ok(Self {
            blobs_dir,
            staging_dir,
            reflink_policy,
        })
    }

    /// Directory containing sharded `<2-hex>/<62-hex>` blobs.
    pub fn blobs_dir(&self) -> &Path {
        &self.blobs_dir
    }

    /// Directory holding transient staging files prior to atomic `rename`.
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }

    /// Returns the sharded filesystem path `blobs/<2-hex>/<62-hex>` for `hash`.
    pub fn blob_path(&self, hash: &ContentHash) -> PathBuf {
        let hex = hash.to_hex();
        self.blobs_dir.join(&hex[..2]).join(&hex[2..])
    }

    fn next_staging_path(&self) -> PathBuf {
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        self.staging_dir.join(format!("blob-{pid}-{seq}.tmp"))
    }

    /// Sweeps and deletes orphaned temporary files left in `<blobs>/.staging/` after an unclean
    /// shutdown, returning the number of removed temporary artifacts.
    pub fn sweep_orphan_temps(&self) -> Result<usize, StoreError> {
        if !self.staging_dir.exists() {
            fs::create_dir_all(&self.staging_dir)?;
            return Ok(0);
        }
        let mut swept = 0usize;
        for item in fs::read_dir(&self.staging_dir)? {
            let entry = item?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                clear_readonly_if_needed(&path);
                fs::remove_file(&path)?;
            }
            swept += 1;
        }
        Ok(swept)
    }

    /// Ingests an external regular file into the content-addressed store without ever hardlinking
    /// the external inode.
    ///
    /// Returns `(ContentHash, byte_size)`. External hardlinks with identical content naturally
    /// deduplicate to the same immutable `ContentHash` blob while remaining completely decoupled
    /// from subsequent external mutations.
    pub fn ingest_file(&self, external_path: &Path) -> Result<(ContentHash, u64), StoreError> {
        let staging_path = self.next_staging_path();
        fs::create_dir_all(&self.staging_dir)?;

        let result = self.stage_from_external(external_path, &staging_path);
        let (hash, size) = match result {
            Ok(pair) => pair,
            Err(err) => {
                let _ = fs::remove_file(&staging_path);
                return Err(err);
            }
        };

        let dest = self.blob_path(&hash);
        if dest.exists() {
            let _ = fs::remove_file(&staging_path);
            return Ok((hash, size));
        }

        if let Some(shard_dir) = dest.parent() {
            fs::create_dir_all(shard_dir)?;
        }

        if let Err(err) = fs::rename(&staging_path, &dest) {
            let _ = fs::remove_file(&staging_path);
            if dest.exists() {
                return Ok((hash, size));
            }
            return Err(StoreError::from(err));
        }

        if let Some(shard_dir) = dest.parent() {
            sync_dir_best_effort(shard_dir);
        }
        Ok((hash, size))
    }

    fn stage_from_external(
        &self,
        external_path: &Path,
        staging_path: &Path,
    ) -> Result<(ContentHash, u64), StoreError> {
        if let ReflinkPolicy::Custom(cloner) = &self.reflink_policy {
            if cloner.try_reflink(external_path, staging_path).is_ok() {
                // Verify that the cloner did NOT hardlink the external inode on Unix, and compute
                // the exact SHA-256 digest of the staged file before sealing.
                if !same_underlying_inode(external_path, staging_path) {
                    let staged = File::open(staging_path)?;
                    staged.sync_all()?;
                    return hash_open_file(staged);
                }
                // Defensive guard: if a misbehaving hook created a hardlink, discard it and copy!
                let _ = fs::remove_file(staging_path);
            }
        }

        // Physical streaming copy into a brand-new staging file while hashing in a single pass.
        let mut reader = File::open(external_path)?;
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(staging_path)?;

        let mut hasher = Sha256::new();
        let mut total: u64 = 0;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
            hasher.update(&buf[..n]);
            total += n as u64;
        }
        writer.sync_all()?;
        Ok((ContentHash::from_bytes(hasher.finalize()), total))
    }
}

fn hash_open_file(mut file: File) -> Result<(ContentHash, u64), StoreError> {
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((ContentHash::from_bytes(hasher.finalize()), total))
}

#[cfg(unix)]
fn same_underlying_inode(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (fs::symlink_metadata(a), fs::symlink_metadata(b)) {
        (Ok(ma), Ok(mb)) => ma.dev() == mb.dev() && ma.ino() == mb.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_underlying_inode(_a: &Path, _b: &Path) -> bool {
    false
}

pub(crate) fn clear_readonly_if_needed(path: &Path) {
    if let Ok(meta) = fs::symlink_metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                perms.set_mode(0o600);
            }
            #[cfg(not(unix))]
            {
                #[allow(clippy::permissions_set_readonly_false)]
                perms.set_readonly(false);
            }
            let _ = fs::set_permissions(path, perms);
        }
    }
}

pub(crate) fn sync_dir_best_effort(dir: &Path) {
    if let Ok(f) = File::open(dir) {
        let _ = f.sync_all();
    }
}

impl BlobStore for FsBlobStore {
    fn put_blob(&self, bytes: &[u8]) -> Result<ContentHash, StoreError> {
        let hash = ContentHash::hash_bytes(bytes);
        let dest = self.blob_path(&hash);
        if dest.exists() {
            return Ok(hash);
        }

        fs::create_dir_all(&self.staging_dir)?;
        let staging = self.next_staging_path();

        let write_res = (|| -> io::Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            Ok(())
        })();

        if let Err(err) = write_res {
            let _ = fs::remove_file(&staging);
            return Err(StoreError::from(err));
        }

        if let Some(shard_dir) = dest.parent() {
            fs::create_dir_all(shard_dir)?;
        }

        if let Err(err) = fs::rename(&staging, &dest) {
            let _ = fs::remove_file(&staging);
            if dest.exists() {
                return Ok(hash);
            }
            return Err(StoreError::from(err));
        }

        if let Some(shard_dir) = dest.parent() {
            sync_dir_best_effort(shard_dir);
        }
        Ok(hash)
    }

    fn get_blob(&self, hash: &ContentHash) -> Result<Vec<u8>, StoreError> {
        let path = self.blob_path(hash);
        match fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                Err(StoreError::BlobNotFound(*hash))
            }
            Err(err) => Err(StoreError::from(err)),
        }
    }

    fn has_blob(&self, hash: &ContentHash) -> Result<bool, StoreError> {
        Ok(self.blob_path(hash).is_file())
    }

    fn delete_blob(&self, hash: &ContentHash) -> Result<bool, StoreError> {
        let path = self.blob_path(hash);
        if !path.exists() {
            return Ok(false);
        }
        clear_readonly_if_needed(&path);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(StoreError::from(err)),
        }
    }

    fn read_blob_at(
        &self,
        hash: &ContentHash,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, StoreError> {
        let path = self.blob_path(hash);
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::BlobNotFound(*hash));
            }
            Err(err) => return Err(StoreError::from(err)),
        };

        if len == 0 {
            return Ok(Vec::new());
        }

        positional_read(&file, offset, len).map_err(StoreError::from)
    }

    fn blob_len(&self, hash: &ContentHash) -> Result<u64, StoreError> {
        let path = self.blob_path(hash);
        match fs::metadata(&path) {
            Ok(meta) => Ok(meta.len()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                Err(StoreError::BlobNotFound(*hash))
            }
            Err(err) => Err(StoreError::from(err)),
        }
    }
}

#[cfg(unix)]
fn positional_read(file: &File, mut offset: u64, len: usize) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut out = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        let n = file.read_at(&mut out[filled..], offset)?;
        if n == 0 {
            break;
        }
        filled += n;
        offset = offset.saturating_add(n as u64);
    }
    out.truncate(filled);
    Ok(out)
}

#[cfg(not(unix))]
fn positional_read(mut file: &File, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    use std::io::Seek;
    file.seek(io::SeekFrom::Start(offset))?;
    let mut out = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        let n = file.read(&mut out[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    out.truncate(filled);
    Ok(out)
}
