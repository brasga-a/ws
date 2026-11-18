//! Crash-safe ACID-style on-disk `FsMetadataStore` implementing `bit_core::MetadataStore`.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use bit_core::{Base, BaseId, MetadataStore, StoreError, TagName, View, ViewId};

use crate::blob::{clear_readonly_if_needed, sync_dir_best_effort};
use crate::codec::{decode_base, decode_tag, decode_view, encode_base, encode_tag, encode_view};

static META_TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

/// ACID-style file-backed `MetadataStore` using checksummed deterministic binary frames and
/// atomic `staging -> sync_all -> rename` commits under an internal `RwLock`.
///
/// Structured cleanly behind `bit_core::MetadataStore` so an embedded B-tree engine (such as `redb`)
/// can drop in transparently without changing callers.
#[derive(Debug)]
pub struct FsMetadataStore {
    meta_dir: PathBuf,
    bases_dir: PathBuf,
    tags_dir: PathBuf,
    views_dir: PathBuf,
    staging_dir: PathBuf,
    lock: RwLock<()>,
}

impl FsMetadataStore {
    /// Opens or initializes an `FsMetadataStore` rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root_ref = root.as_ref();
        let meta_dir = if root_ref.file_name().is_some_and(|n| n == "meta") {
            root_ref.to_path_buf()
        } else {
            root_ref.join("meta")
        };
        let bases_dir = meta_dir.join("bases");
        let tags_dir = meta_dir.join("tags");
        let views_dir = meta_dir.join("views");
        let staging_dir = meta_dir.join(".staging");

        fs::create_dir_all(&bases_dir)?;
        fs::create_dir_all(&tags_dir)?;
        fs::create_dir_all(&views_dir)?;
        fs::create_dir_all(&staging_dir)?;

        Ok(Self {
            meta_dir,
            bases_dir,
            tags_dir,
            views_dir,
            staging_dir,
            lock: RwLock::new(()),
        })
    }

    /// Root metadata directory (`<store>/meta`).
    pub fn meta_dir(&self) -> &Path {
        &self.meta_dir
    }

    /// Staging directory holding transient uncommitted metadata frames.
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }

    /// Cleans up incomplete staging files left behind by an interrupted write prior to daemon
    /// restart, returning the count of removed staging artifacts.
    pub fn recover(&self) -> Result<usize, StoreError> {
        let _guard = self.lock.write().unwrap_or_else(|e| e.into_inner());
        if !self.staging_dir.exists() {
            fs::create_dir_all(&self.staging_dir)?;
            return Ok(0);
        }
        let mut swept = 0usize;
        for item in fs::read_dir(&self.staging_dir)? {
            let entry = item?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                clear_readonly_if_needed(&path);
                fs::remove_file(&path)?;
            }
            swept += 1;
        }
        Ok(swept)
    }

    fn base_path(&self, id: &BaseId) -> PathBuf {
        self.bases_dir.join(format!("{}.base", id.to_hex()))
    }

    fn tag_path(&self, tag: &TagName) -> PathBuf {
        self.tags_dir.join(format!("{}.tag", tag.as_str()))
    }

    fn view_path(&self, id: &ViewId) -> PathBuf {
        self.views_dir.join(format!("{}.view", id.as_str()))
    }

    fn atomic_write_record(&self, dest: &Path, frame: &[u8]) -> Result<(), StoreError> {
        fs::create_dir_all(&self.staging_dir)?;
        let seq = META_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let staging = self.staging_dir.join(format!("meta-{pid}-{seq}.tmp"));

        let write_res = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging)?;
            file.write_all(frame)?;
            file.sync_all()?;
            Ok(())
        })();

        if let Err(err) = write_res {
            let _ = fs::remove_file(&staging);
            return Err(StoreError::from(err));
        }

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        if let Err(err) = fs::rename(&staging, dest) {
            let _ = fs::remove_file(&staging);
            return Err(StoreError::from(err));
        }

        if let Some(parent) = dest.parent() {
            sync_dir_best_effort(parent);
        }
        Ok(())
    }

    fn remove_record_if_present(path: &Path) -> Result<bool, StoreError> {
        match fs::remove_file(path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    sync_dir_best_effort(parent);
                }
                Ok(true)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(StoreError::from(err)),
        }
    }
}

impl MetadataStore for FsMetadataStore {
    fn put_base(&self, base: &Base) -> Result<(), StoreError> {
        let frame = encode_base(base)?;
        let _guard = self.lock.write().unwrap_or_else(|e| e.into_inner());
        let dest = self.base_path(&base.id());
        if dest.exists() {
            return Ok(());
        }
        self.atomic_write_record(&dest, &frame)
    }

    fn get_base(&self, id: &BaseId) -> Result<Option<Base>, StoreError> {
        let _guard = self.lock.read().unwrap_or_else(|e| e.into_inner());
        let path = self.base_path(id);
        match fs::read(&path) {
            Ok(bytes) => {
                let decoded = decode_base(&bytes)?;
                if decoded.id() != *id {
                    return Err(StoreError::CorruptData(format!(
                        "base filename {id} does not match decoded manifest {}",
                        decoded.id()
                    )));
                }
                Ok(Some(decoded))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(StoreError::from(err)),
        }
    }

    fn delete_base(&self, id: &BaseId) -> Result<bool, StoreError> {
        let _guard = self.lock.write().unwrap_or_else(|e| e.into_inner());
        Self::remove_record_if_present(&self.base_path(id))
    }

    fn list_base_ids(&self) -> Result<Vec<BaseId>, StoreError> {
        let _guard = self.lock.read().unwrap_or_else(|e| e.into_inner());
        let mut ids = Vec::new();
        for item in fs::read_dir(&self.bases_dir)? {
            let entry = item?;
            let fname = entry.file_name();
            let Some(name_str) = fname.to_str() else {
                continue;
            };
            let Some(hex_stem) = name_str.strip_suffix(".base") else {
                continue;
            };
            let id = BaseId::from_hex(hex_stem).map_err(|e| {
                StoreError::CorruptData(format!("invalid base filename {name_str:?}: {e}"))
            })?;
            ids.push(id);
        }
        ids.sort();
        Ok(ids)
    }

    fn set_tag(&self, tag: &TagName, base_id: &BaseId) -> Result<(), StoreError> {
        let frame = encode_tag(tag, base_id)?;
        let _guard = self.lock.write().unwrap_or_else(|e| e.into_inner());
        self.atomic_write_record(&self.tag_path(tag), &frame)
    }

    fn get_tag(&self, tag: &TagName) -> Result<Option<BaseId>, StoreError> {
        let _guard = self.lock.read().unwrap_or_else(|e| e.into_inner());
        let path = self.tag_path(tag);
        match fs::read(&path) {
            Ok(bytes) => {
                let (decoded_tag, base_id) = decode_tag(&bytes)?;
                if &decoded_tag != tag {
                    return Err(StoreError::CorruptData(format!(
                        "tag filename {tag} does not match decoded tag {decoded_tag}"
                    )));
                }
                Ok(Some(base_id))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(StoreError::from(err)),
        }
    }

    fn delete_tag(&self, tag: &TagName) -> Result<bool, StoreError> {
        let _guard = self.lock.write().unwrap_or_else(|e| e.into_inner());
        Self::remove_record_if_present(&self.tag_path(tag))
    }

    fn list_tags(&self) -> Result<BTreeMap<TagName, BaseId>, StoreError> {
        let _guard = self.lock.read().unwrap_or_else(|e| e.into_inner());
        let mut map = BTreeMap::new();
        for item in fs::read_dir(&self.tags_dir)? {
            let entry = item?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("tag") {
                continue;
            }
            let bytes = fs::read(&path)?;
            let (tag, base_id) = decode_tag(&bytes)?;
            map.insert(tag, base_id);
        }
        Ok(map)
    }

    fn put_view(&self, view: &View) -> Result<(), StoreError> {
        let frame = encode_view(view)?;
        let _guard = self.lock.write().unwrap_or_else(|e| e.into_inner());
        self.atomic_write_record(&self.view_path(view.id()), &frame)
    }

    fn get_view(&self, id: &ViewId) -> Result<Option<View>, StoreError> {
        let _guard = self.lock.read().unwrap_or_else(|e| e.into_inner());
        let path = self.view_path(id);
        match fs::read(&path) {
            Ok(bytes) => {
                let decoded = decode_view(&bytes)?;
                if decoded.id() != id {
                    return Err(StoreError::CorruptData(format!(
                        "view filename {id} does not match decoded view {}",
                        decoded.id()
                    )));
                }
                Ok(Some(decoded))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(StoreError::from(err)),
        }
    }

    fn delete_view(&self, id: &ViewId) -> Result<bool, StoreError> {
        let _guard = self.lock.write().unwrap_or_else(|e| e.into_inner());
        Self::remove_record_if_present(&self.view_path(id))
    }

    fn list_views(&self) -> Result<Vec<View>, StoreError> {
        let _guard = self.lock.read().unwrap_or_else(|e| e.into_inner());
        let mut views = Vec::new();
        for item in fs::read_dir(&self.views_dir)? {
            let entry = item?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("view") {
                continue;
            }
            let bytes = fs::read(&path)?;
            views.push(decode_view(&bytes)?);
        }
        views.sort_by(|a, b| a.id().cmp(b.id()));
        Ok(views)
    }
}
