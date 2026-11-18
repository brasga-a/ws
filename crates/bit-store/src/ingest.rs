//! Verbatim external directory ingestion (`ingest_external_dir`) into a sealed `Base`.
//!
//! Strictly Git-agnostic (ADR-0003): never reads `.gitignore`, captures `.git/` unless explicitly
//! excluded by caller patterns, preserves verbatim UTF-8 symlink targets, skips special OS files
//! (sockets, FIFOs, block/character devices), and breaks external hardlinks into independent
//! content-addressed blobs.

use std::fs;
use std::path::Path;

use bit_core::{
    Base, BlobStore, ContentHash, DirectoryTree, EntryName, RelPath, StoreError, Timestamp,
    TreeEntry, DEFAULT_DIR_MODE, DEFAULT_FILE_MODE, PERM_MASK,
};

use crate::blob::FsBlobStore;

/// Output of `ingest_external_dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestOutput {
    /// Newly constructed immutable `Base` manifest (ready for `MetadataStore::put_base`).
    pub base: Base,
    /// Underlying `DirectoryTree`.
    pub tree: DirectoryTree,
    /// Relative paths of special OS files (sockets, FIFOs, devices) skipped during ingestion.
    pub skipped_special_files: Vec<RelPath>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    pattern: String,
    anchored: bool,
    has_slash: bool,
    dir_only: bool,
}

/// Pure-`std` explicit exclude-pattern matcher (`--exclude`).
#[derive(Debug, Clone, Default)]
pub struct ExcludeMatcher {
    rules: Vec<CompiledRule>,
}

impl ExcludeMatcher {
    /// Compiles explicit caller exclude patterns.
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Self {
        let mut rules = Vec::new();
        for raw in patterns {
            let trimmed = raw.as_ref().trim();
            if trimmed.is_empty() {
                continue;
            }
            let dir_only = trimmed.ends_with('/');
            let without_trailing = trimmed.trim_end_matches('/');
            let anchored = without_trailing.starts_with('/');
            let clean = without_trailing.trim_start_matches('/');
            if clean.is_empty() {
                continue;
            }
            let has_slash = clean.contains('/');
            rules.push(CompiledRule {
                pattern: clean.to_owned(),
                anchored,
                has_slash,
                dir_only,
            });
        }
        Self { rules }
    }

    /// Returns `true` if `rel_path` (with leaf `entry_name` and `is_dir`) matches any exclude rule.
    pub fn is_excluded(&self, rel_path: &RelPath, entry_name: &EntryName, is_dir: bool) -> bool {
        let rel_str = rel_path.as_str();
        let name_str = entry_name.as_str();

        for rule in &self.rules {
            if rule.dir_only && !is_dir {
                continue;
            }
            if rule.anchored || rule.has_slash {
                if glob_match_path(&rule.pattern, rel_str)
                    || rel_str
                        .strip_prefix(&rule.pattern)
                        .is_some_and(|rest| rest.starts_with('/'))
                {
                    return true;
                }
            } else if glob_match_segment(&rule.pattern, name_str)
                || glob_match_path(&rule.pattern, rel_str)
            {
                return true;
            }
        }
        false
    }
}

/// Matches a path glob where `**` spans `/` boundaries, `*` matches within a single `/` segment,
/// and `?` matches a single non-`/` character.
fn glob_match_path(pattern: &str, candidate: &str) -> bool {
    let pat_segs: Vec<&str> = pattern.split('/').collect();
    let cand_segs: Vec<&str> = if candidate.is_empty() {
        Vec::new()
    } else {
        candidate.split('/').collect()
    };
    match_segments(&pat_segs, &cand_segs)
}

fn match_segments(pat: &[&str], cand: &[&str]) -> bool {
    if pat.is_empty() {
        return cand.is_empty();
    }
    if pat[0] == "**" {
        if match_segments(&pat[1..], cand) {
            return true;
        }
        if !cand.is_empty() {
            return match_segments(pat, &cand[1..]);
        }
        return false;
    }
    if cand.is_empty() {
        return false;
    }
    glob_match_segment(pat[0], cand[0]) && match_segments(&pat[1..], &cand[1..])
}

fn glob_match_segment(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    match_chars(&p, &t)
}

fn match_chars(p: &[char], t: &[char]) -> bool {
    match p.first() {
        None => t.is_empty(),
        Some('*') => match_chars(&p[1..], t) || (!t.is_empty() && match_chars(p, &t[1..])),
        Some('?') => !t.is_empty() && t[0] != '/' && match_chars(&p[1..], &t[1..]),
        Some(&c) => !t.is_empty() && t[0] == c && match_chars(&p[1..], &t[1..]),
    }
}

/// Ingests an external directory tree into `blob_store` and returns a sealed `Base` (`IngestOutput`).
///
/// - Never inspects `.gitignore`; applies only `exclude_patterns`.
/// - Validates UTF-8 entry names and symlink targets.
/// - Preserves regular `File` bytes/modes/`mtime`, `Directory` modes/`mtime`, and verbatim `Symlink` targets.
/// - Skips special OS files (sockets, FIFOs, block/char devices), recording them in `skipped_special_files`.
/// - Breaks external hardlinks into deduplicated content-addressed blobs inside `blob_store`.
pub fn ingest_external_dir<P, S>(
    root: P,
    exclude_patterns: &[S],
    blob_store: &dyn BlobStore,
) -> Result<IngestOutput, StoreError>
where
    P: AsRef<Path>,
    S: AsRef<str>,
{
    ingest_internal(root.as_ref(), exclude_patterns, &mut |file_path| {
        let bytes = fs::read(file_path)?;
        let hash = blob_store.put_blob(&bytes)?;
        Ok((hash, bytes.len() as u64))
    })
}

/// Streaming variant of `ingest_external_dir` specialized for `FsBlobStore` (uses `FsBlobStore::ingest_file`
/// so large files stream in 64 KiB chunks without buffering whole files in memory).
pub fn ingest_external_dir_fs<P, S>(
    root: P,
    exclude_patterns: &[S],
    blob_store: &FsBlobStore,
) -> Result<IngestOutput, StoreError>
where
    P: AsRef<Path>,
    S: AsRef<str>,
{
    ingest_internal(root.as_ref(), exclude_patterns, &mut |file_path| {
        blob_store.ingest_file(file_path)
    })
}

/// Observes `root` into an in-memory `DirectoryTree` (hashing regular files without storing blobs),
/// used for read-only pre-flight inspection during `Apply`.
pub(crate) fn observe_external_dir(root: &Path) -> Result<DirectoryTree, StoreError> {
    let empty: [&str; 0] = [];
    let out = ingest_internal(root, &empty, &mut |file_path| {
        let bytes = fs::read(file_path)?;
        Ok((ContentHash::hash_bytes(&bytes), bytes.len() as u64))
    })?;
    Ok(out.tree)
}

fn ingest_internal<S, F>(
    root: &Path,
    exclude_patterns: &[S],
    store_file: &mut F,
) -> Result<IngestOutput, StoreError>
where
    S: AsRef<str>,
    F: FnMut(&Path) -> Result<(ContentHash, u64), StoreError>,
{
    let root_meta = fs::symlink_metadata(root)?;
    if !root_meta.file_type().is_dir() {
        return Err(StoreError::Io(format!(
            "external root {} is not a directory",
            root.display()
        )));
    }

    let matcher = ExcludeMatcher::new(exclude_patterns);
    let root_mode = host_mode(&root_meta, true);
    let root_mtime = host_mtime(&root_meta);

    let mut entries = Vec::new();
    let mut skipped_special = Vec::new();
    walk_dir_recursive(
        root,
        &RelPath::root(),
        &matcher,
        store_file,
        &mut entries,
        &mut skipped_special,
    )?;

    let tree = DirectoryTree::with_root_and_entries(root_mode, root_mtime, entries)
        .map_err(|e| StoreError::CorruptData(e.to_string()))?;
    let base = Base::from_tree(tree.clone());

    Ok(IngestOutput {
        base,
        tree,
        skipped_special_files: skipped_special,
    })
}

fn walk_dir_recursive<F>(
    host_dir: &Path,
    rel_prefix: &RelPath,
    matcher: &ExcludeMatcher,
    store_file: &mut F,
    entries: &mut Vec<(RelPath, TreeEntry)>,
    skipped_special: &mut Vec<RelPath>,
) -> Result<(), StoreError>
where
    F: FnMut(&Path) -> Result<(ContentHash, u64), StoreError>,
{
    let mut children = Vec::new();
    for item in fs::read_dir(host_dir)? {
        children.push(item?);
    }
    children.sort_by_key(|e| e.file_name());

    for child in children {
        let raw_name = child.file_name();
        let Some(utf8_name) = raw_name.to_str() else {
            return Err(StoreError::CorruptData(format!(
                "non-UTF-8 entry name under {}",
                host_dir.display()
            )));
        };
        let entry_name = EntryName::new(utf8_name).map_err(|e| {
            StoreError::CorruptData(format!("invalid entry name {utf8_name:?}: {e}"))
        })?;
        let rel_path = rel_prefix.join(&entry_name);
        let full_path = child.path();
        let meta = fs::symlink_metadata(&full_path)?;
        let ft = meta.file_type();

        if matcher.is_excluded(&rel_path, &entry_name, ft.is_dir()) {
            continue;
        }

        let mtime = host_mtime(&meta);
        if ft.is_symlink() {
            let link_os = fs::read_link(&full_path)?;
            let Some(target_utf8) = link_os.to_str() else {
                return Err(StoreError::CorruptData(format!(
                    "non-UTF-8 symlink target at {}",
                    full_path.display()
                )));
            };
            let sym = TreeEntry::symlink(target_utf8, mtime)
                .map_err(|e| StoreError::CorruptData(e.to_string()))?;
            entries.push((rel_path, sym));
        } else if ft.is_dir() {
            let mode = host_mode(&meta, true);
            entries.push((rel_path.clone(), TreeEntry::directory(mode, mtime)));
            walk_dir_recursive(
                &full_path,
                &rel_path,
                matcher,
                store_file,
                entries,
                skipped_special,
            )?;
        } else if ft.is_file() {
            let (hash, size) = store_file(&full_path)?;
            let mode = host_mode(&meta, false);
            entries.push((rel_path, TreeEntry::file(hash, size, mode, mtime)));
        } else {
            // Skip sockets, FIFOs, and block/char device nodes without failing ingestion.
            skipped_special.push(rel_path);
        }
    }
    Ok(())
}

pub(crate) fn host_mtime(meta: &fs::Metadata) -> Timestamp {
    meta.modified()
        .map(Timestamp::from)
        .unwrap_or(Timestamp::EPOCH)
}

#[cfg(unix)]
pub(crate) fn host_mode(meta: &fs::Metadata, is_dir: bool) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    let m = meta.permissions().mode() & PERM_MASK;
    if m == 0 {
        if is_dir {
            DEFAULT_DIR_MODE
        } else {
            DEFAULT_FILE_MODE
        }
    } else {
        m
    }
}

#[cfg(not(unix))]
pub(crate) fn host_mode(meta: &fs::Metadata, is_dir: bool) -> u32 {
    if is_dir {
        DEFAULT_DIR_MODE
    } else if meta.permissions().readonly() {
        0o444
    } else {
        DEFAULT_FILE_MODE
    }
}
