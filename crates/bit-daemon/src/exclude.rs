//! Exclude-pattern matching (`ExcludeFilter`) backed by [`bit_store::ExcludeMatcher`].

use std::path::Path;

use bit_core::{CoreError, EntryName, InMemoryBlobStore, InputEntry, RelPath, TreeEntry};
use bit_store::{ingest_external_dir, ExcludeMatcher};

/// Compiled set of `--exclude <pattern>` rules evaluated against relative paths during `Base`
/// creation (strictly Git-agnostic; never reads `.gitignore`).
#[derive(Debug, Clone, Default)]
pub struct ExcludeFilter {
    matcher: ExcludeMatcher,
    empty: bool,
}

impl ExcludeFilter {
    /// Compiles an `ExcludeFilter` from raw CLI pattern strings.
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let collected: Vec<String> = patterns
            .into_iter()
            .map(|s| s.as_ref().trim().trim_start_matches("./").to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        let empty = collected.is_empty();
        let matcher = ExcludeMatcher::new(&collected);
        Self { matcher, empty }
    }

    /// Returns `true` if no active rules are configured.
    pub const fn is_empty(&self) -> bool {
        self.empty
    }

    /// Returns `true` if `rel_path` (whose leaf name is `name`) matches any exclude pattern.
    pub fn is_excluded(&self, rel_path: &RelPath, name: &EntryName) -> bool {
        self.matcher.is_excluded(rel_path, name, true)
    }
}

/// Walks `root_dir` via `bit_store::ingest_external_dir`, pruning excluded entries and skipping
/// special OS files, returning [`InputEntry`] descriptors for [`bit_core::BaseInput::Entries`].
pub fn scan_host_dir_with_excludes(
    root_dir: &Path,
    patterns: &[String],
) -> Result<Vec<InputEntry>, CoreError> {
    let scratch_blobs = InMemoryBlobStore::new();
    let ingested = ingest_external_dir(root_dir, patterns, &scratch_blobs)?;
    let mut entries = Vec::with_capacity(ingested.tree.len());
    for (rel_path, entry) in ingested.tree.entries() {
        match entry {
            TreeEntry::File {
                content,
                mode,
                mtime,
                ..
            } => {
                let bytes = bit_core::BlobStore::get_blob(&scratch_blobs, content)?;
                entries.push(InputEntry::File {
                    path: rel_path.clone(),
                    bytes,
                    mode: *mode,
                    mtime: *mtime,
                });
            }
            TreeEntry::Directory { mode, mtime } => {
                entries.push(InputEntry::Directory {
                    path: rel_path.clone(),
                    mode: *mode,
                    mtime: *mtime,
                });
            }
            TreeEntry::Symlink { target, mtime, .. } => {
                entries.push(InputEntry::Symlink {
                    path: rel_path.clone(),
                    target: target.clone(),
                    mtime: *mtime,
                });
            }
        }
    }
    Ok(entries)
}
