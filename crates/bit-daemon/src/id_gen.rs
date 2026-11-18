//! Auto-generator of portable `ViewId`s for unnamed `Views`.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

use bit_core::{IdError, ViewId};

/// Thread-safe generator producing unique, portable [`ViewId`]s when a caller omits an explicit ID.
#[derive(Debug)]
pub struct ViewIdGenerator {
    prefix: String,
    counter: AtomicU64,
}

impl Default for ViewIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewIdGenerator {
    /// Creates a generator with default `"view"` prefix (`view-0001`, `view-0002`, ...).
    pub fn new() -> Self {
        Self {
            prefix: "view".to_owned(),
            counter: AtomicU64::new(1),
        }
    }

    /// Creates a generator with a validated custom prefix (e.g. `"v"` -> `v-0001`).
    pub fn with_prefix(prefix: impl Into<String>) -> Result<Self, IdError> {
        let prefix = prefix.into();
        // Verify `<prefix>-0001` forms a valid portable `ViewId`.
        let _ = ViewId::new(format!("{prefix}-0001"))?;
        Ok(Self {
            prefix,
            counter: AtomicU64::new(1),
        })
    }

    /// Generates the next available `ViewId` not present in `existing`.
    pub fn next_available<'a, I>(&self, existing: I) -> ViewId
    where
        I: IntoIterator<Item = &'a ViewId>,
    {
        let taken: BTreeSet<&str> = existing.into_iter().map(ViewId::as_str).collect();
        loop {
            let n = self.counter.fetch_add(1, Ordering::SeqCst);
            let candidate_str = format!("{}-{n:04}", self.prefix);
            if !taken.contains(candidate_str.as_str()) {
                if let Ok(id) = ViewId::new(candidate_str) {
                    return id;
                }
            }
        }
    }
}
