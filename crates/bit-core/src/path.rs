//! Validated portable UTF-8 entry names and canonical relative paths (`EntryName` and `RelPath`),
//! with case-preserving canonical comparisons and unambiguous case-insensitive lookup helpers.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

/// Error returned when validating an `EntryName` or `RelPath`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// An `EntryName` or path segment was empty.
    EmptyComponent,
    /// Path contained a NUL byte (`'\0'`).
    ContainsNul,
    /// `EntryName` contained `'/'` or path started/ended with `'/'`.
    InvalidSlash,
    /// Path or component contained `'\\'`.
    ContainsBackslash,
    /// Path or component contained `.` or `..` traversal.
    DotTraversal(String),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyComponent => f.write_str("path component must not be empty"),
            Self::ContainsNul => f.write_str("path must not contain NUL bytes"),
            Self::InvalidSlash => {
                f.write_str("path component must not contain '/' or leading/trailing '/'")
            }
            Self::ContainsBackslash => f.write_str("path must not contain '\\'"),
            Self::DotTraversal(seg) => {
                write!(f, "path must not contain {seg:?} traversal segment")
            }
        }
    }
}

impl std::error::Error for PathError {}

/// Single validated UTF-8 directory entry name.
///
/// Rejects empty strings, NUL (`'\0'`), `'/'`, `'\\'`, `"."`, and `".."`.
/// Canonically case-preserving and case-sensitive (`Eq`, `Ord`, `Hash`), with helper methods
/// for optional unambiguous case-insensitive lookup on macOS and Windows VFS adapters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryName(String);

impl EntryName {
    /// Validates and constructs a single directory `EntryName`.
    pub fn new(raw: impl Into<String>) -> Result<Self, PathError> {
        let s = raw.into();
        validate_entry_name(&s)?;
        Ok(Self(s))
    }

    /// Borrows the entry name as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes `self` and returns the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Computes a Unicode case-folded key (`to_lowercase`) for case-insensitive matching.
    pub fn case_fold_key(&self) -> String {
        self.0.to_lowercase()
    }

    /// Compares `self` case-insensitively (Unicode lowercase) against `other`.
    pub fn eq_case_insensitive(&self, other: &str) -> bool {
        self.0.to_lowercase() == other.to_lowercase()
    }
}

fn validate_entry_name(raw: &str) -> Result<(), PathError> {
    if raw.is_empty() {
        return Err(PathError::EmptyComponent);
    }
    if raw.contains('\0') {
        return Err(PathError::ContainsNul);
    }
    if raw.contains('/') {
        return Err(PathError::InvalidSlash);
    }
    if raw.contains('\\') {
        return Err(PathError::ContainsBackslash);
    }
    if raw == "." || raw == ".." {
        return Err(PathError::DotTraversal(raw.to_owned()));
    }
    Ok(())
}

impl AsRef<str> for EntryName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for EntryName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EntryName {
    type Err = PathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<&str> for EntryName {
    type Error = PathError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for EntryName {
    type Error = PathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Validated canonical relative UTF-8 path inside a `Base` or `View`.
///
/// - The root of a `Base` or `View` is represented by `RelPath::root()` (`""`, zero components).
/// - Non-root paths consist of `'/'`-separated `EntryName` components (`"src/lib.rs"`).
/// - Rejects NUL, `'\\'`, leading/trailing/duplicate `'/'`, `"."`, and `".."` traversal.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(String);

impl RelPath {
    /// Returns the root `RelPath` (`""`).
    pub const fn root() -> Self {
        Self(String::new())
    }

    /// Validates a canonical relative path string.
    ///
    /// Empty string `""` yields `RelPath::root()`. Non-empty strings must be `'/'`-joined valid
    /// `EntryName` segments without leading `'/'`, trailing `'/'`, `'\\'`, NUL, `"."`, or `".."`.
    pub fn new(raw: impl Into<String>) -> Result<Self, PathError> {
        let s = raw.into();
        if s.is_empty() {
            return Ok(Self::root());
        }
        if s.contains('\0') {
            return Err(PathError::ContainsNul);
        }
        if s.contains('\\') {
            return Err(PathError::ContainsBackslash);
        }
        if s.starts_with('/') || s.ends_with('/') {
            return Err(PathError::InvalidSlash);
        }
        for segment in s.split('/') {
            validate_entry_name(segment)?;
        }
        Ok(Self(s))
    }

    /// Normalizes a relative path by stripping redundant `'/'` and `"."` segments while still
    /// rejecting leading `'/'` (absolute paths), `'\\'`, NUL bytes, and `".."` traversal.
    pub fn normalize(raw: &str) -> Result<Self, PathError> {
        if raw.contains('\0') {
            return Err(PathError::ContainsNul);
        }
        if raw.contains('\\') {
            return Err(PathError::ContainsBackslash);
        }
        if raw.starts_with('/') {
            return Err(PathError::InvalidSlash);
        }
        let mut parts = Vec::new();
        for segment in raw.split('/') {
            if segment.is_empty() || segment == "." {
                continue;
            }
            if segment == ".." {
                return Err(PathError::DotTraversal("..".to_owned()));
            }
            validate_entry_name(segment)?;
            parts.push(segment);
        }
        Ok(Self(parts.join("/")))
    }

    /// Builds a `RelPath` from validated `EntryName` components.
    pub fn from_components<'a>(iter: impl IntoIterator<Item = &'a EntryName>) -> Self {
        let mut out = String::new();
        for (idx, comp) in iter.into_iter().enumerate() {
            if idx > 0 {
                out.push('/');
            }
            out.push_str(comp.as_str());
        }
        Self(out)
    }

    /// Returns `true` if `self` is the root `RelPath` (`""`).
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrows the canonical relative path string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the number of path components (`0` for `RelPath::root()`).
    pub fn depth(&self) -> usize {
        if self.0.is_empty() {
            0
        } else {
            self.0.bytes().filter(|&b| b == b'/').count() + 1
        }
    }

    /// Appends a single validated `EntryName` child component.
    pub fn join(&self, child: &EntryName) -> Self {
        if self.0.is_empty() {
            Self(child.as_str().to_owned())
        } else {
            let mut s = String::with_capacity(self.0.len() + 1 + child.as_str().len());
            s.push_str(&self.0);
            s.push('/');
            s.push_str(child.as_str());
            Self(s)
        }
    }

    /// Appends another `RelPath` onto `self`.
    pub fn join_rel(&self, suffix: &RelPath) -> Self {
        if suffix.is_root() {
            self.clone()
        } else if self.is_root() {
            suffix.clone()
        } else {
            let mut s = String::with_capacity(self.0.len() + 1 + suffix.0.len());
            s.push_str(&self.0);
            s.push('/');
            s.push_str(&suffix.0);
            Self(s)
        }
    }

    /// Returns the parent `RelPath`, or `None` if `self` is `RelPath::root()`.
    pub fn parent(&self) -> Option<Self> {
        if self.0.is_empty() {
            return None;
        }
        match self.0.rfind('/') {
            Some(pos) => Some(Self(self.0[..pos].to_owned())),
            None => Some(Self::root()),
        }
    }

    /// Returns the final component as an `EntryName`, or `None` if `self` is `RelPath::root()`.
    pub fn file_name(&self) -> Option<EntryName> {
        if self.0.is_empty() {
            return None;
        }
        let tail = match self.0.rfind('/') {
            Some(pos) => &self.0[pos + 1..],
            None => &self.0,
        };
        Some(EntryName(tail.to_owned()))
    }

    /// Iterates over validated `EntryName` components from outermost to innermost.
    pub fn components(&self) -> impl Iterator<Item = EntryName> + '_ {
        let iter = if self.0.is_empty() {
            None
        } else {
            Some(self.0.split('/').map(|seg| EntryName(seg.to_owned())))
        };
        iter.into_iter().flatten()
    }

    /// Iterates over all non-root ancestor prefixes in top-down order, excluding `self`.
    ///
    /// For `"a/b/c"`, yields `"a"`, then `"a/b"`.
    pub fn strict_ancestors(&self) -> Vec<RelPath> {
        let mut out = Vec::new();
        for (idx, b) in self.0.bytes().enumerate() {
            if b == b'/' {
                out.push(RelPath(self.0[..idx].to_owned()));
            }
        }
        out
    }

    /// Returns `true` if `prefix` is a component-wise prefix of `self`
    /// (`RelPath::root()` is a prefix of every `RelPath`).
    pub fn starts_with(&self, prefix: &RelPath) -> bool {
        if prefix.is_root() {
            return true;
        }
        if self.0 == prefix.0 {
            return true;
        }
        self.0.len() > prefix.0.len()
            && self.0.starts_with(&prefix.0)
            && self.0.as_bytes()[prefix.0.len()] == b'/'
    }

    /// Returns `true` if `self` is strictly nested inside `ancestor` (`self != ancestor`).
    pub fn is_descendant_of(&self, ancestor: &RelPath) -> bool {
        if ancestor.is_root() {
            !self.is_root()
        } else {
            self.0.len() > ancestor.0.len()
                && self.0.starts_with(&ancestor.0)
                && self.0.as_bytes()[ancestor.0.len()] == b'/'
        }
    }

    /// Strips component-wise `prefix` from `self`, returning `Some(RelPath)` if `self.starts_with(prefix)`.
    pub fn strip_prefix(&self, prefix: &RelPath) -> Option<RelPath> {
        if prefix.is_root() {
            return Some(self.clone());
        }
        if self.0 == prefix.0 {
            return Some(RelPath::root());
        }
        if self.is_descendant_of(prefix) {
            Some(RelPath(self.0[prefix.0.len() + 1..].to_owned()))
        } else {
            None
        }
    }
}

impl AsRef<str> for RelPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for RelPath {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RelPath {
    type Err = PathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<&str> for RelPath {
    type Error = PathError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for RelPath {
    type Error = PathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<EntryName> for RelPath {
    fn from(entry: EntryName) -> Self {
        Self(entry.into_inner())
    }
}

/// Case-matching policy for VFS adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaseSensitivity {
    /// Canonical exact UTF-8 byte comparison (Linux / POSIX default).
    #[default]
    CaseSensitive,
    /// Exact match takes priority; otherwise matches a unique case-insensitive entry
    /// and rejects ambiguous multi-way collisions (macOS / Windows helper).
    CaseInsensitiveUnambiguous,
}

/// Error returned when a case-insensitive lookup matches two or more distinct entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousCaseError {
    /// Requested component name.
    pub requested: EntryName,
    /// Canonical conflicting entries present in the directory.
    pub candidates: Vec<EntryName>,
}

impl fmt::Display for AmbiguousCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let joined: Vec<&str> = self.candidates.iter().map(EntryName::as_str).collect();
        write!(
            f,
            "ambiguous case-insensitive lookup for {:?}: matches {:?}",
            self.requested.as_str(),
            joined
        )
    }
}

impl std::error::Error for AmbiguousCaseError {}

/// Outcome of looking up an `EntryName` within a directory entry map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseLookup<'a, T> {
    /// Exact canonical match.
    Exact(&'a EntryName, &'a T),
    /// Unique case-folded match.
    Folded(&'a EntryName, &'a T),
    /// No entry matched.
    NotFound,
    /// Two or more entries matched case-insensitively while none matched exactly.
    Ambiguous(Vec<EntryName>),
}

impl<'a, T> CaseLookup<'a, T> {
    /// Converts the lookup outcome into `Result<Option<(&EntryName, &T)>, AmbiguousCaseError>`.
    pub fn into_result(
        self,
        requested: &EntryName,
    ) -> Result<Option<(&'a EntryName, &'a T)>, AmbiguousCaseError> {
        match self {
            Self::Exact(k, v) | Self::Folded(k, v) => Ok(Some((k, v))),
            Self::NotFound => Ok(None),
            Self::Ambiguous(candidates) => Err(AmbiguousCaseError {
                requested: requested.clone(),
                candidates,
            }),
        }
    }
}

/// Resolves `query` against a directory map under `policy`.
///
/// Exact canonical match always wins even in `CaseInsensitiveUnambiguous` mode (so a directory
/// containing both `"Makefile"` and `"makefile"` still resolves `"Makefile"` unambiguously).
pub fn lookup_entry_in_map<'a, T>(
    entries: &'a BTreeMap<EntryName, T>,
    query: &EntryName,
    policy: CaseSensitivity,
) -> CaseLookup<'a, T> {
    if let Some((k, v)) = entries.get_key_value(query) {
        return CaseLookup::Exact(k, v);
    }
    if policy == CaseSensitivity::CaseSensitive {
        return CaseLookup::NotFound;
    }

    let folded_target = query.case_fold_key();
    let mut matches: Vec<(&'a EntryName, &'a T)> = entries
        .iter()
        .filter(|(k, _)| k.case_fold_key() == folded_target)
        .collect();

    match matches.len() {
        0 => CaseLookup::NotFound,
        1 => {
            let (k, v) = matches.pop().expect("single match");
            CaseLookup::Folded(k, v)
        }
        _ => CaseLookup::Ambiguous(matches.into_iter().map(|(k, _)| k.clone()).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_name_and_rel_path_validation() {
        assert!(EntryName::new("Cargo.toml").is_ok());
        assert!(EntryName::new(".git").is_ok());
        assert!(EntryName::new("café.rs").is_ok());

        for bad in ["", ".", "..", "a/b", "a\\b", "nul\0byte"] {
            assert!(EntryName::new(bad).is_err(), "expected {bad:?} to fail");
        }

        assert!(RelPath::new("").unwrap().is_root());
        let p = RelPath::new("src/core/lib.rs").unwrap();
        assert_eq!(p.depth(), 3);
        assert_eq!(p.parent().unwrap().as_str(), "src/core");
        assert_eq!(p.file_name().unwrap().as_str(), "lib.rs");

        for bad_rel in [
            "/abs/path",
            "trailing/",
            "double//slash",
            ".",
            "..",
            "../up",
            "a/../b",
            "a/./b",
            "win\\sep",
            "bad\0nul",
        ] {
            assert!(
                RelPath::new(bad_rel).is_err(),
                "expected {bad_rel:?} to fail"
            );
        }

        assert_eq!(RelPath::normalize("a/./b//c/").unwrap().as_str(), "a/b/c");
        assert!(RelPath::normalize("a/../b").is_err());
    }

    #[test]
    fn component_prefix_boundaries() {
        let dir = RelPath::new("dir").unwrap();
        let child = RelPath::new("dir/file.txt").unwrap();
        let sibling = RelPath::new("dir_other/file.txt").unwrap();

        assert!(child.starts_with(&dir));
        assert!(child.is_descendant_of(&dir));
        assert!(!dir.is_descendant_of(&dir));
        assert!(!sibling.starts_with(&dir));
        assert_eq!(
            child.strip_prefix(&dir).unwrap(),
            RelPath::new("file.txt").unwrap()
        );
    }

    #[test]
    fn case_insensitive_unambiguous_lookup() {
        let mut map = BTreeMap::new();
        map.insert(EntryName::new("README.md").unwrap(), 1);
        map.insert(EntryName::new("Foo").unwrap(), 2);
        map.insert(EntryName::new("FOO").unwrap(), 3);

        // Unique case-folded match succeeds.
        let readme_q = EntryName::new("readme.md").unwrap();
        assert_eq!(
            lookup_entry_in_map(&map, &readme_q, CaseSensitivity::CaseSensitive),
            CaseLookup::NotFound
        );
        assert_eq!(
            lookup_entry_in_map(&map, &readme_q, CaseSensitivity::CaseInsensitiveUnambiguous)
                .into_result(&readme_q)
                .unwrap()
                .unwrap()
                .1,
            &1
        );

        // Exact match wins even when case-folded siblings exist.
        let exact_foo = EntryName::new("Foo").unwrap();
        assert_eq!(
            lookup_entry_in_map(
                &map,
                &exact_foo,
                CaseSensitivity::CaseInsensitiveUnambiguous
            )
            .into_result(&exact_foo)
            .unwrap()
            .unwrap()
            .1,
            &2
        );

        // Unmatched query hitting two case-folded siblings is rejected as ambiguous.
        let ambig_foo = EntryName::new("foo").unwrap();
        assert!(lookup_entry_in_map(
            &map,
            &ambig_foo,
            CaseSensitivity::CaseInsensitiveUnambiguous
        )
        .into_result(&ambig_foo)
        .is_err());
    }
}
