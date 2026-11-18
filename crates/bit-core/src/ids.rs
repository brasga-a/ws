//! Validated domain identifiers (`TagName`, `ViewId`, and `BaseSelector`).

use std::fmt;
use std::str::FromStr;

use crate::hash::{BaseId, HexDigestError};

/// Maximum length in bytes for single-component portable identifiers (`ViewId`, `TagName`).
pub const MAX_IDENTIFIER_LEN: usize = 255;

/// Validation error for `ViewId`, `TagName`, and `BaseSelector`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// Identifier was empty.
    Empty,
    /// Identifier exceeded `MAX_IDENTIFIER_LEN` bytes.
    TooLong(usize),
    /// Identifier was `"."` or `".."`.
    DotSegment,
    /// Identifier ended with an ASCII dot (`'.'`) or space (`' '`).
    TrailingDotOrSpace,
    /// Identifier contained a character outside `[a-zA-Z0-9._-]`.
    InvalidCharacter { ch: char, index: usize },
    /// Identifier collided (case-insensitively) with a Windows reserved device name.
    WindowsReservedName(String),
    /// `TagName` started with `'-'` or collided with a 64-character hexadecimal `BaseId`.
    ReservedTagFormat(String),
    /// Hex digest parsing error when explicitly parsing a `BaseId`.
    InvalidHex(HexDigestError),
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("identifier must not be empty"),
            Self::TooLong(len) => write!(
                f,
                "identifier length {len} exceeds maximum {MAX_IDENTIFIER_LEN} bytes"
            ),
            Self::DotSegment => f.write_str("identifier must not be '.' or '..'"),
            Self::TrailingDotOrSpace => {
                f.write_str("identifier must not end with a trailing dot or space")
            }
            Self::InvalidCharacter { ch, index } => write!(
                f,
                "identifier contains invalid character {:?} at byte index {index}; allowed: [a-zA-Z0-9._-]",
                ch
            ),
            Self::WindowsReservedName(name) => write!(
                f,
                "identifier {name:?} is a reserved Windows device name"
            ),
            Self::ReservedTagFormat(reason) => write!(f, "invalid tag name: {reason}"),
            Self::InvalidHex(err) => Display::fmt(err, f),
        }
    }
}

use std::fmt::Display;

impl std::error::Error for IdError {}

impl From<HexDigestError> for IdError {
    fn from(err: HexDigestError) -> Self {
        Self::InvalidHex(err)
    }
}

/// Checks whether `name` (or its stem prior to the first `'.'`) matches a Windows reserved
/// device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`) case-insensitively.
pub fn is_windows_reserved_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    let upper = stem.to_ascii_uppercase();
    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        _ if upper.len() == 4 => {
            let bytes = upper.as_bytes();
            let prefix = &bytes[..3];
            let digit = bytes[3];
            (prefix == b"COM" || prefix == b"LPT") && (b'1'..=b'9').contains(&digit)
        }
        _ => false,
    }
}

fn validate_portable_single_component(raw: &str) -> Result<(), IdError> {
    if raw.is_empty() {
        return Err(IdError::Empty);
    }
    if raw.len() > MAX_IDENTIFIER_LEN {
        return Err(IdError::TooLong(raw.len()));
    }
    if raw == "." || raw == ".." {
        return Err(IdError::DotSegment);
    }
    if raw.ends_with('.') || raw.ends_with(' ') {
        return Err(IdError::TrailingDotOrSpace);
    }
    for (idx, ch) in raw.char_indices() {
        if !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-') {
            return Err(IdError::InvalidCharacter { ch, index: idx });
        }
    }
    if is_windows_reserved_name(raw) {
        return Err(IdError::WindowsReservedName(raw.to_owned()));
    }
    Ok(())
}

/// Validated single-component portable identifier for a `View` (`<mount>/<view-id>/`).
///
/// Allowed characters: `[a-zA-Z0-9._-]`. Rejects empty strings, `.`, `..`, trailing dots or
/// spaces, names longer than 255 bytes, and case-insensitive Windows reserved device names
/// (`CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`, including extensions like `CON.1`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ViewId(String);

impl ViewId {
    /// Validates and constructs a `ViewId`.
    pub fn new(raw: impl Into<String>) -> Result<Self, IdError> {
        let s = raw.into();
        validate_portable_single_component(&s)?;
        Ok(Self(s))
    }

    /// Borrows the validated `ViewId` string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the `ViewId` and returns the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for ViewId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ViewId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ViewId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<&str> for ViewId {
    type Error = IdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for ViewId {
    type Error = IdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Validated mutable human-readable `Tag` name pointing to a `Base`.
///
/// Uses the same portable `[a-zA-Z0-9._-]` rules as `ViewId`, additionally rejecting leading `'-'`
/// (to avoid CLI flag ambiguity) and 64-character hexadecimal strings (to stay unambiguous with
/// `BaseId` in `BaseSelector`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TagName(String);

impl TagName {
    /// Validates and constructs a `TagName`.
    pub fn new(raw: impl Into<String>) -> Result<Self, IdError> {
        let s = raw.into();
        validate_portable_single_component(&s)?;
        if s.starts_with('-') {
            return Err(IdError::ReservedTagFormat(
                "tag name must not begin with '-'".to_owned(),
            ));
        }
        if s.len() == BaseId::HEX_LEN && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(IdError::ReservedTagFormat(
                "tag name must not be a 64-character hex BaseId".to_owned(),
            ));
        }
        Ok(Self(s))
    }

    /// Borrows the validated `Tag` name string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the `TagName` and returns the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for TagName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TagName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for TagName {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<&str> for TagName {
    type Error = IdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for TagName {
    type Error = IdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Unambiguous selector identifying a `Base` either by its 64-hex `BaseId` or by a `TagName`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BaseSelector {
    /// Direct immutable `BaseId`.
    Id(BaseId),
    /// Human-readable mutable `TagName`.
    Tag(TagName),
}

impl BaseSelector {
    /// Parses a string into `BaseSelector::Id` if it is a 64-char hex digest, otherwise `BaseSelector::Tag`.
    pub fn parse(raw: &str) -> Result<Self, IdError> {
        if raw.len() == BaseId::HEX_LEN && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(Self::Id(BaseId::from_hex(raw)?))
        } else {
            Ok(Self::Tag(TagName::new(raw)?))
        }
    }
}

impl fmt::Display for BaseSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => Display::fmt(id, f),
            Self::Tag(tag) => Display::fmt(tag, f),
        }
    }
}

impl FromStr for BaseSelector {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<BaseId> for BaseSelector {
    fn from(id: BaseId) -> Self {
        Self::Id(id)
    }
}

impl From<&BaseId> for BaseSelector {
    fn from(id: &BaseId) -> Self {
        Self::Id(*id)
    }
}

impl From<TagName> for BaseSelector {
    fn from(tag: TagName) -> Self {
        Self::Tag(tag)
    }
}

impl From<&TagName> for BaseSelector {
    fn from(tag: &TagName) -> Self {
        Self::Tag(tag.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_id_validation_rules() {
        for valid in [
            "agent-1", "view_01", "v1.2.3", ".hidden", "com10", "lpt0", "console",
        ] {
            assert!(ViewId::new(valid).is_ok(), "expected {valid:?} to be valid");
        }

        for invalid in [
            "",
            ".",
            "..",
            "trailing.",
            "trailing ",
            "has space",
            "a/b",
            "a\\b",
            "CON",
            "con",
            "Prn",
            "AUX",
            "nul",
            "con.txt",
            "COM1",
            "com9",
            "LPT1",
            "lpt9.log",
        ] {
            assert!(
                ViewId::new(invalid).is_err(),
                "expected {invalid:?} to be rejected"
            );
        }
    }

    #[test]
    fn tag_name_and_base_selector_disambiguation() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(TagName::new(hex).is_err());
        assert!(TagName::new("-bad").is_err());
        assert!(TagName::new("release-2026.11").is_ok());

        assert!(matches!(
            BaseSelector::parse(hex).unwrap(),
            BaseSelector::Id(_)
        ));
        assert!(matches!(
            BaseSelector::parse("release-2026.11").unwrap(),
            BaseSelector::Tag(_)
        ));
    }
}
