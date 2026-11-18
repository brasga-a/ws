//! WinFsp mount configuration, owner-user SID access control, and `FSP_FSCTL_VOLUME_PARAMS`
//! modeling true read-path virtualization without NTFS hydration (ADR-0004).

use std::fmt;

use bit_core::ids::MAX_IDENTIFIER_LEN;
use bit_core::path::CaseSensitivity;

use crate::attrs::FileAttributes;
use crate::status::{NtStatus, STATUS_ACCESS_DENIED};

/// Maximum UTF-16 code units permitted for a WinFsp volume label (`FSP_FSCTL_VOLUME_LABEL_SIZE / 2`).
pub const MAX_VOLUME_LABEL_CHARS: usize = 32;

/// Default volume label reported by `get_volume_info`.
pub const DEFAULT_VOLUME_LABEL: &str = "BitViews";

/// Default filesystem type name reported in `WinFspVolumeParams`.
pub const DEFAULT_FS_NAME: &str = "BitWinFsp";

/// Default virtualized total volume capacity reported to Windows tools (`1 TiB`).
pub const DEFAULT_VIRTUAL_TOTAL_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

/// Default virtualized free volume capacity reported to Windows tools (`512 GiB`).
pub const DEFAULT_VIRTUAL_FREE_BYTES: u64 = 512 * 1024 * 1024 * 1024;

/// Validation error when constructing [`OwnerSid`] or [`WinFspMountConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinFspConfigError {
    /// Mount point string was empty.
    EmptyMountPoint,
    /// Mount point contained NUL (`'\0'`).
    MountPointContainsNul,
    /// Mount point contained spaces or whitespace characters (breaks Windows CLI / build tools).
    MountPointContainsWhitespace(String),
    /// Owner SID string failed `S-1-...` structural validation.
    InvalidOwnerSid(String),
    /// Volume label was empty or contained NUL.
    InvalidVolumeLabel(String),
    /// Volume label exceeded [`MAX_VOLUME_LABEL_CHARS`] UTF-16 code units.
    VolumeLabelTooLong(usize),
}

impl fmt::Display for WinFspConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMountPoint => f.write_str("WinFsp mount point must not be empty"),
            Self::MountPointContainsNul => {
                f.write_str("WinFsp mount point must not contain NUL bytes")
            }
            Self::MountPointContainsWhitespace(mp) => write!(
                f,
                "WinFsp mount point {mp:?} must be space-free so build tools remain safe"
            ),
            Self::InvalidOwnerSid(sid) => {
                write!(f, "invalid Windows security identifier (SID): {sid:?}")
            }
            Self::InvalidVolumeLabel(lbl) => write!(f, "invalid WinFsp volume label: {lbl:?}"),
            Self::VolumeLabelTooLong(len) => write!(
                f,
                "WinFsp volume label UTF-16 length {len} exceeds maximum {MAX_VOLUME_LABEL_CHARS}"
            ),
        }
    }
}

impl std::error::Error for WinFspConfigError {}

/// Validated Windows Security Identifier (`S-1-<authority>-<subauthority...>`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnerSid(String);

impl OwnerSid {
    /// Validates a canonical string SID (`S-1-...`).
    pub fn new(raw: impl Into<String>) -> Result<Self, WinFspConfigError> {
        let s = raw.into();
        validate_sid(&s)?;
        Ok(Self(s))
    }

    /// Borrows the validated SID string (`"S-1-..."`).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes `self` and returns the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

fn validate_sid(raw: &str) -> Result<(), WinFspConfigError> {
    let Some(rest) = raw.strip_prefix("S-1-") else {
        return Err(WinFspConfigError::InvalidOwnerSid(raw.to_owned()));
    };
    let mut parts = rest.split('-');
    let Some(authority) = parts.next() else {
        return Err(WinFspConfigError::InvalidOwnerSid(raw.to_owned()));
    };
    if authority.is_empty() || !authority.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WinFspConfigError::InvalidOwnerSid(raw.to_owned()));
    }
    let mut sub_count = 0usize;
    for sub in parts {
        if sub.is_empty() || sub.parse::<u32>().is_err() {
            return Err(WinFspConfigError::InvalidOwnerSid(raw.to_owned()));
        }
        sub_count += 1;
    }
    if sub_count == 0 {
        return Err(WinFspConfigError::InvalidOwnerSid(raw.to_owned()));
    }
    Ok(())
}

impl fmt::Display for OwnerSid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Synthesized Windows security descriptor restricting mount access exclusively to [`OwnerSid`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WinFspSecurityDescriptor {
    /// Owner SID governing the descriptor.
    pub owner_sid: OwnerSid,
    /// Protected DACL SDDL string (`O:{sid}G:{sid}D:P(A;;...;;;{sid})`).
    pub sddl: String,
    /// Whether write/delete access bits are omitted from the DACL (`<mount>\` root).
    pub read_only: bool,
}

impl WinFspSecurityDescriptor {
    /// Builds a protected SDDL security descriptor granting access only to `owner_sid`.
    pub fn for_owner(owner_sid: &OwnerSid, read_only: bool) -> Self {
        let rights = if read_only { "FRFX" } else { "FA" };
        let sid = owner_sid.as_str();
        let sddl = format!("O:{sid}G:{sid}D:P(A;;{rights};;;{sid})");
        Self {
            owner_sid: owner_sid.clone(),
            sddl,
            read_only,
        }
    }
}

/// Output of [`crate::WinFspFileSystem::get_security_by_name`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityByNameResult {
    /// Resolved Windows `FileAttributes`.
    pub file_attributes: FileAttributes,
    /// Present (`Some(IO_REPARSE_TAG_SYMLINK)`) when the path names a symbolic link.
    pub reparse_tag: Option<u32>,
    /// Owner-restricted security descriptor for the target node.
    pub security_descriptor: WinFspSecurityDescriptor,
}

/// WinFsp `FSP_FSCTL_VOLUME_PARAMS` negotiated when mounting the userspace filesystem.
///
/// Reflects ADR-0004:
/// - True read-path virtualization (`read_path_hydration == false`): reads stream directly from
///   content-addressed blobs without hydrating unchanged `Base` files onto NTFS.
/// - `case_preserved_names == true` (`CasePreservedNames = 1`).
/// - `case_sensitive_search` follows [`CaseSensitivity`] (`true` for `CaseSensitive`, `false` for
///   `CaseInsensitiveUnambiguous`).
/// - `reparse_points == true` for symbolic links; `hard_links == false` (`STATUS_NOT_SUPPORTED`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinFspVolumeParams {
    /// Logical sector size in bytes (`4096`).
    pub sector_size: u16,
    /// Sectors per allocation unit (`1`).
    pub sectors_per_allocation_unit: u16,
    /// Maximum path component length (`255`).
    pub max_component_length: u16,
    /// `CaseSensitiveSearch`: `true` for `CaseSensitive`, `false` for `CaseInsensitiveUnambiguous`.
    pub case_sensitive_search: bool,
    /// `CasePreservedNames`: always `true` so created filenames retain exact UTF-8 casing.
    pub case_preserved_names: bool,
    /// `UnicodeOnDisk`: always `true`.
    pub unicode_on_disk: bool,
    /// `PersistentAcls`: `false` (access restricted synthetically to `owner_sid`).
    pub persistent_acls: bool,
    /// `ReparsePoints`: `true` (`IO_REPARSE_TAG_SYMLINK` support).
    pub reparse_points: bool,
    /// `ReparsePointsAccessCheck`: `false`.
    pub reparse_points_access_check: bool,
    /// `NamedStreams`: `false` (ADS unsupported).
    pub named_streams: bool,
    /// `HardLinks`: `false` (hard links return `STATUS_NOT_SUPPORTED`).
    pub hard_links: bool,
    /// `ExtendedAttributes`: `false`.
    pub extended_attributes: bool,
    /// `ReadOnlyVolume`: `false` (`Views` under `<mount>\<view-id>\` are writable, while `<mount>\`
    /// itself enforces `STATUS_MEDIA_WRITE_PROTECTED`).
    pub read_only_volume: bool,
    /// `PassQueryDirectoryPattern`: `true`.
    pub pass_query_directory_pattern: bool,
    /// `FlushAndPurgeOnCleanup`: `true`.
    pub flush_and_purge_on_cleanup: bool,
    /// `UmFileContextIsUserContext2`: `true` (handle-scoped `FileHandleId` context).
    pub um_file_context_is_user_context2: bool,
    /// Explicit ADR-0004 invariant: `false` (zero physical NTFS hydration on file reads).
    pub read_path_hydration: bool,
    /// Filesystem name reported to Win32 `GetVolumeInformationW`.
    pub file_system_name: String,
    /// Optional UNC volume prefix (empty for local drive/directory mounts).
    pub volume_prefix: String,
}

/// WinFsp `FSP_FSCTL_VOLUME_INFO` payload returned by `get_volume_info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinFspVolumeInfo {
    /// Total virtualized capacity in bytes.
    pub total_size: u64,
    /// Available virtualized capacity in bytes.
    pub free_size: u64,
    /// Volume label (up to 32 UTF-16 code units).
    pub volume_label: String,
}

/// Configuration for mounting Bit's single-mount userspace VFS via WinFsp on Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinFspMountConfig {
    mount_point: String,
    owner_sid: OwnerSid,
    case_sensitivity: CaseSensitivity,
    volume_label: String,
    file_system_name: String,
    sector_size: u16,
    sectors_per_allocation_unit: u16,
    volume_total_bytes: u64,
    volume_free_bytes: u64,
}

impl WinFspMountConfig {
    /// Validates `mount_point` (non-empty, NUL-free, and space-free) and `owner_sid` (`S-1-...`),
    /// returning a configuration with `CasePreservedNames = true` and default
    /// [`CaseSensitivity::CaseInsensitiveUnambiguous`] policy for Windows tools.
    pub fn new(
        mount_point: impl Into<String>,
        owner_sid: impl Into<String>,
    ) -> Result<Self, WinFspConfigError> {
        let mp = mount_point.into();
        validate_mount_point(&mp)?;
        let sid = OwnerSid::new(owner_sid)?;
        Ok(Self {
            mount_point: mp,
            owner_sid: sid,
            case_sensitivity: CaseSensitivity::CaseInsensitiveUnambiguous,
            volume_label: DEFAULT_VOLUME_LABEL.to_owned(),
            file_system_name: DEFAULT_FS_NAME.to_owned(),
            sector_size: 4096,
            sectors_per_allocation_unit: 1,
            volume_total_bytes: DEFAULT_VIRTUAL_TOTAL_BYTES,
            volume_free_bytes: DEFAULT_VIRTUAL_FREE_BYTES,
        })
    }

    /// Sets the path case-matching policy (`CaseSensitive` vs `CaseInsensitiveUnambiguous`).
    pub fn with_case_sensitivity(mut self, policy: CaseSensitivity) -> Self {
        self.case_sensitivity = policy;
        self
    }

    /// Sets and validates a custom volume label (`<= 32` UTF-16 code units, non-empty, NUL-free).
    pub fn with_volume_label(
        mut self,
        label: impl Into<String>,
    ) -> Result<Self, WinFspConfigError> {
        let lbl = label.into();
        if lbl.is_empty() || lbl.contains('\0') {
            return Err(WinFspConfigError::InvalidVolumeLabel(lbl));
        }
        let utf16_len = lbl.encode_utf16().count();
        if utf16_len > MAX_VOLUME_LABEL_CHARS {
            return Err(WinFspConfigError::VolumeLabelTooLong(utf16_len));
        }
        self.volume_label = lbl;
        Ok(self)
    }

    /// Sets the virtualized `(total_bytes, free_bytes)` reported by `get_volume_info`.
    pub fn with_virtual_capacity(mut self, total_bytes: u64, free_bytes: u64) -> Self {
        self.volume_total_bytes = total_bytes;
        self.volume_free_bytes = free_bytes.min(total_bytes);
        self
    }

    /// Space-free WinFsp mount point (e.g. `"M:"` or `"C:\\bit\\views"`).
    pub fn mount_point(&self) -> &str {
        &self.mount_point
    }

    /// Owner user SID permitted to access the mount.
    pub const fn owner_sid(&self) -> &OwnerSid {
        &self.owner_sid
    }

    /// Configured [`CaseSensitivity`] policy.
    pub const fn case_sensitivity(&self) -> CaseSensitivity {
        self.case_sensitivity
    }

    /// Configured volume label.
    pub fn volume_label(&self) -> &str {
        &self.volume_label
    }

    /// Verifies that an incoming request caller SID (when supplied by the WinFsp host) matches
    /// [`Self::owner_sid`], returning [`STATUS_ACCESS_DENIED`] otherwise.
    pub fn check_caller_sid(&self, caller_sid: Option<&str>) -> Result<(), NtStatus> {
        match caller_sid {
            None => Ok(()),
            Some(sid) if sid == self.owner_sid.as_str() => Ok(()),
            Some(_) => Err(STATUS_ACCESS_DENIED),
        }
    }

    /// Generates an owner-restricted [`WinFspSecurityDescriptor`].
    pub fn security_descriptor(&self, read_only: bool) -> WinFspSecurityDescriptor {
        WinFspSecurityDescriptor::for_owner(&self.owner_sid, read_only)
    }

    /// Produces the negotiated [`WinFspVolumeParams`] for this mount configuration.
    pub fn volume_params(&self) -> WinFspVolumeParams {
        WinFspVolumeParams {
            sector_size: self.sector_size,
            sectors_per_allocation_unit: self.sectors_per_allocation_unit,
            max_component_length: MAX_IDENTIFIER_LEN as u16,
            case_sensitive_search: self.case_sensitivity == CaseSensitivity::CaseSensitive,
            case_preserved_names: true,
            unicode_on_disk: true,
            persistent_acls: false,
            reparse_points: true,
            reparse_points_access_check: false,
            named_streams: false,
            hard_links: false,
            extended_attributes: false,
            read_only_volume: false,
            pass_query_directory_pattern: true,
            flush_and_purge_on_cleanup: true,
            um_file_context_is_user_context2: true,
            read_path_hydration: false,
            file_system_name: self.file_system_name.clone(),
            volume_prefix: String::new(),
        }
    }

    /// Produces the [`WinFspVolumeInfo`] reported by `get_volume_info`.
    pub fn volume_info(&self) -> WinFspVolumeInfo {
        WinFspVolumeInfo {
            total_size: self.volume_total_bytes,
            free_size: self.volume_free_bytes,
            volume_label: self.volume_label.clone(),
        }
    }
}

fn validate_mount_point(raw: &str) -> Result<(), WinFspConfigError> {
    if raw.is_empty() {
        return Err(WinFspConfigError::EmptyMountPoint);
    }
    if raw.contains('\0') {
        return Err(WinFspConfigError::MountPointContainsNul);
    }
    if raw.chars().any(char::is_whitespace) {
        return Err(WinFspConfigError::MountPointContainsWhitespace(
            raw.to_owned(),
        ));
    }
    Ok(())
}
