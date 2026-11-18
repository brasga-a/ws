//! Bidirectional mapping between POSIX modes / [`NodeKind`] / [`Timestamp`] and Windows
//! [`FileAttributes`], `FILETIME`, and `FSP_FSCTL_FILE_INFO` structures.

use std::fmt;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};

use bit_core::model::{
    NodeKind, Timestamp, DEFAULT_DIR_MODE, DEFAULT_FILE_MODE, DEFAULT_SYMLINK_MODE, PERM_MASK,
};
use bit_core::vfs::VfsAttr;

use crate::reparse::IO_REPARSE_TAG_SYMLINK;

/// 100-nanosecond ticks per second in Windows `FILETIME`.
pub const WINDOWS_TICKS_PER_SEC: u64 = 10_000_000;

/// Seconds between Windows epoch (`1601-01-01T00:00:00Z`) and UNIX epoch (`1970-01-01T00:00:00Z`).
pub const WINDOWS_TO_UNIX_EPOCH_SECS: i64 = 11_644_473_600;

/// Allocation unit rounding size reported in [`WinFspFileInfo`] (`4 KiB`).
pub const ALLOCATION_UNIT_BYTES: u64 = 4096;

/// Windows `FILE_ATTRIBUTE_*` bitmask (`winnt.h`).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FileAttributes(pub u32);

/// File or directory is read-only (`0x0000_0001`).
pub const FILE_ATTRIBUTE_READONLY: FileAttributes = FileAttributes(0x0000_0001);
/// File or directory is hidden (`0x0000_0002`).
pub const FILE_ATTRIBUTE_HIDDEN: FileAttributes = FileAttributes(0x0000_0002);
/// Operating system file (`0x0000_0004`).
pub const FILE_ATTRIBUTE_SYSTEM: FileAttributes = FileAttributes(0x0000_0004);
/// Node is a directory (`0x0000_0010`).
pub const FILE_ATTRIBUTE_DIRECTORY: FileAttributes = FileAttributes(0x0000_0010);
/// Archive attribute bit (`0x0000_0020`).
pub const FILE_ATTRIBUTE_ARCHIVE: FileAttributes = FileAttributes(0x0000_0020);
/// Regular writable file with no other attributes set (`0x0000_0080`, valid only alone).
pub const FILE_ATTRIBUTE_NORMAL: FileAttributes = FileAttributes(0x0000_0080);
/// Node has an associated reparse point such as a symbolic link (`0x0000_0400`).
pub const FILE_ATTRIBUTE_REPARSE_POINT: FileAttributes = FileAttributes(0x0000_0400);
/// Sentinel `INVALID_FILE_ATTRIBUTES` (`0xFFFF_FFFF`).
pub const INVALID_FILE_ATTRIBUTES: FileAttributes = FileAttributes(u32::MAX);

impl FileAttributes {
    /// Empty attribute mask (`0`, meaning "leave unchanged" in `SetBasicInfo`).
    pub const NONE: Self = Self(0);
    /// Associated constant matching [`FILE_ATTRIBUTE_READONLY`].
    pub const READONLY: Self = FILE_ATTRIBUTE_READONLY;
    /// Associated constant matching [`FILE_ATTRIBUTE_DIRECTORY`].
    pub const DIRECTORY: Self = FILE_ATTRIBUTE_DIRECTORY;
    /// Associated constant matching [`FILE_ATTRIBUTE_ARCHIVE`].
    pub const ARCHIVE: Self = FILE_ATTRIBUTE_ARCHIVE;
    /// Associated constant matching [`FILE_ATTRIBUTE_NORMAL`].
    pub const NORMAL: Self = FILE_ATTRIBUTE_NORMAL;
    /// Associated constant matching [`FILE_ATTRIBUTE_REPARSE_POINT`].
    pub const REPARSE_POINT: Self = FILE_ATTRIBUTE_REPARSE_POINT;

    /// Constructs `FileAttributes` from raw Win32 bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the raw Win32 attribute bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` when no bits are set (`0`).
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` when every bit in `other` is present in `self`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Infers the [`NodeKind`] implied by Windows attribute bits.
    pub const fn inferred_node_kind(self) -> NodeKind {
        if self.contains(FILE_ATTRIBUTE_REPARSE_POINT) {
            NodeKind::Symlink
        } else if self.contains(FILE_ATTRIBUTE_DIRECTORY) {
            NodeKind::Directory
        } else {
            NodeKind::File
        }
    }
}

impl BitOr for FileAttributes {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for FileAttributes {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for FileAttributes {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for FileAttributes {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl Not for FileAttributes {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

impl From<u32> for FileAttributes {
    fn from(bits: u32) -> Self {
        Self(bits)
    }
}

impl From<FileAttributes> for u32 {
    fn from(attrs: FileAttributes) -> Self {
        attrs.0
    }
}

impl PartialEq<u32> for FileAttributes {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl fmt::Display for FileAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.0)
    }
}

/// Maps POSIX `(kind, mode, read_only)` to Windows [`FileAttributes`].
///
/// - Directories receive `FILE_ATTRIBUTE_DIRECTORY` (plus `FILE_ATTRIBUTE_READONLY` if write bits
///   `0o222` are absent or `read_only` is `true`).
/// - Symbolic links receive `FILE_ATTRIBUTE_REPARSE_POINT` (plus `FILE_ATTRIBUTE_READONLY` only
///   when `read_only` is `true`).
/// - Regular files receive `FILE_ATTRIBUTE_READONLY` when `(mode & 0o222) == 0 || read_only`,
///   and `FILE_ATTRIBUTE_NORMAL` (alone, per Win32 rules) otherwise.
pub const fn posix_to_file_attributes(
    kind: NodeKind,
    mode: u32,
    read_only: bool,
) -> FileAttributes {
    let clean_mode = mode & PERM_MASK;
    let lacks_write_bits = (clean_mode & 0o222) == 0;
    match kind {
        NodeKind::Directory => {
            if read_only || lacks_write_bits {
                FileAttributes(FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_READONLY.0)
            } else {
                FILE_ATTRIBUTE_DIRECTORY
            }
        }
        NodeKind::Symlink => {
            if read_only {
                FileAttributes(FILE_ATTRIBUTE_REPARSE_POINT.0 | FILE_ATTRIBUTE_READONLY.0)
            } else {
                FILE_ATTRIBUTE_REPARSE_POINT
            }
        }
        NodeKind::File => {
            if read_only || lacks_write_bits {
                FILE_ATTRIBUTE_READONLY
            } else {
                FILE_ATTRIBUTE_NORMAL
            }
        }
    }
}

/// Maps a [`VfsAttr`] directly to Windows [`FileAttributes`].
pub const fn vfs_attr_to_file_attributes(attr: &VfsAttr) -> FileAttributes {
    posix_to_file_attributes(attr.kind, attr.mode, attr.read_only)
}

/// Maps Windows [`FileAttributes`] and [`NodeKind`] to initial POSIX permission bits for a new node.
pub const fn file_attributes_to_posix_mode(attrs: FileAttributes, kind: NodeKind) -> u32 {
    match kind {
        NodeKind::Symlink => DEFAULT_SYMLINK_MODE,
        NodeKind::Directory => {
            if attrs.contains(FILE_ATTRIBUTE_READONLY) {
                0o555
            } else {
                DEFAULT_DIR_MODE
            }
        }
        NodeKind::File => {
            if attrs.contains(FILE_ATTRIBUTE_READONLY) {
                0o444
            } else {
                DEFAULT_FILE_MODE
            }
        }
    }
}

/// Applies a Windows [`FileAttributes`] update onto an existing POSIX `current_mode` without
/// clobbering executable permission bits (`0o111`).
///
/// Returns `None` when `attrs` is `0` (`NONE`) or `INVALID_FILE_ATTRIBUTES` ("preserve existing").
pub const fn apply_file_attributes_to_mode(
    attrs: FileAttributes,
    kind: NodeKind,
    current_mode: u32,
) -> Option<u32> {
    if attrs.is_empty() || attrs.0 == INVALID_FILE_ATTRIBUTES.0 {
        return None;
    }
    if matches!(kind, NodeKind::Symlink) {
        return Some(DEFAULT_SYMLINK_MODE);
    }

    let base = current_mode & PERM_MASK;
    let readable = if (base & 0o444) == 0 {
        base | 0o444
    } else {
        base
    };

    if attrs.contains(FILE_ATTRIBUTE_READONLY) {
        Some(readable & !0o222)
    } else {
        Some(readable | 0o200)
    }
}

/// Converts a [`Timestamp`] (`mtime`) into a 64-bit Windows `FILETIME` (100ns ticks since 1601).
///
/// Timestamps prior to `1601-01-01T00:00:00Z` clamp to `0`.
pub const fn timestamp_to_filetime(ts: Timestamp) -> u64 {
    let win_secs = ts.secs.saturating_add(WINDOWS_TO_UNIX_EPOCH_SECS);
    if win_secs < 0 {
        return 0;
    }
    let sec_ticks = (win_secs as u64).saturating_mul(WINDOWS_TICKS_PER_SEC);
    let nano_ticks = (ts.nanos / 100) as u64;
    sec_ticks.saturating_add(nano_ticks)
}

/// Converts a 64-bit Windows `FILETIME` into a [`Timestamp`].
pub const fn filetime_to_timestamp(filetime: u64) -> Timestamp {
    let win_secs = (filetime / WINDOWS_TICKS_PER_SEC) as i64;
    let rem_ticks = (filetime % WINDOWS_TICKS_PER_SEC) as u32;
    Timestamp {
        secs: win_secs - WINDOWS_TO_UNIX_EPOCH_SECS,
        nanos: rem_ticks * 100,
    }
}

/// WinFsp `FSP_FSCTL_FILE_INFO` metadata structure returned by open, create, stat, write, and
/// directory enumeration callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WinFspFileInfo {
    /// Windows `FILE_ATTRIBUTE_*` flags.
    pub file_attributes: FileAttributes,
    /// Reparse tag (`IO_REPARSE_TAG_SYMLINK` for symbolic links, `0` otherwise).
    pub reparse_tag: u32,
    /// Rounded allocation size in bytes.
    pub allocation_size: u64,
    /// Logical byte size (`0` for directories).
    pub file_size: u64,
    /// Creation `FILETIME`.
    pub creation_time: u64,
    /// Last-access `FILETIME`.
    pub last_access_time: u64,
    /// Last-write `FILETIME`.
    pub last_write_time: u64,
    /// Metadata change `FILETIME`.
    pub change_time: u64,
    /// Stable 64-bit file index (`VfsAttr::ino`).
    pub index_number: u64,
    /// Always `0` in WinFsp `FSP_FSCTL_FILE_INFO` (hard links are unsupported).
    pub hard_links: u32,
    /// Extended attribute byte size (`0`).
    pub ea_size: u32,
}

impl WinFspFileInfo {
    /// Projects a [`VfsAttr`] into a [`WinFspFileInfo`].
    pub const fn from_vfs_attr(attr: &VfsAttr) -> Self {
        let file_attributes = vfs_attr_to_file_attributes(attr);
        let reparse_tag = match attr.kind {
            NodeKind::Symlink => IO_REPARSE_TAG_SYMLINK,
            NodeKind::File | NodeKind::Directory => 0,
        };
        let file_size = match attr.kind {
            NodeKind::Directory => 0,
            NodeKind::File | NodeKind::Symlink => attr.size,
        };
        let allocation_size = if file_size == 0 {
            0
        } else {
            let rem = file_size % ALLOCATION_UNIT_BYTES;
            if rem == 0 {
                file_size
            } else {
                file_size.saturating_add(ALLOCATION_UNIT_BYTES - rem)
            }
        };
        let ft = timestamp_to_filetime(attr.mtime);
        Self {
            file_attributes,
            reparse_tag,
            allocation_size,
            file_size,
            creation_time: ft,
            last_access_time: ft,
            last_write_time: ft,
            change_time: ft,
            index_number: attr.ino,
            hard_links: 0,
            ea_size: 0,
        }
    }
}

/// Attribute and timestamp update payload passed to [`crate::WinFspFileSystem::set_basic_info`].
///
/// Following Win32 / WinFsp conventions:
/// - `file_attributes == FileAttributes::NONE` (`0`) or `INVALID_FILE_ATTRIBUTES` preserves mode.
/// - Any timestamp equal to `0` or `u64::MAX` preserves the existing timestamp.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BasicInfoUpdate {
    /// New Windows file attributes (`0` or `u32::MAX` to leave unchanged).
    pub file_attributes: FileAttributes,
    /// Creation `FILETIME` (`0` or `u64::MAX` to leave unchanged).
    pub creation_time: u64,
    /// Last-access `FILETIME` (`0` or `u64::MAX` to leave unchanged).
    pub last_access_time: u64,
    /// Last-write `FILETIME` (`0` or `u64::MAX` to leave unchanged).
    pub last_write_time: u64,
    /// Change `FILETIME` (`0` or `u64::MAX` to leave unchanged).
    pub change_time: u64,
}

impl BasicInfoUpdate {
    /// Convenience constructor updating only `file_attributes`.
    pub const fn attributes_only(file_attributes: FileAttributes) -> Self {
        Self {
            file_attributes,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
        }
    }

    /// Convenience constructor updating only `last_write_time` (`mtime`).
    pub const fn last_write_only(last_write_time: u64) -> Self {
        Self {
            file_attributes: FileAttributes::NONE,
            creation_time: 0,
            last_access_time: 0,
            last_write_time,
            change_time: 0,
        }
    }

    /// Extracts the effective [`Timestamp`] update when `last_write_time` or `change_time` is set.
    pub const fn effective_mtime(&self) -> Option<Timestamp> {
        if self.last_write_time != 0 && self.last_write_time != u64::MAX {
            Some(filetime_to_timestamp(self.last_write_time))
        } else if self.change_time != 0 && self.change_time != u64::MAX {
            Some(filetime_to_timestamp(self.change_time))
        } else {
            None
        }
    }
}
