//! Windows `NTSTATUS` codes and `VfsError` protocol translations for WinFsp.

use std::fmt;

use bit_core::vfs::VfsError;

/// 32-bit Windows `NTSTATUS` return code used across WinFsp callbacks.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NtStatus(pub u32);

/// Operation completed without error (`0x0000_0000`).
pub const STATUS_SUCCESS: NtStatus = NtStatus(0x0000_0000);
/// Asynchronous request is still in flight (`0x0000_0103`).
pub const STATUS_PENDING: NtStatus = NtStatus(0x0000_0103);
/// Buffer held partial output while additional data remains (`0x8000_0005`).
pub const STATUS_BUFFER_OVERFLOW: NtStatus = NtStatus(0x8000_0005);
/// Directory enumeration reached its end (`0x8000_0006`).
pub const STATUS_NO_MORE_FILES: NtStatus = NtStatus(0x8000_0006);
/// Supplied file handle is unknown or closed (`0xC000_0008`).
pub const STATUS_INVALID_HANDLE: NtStatus = NtStatus(0xC000_0008);
/// Malformed argument, offset, or buffer layout (`0xC000_000D`).
pub const STATUS_INVALID_PARAMETER: NtStatus = NtStatus(0xC000_000D);
/// Requested file does not exist (`0xC000_000F`).
pub const STATUS_NO_SUCH_FILE: NtStatus = NtStatus(0xC000_000F);
/// Request is invalid for the current mount state (`0xC000_0010`).
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = NtStatus(0xC000_0010);
/// Read offset reached or passed end-of-file (`0xC000_0011`).
pub const STATUS_END_OF_FILE: NtStatus = NtStatus(0xC000_0011);
/// Caller SID or file mode forbids the requested access (`0xC000_0022`).
pub const STATUS_ACCESS_DENIED: NtStatus = NtStatus(0xC000_0022);
/// Output buffer is too small to hold the requested payload (`0xC000_0023`).
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = NtStatus(0xC000_0023);
/// Path component syntax is invalid (`0xC000_0033`).
pub const STATUS_OBJECT_NAME_INVALID: NtStatus = NtStatus(0xC000_0033);
/// Entry or `View` was not found (`0xC000_0034`).
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = NtStatus(0xC000_0034);
/// Exclusive creation collided with an existing entry or ambiguous case match (`0xC000_0035`).
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = NtStatus(0xC000_0035);
/// Ancestor directory path does not exist (`0xC000_003A`).
pub const STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = NtStatus(0xC000_003A);
/// Handle target has already been queued for deletion (`0xC000_0056`).
pub const STATUS_DELETE_PENDING: NtStatus = NtStatus(0xC000_0056);
/// Write or structural mutation attempted on the read-only `<mount>\` root (`0xC000_00A2`).
pub const STATUS_MEDIA_WRITE_PROTECTED: NtStatus = NtStatus(0xC000_00A2);
/// Regular-file operation attempted on a directory (`0xC000_00BA`).
pub const STATUS_FILE_IS_A_DIRECTORY: NtStatus = NtStatus(0xC000_00BA);
/// Unsupported filesystem feature such as hard links (`0xC000_00BB`).
pub const STATUS_NOT_SUPPORTED: NtStatus = NtStatus(0xC000_00BB);
/// Rename attempted across two distinct `Views` (`0xC000_00D4`).
pub const STATUS_NOT_SAME_DEVICE: NtStatus = NtStatus(0xC000_00D4);
/// Attempted to remove or overwrite a non-empty directory (`0xC000_0101`).
pub const STATUS_DIRECTORY_NOT_EMPTY: NtStatus = NtStatus(0xC000_0101);
/// Directory operation attempted on a non-directory entry (`0xC000_0103`).
pub const STATUS_NOT_A_DIRECTORY: NtStatus = NtStatus(0xC000_0103);
/// Component or path exceeded maximum length (`0xC000_0106`).
pub const STATUS_NAME_TOO_LONG: NtStatus = NtStatus(0xC000_0106);
/// Deletion refused because entry carries `FILE_ATTRIBUTE_READONLY` (`0xC000_0121`).
pub const STATUS_CANNOT_DELETE: NtStatus = NtStatus(0xC000_0121);
/// Backing store or I/O failure (`0xC000_0185`).
pub const STATUS_IO_DEVICE_ERROR: NtStatus = NtStatus(0xC000_0185);
/// Reparse operation requested on a node that is not a symbolic link (`0xC000_0275`).
pub const STATUS_NOT_A_REPARSE_POINT: NtStatus = NtStatus(0xC000_0275);
/// Reparse data payload failed validation (`0xC000_0278`).
pub const STATUS_IO_REPARSE_DATA_INVALID: NtStatus = NtStatus(0xC000_0278);
/// Reparse tag other than `IO_REPARSE_TAG_SYMLINK` was supplied (`0xC000_0279`).
pub const STATUS_IO_REPARSE_TAG_NOT_HANDLED: NtStatus = NtStatus(0xC000_0279);

impl NtStatus {
    /// Associated constant matching [`STATUS_SUCCESS`].
    pub const SUCCESS: Self = STATUS_SUCCESS;
    /// Associated constant matching [`STATUS_INVALID_HANDLE`].
    pub const INVALID_HANDLE: Self = STATUS_INVALID_HANDLE;
    /// Associated constant matching [`STATUS_INVALID_PARAMETER`].
    pub const INVALID_PARAMETER: Self = STATUS_INVALID_PARAMETER;
    /// Associated constant matching [`STATUS_ACCESS_DENIED`].
    pub const ACCESS_DENIED: Self = STATUS_ACCESS_DENIED;
    /// Associated constant matching [`STATUS_OBJECT_NAME_NOT_FOUND`].
    pub const OBJECT_NAME_NOT_FOUND: Self = STATUS_OBJECT_NAME_NOT_FOUND;
    /// Associated constant matching [`STATUS_OBJECT_NAME_COLLISION`].
    pub const OBJECT_NAME_COLLISION: Self = STATUS_OBJECT_NAME_COLLISION;
    /// Associated constant matching [`STATUS_MEDIA_WRITE_PROTECTED`].
    pub const MEDIA_WRITE_PROTECTED: Self = STATUS_MEDIA_WRITE_PROTECTED;
    /// Associated constant matching [`STATUS_FILE_IS_A_DIRECTORY`].
    pub const FILE_IS_A_DIRECTORY: Self = STATUS_FILE_IS_A_DIRECTORY;
    /// Associated constant matching [`STATUS_NOT_SUPPORTED`].
    pub const NOT_SUPPORTED: Self = STATUS_NOT_SUPPORTED;
    /// Associated constant matching [`STATUS_NOT_SAME_DEVICE`].
    pub const NOT_SAME_DEVICE: Self = STATUS_NOT_SAME_DEVICE;
    /// Associated constant matching [`STATUS_DIRECTORY_NOT_EMPTY`].
    pub const DIRECTORY_NOT_EMPTY: Self = STATUS_DIRECTORY_NOT_EMPTY;
    /// Associated constant matching [`STATUS_NOT_A_DIRECTORY`].
    pub const NOT_A_DIRECTORY: Self = STATUS_NOT_A_DIRECTORY;
    /// Associated constant matching [`STATUS_NAME_TOO_LONG`].
    pub const NAME_TOO_LONG: Self = STATUS_NAME_TOO_LONG;
    /// Associated constant matching [`STATUS_CANNOT_DELETE`].
    pub const CANNOT_DELETE: Self = STATUS_CANNOT_DELETE;
    /// Associated constant matching [`STATUS_IO_DEVICE_ERROR`].
    pub const IO_DEVICE_ERROR: Self = STATUS_IO_DEVICE_ERROR;

    /// Returns the raw 32-bit `NTSTATUS` code.
    pub const fn code(self) -> u32 {
        self.0
    }

    /// Returns `true` when the `NTSTATUS` severity bit indicates non-error (`NT_SUCCESS`).
    pub const fn is_success(self) -> bool {
        (self.0 & 0x8000_0000) == 0
    }

    /// Returns `true` when the `NTSTATUS` severity bits equal `0b11` (`NT_ERROR`).
    pub const fn is_error(self) -> bool {
        (self.0 & 0xC000_0000) == 0xC000_0000
    }

    /// Maps a portable [`VfsError`] to its canonical Windows `NTSTATUS` code.
    pub const fn from_vfs_error(err: &VfsError) -> Self {
        match err {
            VfsError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
            VfsError::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
            VfsError::NotADirectory => STATUS_NOT_A_DIRECTORY,
            VfsError::IsADirectory => STATUS_FILE_IS_A_DIRECTORY,
            VfsError::DirectoryNotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
            VfsError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
            VfsError::CrossDevice => STATUS_NOT_SAME_DEVICE,
            VfsError::NotSupported => STATUS_NOT_SUPPORTED,
            VfsError::PermissionDenied => STATUS_ACCESS_DENIED,
            VfsError::NameTooLong => STATUS_NAME_TOO_LONG,
            VfsError::InvalidInput(_) => STATUS_INVALID_PARAMETER,
            VfsError::AmbiguousCase(_) => STATUS_OBJECT_NAME_COLLISION,
            VfsError::Io(_) => STATUS_IO_DEVICE_ERROR,
        }
    }

    /// Symbolic name for known `NTSTATUS` codes used by `bit-vfs-winfsp`.
    pub const fn name(self) -> &'static str {
        match self {
            STATUS_SUCCESS => "STATUS_SUCCESS",
            STATUS_PENDING => "STATUS_PENDING",
            STATUS_BUFFER_OVERFLOW => "STATUS_BUFFER_OVERFLOW",
            STATUS_NO_MORE_FILES => "STATUS_NO_MORE_FILES",
            STATUS_INVALID_HANDLE => "STATUS_INVALID_HANDLE",
            STATUS_INVALID_PARAMETER => "STATUS_INVALID_PARAMETER",
            STATUS_NO_SUCH_FILE => "STATUS_NO_SUCH_FILE",
            STATUS_INVALID_DEVICE_REQUEST => "STATUS_INVALID_DEVICE_REQUEST",
            STATUS_END_OF_FILE => "STATUS_END_OF_FILE",
            STATUS_ACCESS_DENIED => "STATUS_ACCESS_DENIED",
            STATUS_BUFFER_TOO_SMALL => "STATUS_BUFFER_TOO_SMALL",
            STATUS_OBJECT_NAME_INVALID => "STATUS_OBJECT_NAME_INVALID",
            STATUS_OBJECT_NAME_NOT_FOUND => "STATUS_OBJECT_NAME_NOT_FOUND",
            STATUS_OBJECT_NAME_COLLISION => "STATUS_OBJECT_NAME_COLLISION",
            STATUS_OBJECT_PATH_NOT_FOUND => "STATUS_OBJECT_PATH_NOT_FOUND",
            STATUS_DELETE_PENDING => "STATUS_DELETE_PENDING",
            STATUS_MEDIA_WRITE_PROTECTED => "STATUS_MEDIA_WRITE_PROTECTED",
            STATUS_FILE_IS_A_DIRECTORY => "STATUS_FILE_IS_A_DIRECTORY",
            STATUS_NOT_SUPPORTED => "STATUS_NOT_SUPPORTED",
            STATUS_NOT_SAME_DEVICE => "STATUS_NOT_SAME_DEVICE",
            STATUS_DIRECTORY_NOT_EMPTY => "STATUS_DIRECTORY_NOT_EMPTY",
            STATUS_NOT_A_DIRECTORY => "STATUS_NOT_A_DIRECTORY",
            STATUS_NAME_TOO_LONG => "STATUS_NAME_TOO_LONG",
            STATUS_CANNOT_DELETE => "STATUS_CANNOT_DELETE",
            STATUS_IO_DEVICE_ERROR => "STATUS_IO_DEVICE_ERROR",
            STATUS_NOT_A_REPARSE_POINT => "STATUS_NOT_A_REPARSE_POINT",
            STATUS_IO_REPARSE_DATA_INVALID => "STATUS_IO_REPARSE_DATA_INVALID",
            STATUS_IO_REPARSE_TAG_NOT_HANDLED => "STATUS_IO_REPARSE_TAG_NOT_HANDLED",
            _ => "STATUS_UNKNOWN",
        }
    }
}

/// Converts a [`VfsError`] reference into its WinFsp [`NtStatus`].
pub const fn vfs_error_to_ntstatus(err: &VfsError) -> NtStatus {
    NtStatus::from_vfs_error(err)
}

impl From<&VfsError> for NtStatus {
    fn from(err: &VfsError) -> Self {
        Self::from_vfs_error(err)
    }
}

impl From<VfsError> for NtStatus {
    fn from(err: VfsError) -> Self {
        Self::from_vfs_error(&err)
    }
}

impl fmt::Display for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:08X})", self.name(), self.0)
    }
}

impl std::error::Error for NtStatus {}
