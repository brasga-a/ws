//! WinFsp host lifecycle and typed request/response dispatcher (`WinFspDispatcher`).

use std::sync::{Arc, RwLock};

use bit_core::vfs::VfsOperations;

use crate::attrs::{BasicInfoUpdate, FileAttributes, WinFspFileInfo};
use crate::config::{
    SecurityByNameResult, WinFspMountConfig, WinFspVolumeInfo, WinFspVolumeParams,
};
use crate::fs::{
    CleanupFlags, CreateParams, FileHandleId, OpenOptions, WinFspDirEntry, WinFspFileSystem,
};
use crate::reparse::ReparsePointData;
use crate::status::{NtStatus, STATUS_INVALID_DEVICE_REQUEST};

/// Lifecycle state of a [`WinFspDispatcher`] host session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MountState {
    /// Dispatcher has not yet started or has been stopped.
    Unmounted,
    /// Dispatcher is actively serving WinFsp requests at `mount_point`.
    Mounted,
}

/// Typed WinFsp callback request routed through [`WinFspDispatcher::dispatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinFspRequest {
    /// Queries volume capacity and label (`GetVolumeInfo`).
    GetVolumeInfo,
    /// Queries pre-open attributes, reparse tag, and owner security descriptor (`GetSecurityByName`).
    GetSecurityByName { path: String },
    /// Opens an existing entry (`Open`).
    Open { path: String, options: OpenOptions },
    /// Creates a new file, directory, or symlink (`Create` / `CreateEx`).
    Create { path: String, params: CreateParams },
    /// Reads up to `length` bytes starting at `offset` (`Read`).
    Read {
        handle: FileHandleId,
        offset: u64,
        length: usize,
    },
    /// Writes `data` at `offset` (`Write`).
    Write {
        handle: FileHandleId,
        offset: u64,
        data: Vec<u8>,
        write_to_end_of_file: bool,
        constrained_io: bool,
    },
    /// Truncates an open file to zero bytes and updates attributes (`Overwrite`).
    Overwrite {
        handle: FileHandleId,
        file_attributes: FileAttributes,
        replace_file_attributes: bool,
        allocation_size: u64,
    },
    /// Resizes an open file (`SetFileSize`).
    SetFileSize {
        handle: FileHandleId,
        new_size: u64,
        set_allocation_size: bool,
    },
    /// Toggles delete-on-close disposition (`CanDelete` / `SetDelete`).
    SetDeleteOnClose {
        handle: FileHandleId,
        delete_on_close: bool,
    },
    /// Executes pre-close cleanup including delete-on-close (`Cleanup`).
    Cleanup {
        handle: FileHandleId,
        flags: CleanupFlags,
    },
    /// Closes an open handle (`Close`).
    Close { handle: FileHandleId },
    /// Queries metadata on an open handle (`GetFileInfo`).
    GetFileInfo { handle: FileHandleId },
    /// Updates attributes and/or timestamps on an open handle (`SetBasicInfo`).
    SetBasicInfo {
        handle: FileHandleId,
        update: BasicInfoUpdate,
    },
    /// Enumerates directory entries (`ReadDirectory`).
    ReadDirectory {
        handle: FileHandleId,
        pattern: Option<String>,
        marker: Option<String>,
    },
    /// Renames an open handle to `new_path` (`Rename`).
    Rename {
        handle: FileHandleId,
        new_path: String,
        replace_if_exists: bool,
    },
    /// Reads symbolic link reparse data from an open handle (`GetReparsePoint`).
    GetReparsePoint { handle: FileHandleId },
    /// Reads symbolic link reparse data by path (`GetReparsePointByName`).
    GetReparsePointByName { path: String },
    /// Installs symbolic link reparse data onto an open handle (`SetReparsePoint`).
    SetReparsePoint {
        handle: FileHandleId,
        data: ReparsePointData,
    },
    /// Attempts to create a hard link (`STATUS_NOT_SUPPORTED`).
    CreateHardLink {
        existing_path: String,
        new_link_path: String,
    },
}

/// Typed WinFsp callback response returned by [`WinFspDispatcher::dispatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinFspResponse {
    /// Unit completion (`STATUS_SUCCESS`).
    Empty,
    /// `GetVolumeInfo` payload.
    VolumeInfo(WinFspVolumeInfo),
    /// `GetSecurityByName` payload.
    SecurityByName(SecurityByNameResult),
    /// `Open` or `Create` handle + metadata payload.
    Opened {
        handle: FileHandleId,
        file_info: WinFspFileInfo,
    },
    /// `Read` byte payload (`0..=length` bytes).
    ReadData(Vec<u8>),
    /// `Write` byte count + updated metadata.
    Written {
        bytes_written: u64,
        file_info: WinFspFileInfo,
    },
    /// `GetFileInfo`, `SetBasicInfo`, `SetFileSize`, `Overwrite`, or `SetReparsePoint` metadata.
    FileInfo(WinFspFileInfo),
    /// `ReadDirectory` entry list.
    DirectoryEntries(Vec<WinFspDirEntry>),
    /// `GetReparsePoint` or `GetReparsePointByName` payload.
    ReparsePoint(ReparsePointData),
}

/// Host session adapter managing mount lifecycle, owner-SID verification, and request dispatch
/// onto [`WinFspFileSystem`].
#[derive(Debug)]
pub struct WinFspDispatcher {
    fs: Arc<WinFspFileSystem>,
    state: RwLock<MountState>,
}

impl WinFspDispatcher {
    /// Creates an unmounted [`WinFspDispatcher`] wrapping a fresh [`WinFspFileSystem`].
    pub fn new(vfs: Arc<dyn VfsOperations>, config: WinFspMountConfig) -> Self {
        Self::from_filesystem(Arc::new(WinFspFileSystem::new(vfs, config)))
    }

    /// Creates an unmounted [`WinFspDispatcher`] over an existing `Arc<WinFspFileSystem>`.
    pub fn from_filesystem(fs: Arc<WinFspFileSystem>) -> Self {
        Self {
            fs,
            state: RwLock::new(MountState::Unmounted),
        }
    }

    /// Transitions the dispatcher into [`MountState::Mounted`] and returns negotiated
    /// [`WinFspVolumeParams`].
    pub fn start(&self) -> Result<WinFspVolumeParams, NtStatus> {
        let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
        *guard = MountState::Mounted;
        Ok(self.fs.volume_params())
    }

    /// Stops the mount session and releases any remaining open file handles.
    pub fn stop(&self) -> Result<(), NtStatus> {
        let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
        *guard = MountState::Unmounted;
        self.fs.clear_open_handles();
        Ok(())
    }

    /// Current [`MountState`].
    pub fn state(&self) -> MountState {
        *self.state.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Returns `true` when the dispatcher is currently [`MountState::Mounted`].
    pub fn is_mounted(&self) -> bool {
        self.state() == MountState::Mounted
    }

    /// Configured space-free mount point string.
    pub fn mount_point(&self) -> &str {
        self.fs.config().mount_point()
    }

    /// Negotiated `FSP_FSCTL_VOLUME_PARAMS` for this dispatcher.
    pub fn volume_params(&self) -> WinFspVolumeParams {
        self.fs.volume_params()
    }

    /// Borrows the underlying [`WinFspFileSystem`].
    pub const fn filesystem(&self) -> &Arc<WinFspFileSystem> {
        &self.fs
    }

    /// Dispatches a [`WinFspRequest`] as the configured owner user.
    pub fn dispatch(&self, request: WinFspRequest) -> Result<WinFspResponse, NtStatus> {
        self.dispatch_with_sid(None, request)
    }

    /// Dispatches a [`WinFspRequest`], verifying `caller_sid` against the mount's owner SID first.
    pub fn dispatch_with_sid(
        &self,
        caller_sid: Option<&str>,
        request: WinFspRequest,
    ) -> Result<WinFspResponse, NtStatus> {
        if !self.is_mounted() {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        self.fs.config().check_caller_sid(caller_sid)?;

        match request {
            WinFspRequest::GetVolumeInfo => {
                Ok(WinFspResponse::VolumeInfo(self.fs.get_volume_info()?))
            }
            WinFspRequest::GetSecurityByName { path } => Ok(WinFspResponse::SecurityByName(
                self.fs.get_security_by_name_as(caller_sid, &path)?,
            )),
            WinFspRequest::Open { path, mut options } => {
                if options.caller_sid.is_none() {
                    options.caller_sid = caller_sid.map(str::to_owned);
                }
                let (handle, file_info) = self.fs.open(&path, options)?;
                Ok(WinFspResponse::Opened { handle, file_info })
            }
            WinFspRequest::Create { path, mut params } => {
                if params.caller_sid.is_none() {
                    params.caller_sid = caller_sid.map(str::to_owned);
                }
                let (handle, file_info) = self.fs.create(&path, params)?;
                Ok(WinFspResponse::Opened { handle, file_info })
            }
            WinFspRequest::Read {
                handle,
                offset,
                length,
            } => {
                let mut buf = vec![0u8; length];
                let n = self.fs.read(handle, offset, &mut buf)?;
                buf.truncate(n);
                Ok(WinFspResponse::ReadData(buf))
            }
            WinFspRequest::Write {
                handle,
                offset,
                data,
                write_to_end_of_file,
                constrained_io,
            } => {
                let (bytes_written, file_info) = self.fs.write_ex(
                    handle,
                    offset,
                    &data,
                    write_to_end_of_file,
                    constrained_io,
                )?;
                Ok(WinFspResponse::Written {
                    bytes_written,
                    file_info,
                })
            }
            WinFspRequest::Overwrite {
                handle,
                file_attributes,
                replace_file_attributes,
                allocation_size,
            } => {
                let info = self.fs.overwrite(
                    handle,
                    file_attributes,
                    replace_file_attributes,
                    allocation_size,
                )?;
                Ok(WinFspResponse::FileInfo(info))
            }
            WinFspRequest::SetFileSize {
                handle,
                new_size,
                set_allocation_size,
            } => {
                let info = self
                    .fs
                    .set_file_size(handle, new_size, set_allocation_size)?;
                Ok(WinFspResponse::FileInfo(info))
            }
            WinFspRequest::SetDeleteOnClose {
                handle,
                delete_on_close,
            } => {
                self.fs.set_delete_on_close(handle, delete_on_close)?;
                Ok(WinFspResponse::Empty)
            }
            WinFspRequest::Cleanup { handle, flags } => {
                self.fs.cleanup(handle, flags)?;
                Ok(WinFspResponse::Empty)
            }
            WinFspRequest::Close { handle } => {
                self.fs.close(handle)?;
                Ok(WinFspResponse::Empty)
            }
            WinFspRequest::GetFileInfo { handle } => {
                Ok(WinFspResponse::FileInfo(self.fs.get_file_info(handle)?))
            }
            WinFspRequest::SetBasicInfo { handle, update } => Ok(WinFspResponse::FileInfo(
                self.fs.set_basic_info(handle, update)?,
            )),
            WinFspRequest::ReadDirectory {
                handle,
                pattern,
                marker,
            } => {
                let entries =
                    self.fs
                        .read_directory(handle, pattern.as_deref(), marker.as_deref())?;
                Ok(WinFspResponse::DirectoryEntries(entries))
            }
            WinFspRequest::Rename {
                handle,
                new_path,
                replace_if_exists,
            } => {
                self.fs.rename(handle, &new_path, replace_if_exists)?;
                Ok(WinFspResponse::Empty)
            }
            WinFspRequest::GetReparsePoint { handle } => Ok(WinFspResponse::ReparsePoint(
                self.fs.get_reparse_point(handle)?,
            )),
            WinFspRequest::GetReparsePointByName { path } => Ok(WinFspResponse::ReparsePoint(
                self.fs.get_reparse_point_by_name(&path)?,
            )),
            WinFspRequest::SetReparsePoint { handle, data } => {
                let info = self.fs.set_reparse_point(handle, data)?;
                Ok(WinFspResponse::FileInfo(info))
            }
            WinFspRequest::CreateHardLink {
                existing_path,
                new_link_path,
            } => {
                let info = self.fs.create_hard_link(&existing_path, &new_link_path)?;
                Ok(WinFspResponse::FileInfo(info))
            }
        }
    }
}
