//! Windows `REPARSE_DATA_BUFFER` symbolic link handling (`IO_REPARSE_TAG_SYMLINK`) for WinFsp.

use bit_core::model::validate_symlink_target;

use crate::status::{
    NtStatus, STATUS_BUFFER_TOO_SMALL, STATUS_IO_REPARSE_DATA_INVALID,
    STATUS_IO_REPARSE_TAG_NOT_HANDLED,
};

/// Win32 reparse tag for symbolic links (`0xA000_000C`).
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

/// Win32 reparse tag for NTFS mount points / junctions (`0xA000_0003`, unsupported for creation).
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

/// Flag in `SymbolicLinkReparseBuffer.Flags` indicating a relative target (`0x0000_0001`).
pub const SYMLINK_FLAG_RELATIVE: u32 = 0x0000_0001;

/// Byte length of the fixed `REPARSE_DATA_BUFFER` outer header (`ReparseTag + ReparseDataLength + Reserved`).
pub const REPARSE_DATA_HEADER_LEN: usize = 8;

/// Byte length of the inner `SymbolicLinkReparseBuffer` header (`4 * u16 + u32`).
pub const SYMLINK_REPARSE_HEADER_LEN: usize = 12;

/// Parsed symbolic link reparse point payload exchanged via `get_reparse_point` and `set_reparse_point`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReparsePointData {
    /// Reparse tag (`IO_REPARSE_TAG_SYMLINK`).
    pub reparse_tag: u32,
    /// Verbatim UTF-8 target string persisted in [`bit_core::vfs::VfsOperations`].
    pub target: String,
    /// Windows NT `SubstituteName` (prefixed with `\??\` for drive-letter absolute paths).
    pub substitute_name: String,
    /// Windows user-visible `PrintName`.
    pub print_name: String,
    /// `SYMLINK_FLAG_RELATIVE` (`1`) for relative targets, `0` for absolute targets.
    pub flags: u32,
}

impl ReparsePointData {
    /// Constructs a validated `IO_REPARSE_TAG_SYMLINK` payload from a verbatim UTF-8 `target`.
    pub fn symlink(target: impl Into<String>) -> Result<Self, NtStatus> {
        let target = target.into();
        validate_symlink_target(&target).map_err(|_| STATUS_IO_REPARSE_DATA_INVALID)?;

        let is_relative = is_relative_symlink_target(&target);
        let flags = if is_relative {
            SYMLINK_FLAG_RELATIVE
        } else {
            0
        };
        let print_name = target.clone();
        let substitute_name = if is_drive_absolute(&target) {
            format!(r"\??\{}", target.replace('/', r"\"))
        } else {
            target.clone()
        };

        Ok(Self {
            reparse_tag: IO_REPARSE_TAG_SYMLINK,
            target,
            substitute_name,
            print_name,
            flags,
        })
    }

    /// Returns `true` when [`SYMLINK_FLAG_RELATIVE`] is set.
    pub const fn is_relative(&self) -> bool {
        (self.flags & SYMLINK_FLAG_RELATIVE) != 0
    }

    /// Serializes this payload into a standard little-endian Windows `REPARSE_DATA_BUFFER`.
    pub fn encode_reparse_buffer(&self) -> Result<Vec<u8>, NtStatus> {
        if self.reparse_tag != IO_REPARSE_TAG_SYMLINK {
            return Err(STATUS_IO_REPARSE_TAG_NOT_HANDLED);
        }
        validate_symlink_target(&self.target).map_err(|_| STATUS_IO_REPARSE_DATA_INVALID)?;

        let sub_utf16: Vec<u16> = self.substitute_name.encode_utf16().collect();
        let print_utf16: Vec<u16> = self.print_name.encode_utf16().collect();

        let sub_byte_len = sub_utf16
            .len()
            .checked_mul(2)
            .ok_or(STATUS_IO_REPARSE_DATA_INVALID)?;
        let print_byte_len = print_utf16
            .len()
            .checked_mul(2)
            .ok_or(STATUS_IO_REPARSE_DATA_INVALID)?;
        let data_len = SYMLINK_REPARSE_HEADER_LEN
            .checked_add(sub_byte_len)
            .and_then(|n| n.checked_add(print_byte_len))
            .ok_or(STATUS_IO_REPARSE_DATA_INVALID)?;

        let data_len_u16 = u16::try_from(data_len).map_err(|_| STATUS_IO_REPARSE_DATA_INVALID)?;
        let sub_offset_u16 = 0u16;
        let sub_len_u16 =
            u16::try_from(sub_byte_len).map_err(|_| STATUS_IO_REPARSE_DATA_INVALID)?;
        let print_offset_u16 = sub_len_u16;
        let print_len_u16 =
            u16::try_from(print_byte_len).map_err(|_| STATUS_IO_REPARSE_DATA_INVALID)?;

        let mut buf = Vec::with_capacity(REPARSE_DATA_HEADER_LEN + data_len);
        buf.extend_from_slice(&self.reparse_tag.to_le_bytes());
        buf.extend_from_slice(&data_len_u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        buf.extend_from_slice(&sub_offset_u16.to_le_bytes());
        buf.extend_from_slice(&sub_len_u16.to_le_bytes());
        buf.extend_from_slice(&print_offset_u16.to_le_bytes());
        buf.extend_from_slice(&print_len_u16.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());

        for unit in sub_utf16 {
            buf.extend_from_slice(&unit.to_le_bytes());
        }
        for unit in print_utf16 {
            buf.extend_from_slice(&unit.to_le_bytes());
        }

        Ok(buf)
    }

    /// Copies the encoded `REPARSE_DATA_BUFFER` into caller-supplied `out`, returning the number
    /// of bytes written or [`STATUS_BUFFER_TOO_SMALL`].
    pub fn write_into_buffer(&self, out: &mut [u8]) -> Result<usize, NtStatus> {
        let encoded = self.encode_reparse_buffer()?;
        if out.len() < encoded.len() {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        out[..encoded.len()].copy_from_slice(&encoded);
        Ok(encoded.len())
    }

    /// Parses a little-endian Windows `REPARSE_DATA_BUFFER` into [`ReparsePointData`].
    pub fn decode_reparse_buffer(buf: &[u8]) -> Result<Self, NtStatus> {
        if buf.len() < REPARSE_DATA_HEADER_LEN {
            return Err(STATUS_IO_REPARSE_DATA_INVALID);
        }
        let reparse_tag = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if reparse_tag != IO_REPARSE_TAG_SYMLINK {
            return Err(STATUS_IO_REPARSE_TAG_NOT_HANDLED);
        }

        let data_len = u16::from_le_bytes([buf[4], buf[5]]) as usize;
        if data_len < SYMLINK_REPARSE_HEADER_LEN || buf.len() < REPARSE_DATA_HEADER_LEN + data_len {
            return Err(STATUS_IO_REPARSE_DATA_INVALID);
        }

        let inner = &buf[REPARSE_DATA_HEADER_LEN..REPARSE_DATA_HEADER_LEN + data_len];
        let sub_offset = u16::from_le_bytes([inner[0], inner[1]]) as usize;
        let sub_len = u16::from_le_bytes([inner[2], inner[3]]) as usize;
        let print_offset = u16::from_le_bytes([inner[4], inner[5]]) as usize;
        let print_len = u16::from_le_bytes([inner[6], inner[7]]) as usize;
        let flags = u32::from_le_bytes([inner[8], inner[9], inner[10], inner[11]]);

        let path_buf = &inner[SYMLINK_REPARSE_HEADER_LEN..];
        let substitute_name = decode_utf16_slice(path_buf, sub_offset, sub_len)?;
        let print_name = decode_utf16_slice(path_buf, print_offset, print_len)?;

        let raw_target = if !print_name.is_empty() {
            print_name.clone()
        } else {
            substitute_name
                .strip_prefix(r"\??\")
                .unwrap_or(&substitute_name)
                .to_owned()
        };

        validate_symlink_target(&raw_target).map_err(|_| STATUS_IO_REPARSE_DATA_INVALID)?;

        Ok(Self {
            reparse_tag,
            target: raw_target,
            substitute_name,
            print_name,
            flags,
        })
    }
}

fn decode_utf16_slice(path_buf: &[u8], offset: usize, byte_len: usize) -> Result<String, NtStatus> {
    if !byte_len.is_multiple_of(2) {
        return Err(STATUS_IO_REPARSE_DATA_INVALID);
    }
    let end = offset
        .checked_add(byte_len)
        .ok_or(STATUS_IO_REPARSE_DATA_INVALID)?;
    if end > path_buf.len() {
        return Err(STATUS_IO_REPARSE_DATA_INVALID);
    }
    let slice = &path_buf[offset..end];
    let (pairs, _) = slice.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
    String::from_utf16(&units).map_err(|_| STATUS_IO_REPARSE_DATA_INVALID)
}

fn is_drive_absolute(target: &str) -> bool {
    let bytes = target.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

fn is_relative_symlink_target(target: &str) -> bool {
    !(target.starts_with('/') || target.starts_with('\\') || is_drive_absolute(target))
}
