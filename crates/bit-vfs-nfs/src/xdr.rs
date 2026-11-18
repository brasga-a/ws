//! Pure-`std` big-endian XDR (RFC 4506) reader and writer with 4-byte boundary alignment.

use std::fmt;

/// XDR alignment quantum in bytes (RFC 4506 §3).
pub const XDR_ALIGNMENT: usize = 4;

/// Computes the number of zero-padding bytes (`0..=3`) required to align `len` to 4 bytes.
pub const fn xdr_pad_len(len: usize) -> usize {
    (XDR_ALIGNMENT - (len & 3)) & 3
}

/// Decoding error returned by [`XdrReader`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XdrError {
    /// Input buffer ended before the expected XDR item or alignment padding completed.
    UnexpectedEof,
    /// XDR boolean discriminant was neither `0` nor `1`.
    InvalidBool(u32),
    /// XDR string payload was not valid UTF-8.
    InvalidUtf8,
    /// Variable-length XDR opaque or array exceeded the protocol maximum.
    LengthLimitExceeded { len: usize, max: usize },
    /// XDR enum / union discriminant was not recognized.
    InvalidEnumDiscriminant(u32),
}

impl fmt::Display for XdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("unexpected end of XDR buffer"),
            Self::InvalidBool(v) => write!(f, "invalid XDR bool discriminant: {v}"),
            Self::InvalidUtf8 => f.write_str("XDR string is not valid UTF-8"),
            Self::LengthLimitExceeded { len, max } => {
                write!(f, "XDR length {len} exceeds maximum allowed {max}")
            }
            Self::InvalidEnumDiscriminant(v) => {
                write!(f, "unrecognized XDR enum discriminant: {v}")
            }
        }
    }
}

impl std::error::Error for XdrError {}

/// Zero-copy big-endian XDR reader over a byte slice.
#[derive(Debug, Clone)]
pub struct XdrReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> XdrReader<'a> {
    /// Wraps `buf` at offset `0`.
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Current byte offset into the underlying buffer.
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Number of unread bytes remaining.
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Returns `true` when all bytes have been consumed.
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Borrows the unread tail slice.
    pub fn remaining_slice(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], XdrError> {
        let end = self.pos.checked_add(n).ok_or(XdrError::UnexpectedEof)?;
        if end > self.buf.len() {
            return Err(XdrError::UnexpectedEof);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Reads an unsigned 32-bit big-endian integer.
    pub fn read_u32(&mut self) -> Result<u32, XdrError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a signed 32-bit big-endian integer.
    pub fn read_i32(&mut self) -> Result<i32, XdrError> {
        Ok(self.read_u32()? as i32)
    }

    /// Reads an unsigned 64-bit big-endian hyper integer.
    pub fn read_u64(&mut self) -> Result<u64, XdrError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Reads a signed 64-bit big-endian hyper integer.
    pub fn read_i64(&mut self) -> Result<i64, XdrError> {
        Ok(self.read_u64()? as i64)
    }

    /// Reads an XDR `bool` (`0 => false`, `1 => true`).
    pub fn read_bool(&mut self) -> Result<bool, XdrError> {
        match self.read_u32()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(XdrError::InvalidBool(other)),
        }
    }

    /// Reads a fixed-length opaque array `opaque[N]` and consumes trailing 4-byte alignment padding.
    pub fn read_fixed_opaque<const N: usize>(&mut self) -> Result<[u8; N], XdrError> {
        let raw = self.take(N)?;
        let pad = xdr_pad_len(N);
        if pad > 0 {
            let _ = self.take(pad)?;
        }
        let mut out = [0u8; N];
        out.copy_from_slice(raw);
        Ok(out)
    }

    /// Reads a variable-length `opaque<max_len>` slice and consumes 4-byte alignment padding.
    pub fn read_opaque_slice(&mut self, max_len: usize) -> Result<&'a [u8], XdrError> {
        let len = self.read_u32()? as usize;
        if len > max_len {
            return Err(XdrError::LengthLimitExceeded { len, max: max_len });
        }
        let data = self.take(len)?;
        let pad = xdr_pad_len(len);
        if pad > 0 {
            let _ = self.take(pad)?;
        }
        Ok(data)
    }

    /// Reads a variable-length `opaque<max_len>` into an owned `Vec<u8>`.
    pub fn read_opaque(&mut self, max_len: usize) -> Result<Vec<u8>, XdrError> {
        Ok(self.read_opaque_slice(max_len)?.to_vec())
    }

    /// Reads a variable-length UTF-8 `string<max_len>`.
    pub fn read_string(&mut self, max_len: usize) -> Result<String, XdrError> {
        let bytes = self.read_opaque_slice(max_len)?;
        let s = std::str::from_utf8(bytes).map_err(|_| XdrError::InvalidUtf8)?;
        Ok(s.to_owned())
    }
}

/// Big-endian XDR buffer writer maintaining 4-byte alignment.
#[derive(Debug, Clone, Default)]
pub struct XdrWriter {
    buf: Vec<u8>,
}

impl XdrWriter {
    /// Creates an empty `XdrWriter`.
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Creates an `XdrWriter` with pre-allocated byte capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Current encoded byte length (always a multiple of 4).
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if nothing has been written yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Borrows the encoded XDR bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Consumes the writer and returns the encoded XDR buffer.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Appends raw pre-aligned XDR bytes.
    pub fn write_raw_aligned(&mut self, aligned_bytes: &[u8]) {
        debug_assert_eq!(aligned_bytes.len() % XDR_ALIGNMENT, 0);
        self.buf.extend_from_slice(aligned_bytes);
    }

    /// Writes an unsigned 32-bit big-endian integer.
    pub fn write_u32(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    /// Writes a signed 32-bit big-endian integer.
    pub fn write_i32(&mut self, val: i32) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    /// Writes an unsigned 64-bit big-endian hyper integer.
    pub fn write_u64(&mut self, val: u64) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    /// Writes a signed 64-bit big-endian hyper integer.
    pub fn write_i64(&mut self, val: i64) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    /// Writes an XDR `bool` (`0` or `1`).
    pub fn write_bool(&mut self, val: bool) {
        self.write_u32(u32::from(val));
    }

    /// Writes fixed-length opaque bytes `opaque[N]` followed by zero-padding to 4 bytes.
    pub fn write_fixed_opaque(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        let pad = xdr_pad_len(bytes.len());
        if pad > 0 {
            const ZEROS: [u8; 3] = [0, 0, 0];
            self.buf.extend_from_slice(&ZEROS[..pad]);
        }
    }

    /// Writes variable-length `opaque<>` (`u32` length prefix + bytes + zero-padding).
    pub fn write_opaque(&mut self, bytes: &[u8]) {
        self.write_u32(bytes.len() as u32);
        self.write_fixed_opaque(bytes);
    }

    /// Writes an XDR `string<>` (`u32` byte length + UTF-8 bytes + zero-padding).
    pub fn write_string(&mut self, s: &str) {
        self.write_opaque(s.as_bytes());
    }
}
