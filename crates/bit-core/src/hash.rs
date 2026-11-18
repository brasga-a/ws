//! Deterministic SHA-256 hashing and 32-byte digest identifiers (`ContentHash` and `BaseId`).

use std::fmt;
use std::str::FromStr;

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Streaming FIPS 180-4 SHA-256 hasher implemented in safe `std` Rust.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total_bytes: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sha256")
            .field("total_bytes", &self.total_bytes)
            .finish_non_exhaustive()
    }
}

impl Sha256 {
    /// Creates a fresh SHA-256 state.
    pub const fn new() -> Self {
        Self {
            state: H0,
            block: [0u8; 64],
            block_len: 0,
            total_bytes: 0,
        }
    }

    /// Feeds bytes into the hasher.
    pub fn update(&mut self, mut input: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(input.len() as u64);

        if self.block_len > 0 {
            let need = 64 - self.block_len;
            if input.len() < need {
                self.block[self.block_len..self.block_len + input.len()].copy_from_slice(input);
                self.block_len += input.len();
                return;
            }
            self.block[self.block_len..64].copy_from_slice(&input[..need]);
            let full_block = self.block;
            compress_block(&mut self.state, &full_block);
            self.block_len = 0;
            input = &input[need..];
        }

        while input.len() >= 64 {
            let mut chunk = [0u8; 64];
            chunk.copy_from_slice(&input[..64]);
            compress_block(&mut self.state, &chunk);
            input = &input[64..];
        }

        if !input.is_empty() {
            self.block[..input.len()].copy_from_slice(input);
            self.block_len = input.len();
        }
    }

    /// Feeds a length-prefixed byte slice (big-endian `u64` length followed by payload)
    /// for unambiguous structured manifest hashing.
    pub fn update_len_prefixed(&mut self, bytes: &[u8]) {
        self.update(&(bytes.len() as u64).to_be_bytes());
        self.update(bytes);
    }

    /// Consumes the hasher and produces a 32-byte SHA-256 digest.
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.block[self.block_len] = 0x80;
        self.block_len += 1;

        if self.block_len > 56 {
            self.block[self.block_len..64].fill(0);
            let full_block = self.block;
            compress_block(&mut self.state, &full_block);
            self.block_len = 0;
        }

        self.block[self.block_len..56].fill(0);
        self.block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let final_block = self.block;
        compress_block(&mut self.state, &final_block);

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Computes the SHA-256 digest of `bytes` in one shot.
    pub fn digest(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(bytes);
        hasher.finalize()
    }
}

fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, slot) in w.iter_mut().take(16).enumerate() {
        let offset = i * 4;
        *slot = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Error returned when parsing a 64-character hex digest fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexDigestError {
    /// Input byte length was not 64 hex characters.
    InvalidLength(usize),
    /// Input contained a non-hexadecimal byte at the given byte index.
    InvalidHexByte { index: usize, byte: u8 },
}

impl fmt::Display for HexDigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(len) => {
                write!(
                    f,
                    "expected 64 hex characters for 32-byte digest, got {len}"
                )
            }
            Self::InvalidHexByte { index, byte } => {
                write!(f, "invalid hex byte 0x{byte:02x} at index {index}")
            }
        }
    }
}

impl std::error::Error for HexDigestError {}

pub(crate) fn encode_hex_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn decode_hex_32(hex: &str) -> Result<[u8; 32], HexDigestError> {
    let raw = hex.as_bytes();
    if raw.len() != 64 {
        return Err(HexDigestError::InvalidLength(raw.len()));
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi_idx = i * 2;
        let lo_idx = hi_idx + 1;
        let hi = decode_nibble(raw[hi_idx]).ok_or(HexDigestError::InvalidHexByte {
            index: hi_idx,
            byte: raw[hi_idx],
        })?;
        let lo = decode_nibble(raw[lo_idx]).ok_or(HexDigestError::InvalidHexByte {
            index: lo_idx,
            byte: raw[lo_idx],
        })?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

const fn decode_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Immutable 32-byte SHA-256 digest identifying file content bytes in a `BlobStore`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// Byte length of a `ContentHash`.
    pub const LEN: usize = 32;
    /// Hex string length of a `ContentHash`.
    pub const HEX_LEN: usize = 64;

    /// Wraps an already-computed 32-byte digest.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Computes the SHA-256 `ContentHash` of arbitrary file content bytes.
    pub fn hash_bytes(content: &[u8]) -> Self {
        Self(Sha256::digest(content))
    }

    /// Returns the `ContentHash` of an empty byte slice (`""`).
    pub fn empty() -> Self {
        Self::hash_bytes(b"")
    }

    /// Borrows the underlying 32-byte digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the underlying 32-byte digest by value.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Formats the digest as a 64-character lowercase hexadecimal string.
    pub fn to_hex(&self) -> String {
        encode_hex_32(&self.0)
    }

    /// Parses a 64-character hexadecimal string into a `ContentHash`.
    pub fn from_hex(hex: &str) -> Result<Self, HexDigestError> {
        decode_hex_32(hex).map(Self)
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({})", self.to_hex())
    }
}

impl FromStr for ContentHash {
    type Err = HexDigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl From<[u8; 32]> for ContentHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Immutable 32-byte SHA-256 identifier of a sealed `Base` manifest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BaseId([u8; 32]);

impl BaseId {
    /// Byte length of a `BaseId`.
    pub const LEN: usize = 32;
    /// Hex string length of a `BaseId`.
    pub const HEX_LEN: usize = 64;

    /// Wraps a 32-byte digest as a `BaseId`.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying 32-byte digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the underlying 32-byte digest by value.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Formats the `BaseId` as a 64-character lowercase hexadecimal string.
    pub fn to_hex(&self) -> String {
        encode_hex_32(&self.0)
    }

    /// Parses a 64-character hexadecimal string into a `BaseId`.
    pub fn from_hex(hex: &str) -> Result<Self, HexDigestError> {
        decode_hex_32(hex).map(Self)
    }
}

impl fmt::Display for BaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for BaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BaseId({})", self.to_hex())
    }
}

impl FromStr for BaseId {
    type Err = HexDigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl From<[u8; 32]> for BaseId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_nist_vectors() {
        assert_eq!(
            ContentHash::hash_bytes(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            ContentHash::hash_bytes(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            ContentHash::hash_bytes(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
                .to_hex(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn digest_hex_roundtrip_and_errors() {
        let digest = ContentHash::hash_bytes(b"hello bit");
        let hex = digest.to_hex();
        assert_eq!(ContentHash::from_hex(&hex).unwrap(), digest);
        assert_eq!(ContentHash::from_hex(&hex.to_uppercase()).unwrap(), digest);

        let base_id = BaseId::from_hex(&hex).unwrap();
        assert_eq!(base_id.to_hex(), hex);

        assert!(matches!(
            ContentHash::from_hex("abcd"),
            Err(HexDigestError::InvalidLength(4))
        ));
        let bad = format!("z{}", &hex[1..]);
        assert!(matches!(
            BaseId::from_hex(&bad),
            Err(HexDigestError::InvalidHexByte {
                index: 0,
                byte: b'z'
            })
        ));
    }
}
