//! ONC-RPC v2 message envelope, `AUTH_UNIX` (`AUTH_SYS`) credential parser, and RFC 5531 §11
//! TCP record-marking framing.

use std::fmt;
use std::io::{self, Read, Write};

use crate::xdr::{XdrError, XdrReader, XdrWriter};

/// ONC-RPC protocol version (`2`, RFC 5531).
pub const RPC_VERSION: u32 = 2;

/// RFC 5531 record-marking bit indicating the final fragment of an RPC record.
pub const LAST_FRAGMENT_BIT: u32 = 0x8000_0000;

/// Mask extracting the 31-bit byte length of a single RFC 5531 record fragment.
pub const FRAGMENT_LEN_MASK: u32 = 0x7FFF_FFFF;

/// Maximum assembled ONC-RPC record byte size accepted over TCP (`2 MiB`).
pub const MAX_RPC_RECORD_LEN: usize = 2 * 1024 * 1024;

/// Maximum number of fragments permitted in a single assembled ONC-RPC record.
pub const MAX_RPC_FRAGMENTS: usize = 256;

/// Maximum byte length of an `opaque_auth` credential or verifier body (RFC 5531 §8.2).
pub const MAX_AUTH_BYTES: usize = 400;

/// Maximum machine name length in `AUTH_UNIX` (`AUTH_SYS`, RFC 5531 §9.2).
pub const MAX_MACHINE_NAME_LEN: usize = 255;

/// Maximum supplementary group count accepted in `AUTH_UNIX` credentials.
pub const MAX_UNIX_GIDS: usize = 64;

/// RPC message type discriminant (`msg_type::CALL`).
pub const RPC_MSG_CALL: u32 = 0;
/// RPC message type discriminant (`msg_type::REPLY`).
pub const RPC_MSG_REPLY: u32 = 1;

/// Credential flavor `AUTH_NONE` (`0`).
pub const AUTH_NONE: u32 = 0;
/// Credential flavor `AUTH_UNIX` / `AUTH_SYS` (`1`).
pub const AUTH_UNIX: u32 = 1;

/// `reply_stat::MSG_ACCEPTED` (`0`).
pub const MSG_ACCEPTED: u32 = 0;
/// `reply_stat::MSG_DENIED` (`1`).
pub const MSG_DENIED: u32 = 1;

/// `reject_stat::RPC_MISMATCH` (`0`).
pub const RPC_MISMATCH: u32 = 0;
/// `reject_stat::AUTH_ERROR` (`1`).
pub const AUTH_ERROR: u32 = 1;

/// Framing or envelope error while reading/writing ONC-RPC records.
#[derive(Debug)]
pub enum RpcError {
    /// Underlying socket or stream I/O failure.
    Io(io::Error),
    /// XDR envelope decoding failure.
    Xdr(XdrError),
    /// Assembled RPC record exceeded `MAX_RPC_RECORD_LEN`.
    RecordTooLarge { len: usize, max: usize },
    /// Fragmented RPC record exceeded `MAX_RPC_FRAGMENTS`.
    TooManyFragments(usize),
    /// Expected an RPC `CALL` (`0`) message, received another `msg_type`.
    NotACallMessage(u32),
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "RPC stream I/O error: {err}"),
            Self::Xdr(err) => write!(f, "RPC XDR decode error: {err}"),
            Self::RecordTooLarge { len, max } => {
                write!(f, "RPC record size {len} exceeds limit {max}")
            }
            Self::TooManyFragments(count) => {
                write!(f, "RPC record fragment count {count} exceeds limit")
            }
            Self::NotACallMessage(msg_type) => {
                write!(f, "expected RPC CALL (0), got msg_type {msg_type}")
            }
        }
    }
}

impl std::error::Error for RpcError {}

impl From<io::Error> for RpcError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<XdrError> for RpcError {
    fn from(err: XdrError) -> Self {
        Self::Xdr(err)
    }
}

/// ONC-RPC `opaque_auth` structure (`flavor` + opaque `body`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueAuth {
    /// Authentication flavor (`AUTH_NONE = 0`, `AUTH_UNIX = 1`, ...).
    pub flavor: u32,
    /// Raw XDR-encoded credential or verifier bytes (`<= 400` bytes).
    pub body: Vec<u8>,
}

impl OpaqueAuth {
    /// Returns the empty `AUTH_NONE` credential/verifier.
    pub const fn none() -> Self {
        Self {
            flavor: AUTH_NONE,
            body: Vec::new(),
        }
    }

    /// Decodes an `opaque_auth` from `reader`.
    pub fn decode(reader: &mut XdrReader<'_>) -> Result<Self, XdrError> {
        let flavor = reader.read_u32()?;
        let body = reader.read_opaque(MAX_AUTH_BYTES)?;
        Ok(Self { flavor, body })
    }

    /// Encodes `self` into `writer`.
    pub fn encode(&self, writer: &mut XdrWriter) {
        writer.write_u32(self.flavor);
        writer.write_opaque(&self.body);
    }
}

/// Parsed `AUTH_UNIX` (`AUTH_SYS`, flavor `1`) RPC credential (RFC 5531 §9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUnixCred {
    /// Arbitrary client timestamp / stamp.
    pub stamp: u32,
    /// Client host name (`string<255>`).
    pub machine_name: String,
    /// Effective numeric POSIX user ID of the caller.
    pub uid: u32,
    /// Effective numeric POSIX primary group ID of the caller.
    pub gid: u32,
    /// Supplementary numeric group IDs.
    pub gids: Vec<u32>,
}

impl AuthUnixCred {
    /// Decodes an `AUTH_UNIX` credential payload from `opaque_auth.body`.
    pub fn decode(body: &[u8]) -> Result<Self, XdrError> {
        let mut r = XdrReader::new(body);
        let stamp = r.read_u32()?;
        let machine_name = r.read_string(MAX_MACHINE_NAME_LEN)?;
        let uid = r.read_u32()?;
        let gid = r.read_u32()?;
        let gid_count = r.read_u32()? as usize;
        if gid_count > MAX_UNIX_GIDS {
            return Err(XdrError::LengthLimitExceeded {
                len: gid_count,
                max: MAX_UNIX_GIDS,
            });
        }
        let mut gids = Vec::with_capacity(gid_count);
        for _ in 0..gid_count {
            gids.push(r.read_u32()?);
        }
        Ok(Self {
            stamp,
            machine_name,
            uid,
            gid,
            gids,
        })
    }

    /// Encodes this `AUTH_UNIX` credential into an XDR byte vector.
    pub fn encode_body(&self) -> Vec<u8> {
        let mut w = XdrWriter::with_capacity(32 + self.machine_name.len() + self.gids.len() * 4);
        w.write_u32(self.stamp);
        w.write_string(&self.machine_name);
        w.write_u32(self.uid);
        w.write_u32(self.gid);
        w.write_u32(self.gids.len() as u32);
        for &g in &self.gids {
            w.write_u32(g);
        }
        w.into_bytes()
    }

    /// Wraps this credential into an [`OpaqueAuth`] with `flavor = AUTH_UNIX`.
    pub fn to_opaque_auth(&self) -> OpaqueAuth {
        OpaqueAuth {
            flavor: AUTH_UNIX,
            body: self.encode_body(),
        }
    }
}

/// ONC-RPC `auth_stat` rejection codes (RFC 5531 §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthStat {
    /// Success (`0`).
    AuthOk = 0,
    /// Malformed credential (`AUTH_BADCRED = 1`).
    AuthBadCred = 1,
    /// Client must begin a new session (`AUTH_REJECTEDCRED = 2`).
    AuthRejectedCred = 2,
    /// Malformed verifier (`AUTH_BADVERF = 3`).
    AuthBadVerf = 3,
    /// Expired or replayed verifier (`AUTH_REJECTEDVERF = 4`).
    AuthRejectedVerf = 4,
    /// Rejected for security policy (`AUTH_TOOWEAK = 5`, e.g. non-owner `uid` or `AUTH_NONE`).
    AuthTooWeak = 5,
}

impl AuthStat {
    /// Converts a raw `u32` discriminant into `AuthStat`.
    pub const fn from_u32(val: u32) -> Result<Self, XdrError> {
        match val {
            0 => Ok(Self::AuthOk),
            1 => Ok(Self::AuthBadCred),
            2 => Ok(Self::AuthRejectedCred),
            3 => Ok(Self::AuthBadVerf),
            4 => Ok(Self::AuthRejectedVerf),
            5 => Ok(Self::AuthTooWeak),
            other => Err(XdrError::InvalidEnumDiscriminant(other)),
        }
    }
}

/// ONC-RPC `accept_stat` codes inside an accepted reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcAcceptStat {
    /// `SUCCESS (0)` carrying procedure-specific XDR result bytes.
    Success(Vec<u8>),
    /// `PROG_UNAVAIL (1)`: unknown RPC program number.
    ProgUnavail,
    /// `PROG_MISMATCH (2)`: unsupported program version (`low..=high` supported).
    ProgMismatch { low: u32, high: u32 },
    /// `PROC_UNAVAIL (3)`: unknown procedure number.
    ProcUnavail,
    /// `GARBAGE_ARGS (4)`: procedure could not decode XDR arguments.
    GarbageArgs,
    /// `SYSTEM_ERR (5)`: internal server error.
    SystemErr,
}

/// ONC-RPC `rejected_reply` body when `reply_stat == MSG_DENIED`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcRejectedReply {
    /// `RPC_MISMATCH (0)`: unsupported ONC-RPC envelope version (`rpcvers != 2`).
    RpcMismatch { low: u32, high: u32 },
    /// `AUTH_ERROR (1)`: credential verification failed.
    AuthError(AuthStat),
}

/// ONC-RPC `reply_body` union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcReplyBody {
    /// `MSG_ACCEPTED (0)` with server verifier and `accept_stat`.
    Accepted {
        verf: OpaqueAuth,
        stat: RpcAcceptStat,
    },
    /// `MSG_DENIED (1)` with rejection cause.
    Denied(RpcRejectedReply),
}

/// Complete ONC-RPC `REPLY` message (`xid` + `reply_body`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcReply {
    /// Transaction identifier matching the originating [`RpcCall`].
    pub xid: u32,
    /// Accepted or denied reply payload.
    pub body: RpcReplyBody,
}

impl RpcReply {
    /// Constructs a `MSG_ACCEPTED / SUCCESS` reply with `AUTH_NONE` verifier.
    pub const fn success(xid: u32, result_bytes: Vec<u8>) -> Self {
        Self {
            xid,
            body: RpcReplyBody::Accepted {
                verf: OpaqueAuth::none(),
                stat: RpcAcceptStat::Success(result_bytes),
            },
        }
    }

    /// Constructs a `MSG_ACCEPTED` non-success status reply (`PROG_UNAVAIL`, `GARBAGE_ARGS`, etc.).
    pub const fn accepted_error(xid: u32, stat: RpcAcceptStat) -> Self {
        Self {
            xid,
            body: RpcReplyBody::Accepted {
                verf: OpaqueAuth::none(),
                stat,
            },
        }
    }

    /// Constructs a `MSG_DENIED / AUTH_ERROR` reply.
    pub const fn auth_error(xid: u32, stat: AuthStat) -> Self {
        Self {
            xid,
            body: RpcReplyBody::Denied(RpcRejectedReply::AuthError(stat)),
        }
    }

    /// Constructs a `MSG_DENIED / RPC_MISMATCH` reply for `rpcvers != 2`.
    pub const fn rpc_mismatch(xid: u32) -> Self {
        Self {
            xid,
            body: RpcReplyBody::Denied(RpcRejectedReply::RpcMismatch {
                low: RPC_VERSION,
                high: RPC_VERSION,
            }),
        }
    }

    /// Encodes this RPC reply into an unframed XDR message buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = XdrWriter::with_capacity(64);
        w.write_u32(self.xid);
        w.write_u32(RPC_MSG_REPLY);
        match &self.body {
            RpcReplyBody::Accepted { verf, stat } => {
                w.write_u32(MSG_ACCEPTED);
                verf.encode(&mut w);
                match stat {
                    RpcAcceptStat::Success(payload) => {
                        w.write_u32(0);
                        w.write_raw_aligned(payload);
                    }
                    RpcAcceptStat::ProgUnavail => w.write_u32(1),
                    RpcAcceptStat::ProgMismatch { low, high } => {
                        w.write_u32(2);
                        w.write_u32(*low);
                        w.write_u32(*high);
                    }
                    RpcAcceptStat::ProcUnavail => w.write_u32(3),
                    RpcAcceptStat::GarbageArgs => w.write_u32(4),
                    RpcAcceptStat::SystemErr => w.write_u32(5),
                }
            }
            RpcReplyBody::Denied(rej) => {
                w.write_u32(MSG_DENIED);
                match rej {
                    RpcRejectedReply::RpcMismatch { low, high } => {
                        w.write_u32(RPC_MISMATCH);
                        w.write_u32(*low);
                        w.write_u32(*high);
                    }
                    RpcRejectedReply::AuthError(stat) => {
                        w.write_u32(AUTH_ERROR);
                        w.write_u32(*stat as u32);
                    }
                }
            }
        }
        w.into_bytes()
    }

    /// Decodes an unframed XDR `REPLY` message (useful in protocol and round-trip tests).
    pub fn decode(bytes: &[u8]) -> Result<Self, XdrError> {
        let mut r = XdrReader::new(bytes);
        let xid = r.read_u32()?;
        let msg_type = r.read_u32()?;
        if msg_type != RPC_MSG_REPLY {
            return Err(XdrError::InvalidEnumDiscriminant(msg_type));
        }
        let reply_stat = r.read_u32()?;
        let body = match reply_stat {
            MSG_ACCEPTED => {
                let verf = OpaqueAuth::decode(&mut r)?;
                let accept_disc = r.read_u32()?;
                let stat = match accept_disc {
                    0 => RpcAcceptStat::Success(r.remaining_slice().to_vec()),
                    1 => RpcAcceptStat::ProgUnavail,
                    2 => RpcAcceptStat::ProgMismatch {
                        low: r.read_u32()?,
                        high: r.read_u32()?,
                    },
                    3 => RpcAcceptStat::ProcUnavail,
                    4 => RpcAcceptStat::GarbageArgs,
                    5 => RpcAcceptStat::SystemErr,
                    other => return Err(XdrError::InvalidEnumDiscriminant(other)),
                };
                RpcReplyBody::Accepted { verf, stat }
            }
            MSG_DENIED => {
                let reject_disc = r.read_u32()?;
                let rej = match reject_disc {
                    RPC_MISMATCH => RpcRejectedReply::RpcMismatch {
                        low: r.read_u32()?,
                        high: r.read_u32()?,
                    },
                    AUTH_ERROR => RpcRejectedReply::AuthError(AuthStat::from_u32(r.read_u32()?)?),
                    other => return Err(XdrError::InvalidEnumDiscriminant(other)),
                };
                RpcReplyBody::Denied(rej)
            }
            other => return Err(XdrError::InvalidEnumDiscriminant(other)),
        };
        Ok(Self { xid, body })
    }
}

/// Decoded ONC-RPC `CALL` header plus borrowed procedure-argument slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcCall<'a> {
    /// Client-chosen transaction ID.
    pub xid: u32,
    /// ONC-RPC protocol version (`2` expected).
    pub rpcvers: u32,
    /// Target RPC program (`100003` for NFS, `100005` for MOUNT).
    pub prog: u32,
    /// Target RPC program version (`3` for `NFSv3` and `MOUNTv3`).
    pub vers: u32,
    /// Procedure number within `prog`.
    pub proc_num: u32,
    /// Caller authentication credential.
    pub cred: OpaqueAuth,
    /// Caller authentication verifier.
    pub verf: OpaqueAuth,
    /// Unread procedure-specific XDR arguments.
    pub args: &'a [u8],
}

impl<'a> RpcCall<'a> {
    /// Parses an unframed ONC-RPC `CALL` message from `bytes`.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, RpcError> {
        let mut r = XdrReader::new(bytes);
        let xid = r.read_u32()?;
        let msg_type = r.read_u32()?;
        if msg_type != RPC_MSG_CALL {
            return Err(RpcError::NotACallMessage(msg_type));
        }
        let rpcvers = r.read_u32()?;
        if rpcvers != RPC_VERSION {
            return Ok(Self {
                xid,
                rpcvers,
                prog: 0,
                vers: 0,
                proc_num: 0,
                cred: OpaqueAuth::none(),
                verf: OpaqueAuth::none(),
                args: &[],
            });
        }
        let prog = r.read_u32()?;
        let vers = r.read_u32()?;
        let proc_num = r.read_u32()?;
        let cred = OpaqueAuth::decode(&mut r)?;
        let verf = OpaqueAuth::decode(&mut r)?;
        Ok(Self {
            xid,
            rpcvers,
            prog,
            vers,
            proc_num,
            cred,
            verf,
            args: r.remaining_slice(),
        })
    }

    /// Encodes an unframed ONC-RPC `CALL` message (for client tests and round-trip verification).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = XdrWriter::with_capacity(48 + self.args.len());
        w.write_u32(self.xid);
        w.write_u32(RPC_MSG_CALL);
        w.write_u32(self.rpcvers);
        w.write_u32(self.prog);
        w.write_u32(self.vers);
        w.write_u32(self.proc_num);
        self.cred.encode(&mut w);
        self.verf.encode(&mut w);
        w.write_raw_aligned(self.args);
        w.into_bytes()
    }
}

/// Enforces the mandatory `owner_uid` check on incoming ONC-RPC calls (ADR-0004).
///
/// - Any call presenting `AUTH_UNIX` (`flavor == 1`) is decoded (`AuthBadCred` if malformed) and
///   checked for `cred.uid == owner_uid` (`AuthTooWeak` if `uid != owner_uid`).
/// - `AUTH_NONE` (`flavor == 0`) is permitted strictly on `proc_num == 0` (`NULL` liveness ping),
///   which touches zero filesystem state; on any non-`NULL` procedure, `AUTH_NONE` (and any
///   non-`AUTH_UNIX` flavor) is rejected with [`AuthStat::AuthTooWeak`].
pub fn validate_call_credentials(
    call: &RpcCall<'_>,
    owner_uid: u32,
) -> Result<Option<AuthUnixCred>, AuthStat> {
    match call.cred.flavor {
        AUTH_UNIX => {
            let parsed =
                AuthUnixCred::decode(&call.cred.body).map_err(|_| AuthStat::AuthBadCred)?;
            if parsed.uid != owner_uid {
                return Err(AuthStat::AuthTooWeak);
            }
            Ok(Some(parsed))
        }
        AUTH_NONE if call.proc_num == 0 => Ok(None),
        _ => Err(AuthStat::AuthTooWeak),
    }
}

/// Wraps `payload` into a single-fragment RFC 5531 TCP record (`LAST_FRAGMENT_BIT | len` + bytes).
pub fn encode_rpc_record(payload: &[u8]) -> Vec<u8> {
    encode_rpc_record_fragmented(payload, payload.len().max(1))
}

/// Wraps `payload` into one or more RFC 5531 TCP record fragments of at most `max_fragment_size`
/// bytes each, setting `LAST_FRAGMENT_BIT` on the final fragment.
pub fn encode_rpc_record_fragmented(payload: &[u8], max_fragment_size: usize) -> Vec<u8> {
    let chunk_limit = max_fragment_size.clamp(1, FRAGMENT_LEN_MASK as usize);
    if payload.is_empty() {
        return LAST_FRAGMENT_BIT.to_be_bytes().to_vec();
    }

    let chunks: Vec<&[u8]> = payload.chunks(chunk_limit).collect();
    let mut out = Vec::with_capacity(chunks.len() * 4 + payload.len());
    for (idx, chunk) in chunks.iter().enumerate() {
        let is_last = idx + 1 == chunks.len();
        let header = (chunk.len() as u32) | if is_last { LAST_FRAGMENT_BIT } else { 0 };
        out.extend_from_slice(&header.to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

/// Reads one complete RFC 5531 record-marked ONC-RPC message from `reader`, reassembling
/// multi-fragment records up to `MAX_RPC_RECORD_LEN`.
///
/// Returns `Ok(None)` on clean EOF prior to reading the first byte of a record header.
pub fn read_rpc_record<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, RpcError> {
    let mut assembled = Vec::new();
    let mut fragments = 0usize;

    loop {
        fragments += 1;
        if fragments > MAX_RPC_FRAGMENTS {
            return Err(RpcError::TooManyFragments(fragments));
        }

        let mut header_buf = [0u8; 4];
        if !read_header_or_clean_eof(reader, &mut header_buf, fragments == 1)? {
            return Ok(None);
        }

        let header = u32::from_be_bytes(header_buf);
        let is_last = (header & LAST_FRAGMENT_BIT) != 0;
        let frag_len = (header & FRAGMENT_LEN_MASK) as usize;

        let new_len = assembled
            .len()
            .checked_add(frag_len)
            .ok_or(RpcError::RecordTooLarge {
                len: usize::MAX,
                max: MAX_RPC_RECORD_LEN,
            })?;
        if new_len > MAX_RPC_RECORD_LEN {
            return Err(RpcError::RecordTooLarge {
                len: new_len,
                max: MAX_RPC_RECORD_LEN,
            });
        }

        let start = assembled.len();
        assembled.resize(new_len, 0);
        reader.read_exact(&mut assembled[start..new_len])?;

        if is_last {
            return Ok(Some(assembled));
        }
    }
}

fn read_header_or_clean_eof<R: Read>(
    reader: &mut R,
    buf: &mut [u8; 4],
    allow_clean_eof: bool,
) -> io::Result<bool> {
    let mut offset = 0usize;
    while offset < 4 {
        match reader.read(&mut buf[offset..]) {
            Ok(0) => {
                if offset == 0 && allow_clean_eof {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated RFC 5531 RPC fragment header",
                ));
            }
            Ok(n) => offset += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(true)
}

/// Decodes a single RFC 5531 record from an in-memory byte slice.
pub fn decode_rpc_record(framed: &[u8]) -> Result<Vec<u8>, RpcError> {
    let mut cursor = io::Cursor::new(framed);
    read_rpc_record(&mut cursor)?.ok_or_else(|| {
        RpcError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty RPC record buffer",
        ))
    })
}

/// Writes `payload` as an RFC 5531 record-marked message to `writer` and flushes it.
pub fn write_rpc_record<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), RpcError> {
    let framed = encode_rpc_record(payload);
    writer.write_all(&framed)?;
    writer.flush()?;
    Ok(())
}
