use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;

use bit_core::{
    BaseInput, BaseSelector, ControlPlane, CoreEngine, InMemoryCoreEngine, InputEntry, TagName,
    Timestamp, ViewId,
};

use crate::{
    build_stale_umount_args, build_stale_umount_command, decode_rpc_record, encode_rpc_record,
    encode_rpc_record_fragmented, read_rpc_record, write_rpc_record, AuthStat, AuthUnixCred,
    NfsConfigError, NfsDispatcher, NfsFattr3, NfsFileHandle, NfsFileType, NfsLoopbackServer,
    NfsMountConfig, NfsSattr3, NfsServerError, OpaqueAuth, RpcAcceptStat, RpcCall,
    RpcRejectedReply, RpcReply, RpcReplyBody, XdrError, XdrReader, XdrWriter, ACCESS3_DELETE,
    ACCESS3_LOOKUP, ACCESS3_MODIFY, ACCESS3_READ, FSF3_CANSETTIME, FSF3_HOMOGENEOUS, FSF3_LINK,
    FSF3_SYMLINK, LOOPBACK_NFS_SHARE_SPEC, MACOS_MOUNT_NFS_BIN, MACOS_UMOUNT_BIN, MNT3ERR_NOENT,
    MNT3_OK, MOUNTPROC3_DUMP, MOUNTPROC3_MNT, MOUNTPROC3_NULL, MOUNTPROC3_UMNT, MOUNT_PROGRAM,
    MOUNT_V3, NFS3ERR_BADHANDLE, NFS3ERR_CTIME_MISMATCH, NFS3ERR_EXIST, NFS3ERR_NOENT,
    NFS3ERR_NOTEMPTY, NFS3ERR_NOTSUPP, NFS3ERR_ROFS, NFS3ERR_STALE, NFS3ERR_TOOSMALL, NFS3ERR_XDEV,
    NFS3_FILE_STABLE, NFS3_OK, NFSPROC3_ACCESS, NFSPROC3_CREATE, NFSPROC3_FLUSH_WRITES,
    NFSPROC3_FSINFO, NFSPROC3_FSSTAT, NFSPROC3_GETATTR, NFSPROC3_LINK, NFSPROC3_LOOKUP,
    NFSPROC3_MKDIR, NFSPROC3_MKNOD, NFSPROC3_NULL, NFSPROC3_PATHCONF, NFSPROC3_READ,
    NFSPROC3_READDIR, NFSPROC3_READDIRPLUS, NFSPROC3_READLINK, NFSPROC3_REMOVE, NFSPROC3_RENAME,
    NFSPROC3_RMDIR, NFSPROC3_SETATTR, NFSPROC3_SYMLINK, NFSPROC3_WRITE, NFS_PROGRAM, NFS_V3,
    RPC_VERSION,
};

const OWNER_UID: u32 = 501;
const OWNER_GID: u32 = 20;

fn owner_cred() -> OpaqueAuth {
    AuthUnixCred {
        stamp: 0x1234_5678,
        machine_name: "macbook-local".to_owned(),
        uid: OWNER_UID,
        gid: OWNER_GID,
        gids: vec![OWNER_GID, 80],
    }
    .to_opaque_auth()
}

fn foreign_cred(uid: u32) -> OpaqueAuth {
    AuthUnixCred {
        stamp: 99,
        machine_name: "intruder".to_owned(),
        uid,
        gid: 20,
        gids: vec![20],
    }
    .to_opaque_auth()
}

fn call_rpc(
    disp: &NfsDispatcher,
    xid: u32,
    prog: u32,
    vers: u32,
    proc_num: u32,
    cred: OpaqueAuth,
    args: &[u8],
) -> RpcReply {
    let call = RpcCall {
        xid,
        rpcvers: RPC_VERSION,
        prog,
        vers,
        proc_num,
        cred,
        verf: OpaqueAuth::none(),
        args,
    };
    let encoded_call = call.encode();
    let raw_reply = disp.handle_rpc_message(&encoded_call).unwrap();
    RpcReply::decode(&raw_reply).unwrap()
}

fn call_nfs_ok(disp: &NfsDispatcher, proc_num: u32, args: &[u8]) -> Vec<u8> {
    let reply = call_rpc(disp, 42, NFS_PROGRAM, NFS_V3, proc_num, owner_cred(), args);
    match reply.body {
        RpcReplyBody::Accepted {
            stat: RpcAcceptStat::Success(payload),
            ..
        } => payload,
        other => panic!("expected RPC SUCCESS, got {other:?}"),
    }
}

fn call_mount_ok(disp: &NfsDispatcher, proc_num: u32, args: &[u8]) -> Vec<u8> {
    let reply = call_rpc(
        disp,
        7,
        MOUNT_PROGRAM,
        MOUNT_V3,
        proc_num,
        owner_cred(),
        args,
    );
    match reply.body {
        RpcReplyBody::Accepted {
            stat: RpcAcceptStat::Success(payload),
            ..
        } => payload,
        other => panic!("expected RPC SUCCESS, got {other:?}"),
    }
}

fn setup_engine_with_two_views() -> Arc<InMemoryCoreEngine> {
    let engine = Arc::new(CoreEngine::in_memory());
    let entries = vec![
        InputEntry::file("README.md", b"hello from base\n".to_vec()).unwrap(),
        InputEntry::file("src/lib.rs", b"pub fn answer() -> u32 { 42 }\n".to_vec()).unwrap(),
        InputEntry::symlink("latest", "src/lib.rs").unwrap(),
    ];
    let tag = TagName::new("initial").unwrap();
    let base_info = engine
        .create_base(BaseInput::Entries(entries), Some(tag))
        .unwrap();

    engine
        .create_view(
            ViewId::new("view-a").unwrap(),
            BaseSelector::Id(base_info.id),
        )
        .unwrap();
    engine
        .create_view(
            ViewId::new("view-b").unwrap(),
            BaseSelector::Id(base_info.id),
        )
        .unwrap();
    engine
}

fn lookup_ok(disp: &NfsDispatcher, dir_fh: &[u8], name: &str) -> (Vec<u8>, NfsFattr3) {
    let mut w = XdrWriter::new();
    w.write_opaque(dir_fh);
    w.write_string(name);
    let payload = call_nfs_ok(disp, NFSPROC3_LOOKUP, w.as_slice());
    let mut r = XdrReader::new(&payload);
    assert_eq!(r.read_u32().unwrap(), NFS3_OK);
    let fh = r.read_opaque(64).unwrap();
    assert!(r.read_bool().unwrap());
    let attr = NfsFattr3::decode(&mut r).unwrap();
    (fh, attr)
}

#[test]
fn config_enforces_strict_loopback_and_builds_macos_commands() {
    let ephemeral = NfsMountConfig::loopback(0, OWNER_UID, "/Users/alice/.bit/views")
        .unwrap()
        .with_owner_gid(OWNER_GID);
    assert_eq!(ephemeral.bind_addr(), "127.0.0.1:0".parse().unwrap());
    assert_eq!(ephemeral.owner_uid(), OWNER_UID);
    assert_eq!(ephemeral.owner_gid(), OWNER_GID);
    assert_eq!(
        ephemeral.mount_nfs_args(51234),
        vec![
            "-o".to_owned(),
            "vers=3,tcp,nolocks,locallocks,port=51234,mountport=51234".to_owned(),
            LOOPBACK_NFS_SHARE_SPEC.to_owned(),
            "/Users/alice/.bit/views".to_owned(),
        ]
    );

    let split_ports = ephemeral.clone().with_mount_port(51235);
    assert_eq!(
        split_ports.mount_options(51234),
        "vers=3,tcp,nolocks,locallocks,port=51234,mountport=51235"
    );

    let mount_cmd = ephemeral.mount_nfs_command(51234);
    assert_eq!(mount_cmd.get_program(), MACOS_MOUNT_NFS_BIN);

    assert_eq!(
        build_stale_umount_args(ephemeral.mount_point()),
        vec!["-f".to_owned(), "/Users/alice/.bit/views".to_owned()]
    );
    let umount_cmd = build_stale_umount_command(ephemeral.mount_point());
    assert_eq!(umount_cmd.get_program(), MACOS_UMOUNT_BIN);

    // Reject empty mount point.
    assert_eq!(
        NfsMountConfig::loopback(0, OWNER_UID, ""),
        Err(NfsConfigError::EmptyMountPoint)
    );

    // Reject non-127.0.0.1 IPv4 and IPv6 addresses.
    let rejected_addrs: [SocketAddr; 5] = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 2049),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 2049),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 2049),
    ];
    for bad in rejected_addrs {
        assert_eq!(
            NfsMountConfig::new(bad, OWNER_UID, "/Users/alice/.bit/views"),
            Err(NfsConfigError::NonLoopbackBindAddress(bad.ip()))
        );
    }
}

#[test]
fn xdr_and_rpc_record_framing_round_trip() {
    let mut w = XdrWriter::new();
    w.write_u32(0xDEAD_BEEF);
    w.write_i32(-42);
    w.write_u64(0x0123_4567_89AB_CDEF);
    w.write_i64(-9_000_000_000);
    w.write_bool(true);
    w.write_bool(false);
    w.write_fixed_opaque(&[1, 2, 3, 4, 5]);
    w.write_opaque(b"abc");
    w.write_string("hello-utf8-✓");
    assert_eq!(w.len() % 4, 0);

    let raw = w.into_bytes();
    let mut r = XdrReader::new(&raw);
    assert_eq!(r.read_u32().unwrap(), 0xDEAD_BEEF);
    assert_eq!(r.read_i32().unwrap(), -42);
    assert_eq!(r.read_u64().unwrap(), 0x0123_4567_89AB_CDEF);
    assert_eq!(r.read_i64().unwrap(), -9_000_000_000);
    assert!(r.read_bool().unwrap());
    assert!(!r.read_bool().unwrap());
    assert_eq!(r.read_fixed_opaque::<5>().unwrap(), [1, 2, 3, 4, 5]);
    assert_eq!(r.read_opaque(16).unwrap(), b"abc");
    assert_eq!(r.read_string(32).unwrap(), "hello-utf8-✓");
    assert!(r.is_empty());

    // Error paths: invalid bool and length overflow.
    let mut bad_bool = XdrWriter::new();
    bad_bool.write_u32(7);
    assert_eq!(
        XdrReader::new(bad_bool.as_slice()).read_bool(),
        Err(XdrError::InvalidBool(7))
    );
    assert_eq!(
        XdrReader::new(&raw).read_opaque(2),
        Err(XdrError::LengthLimitExceeded {
            len: 0xDEAD_BEEF,
            max: 2
        })
    );

    // Single-fragment and multi-fragment RFC 5531 record marking.
    let single = encode_rpc_record(&raw);
    assert_eq!(decode_rpc_record(&single).unwrap(), raw);

    let multi = encode_rpc_record_fragmented(&raw, 7);
    let mut cursor = Cursor::new(multi);
    assert_eq!(read_rpc_record(&mut cursor).unwrap().unwrap(), raw);
    // Clean EOF after last record returns Ok(None).
    assert_eq!(read_rpc_record(&mut cursor).unwrap(), None);

    // Stream write + read round-trip.
    let mut stream_buf = Vec::new();
    write_rpc_record(&mut stream_buf, b"aligned!").unwrap();
    let mut reader = Cursor::new(stream_buf);
    assert_eq!(
        read_rpc_record(&mut reader).unwrap().unwrap(),
        b"aligned!".to_vec()
    );
}

#[test]
fn auth_unix_rejects_wrong_uid_missing_cred_and_malformed_body() {
    let engine = setup_engine_with_two_views();
    let disp = NfsDispatcher::new(engine, OWNER_UID);

    let mut mnt_args = XdrWriter::new();
    mnt_args.write_string("/");

    // Wrong uid (1000 != 501) on MOUNTv3 MNT -> AuthTooWeak.
    let wrong_mnt = call_rpc(
        &disp,
        1,
        MOUNT_PROGRAM,
        MOUNT_V3,
        MOUNTPROC3_MNT,
        foreign_cred(1000),
        mnt_args.as_slice(),
    );
    assert_eq!(
        wrong_mnt.body,
        RpcReplyBody::Denied(RpcRejectedReply::AuthError(AuthStat::AuthTooWeak))
    );

    // Wrong uid on NFSv3 NULL -> AuthTooWeak.
    let wrong_null = call_rpc(
        &disp,
        2,
        NFS_PROGRAM,
        NFS_V3,
        NFSPROC3_NULL,
        foreign_cred(0),
        &[],
    );
    assert_eq!(
        wrong_null.body,
        RpcReplyBody::Denied(RpcRejectedReply::AuthError(AuthStat::AuthTooWeak))
    );

    // AUTH_NONE on NULL is allowed for standard RPC liveness pings...
    let anon_null = call_rpc(
        &disp,
        3,
        NFS_PROGRAM,
        NFS_V3,
        NFSPROC3_NULL,
        OpaqueAuth::none(),
        &[],
    );
    assert!(matches!(
        &anon_null.body,
        RpcReplyBody::Accepted {
            stat: RpcAcceptStat::Success(b),
            ..
        } if b.is_empty()
    ));

    // ...but AUTH_NONE on non-NULL procedures is strictly rejected.
    let mut getattr_args = XdrWriter::new();
    disp.root_file_handle().encode(&mut getattr_args);
    let anon_getattr = call_rpc(
        &disp,
        4,
        NFS_PROGRAM,
        NFS_V3,
        NFSPROC3_GETATTR,
        OpaqueAuth::none(),
        getattr_args.as_slice(),
    );
    assert_eq!(
        anon_getattr.body,
        RpcReplyBody::Denied(RpcRejectedReply::AuthError(AuthStat::AuthTooWeak))
    );

    // Malformed AUTH_UNIX body -> AuthBadCred.
    let broken = OpaqueAuth {
        flavor: 1,
        body: vec![0xFF, 0x00],
    };
    let bad_cred = call_rpc(
        &disp,
        5,
        NFS_PROGRAM,
        NFS_V3,
        NFSPROC3_GETATTR,
        broken,
        getattr_args.as_slice(),
    );
    assert_eq!(
        bad_cred.body,
        RpcReplyBody::Denied(RpcRejectedReply::AuthError(AuthStat::AuthBadCred))
    );
}

#[test]
fn mount_v3_and_nfs_v3_full_lifecycle_cow_rofs_xdev_and_notsupp() {
    let engine = setup_engine_with_two_views();
    let disp = NfsDispatcher::new(engine.clone(), OWNER_UID).with_owner_gid(OWNER_GID);

    // 1. MOUNTv3 NULL, MNT("/"), MNT("/missing"), DUMP, UMNT("/")
    assert!(call_mount_ok(&disp, MOUNTPROC3_NULL, &[]).is_empty());

    let mut mnt_w = XdrWriter::new();
    mnt_w.write_string("/");
    let mnt_res = call_mount_ok(&disp, MOUNTPROC3_MNT, mnt_w.as_slice());
    let mut mnt_r = XdrReader::new(&mnt_res);
    assert_eq!(mnt_r.read_u32().unwrap(), MNT3_OK);
    let root_fh = mnt_r.read_opaque(64).unwrap();
    assert_eq!(mnt_r.read_u32().unwrap(), 1);
    assert_eq!(mnt_r.read_u32().unwrap(), 1); // AUTH_UNIX
    assert_eq!(disp.active_mount_count(), 1);

    let mut bad_mnt_w = XdrWriter::new();
    bad_mnt_w.write_string("/nonexistent");
    let bad_mnt_res = call_mount_ok(&disp, MOUNTPROC3_MNT, bad_mnt_w.as_slice());
    assert_eq!(
        XdrReader::new(&bad_mnt_res).read_u32().unwrap(),
        MNT3ERR_NOENT
    );

    let dump_res = call_mount_ok(&disp, MOUNTPROC3_DUMP, &[]);
    assert!(!XdrReader::new(&dump_res).read_bool().unwrap());

    // 2. GETATTR & ACCESS on read-only <mount>/ root
    let mut ga_w = XdrWriter::new();
    ga_w.write_opaque(&root_fh);
    let ga_res = call_nfs_ok(&disp, NFSPROC3_GETATTR, ga_w.as_slice());
    let mut ga_r = XdrReader::new(&ga_res);
    assert_eq!(ga_r.read_u32().unwrap(), NFS3_OK);
    let root_attr = NfsFattr3::decode(&mut ga_r).unwrap();
    assert_eq!(root_attr.ftype, NfsFileType::Directory);
    assert_eq!(root_attr.mode, 0o555);
    assert_eq!(root_attr.uid, OWNER_UID);
    assert_eq!(root_attr.gid, OWNER_GID);

    let mut acc_w = XdrWriter::new();
    acc_w.write_opaque(&root_fh);
    acc_w.write_u32(ACCESS3_READ | ACCESS3_LOOKUP | ACCESS3_MODIFY | ACCESS3_DELETE);
    let acc_res = call_nfs_ok(&disp, NFSPROC3_ACCESS, acc_w.as_slice());
    let mut acc_r = XdrReader::new(&acc_res);
    assert_eq!(acc_r.read_u32().unwrap(), NFS3_OK);
    assert!(acc_r.read_bool().unwrap());
    let _ = NfsFattr3::decode(&mut acc_r).unwrap();
    assert_eq!(acc_r.read_u32().unwrap(), ACCESS3_READ | ACCESS3_LOOKUP);

    // 3. Read-only <mount>/ root rejects mutations with NFS3ERR_ROFS (30).
    let mut ro_mkdir = XdrWriter::new();
    ro_mkdir.write_opaque(&root_fh);
    ro_mkdir.write_string("illegal-view");
    NfsSattr3::default().encode(&mut ro_mkdir);
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_MKDIR, ro_mkdir.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_ROFS
    );

    let mut ro_create = XdrWriter::new();
    ro_create.write_opaque(&root_fh);
    ro_create.write_string("illegal.txt");
    ro_create.write_u32(0); // UNCHECKED
    NfsSattr3::default().encode(&mut ro_create);
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_CREATE, ro_create.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_ROFS
    );

    let mut ro_rm = XdrWriter::new();
    ro_rm.write_opaque(&root_fh);
    ro_rm.write_string("view-a");
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_RMDIR, ro_rm.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_ROFS
    );

    let mut ro_setattr = XdrWriter::new();
    ro_setattr.write_opaque(&root_fh);
    NfsSattr3 {
        mode: Some(0o777),
        ..NfsSattr3::default()
    }
    .encode(&mut ro_setattr);
    ro_setattr.write_bool(false);
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_SETATTR, ro_setattr.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_ROFS
    );

    // 4. LOOKUP view-a & view-b, `.` / `..` / missing -> NFS3ERR_NOENT, READ & READLINK, and CoW WRITE isolation
    let (view_a_fh, view_a_attr) = lookup_ok(&disp, &root_fh, "view-a");
    let (dot_fh, dot_attr) = lookup_ok(&disp, &view_a_fh, ".");
    assert_eq!(dot_fh, view_a_fh);
    assert_eq!(dot_attr.fileid, view_a_attr.fileid);
    let (dotdot_fh, _) = lookup_ok(&disp, &view_a_fh, "..");
    assert_eq!(dotdot_fh, root_fh);

    let mut missing_lk = XdrWriter::new();
    missing_lk.write_opaque(&view_a_fh);
    missing_lk.write_string("does-not-exist.txt");
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_LOOKUP, missing_lk.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_NOENT
    );

    let (view_b_fh, _) = lookup_ok(&disp, &root_fh, "view-b");
    let (readme_a_fh, readme_a_attr) = lookup_ok(&disp, &view_a_fh, "README.md");
    let (readme_b_fh, _) = lookup_ok(&disp, &view_b_fh, "README.md");
    assert_eq!(readme_a_attr.size, 16);

    // READLINK on `latest`
    let (latest_fh, latest_attr) = lookup_ok(&disp, &view_a_fh, "latest");
    assert_eq!(latest_attr.ftype, NfsFileType::Symlink);
    let mut rl_w = XdrWriter::new();
    rl_w.write_opaque(&latest_fh);
    let rl_res = call_nfs_ok(&disp, NFSPROC3_READLINK, rl_w.as_slice());
    let mut rl_r = XdrReader::new(&rl_res);
    assert_eq!(rl_r.read_u32().unwrap(), NFS3_OK);
    assert!(rl_r.read_bool().unwrap());
    let _ = NfsFattr3::decode(&mut rl_r).unwrap();
    assert_eq!(rl_r.read_string(1024).unwrap(), "src/lib.rs");

    // CoW WRITE on view-a/README.md at offset 6
    let new_tail = b"view-a overlay!\n";
    let mut wr_w = XdrWriter::new();
    wr_w.write_opaque(&readme_a_fh);
    wr_w.write_u64(6);
    wr_w.write_u32(new_tail.len() as u32);
    wr_w.write_u32(0); // UNSTABLE requested -> server upgrades to NFS3_FILE_STABLE
    wr_w.write_opaque(new_tail);
    let wr_res = call_nfs_ok(&disp, NFSPROC3_WRITE, wr_w.as_slice());
    let mut wr_r = XdrReader::new(&wr_res);
    assert_eq!(wr_r.read_u32().unwrap(), NFS3_OK);
    // skip wcc_data: pre_op_attr (bool + 24B) + post_op_attr (bool + 84B)
    assert!(wr_r.read_bool().unwrap());
    let _ = wr_r.read_fixed_opaque::<24>().unwrap();
    assert!(wr_r.read_bool().unwrap());
    let updated_attr = NfsFattr3::decode(&mut wr_r).unwrap();
    assert_eq!(updated_attr.size, 22);
    assert_eq!(wr_r.read_u32().unwrap(), new_tail.len() as u32);
    assert_eq!(wr_r.read_u32().unwrap(), NFS3_FILE_STABLE);
    let _verf = wr_r.read_fixed_opaque::<8>().unwrap();

    // Verify READ on view-a sees CoW bytes, while view-b still reads untouched Base bytes!
    let read_file = |fh: &[u8]| -> Vec<u8> {
        let mut rw = XdrWriter::new();
        rw.write_opaque(fh);
        rw.write_u64(0);
        rw.write_u32(4096);
        let res = call_nfs_ok(&disp, NFSPROC3_READ, rw.as_slice());
        let mut rr = XdrReader::new(&res);
        assert_eq!(rr.read_u32().unwrap(), NFS3_OK);
        assert!(rr.read_bool().unwrap());
        let _ = NfsFattr3::decode(&mut rr).unwrap();
        let count = rr.read_u32().unwrap() as usize;
        assert!(rr.read_bool().unwrap()); // eof
        let bytes = rr.read_opaque(4096).unwrap();
        assert_eq!(bytes.len(), count);
        bytes
    };
    assert_eq!(read_file(&readme_a_fh), b"hello view-a overlay!\n");
    assert_eq!(read_file(&readme_b_fh), b"hello from base\n");

    // 5. CREATE, SETATTR, intra-View RENAME preserving open filehandle, SYMLINK, MKDIR/RMDIR
    let mut cr_w = XdrWriter::new();
    cr_w.write_opaque(&view_a_fh);
    cr_w.write_string("notes.txt");
    cr_w.write_u32(1); // GUARDED
    NfsSattr3 {
        mode: Some(0o600),
        ..NfsSattr3::default()
    }
    .encode(&mut cr_w);
    let cr_res = call_nfs_ok(&disp, NFSPROC3_CREATE, cr_w.as_slice());
    let mut cr_r = XdrReader::new(&cr_res);
    assert_eq!(cr_r.read_u32().unwrap(), NFS3_OK);
    assert!(cr_r.read_bool().unwrap());
    let notes_fh = cr_r.read_opaque(64).unwrap();

    // Second GUARDED create on existing file returns NFS3ERR_EXIST.
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_CREATE, cr_w.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_EXIST
    );

    // Write into notes.txt, then RENAME notes.txt -> src/moved_notes.txt and read via original fh!
    let mut notes_wr = XdrWriter::new();
    notes_wr.write_opaque(&notes_fh);
    notes_wr.write_u64(0);
    notes_wr.write_u32(9);
    notes_wr.write_u32(NFS3_FILE_STABLE);
    notes_wr.write_opaque(b"persisted");
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_WRITE, notes_wr.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3_OK
    );

    let (src_fh, _) = lookup_ok(&disp, &view_a_fh, "src");
    let mut ren_same = XdrWriter::new();
    ren_same.write_opaque(&view_a_fh);
    ren_same.write_string("notes.txt");
    ren_same.write_opaque(&src_fh);
    ren_same.write_string("moved_notes.txt");
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_RENAME, ren_same.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3_OK
    );
    assert_eq!(read_file(&notes_fh), b"persisted");

    // SETATTR guard mismatch vs truncate
    let mut bad_guard_sa = XdrWriter::new();
    bad_guard_sa.write_opaque(&notes_fh);
    NfsSattr3 {
        size: Some(4),
        ..NfsSattr3::default()
    }
    .encode(&mut bad_guard_sa);
    bad_guard_sa.write_bool(true);
    bad_guard_sa.write_u32(999_999);
    bad_guard_sa.write_u32(0);
    assert_eq!(
        XdrReader::new(&call_nfs_ok(
            &disp,
            NFSPROC3_SETATTR,
            bad_guard_sa.as_slice()
        ))
        .read_u32()
        .unwrap(),
        NFS3ERR_CTIME_MISMATCH
    );

    let mut trunc_sa = XdrWriter::new();
    trunc_sa.write_opaque(&notes_fh);
    NfsSattr3 {
        mode: Some(0o755),
        size: Some(4),
        mtime: Some(Timestamp::new(1_700_000_000, 500)),
        ..NfsSattr3::default()
    }
    .encode(&mut trunc_sa);
    trunc_sa.write_bool(false);
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_SETATTR, trunc_sa.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3_OK
    );
    assert_eq!(read_file(&notes_fh), b"pers");

    // 6. Cross-View RENAME returns NFS3ERR_XDEV (18)
    let mut ren_xdev = XdrWriter::new();
    ren_xdev.write_opaque(&view_a_fh);
    ren_xdev.write_string("README.md");
    ren_xdev.write_opaque(&view_b_fh);
    ren_xdev.write_string("README_stolen.md");
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_RENAME, ren_xdev.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_XDEV
    );

    // 7. LINK and MKNOD return NFS3ERR_NOTSUPP (10004)
    let mut link_w = XdrWriter::new();
    link_w.write_opaque(&readme_a_fh);
    link_w.write_opaque(&view_a_fh);
    link_w.write_string("hardlink.md");
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_LINK, link_w.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_NOTSUPP
    );

    let mut mknod_w = XdrWriter::new();
    mknod_w.write_opaque(&view_a_fh);
    mknod_w.write_string("fifo");
    mknod_w.write_u32(7); // NF3FIFO
    NfsSattr3::default().encode(&mut mknod_w);
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_MKNOD, mknod_w.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_NOTSUPP
    );

    // 8. MKDIR, RMDIR (non-empty vs empty), SYMLINK, REMOVE + stale filehandle verification
    let mut mkdir_w = XdrWriter::new();
    mkdir_w.write_opaque(&view_a_fh);
    mkdir_w.write_string("sub");
    NfsSattr3::default().encode(&mut mkdir_w);
    let mkdir_res = call_nfs_ok(&disp, NFSPROC3_MKDIR, mkdir_w.as_slice());
    let mut mkdir_r = XdrReader::new(&mkdir_res);
    assert_eq!(mkdir_r.read_u32().unwrap(), NFS3_OK);
    assert!(mkdir_r.read_bool().unwrap());
    let sub_fh = mkdir_r.read_opaque(64).unwrap();

    // Non-empty RMDIR on `src` returns NFS3ERR_NOTEMPTY.
    let mut rmdir_nonempty = XdrWriter::new();
    rmdir_nonempty.write_opaque(&view_a_fh);
    rmdir_nonempty.write_string("src");
    assert_eq!(
        XdrReader::new(&call_nfs_ok(
            &disp,
            NFSPROC3_RMDIR,
            rmdir_nonempty.as_slice()
        ))
        .read_u32()
        .unwrap(),
        NFS3ERR_NOTEMPTY
    );

    // Empty RMDIR on `sub` succeeds and invalidates `sub_fh` as NFS3ERR_STALE.
    let mut rmdir_ok = XdrWriter::new();
    rmdir_ok.write_opaque(&view_a_fh);
    rmdir_ok.write_string("sub");
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_RMDIR, rmdir_ok.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3_OK
    );
    let mut stale_ga = XdrWriter::new();
    stale_ga.write_opaque(&sub_fh);
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_GETATTR, stale_ga.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_STALE
    );

    let mut sym_w = XdrWriter::new();
    sym_w.write_opaque(&view_a_fh);
    sym_w.write_string("ext-link");
    NfsSattr3::default().encode(&mut sym_w);
    sym_w.write_string("/tmp/outside-target");
    let sym_res = call_nfs_ok(&disp, NFSPROC3_SYMLINK, sym_w.as_slice());
    let mut sym_r = XdrReader::new(&sym_res);
    assert_eq!(sym_r.read_u32().unwrap(), NFS3_OK);
    assert!(sym_r.read_bool().unwrap());
    let sym_fh = sym_r.read_opaque(64).unwrap();

    let mut rm_w = XdrWriter::new();
    rm_w.write_opaque(&view_a_fh);
    rm_w.write_string("ext-link");
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_REMOVE, rm_w.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3_OK
    );
    let mut stale_sym = XdrWriter::new();
    stale_sym.write_opaque(&sym_fh);
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_GETATTR, stale_sym.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_STALE
    );

    // 9. READDIR cookie pagination + READDIRPLUS + FSSTAT/FSINFO/PATHCONF/FLUSH_WRITES
    let mut rd_small = XdrWriter::new();
    rd_small.write_opaque(&view_a_fh);
    rd_small.write_u64(0);
    rd_small.write_fixed_opaque(&[0u8; 8]);
    rd_small.write_u32(64);
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_READDIR, rd_small.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_TOOSMALL
    );

    let mut collected_names = Vec::new();
    let mut cookie = 0u64;
    loop {
        let mut rd_w = XdrWriter::new();
        rd_w.write_opaque(&view_a_fh);
        rd_w.write_u64(cookie);
        rd_w.write_fixed_opaque(&[0u8; 8]);
        rd_w.write_u32(180); // tight buffer forces multi-page cookie continuation
        let rd_res = call_nfs_ok(&disp, NFSPROC3_READDIR, rd_w.as_slice());
        let mut rd_r = XdrReader::new(&rd_res);
        assert_eq!(rd_r.read_u32().unwrap(), NFS3_OK);
        assert!(rd_r.read_bool().unwrap());
        let _ = NfsFattr3::decode(&mut rd_r).unwrap();
        let _verf = rd_r.read_fixed_opaque::<8>().unwrap();
        while rd_r.read_bool().unwrap() {
            let _ino = rd_r.read_u64().unwrap();
            let name = rd_r.read_string(255).unwrap();
            cookie = rd_r.read_u64().unwrap();
            collected_names.push(name);
        }
        let eof = rd_r.read_bool().unwrap();
        if eof {
            break;
        }
    }
    assert_eq!(
        collected_names,
        vec![".", "..", "README.md", "latest", "src"]
    );

    let mut rdp_w = XdrWriter::new();
    rdp_w.write_opaque(&root_fh);
    rdp_w.write_u64(0);
    rdp_w.write_fixed_opaque(&[0u8; 8]);
    rdp_w.write_u32(4096);
    rdp_w.write_u32(8192);
    let rdp_res = call_nfs_ok(&disp, NFSPROC3_READDIRPLUS, rdp_w.as_slice());
    let mut rdp_r = XdrReader::new(&rdp_res);
    assert_eq!(rdp_r.read_u32().unwrap(), NFS3_OK);
    assert!(rdp_r.read_bool().unwrap());
    let _ = NfsFattr3::decode(&mut rdp_r).unwrap();
    let _ = rdp_r.read_fixed_opaque::<8>().unwrap();
    let mut root_entries = Vec::new();
    while rdp_r.read_bool().unwrap() {
        let _ino = rdp_r.read_u64().unwrap();
        let name = rdp_r.read_string(255).unwrap();
        let _ck = rdp_r.read_u64().unwrap();
        if rdp_r.read_bool().unwrap() {
            let _ = NfsFattr3::decode(&mut rdp_r).unwrap();
        }
        if rdp_r.read_bool().unwrap() {
            let _ = rdp_r.read_opaque(64).unwrap();
        }
        root_entries.push(name);
    }
    assert!(rdp_r.read_bool().unwrap());
    assert_eq!(root_entries, vec![".", "..", "view-a", "view-b"]);

    // FSSTAT, FSINFO (verifying FSF3_LINK is NOT set), PATHCONF, FLUSH_WRITES, bad handle
    let mut fs_w = XdrWriter::new();
    fs_w.write_opaque(&root_fh);
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_FSSTAT, fs_w.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3_OK
    );

    let fsinfo_res = call_nfs_ok(&disp, NFSPROC3_FSINFO, fs_w.as_slice());
    let mut fsi_r = XdrReader::new(&fsinfo_res);
    assert_eq!(fsi_r.read_u32().unwrap(), NFS3_OK);
    assert!(fsi_r.read_bool().unwrap());
    let _ = NfsFattr3::decode(&mut fsi_r).unwrap();
    for _ in 0..7 {
        let _ = fsi_r.read_u32().unwrap();
    }
    let _maxf = fsi_r.read_u64().unwrap();
    let _gran_s = fsi_r.read_u32().unwrap();
    let _gran_ns = fsi_r.read_u32().unwrap();
    let props = fsi_r.read_u32().unwrap();
    assert_eq!(props & FSF3_LINK, 0);
    assert_eq!(props, FSF3_SYMLINK | FSF3_HOMOGENEOUS | FSF3_CANSETTIME);

    let pc_res = call_nfs_ok(&disp, NFSPROC3_PATHCONF, fs_w.as_slice());
    let mut pc_r = XdrReader::new(&pc_res);
    assert_eq!(pc_r.read_u32().unwrap(), NFS3_OK);
    assert!(pc_r.read_bool().unwrap());
    let _ = NfsFattr3::decode(&mut pc_r).unwrap();
    assert_eq!(pc_r.read_u32().unwrap(), 1); // linkmax
    assert_eq!(pc_r.read_u32().unwrap(), 255); // name_max

    let mut fl_w = XdrWriter::new();
    fl_w.write_opaque(&notes_fh);
    fl_w.write_u64(0);
    fl_w.write_u32(0);
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_FLUSH_WRITES, fl_w.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3_OK
    );

    let mut bad_fh_w = XdrWriter::new();
    bad_fh_w.write_opaque(b"short");
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_GETATTR, bad_fh_w.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_BADHANDLE
    );

    let wrong_epoch_fh = NfsFileHandle::new(0x9999_9999, 1);
    let mut epoch_w = XdrWriter::new();
    wrong_epoch_fh.encode(&mut epoch_w);
    assert_eq!(
        XdrReader::new(&call_nfs_ok(&disp, NFSPROC3_GETATTR, epoch_w.as_slice()))
            .read_u32()
            .unwrap(),
        NFS3ERR_STALE
    );

    // UMNT decrements active mount count back to 0.
    let _ = call_mount_ok(&disp, MOUNTPROC3_UMNT, mnt_w.as_slice());
    assert_eq!(disp.active_mount_count(), 0);
}

#[test]
fn loopback_tcp_server_end_to_end_round_trip() {
    let engine = setup_engine_with_two_views();
    let cfg = NfsMountConfig::loopback(0, OWNER_UID, "/Users/alice/.bit/views").unwrap();

    let server = match NfsLoopbackServer::bind(cfg, engine) {
        Ok(s) => s,
        Err(NfsServerError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            // Host sandbox disallows binding loopback TCP sockets; stream framing is covered above.
            return;
        }
        Err(other) => panic!("unexpected bind error: {other}"),
    };

    let port = server.bound_port();
    assert_ne!(port, 0);
    assert_eq!(server.local_addr().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(server.mount_nfs_args()[1].contains(&format!("port={port},mountport={port}")));

    let running = server.start().unwrap();
    let mut client = TcpStream::connect(running.local_addr()).unwrap();

    let mut mnt_args = XdrWriter::new();
    mnt_args.write_string("/");
    let mnt_call = RpcCall {
        xid: 101,
        rpcvers: RPC_VERSION,
        prog: MOUNT_PROGRAM,
        vers: MOUNT_V3,
        proc_num: MOUNTPROC3_MNT,
        cred: owner_cred(),
        verf: OpaqueAuth::none(),
        args: mnt_args.as_slice(),
    };
    write_rpc_record(&mut client, &mnt_call.encode()).unwrap();
    let raw_reply = read_rpc_record(&mut client).unwrap().unwrap();
    let reply = RpcReply::decode(&raw_reply).unwrap();
    assert_eq!(reply.xid, 101);
    let RpcReplyBody::Accepted {
        stat: RpcAcceptStat::Success(payload),
        ..
    } = reply.body
    else {
        panic!("expected MNT success over TCP");
    };
    let mut r = XdrReader::new(&payload);
    assert_eq!(r.read_u32().unwrap(), MNT3_OK);
    let root_fh = r.read_opaque(64).unwrap();

    // Verify wrong-uid rejection over TCP on the same connection.
    let mut ga_args = XdrWriter::new();
    ga_args.write_opaque(&root_fh);
    let bad_call = RpcCall {
        xid: 102,
        rpcvers: RPC_VERSION,
        prog: NFS_PROGRAM,
        vers: NFS_V3,
        proc_num: NFSPROC3_GETATTR,
        cred: foreign_cred(999),
        verf: OpaqueAuth::none(),
        args: ga_args.as_slice(),
    };
    write_rpc_record(&mut client, &bad_call.encode()).unwrap();
    let bad_raw = read_rpc_record(&mut client).unwrap().unwrap();
    let bad_reply = RpcReply::decode(&bad_raw).unwrap();
    assert_eq!(
        bad_reply.body,
        RpcReplyBody::Denied(RpcRejectedReply::AuthError(AuthStat::AuthTooWeak))
    );

    drop(client);
    running.shutdown();
}
