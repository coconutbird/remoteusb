//! Pure policy/protocol and loopback lifecycle tests; no platform operations.

use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio::time::{Instant, timeout};

use super::{
    DEVICE_BYTES, IMPORT, IMPORT_REJECTED, MAX_DEVICES, Policy, busid, decode_device_list,
    decode_import, finish_mutation, forward, handle, run, settle_mutation,
};
use crate::inventory::Device;

const WAIT: Duration = Duration::from_secs(3);

fn policy(allowed: Option<&[&str]>) -> Policy {
    Policy {
        allowed: allowed.map(|ids| Arc::new(ids.iter().map(|id| (*id).to_owned()).collect())),
        reserved: Arc::default(),
    }
}

fn field(id: &str) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..id.len()].copy_from_slice(id.as_bytes());
    bytes
}

fn device(id: &str, shared: bool, busy: bool) -> Device {
    Device {
        busid: id.to_owned(),
        vendor: 0x1050,
        product: 0x0407,
        name: "USB device".to_owned(),
        shared,
        busy,
    }
}

fn descriptor(id: &str, interfaces: u8) -> [u8; DEVICE_BYTES] {
    let mut bytes = [0; DEVICE_BYTES];
    bytes[256..288].copy_from_slice(&field(id));
    bytes[300..304].copy_from_slice(&[0x10, 0x50, 4, 7]);
    bytes[311] = interfaces;
    bytes
}

async fn sockets() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (socket, _) = listener.accept().await.unwrap();
    (socket, peer)
}

#[test]
fn native_busids_require_a_single_valid_zero_padded_identifier() {
    for id in ["1-2", "12-4.1", "device_1", "A"] {
        assert_eq!(busid(&field(id)).unwrap(), id);
    }
    for id in ["", "../device", "a/b", "a b", "\u{1b}[2J", "é"] {
        assert!(busid(&field(id)).is_err());
    }
    assert!(busid(&[b'1'; 32]).is_err());
    let mut padded = field("1-2");
    padded[31] = b'a';
    assert!(busid(&padded).is_err());
}

#[test]
fn reservations_exclude_same_device_until_owner_cleanup_finishes() {
    let policy = policy(Some(&["1-2", "1-3"]));
    let first = policy.reserve("1-2").unwrap();
    assert!(
        matches!(policy.reserve("1-2"), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    assert!(
        matches!(policy.reserve("1-4"), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    let second = policy.reserve("1-3").unwrap();
    drop(first);
    let next = policy.reserve("1-2").unwrap();
    drop(next);
    drop(second);
    assert!(
        policy
            .reserved
            .lock()
            .is_ok_and(|reserved| reserved.is_empty())
    );
}

#[test]
fn inventory_includes_unshared_candidates_and_marks_owned_and_native_busy() {
    let selected = policy(Some(&["1-2", "1-3", "1-4"]));
    let reservation = selected.reserve("1-2").unwrap();
    let mut devices = vec![
        device("1-2", false, false),
        device("1-3", true, false),
        device("1-4", true, true),
        device("1-5", false, false),
    ];
    selected.filter(&mut devices).unwrap();
    assert_eq!(devices.len(), 3);
    assert!(!devices[0].shared);
    assert!(devices[0].busy);
    assert!(devices[1].shared);
    assert!(!devices[1].busy);
    assert!(devices[2].busy);
    drop(reservation);
    let mut available = vec![device("1-2", false, false)];
    selected.filter(&mut available).unwrap();
    assert!(!available[0].busy);
    assert!(policy(None).permits("1-9"));
    assert!(!policy(Some(&[])).permits("1-9"));
}

#[test]
fn failed_cleanup_keeps_the_busid_reserved_until_manager_teardown() {
    let policy = policy(None);
    policy.reserve("1-2").unwrap().preserve();
    assert!(
        matches!(policy.reserve("1-2"), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let mut devices = vec![device("1-2", true, false)];
    policy.filter(&mut devices).unwrap();
    assert!(devices[0].busy);
    assert!(policy.reserve("1-3").is_ok());
}

#[tokio::test]
async fn native_lists_filter_whole_records_without_fabricating_descriptors() {
    let mut bytes = vec![1, 0x11, 0, 5, 0, 0, 0, 0];
    bytes.extend_from_slice(&3_u32.to_be_bytes());
    for (id, interfaces) in [("1-1", 3_u8), ("1-2", 2), ("1-3", 1)] {
        bytes.extend_from_slice(&descriptor(id, interfaces));
        for index in 0..interfaces {
            bytes.extend_from_slice(&[index, 0xaa, 0xbb, 0xcc]);
        }
    }
    let allowed = policy(Some(&["1-2"]));
    let result = decode_device_list(&mut bytes.as_slice(), &allowed)
        .await
        .unwrap();
    let mut expected = vec![1, 0x11, 0, 5, 0, 0, 0, 0];
    expected.extend_from_slice(&1_u32.to_be_bytes());
    expected.extend_from_slice(&descriptor("1-2", 2));
    expected.extend_from_slice(&[0, 0xaa, 0xbb, 0xcc, 1, 0xaa, 0xbb, 0xcc]);
    assert_eq!(result, expected);
    assert_eq!(
        decode_device_list(&mut bytes.as_slice(), &policy(None))
            .await
            .unwrap(),
        bytes
    );
}

#[tokio::test]
async fn native_list_bounds_and_truncations_are_rejected() {
    let header = [1, 0x11, 0, 5, 0, 0, 0, 0];
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(&(MAX_DEVICES + 1).to_be_bytes());
    assert!(
        decode_device_list(&mut bytes.as_slice(), &policy(None))
            .await
            .is_err()
    );
    bytes.truncate(8);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&descriptor("1-2", 1));
    assert!(
        decode_device_list(&mut bytes.as_slice(), &policy(None))
            .await
            .is_err()
    );
    let rejected = [1, 0x11, 0, 5, 0, 0, 0, 3];
    assert_eq!(
        decode_device_list(&mut rejected.as_slice(), &policy(None))
            .await
            .unwrap(),
        rejected
    );
}

#[tokio::test]
async fn native_import_preserves_real_reply_and_requires_requested_identity() {
    let mut bytes = vec![1, 0x11, 0, 3, 0, 0, 0, 0];
    bytes.extend_from_slice(&descriptor("1-2", 3));
    let (decoded, length) = decode_import(&mut bytes.as_slice(), &field("1-2"))
        .await
        .unwrap();
    assert_eq!(length, bytes.len());
    assert_eq!(decoded.as_slice(), bytes);
    assert!(
        decode_import(&mut bytes.as_slice(), &field("1-3"))
            .await
            .is_err()
    );
    bytes.pop();
    assert!(
        decode_import(&mut bytes.as_slice(), &field("1-2"))
            .await
            .is_err()
    );
    for status in 1_u8..=5 {
        let denied = [1, 0x11, 0, 3, 0, 0, 0, status];
        let (reply, length) = decode_import(&mut denied.as_slice(), &field("1-2"))
            .await
            .unwrap();
        assert_eq!(length, 8);
        assert_eq!(&reply[..8], &denied);
    }
    let wrong = [1, 0x11, 0, 5, 0, 0, 0, 1];
    assert!(
        decode_import(&mut wrong.as_slice(), &field("1-2"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn denied_invalid_and_busy_native_imports_have_negative_proof_without_binding() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    for mode in 0..3 {
        let (socket, mut peer) = sockets().await;
        let policy = policy(Some(&["1-2"]));
        let reservation = if mode == 2 {
            Some(policy.reserve("1-2").unwrap())
        } else {
            None
        };
        let (_owner, stop) = watch::channel(false);
        let task = tokio::spawn(handle(
            socket,
            upstream.local_addr().unwrap(),
            policy,
            stop,
            WAIT,
        ));
        peer.write_all(&IMPORT).await.unwrap();
        let id = match mode {
            0 => field("1-3"),
            1 => field("../bad"),
            _ => field("1-2"),
        };
        peer.write_all(&id).await.unwrap();
        let mut reply = [0; 8];
        timeout(WAIT, peer.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, IMPORT_REJECTED);
        timeout(WAIT, task).await.unwrap().unwrap().unwrap();
        drop(reservation);
    }
    assert!(
        timeout(Duration::from_millis(20), upstream.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn mutation_deadline_waits_for_completion_and_keeps_exclusion() {
    let (socket, mut peer) = sockets().await;
    let policy = policy(None);
    let reservation = policy.reserve("1-2").unwrap();
    let (_stop, mut stopped) = watch::channel(false);
    let (release, released) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut socket = Some(socket);
        let (result, cancelled) = settle_mutation(
            async {
                released.await.map_err(io::Error::other)?;
                Ok::<_, io::Error>(())
            },
            &mut socket,
            Instant::now(),
            &mut stopped,
        )
        .await;
        assert!(cancelled);
        result.unwrap();
        assert!(socket.is_some());
        drop(socket);
        drop(reservation);
    });
    assert!(
        timeout(Duration::from_millis(20), peer.read_u8())
            .await
            .is_err()
    );
    assert!(policy.reserve("1-2").is_err());
    assert!(!task.is_finished());
    release.send(()).unwrap();
    timeout(WAIT, task).await.unwrap().unwrap();
    assert!(policy.reserve("1-2").is_ok());
}

#[tokio::test]
async fn shutdown_after_mutation_deadline_closes_socket_but_does_not_cancel() {
    let (socket, mut peer) = sockets().await;
    let (stop, mut stopped) = watch::channel(false);
    let (release, released) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut socket = Some(socket);
        let (result, cancelled) = settle_mutation(
            async {
                released.await.map_err(io::Error::other)?;
                Ok::<_, io::Error>(())
            },
            &mut socket,
            Instant::now(),
            &mut stopped,
        )
        .await;
        assert!(cancelled);
        result.unwrap();
        assert!(socket.is_none());
    });
    assert!(
        timeout(Duration::from_millis(20), peer.read_u8())
            .await
            .is_err()
    );
    stop.send_replace(true);
    assert_eq!(
        timeout(WAIT, peer.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(!task.is_finished());
    release.send(()).unwrap();
    timeout(WAIT, task).await.unwrap().unwrap();
}

#[tokio::test]
async fn peer_half_close_during_mutation_closes_owned_socket_and_awaits_completion() {
    let (socket, mut peer) = sockets().await;
    let (_stop, mut stopped) = watch::channel(false);
    let (release, released) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut socket = Some(socket);
        let (result, cancelled) = settle_mutation(
            async {
                released.await.map_err(io::Error::other)?;
                Ok::<_, io::Error>(())
            },
            &mut socket,
            Instant::now() + WAIT,
            &mut stopped,
        )
        .await;
        result.unwrap();
        assert!(cancelled);
        assert!(socket.is_none());
    });
    peer.shutdown().await.unwrap();
    assert_eq!(
        timeout(WAIT, peer.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(!task.is_finished());
    release.send(()).unwrap();
    timeout(WAIT, task).await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_during_cleanup_closes_socket_and_awaits_restoration() {
    let (socket, mut peer) = sockets().await;
    let (stop, mut stopped) = watch::channel(false);
    let (release, released) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut socket = Some(socket);
        finish_mutation(
            async {
                released.await.unwrap();
            },
            &mut socket,
            &mut stopped,
        )
        .await;
        assert!(socket.is_none());
    });
    stop.send_replace(true);
    assert_eq!(
        timeout(WAIT, peer.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(!task.is_finished());
    release.send(()).unwrap();
    timeout(WAIT, task).await.unwrap().unwrap();
}

#[tokio::test]
async fn bounded_forwarding_closes_on_either_half_close_and_shutdown() {
    for mode in 0..3 {
        let (mut local, mut client) = sockets().await;
        let (mut native, mut server) = sockets().await;
        let (stop, mut stopped) = watch::channel(false);
        let task =
            tokio::spawn(async move { forward(&mut local, &mut native, &mut stopped).await });
        client.write_all(b"outbound bytes").await.unwrap();
        let mut outbound = [0; 14];
        timeout(WAIT, server.read_exact(&mut outbound))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&outbound, b"outbound bytes");
        server.write_all(b"distinct inbound").await.unwrap();
        let mut inbound = [0; 16];
        timeout(WAIT, client.read_exact(&mut inbound))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&inbound, b"distinct inbound");
        assert!(!task.is_finished());
        match mode {
            0 => client.shutdown().await.unwrap(),
            1 => server.shutdown().await.unwrap(),
            _ => {
                stop.send_replace(true);
            }
        }
        timeout(WAIT, task).await.unwrap().unwrap().unwrap();
        assert_eq!(
            timeout(WAIT, client.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(
            timeout(WAIT, server.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn management_capacity_and_shutdown_cover_stalled_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(run(
        listener,
        backend.local_addr().unwrap(),
        Some(BTreeSet::new()),
        async {
            let _ = stopped.await;
        },
        1,
        WAIT,
    ));
    let mut stalled = TcpStream::connect(address).await.unwrap();
    stalled.write_all(&IMPORT[..3]).await.unwrap();
    let mut queued = TcpStream::connect(address).await.unwrap();
    queued.write_all(&IMPORT).await.unwrap();
    queued.write_all(&field("1-2")).await.unwrap();
    let mut reply = [0; 8];
    assert!(
        timeout(Duration::from_millis(20), queued.read_exact(&mut reply))
            .await
            .is_err()
    );
    stalled.shutdown().await.unwrap();
    timeout(WAIT, queued.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, IMPORT_REJECTED);
    let mut final_stalled = TcpStream::connect(address).await.unwrap();
    final_stalled.write_all(&IMPORT[..3]).await.unwrap();
    stop.send(()).unwrap();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    assert!(
        timeout(WAIT, final_stalled.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(20), backend.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn stalled_import_setup_times_out_without_any_platform_operation() {
    let (socket, mut peer) = sockets().await;
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_stop, stop) = watch::channel(false);
    let task = tokio::spawn(handle(
        socket,
        backend.local_addr().unwrap(),
        policy(None),
        stop,
        Duration::from_millis(20),
    ));
    peer.write_all(&IMPORT).await.unwrap();
    peer.write_all(b"1-").await.unwrap();
    let mut reply = [0; 8];
    timeout(WAIT, peer.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, IMPORT_REJECTED);
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    assert!(
        timeout(Duration::from_millis(20), backend.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn peer_half_close_during_native_handshake_closes_native_socket() {
    let (mut socket, mut peer) = sockets().await;
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = backend.local_addr().unwrap();
    let (_stop, mut stop) = watch::channel(false);
    let task = tokio::spawn(async move {
        let outcome = super::attach(
            &mut socket,
            address,
            &field("1-2"),
            Instant::now() + WAIT,
            &mut stop,
        )
        .await;
        assert!(matches!(outcome, super::Attachment::Ended(Ok(()))));
    });
    let (mut native, _) = timeout(WAIT, backend.accept()).await.unwrap().unwrap();
    let mut request = [0; 40];
    timeout(WAIT, native.read_exact(&mut request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&request[..8], &IMPORT);
    assert_eq!(&request[8..], &field("1-2"));
    peer.shutdown().await.unwrap();
    timeout(WAIT, task).await.unwrap().unwrap();
    assert_eq!(
        timeout(WAIT, native.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(
        timeout(WAIT, peer.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
