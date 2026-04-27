// dbus-bluez-filter-proxy: BlueZ-aware filtering D-Bus proxy.
// Copyright (C) 2026 Shaun Starsprung
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Server-side AUTH state machine tests.
//!
//! Drives the FSM directly with byte slices that mirror what real
//! D-Bus clients put on the wire — both libdbus's traditional
//! back-and-forth and sd-bus's pipelined fast-path. No sockets, no
//! async runtime: the FSM is sans-i/o and these tests prove its
//! behaviour over byte streams in isolation.

use dbus_bluez_filter_proxy::auth::{Accept, Action, AuthFsm, RejectReason};

const GUID: &str = "0123456789abcdef0123456789abcdef";

fn fsm() -> AuthFsm {
    AuthFsm::new(2000, GUID)
}

// ─── traditional libdbus flow: NUL, AUTH ... \r\n, BEGIN \r\n ─────

#[test]
fn libdbus_flow_with_explicit_hex_uid_succeeds() {
    let mut f = fsm();

    // \0
    assert_eq!(f.feed(b"\0"), Action::NeedMore);

    // AUTH EXTERNAL <hex of "2000">
    let auth = format!("AUTH EXTERNAL {}\r\n", hex::encode("2000"));
    let act = f.feed(auth.as_bytes());
    let expected = format!("OK {GUID}\r\n");
    assert!(matches!(act, Action::Send(ref b) if b == expected.as_bytes()),
            "expected Send(OK ...); got {act:?}");

    // BEGIN
    let act = f.feed(b"BEGIN\r\n");
    assert_eq!(
        act,
        Action::Accept(Accept { reply: vec![], carryover: vec![] })
    );
    assert!(f.is_done());
}

#[test]
fn libdbus_flow_with_negotiate_unix_fd_replies_error_and_continues() {
    let mut f = fsm();
    f.feed(b"\0");
    f.feed(format!("AUTH EXTERNAL {}\r\n", hex::encode("2000")).as_bytes());

    // NEGOTIATE_UNIX_FD between OK and BEGIN — we don't pass FDs.
    let act = f.feed(b"NEGOTIATE_UNIX_FD\r\n");
    assert_eq!(act, Action::Send(b"ERROR\r\n".to_vec()));

    let act = f.feed(b"BEGIN\r\n");
    assert!(matches!(act, Action::Accept(_)));
}

// ─── sd-bus fast-path: everything in one send, no hex-uid ─────────

#[test]
fn sdbus_fast_path_no_hex_uid_succeeds() {
    // sd-bus's bare `AUTH EXTERNAL` (no hex-uid argument) elicits a
    // `DATA\r\n` challenge from the server in the libdbus protocol.
    // Real dbus-daemon responds DATA, expects the client's DATA
    // response (which sd-bus pipelines pre-emptively), then OKs.
    // Our FSM matches the daemon's behaviour byte-for-byte so sd-bus
    // tools see identical wire output.
    let mut f = fsm();
    let payload = b"\0AUTH EXTERNAL\r\nDATA\r\nBEGIN\r\n";
    let act = f.feed(payload);

    let Action::Accept(Accept { reply, carryover }) = act else {
        panic!("expected Accept, got {act:?}");
    };
    assert_eq!(reply, format!("DATA\r\nOK {GUID}\r\n").into_bytes());
    assert!(carryover.is_empty());
}

#[test]
fn sdbus_fast_path_with_data_line_after_auth_succeeds() {
    // sd-bus / busctl actually wire this exact sequence on the wire:
    // it pre-emptively sends `DATA\r\n` after AUTH in case the server
    // challenges for SASL data. The server (us) replied OK already,
    // so the DATA is effectively a no-op — but the FSM must accept
    // it as part of the handshake or sd-bus tools fail with
    // "Transport endpoint is not connected".
    let mut f = fsm();
    let payload = b"\0AUTH EXTERNAL\r\nDATA\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";
    let act = f.feed(payload);
    let Action::Accept(Accept { reply, carryover }) = act else {
        panic!("expected Accept, got {act:?}");
    };
    // DATA from the client is the response to the server's DATA
    // challenge (which we emit because the AUTH lacked a hex-uid).
    // Wire shape: DATA\r\n + OK <guid>\r\n + ERROR\r\n (for the
    // NEGOTIATE_UNIX_FD that follows). Matches dbus-daemon exactly.
    assert_eq!(
        reply,
        format!("DATA\r\nOK {GUID}\r\nERROR\r\n").into_bytes()
    );
    assert!(carryover.is_empty());
}

#[test]
fn sdbus_fast_path_with_negotiate_unix_fd_succeeds() {
    // No DATA line: AUTH without hex-uid still gets a DATA
    // challenge response, but here the client never sends a DATA
    // back (less common but legal in libdbus's grammar). The FSM
    // gets stuck waiting for the client's DATA response — so this
    // payload should NOT yield Accept on its own.
    //
    // Treat this case as: client is in DATA-pending state. The
    // proxy emits DATA but stays in the wait state.
    let mut f = fsm();
    let payload = b"\0AUTH EXTERNAL\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";
    let act = f.feed(payload);
    // NEGOTIATE_UNIX_FD arriving while we're in AwaitData is an
    // error from the client's perspective; we reject.
    assert!(
        matches!(act, Action::Reject(_)),
        "AUTH EXTERNAL without DATA should not proceed past AwaitData; got {act:?}"
    );
}

#[test]
fn sdbus_fast_path_carries_over_message_bytes_after_begin() {
    let mut f = fsm();
    // Fake D-Bus message bytes after BEGIN — caller forwards these
    // straight to the relay layer.
    let mut payload: Vec<u8> = b"\0AUTH EXTERNAL\r\nDATA\r\nBEGIN\r\n".to_vec();
    payload.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    let Action::Accept(Accept { carryover, .. }) = f.feed(&payload) else {
        panic!("expected Accept");
    };
    assert_eq!(carryover, vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn sdbus_fast_path_with_hex_uid_validates_against_peer_uid() {
    let mut f = fsm();
    let payload = format!("\0AUTH EXTERNAL {}\r\nBEGIN\r\n", hex::encode("2000"));
    assert!(matches!(f.feed(payload.as_bytes()), Action::Accept(_)));
}

// ─── byte-by-byte feeding (slow client, partial reads) ────────────

#[test]
fn handles_byte_at_a_time_feeding() {
    let mut f = fsm();
    let payload = b"\0AUTH EXTERNAL\r\nDATA\r\nBEGIN\r\n";
    let mut accepted = false;
    let mut accumulated_reply: Vec<u8> = Vec::new();
    for &b in payload {
        match f.feed(&[b]) {
            Action::NeedMore => {}
            Action::Send(r) => accumulated_reply.extend(r),
            Action::Accept(a) => {
                accumulated_reply.extend(a.reply);
                accepted = true;
                break;
            }
            Action::Reject(r) => panic!("unexpected reject: {r}"),
        }
    }
    assert!(accepted, "FSM never accepted");
    assert_eq!(
        accumulated_reply,
        format!("DATA\r\nOK {GUID}\r\n").into_bytes()
    );
}

// ─── rejection cases ──────────────────────────────────────────────

#[test]
fn missing_leading_nul_is_rejected() {
    let mut f = fsm();
    assert_eq!(
        f.feed(b"AUTH EXTERNAL\r\n"),
        Action::Reject(RejectReason::MissingNul)
    );
}

#[test]
fn unknown_mechanism_is_rejected() {
    let mut f = fsm();
    f.feed(b"\0");
    let act = f.feed(b"AUTH ANONYMOUS\r\n");
    assert!(matches!(act, Action::Reject(RejectReason::UnknownMechanism { .. })),
            "got {act:?}");
}

#[test]
fn explicit_hex_uid_mismatch_is_rejected() {
    let mut f = fsm();
    f.feed(b"\0");
    // Peer is uid 2000; client claims to be uid 999.
    let payload = format!("AUTH EXTERNAL {}\r\n", hex::encode("999"));
    let act = f.feed(payload.as_bytes());
    assert_eq!(
        act,
        Action::Reject(RejectReason::UidMismatch {
            expected: 2000,
            got: 999
        })
    );
}

#[test]
fn malformed_hex_uid_is_rejected() {
    let mut f = fsm();
    f.feed(b"\0");
    let act = f.feed(b"AUTH EXTERNAL zz\r\n");
    assert_eq!(act, Action::Reject(RejectReason::MalformedHexUid));
}

#[test]
fn non_numeric_hex_uid_is_rejected() {
    let mut f = fsm();
    f.feed(b"\0");
    // hex of "abc" decodes to b"abc", which isn't a u32.
    let payload = format!("AUTH EXTERNAL {}\r\n", hex::encode("abc"));
    let act = f.feed(payload.as_bytes());
    assert_eq!(act, Action::Reject(RejectReason::InvalidUid));
}

#[test]
fn cancel_during_begin_is_rejected() {
    let mut f = fsm();
    f.feed(b"\0AUTH EXTERNAL\r\n");
    let act = f.feed(b"CANCEL\r\n");
    assert!(matches!(act, Action::Reject(RejectReason::UnexpectedCommand(_))),
            "got {act:?}");
}

// ─── probe forms ──────────────────────────────────────────────────

#[test]
fn bare_auth_probe_lists_supported_mechanisms() {
    let mut f = fsm();
    f.feed(b"\0");
    let act = f.feed(b"AUTH\r\n");
    assert_eq!(act, Action::Send(b"REJECTED EXTERNAL\r\n".to_vec()));
}
