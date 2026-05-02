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

//! Regression test for `dbus-fast` (and therefore `bleak`) compatibility.
//!
//! `dbus-fast` opens connections with `negotiate_unix_fd=True`, which
//! injects `NEGOTIATE_UNIX_FD\r\n` between `AUTH EXTERNAL` and `BEGIN`.
//! The D-Bus SASL spec lets a server respond either `AGREE_UNIX_FD\r\n`
//! ("yes, I'll pass FDs") or `ERROR\r\n` ("no, but the connection is
//! still valid — proceed without FD passing").
//!
//! Real-world Python clients depend on `AGREE_UNIX_FD`:
//! `dbus_fast/auth.py:97` raises `AuthError` on any reply that isn't
//! `AGREE_UNIX_FD`, including the spec-legal `ERROR`. `bleak`'s
//! `BleakClient` always sets `negotiate_unix_fd=True`, so an `ERROR`
//! response hard-fails connect with `authentication failed: ERROR: []`
//! before BlueZ method calls can even start.
//!
//! The proxy therefore must produce `AGREE_UNIX_FD` whenever the
//! upstream daemon supports FD passing — which `dbus-daemon` always
//! does on Linux. The cleanest way to guarantee that without a
//! standalone re-implementation that drifts from upstream is to make
//! the SASL phase a transparent byte forwarder: whatever upstream
//! says, the client sees.

mod helpers;

use helpers::TestEnv;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Strip the leading `unix:path=` prefix that the test harness uses.
fn proxy_socket_path(env: &TestEnv) -> std::path::PathBuf {
    env.proxy_addr()
        .strip_prefix("unix:path=")
        .expect("proxy_addr is a unix:path= URI")
        .into()
}

/// Read until the buffer contains the supplied terminator or the
/// short timeout elapses. Returns whatever bytes arrived.
async fn read_with_timeout(stream: &mut UnixStream, until: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 256];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        match tokio::time::timeout(remaining, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(Err(_)) => break,
            Err(_) => break,
        }
        if buf.windows(until.len()).any(|w| w == until) {
            break;
        }
    }
    buf
}

/// Replicate the exact byte sequence `dbus-fast` sends when
/// `negotiate_unix_fd=True` is in effect. Connect to the proxy, send
/// the pipelined SASL handshake, and assert the server reply contains
/// both `OK <guid>` and `AGREE_UNIX_FD`. Pre-fix the proxy returns
/// `ERROR` here, which `dbus-fast` surfaces as `AuthError`.
#[tokio::test]
async fn negotiate_unix_fd_yields_agree() {
    let env = TestEnv::start().await.expect("env start");
    let path = proxy_socket_path(&env);
    let mut stream = UnixStream::connect(&path).await.expect("connect proxy");

    // dbus-fast's pipelined fast-path: NUL byte + AUTH EXTERNAL with
    // hex-encoded uid + NEGOTIATE_UNIX_FD + BEGIN, all in one write.
    let uid = nix::unistd::geteuid().as_raw();
    let hex_uid = hex::encode(uid.to_string());
    let payload = format!("\0AUTH EXTERNAL {hex_uid}\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n");
    stream
        .write_all(payload.as_bytes())
        .await
        .expect("write SASL");

    // Wait for the SASL portion of the reply. AGREE_UNIX_FD lands as
    // a separate line after `OK <guid>\r\n`, so wait specifically for
    // its CRLF terminator.
    let reply = read_with_timeout(&mut stream, b"AGREE_UNIX_FD\r\n").await;
    let s = String::from_utf8_lossy(&reply);
    assert!(
        s.contains("OK "),
        "expected OK <guid> line in SASL reply, got {s:?}"
    );
    assert!(
        s.contains("AGREE_UNIX_FD"),
        "expected AGREE_UNIX_FD reply (got ERROR or no FD response): {s:?}"
    );
    assert!(
        !s.contains("ERROR"),
        "proxy must not respond ERROR to NEGOTIATE_UNIX_FD when \
         upstream supports FD passing — dbus-fast / bleak treat any \
         non-AGREE reply as auth failure. Got: {s:?}"
    );
}
