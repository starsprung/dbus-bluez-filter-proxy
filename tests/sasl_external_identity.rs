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

//! SASL EXTERNAL through the proxy when the client's uid differs
//! from the proxy's.
//!
//! `--peer-uid` lets a proxy running as one uid (typically root)
//! accept a client running as another (a `user: 1000:1000`
//! container). The client sends its *own* uid in `AUTH EXTERNAL
//! <hex-uid>`; if that were forwarded verbatim, dbus-daemon would
//! compare it against the proxy's `SO_PEERCRED` and reject the
//! handshake. The proxy must substitute its own identity.
//!
//! The tests can't change uid, so they model the mismatch from the
//! other side: the socket credentials say (our uid) while the SASL
//! line claims (our uid + 1). That is exactly the situation the
//! upstream daemon sees in the `--peer-uid` deployment.

mod helpers;

use dbus_bluez_filter_proxy::wire;
use helpers::TestEnv;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

fn proxy_socket_path(env: &TestEnv) -> std::path::PathBuf {
    env.proxy_addr()
        .strip_prefix("unix:path=")
        .expect("proxy_addr is a unix:path= URI")
        .into()
}

fn foreign_uid_hex() -> String {
    hex::encode((nix::unistd::geteuid().as_raw() + 1).to_string())
}

/// Read one `\r\n`-terminated line (without the terminator).
async fn read_line(stream: &mut UnixStream, pending: &mut Vec<u8>) -> String {
    let mut tmp = [0u8; 256];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(i) = pending.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(&pending[..i]).into_owned();
            pending.drain(..i + 2);
            return line;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, stream.read(&mut tmp)).await {
            Ok(Ok(n)) if n > 0 => pending.extend_from_slice(&tmp[..n]),
            other => panic!(
                "no SASL line within 2s (got {other:?}); buffered: {:?}",
                String::from_utf8_lossy(pending)
            ),
        }
    }
}

/// Read one complete D-Bus message frame.
async fn read_message(stream: &mut UnixStream, pending: &mut Vec<u8>) -> Vec<u8> {
    let mut tmp = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if pending.len() >= wire::FIXED_HEADER_LEN {
            let n = wire::peek_message_size(&pending[..wire::FIXED_HEADER_LEN]).expect("frame");
            if pending.len() >= n {
                return pending.drain(..n).collect();
            }
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, stream.read(&mut tmp)).await {
            Ok(Ok(n)) if n > 0 => pending.extend_from_slice(&tmp[..n]),
            other => panic!("no message frame within 2s (got {other:?})"),
        }
    }
}

/// Common form: identity as the initial response. Then finish the
/// handshake and prove the connection is usable by getting a reply
/// to `Hello`.
#[tokio::test]
async fn auth_external_with_foreign_uid_succeeds_and_connection_works() {
    let env = TestEnv::start().await.expect("env start");
    let mut s = UnixStream::connect(proxy_socket_path(&env)).await.unwrap();
    let mut pending = Vec::new();

    s.write_all(format!("\0AUTH EXTERNAL {}\r\n", foreign_uid_hex()).as_bytes())
        .await
        .unwrap();
    let reply = read_line(&mut s, &mut pending).await;
    assert!(
        reply.starts_with("OK "),
        "client claiming a uid other than the proxy's must still authenticate; upstream said {reply:?}"
    );

    let hello = zbus::message::Message::method("/org/freedesktop/DBus", "Hello")
        .unwrap()
        .destination("org.freedesktop.DBus")
        .unwrap()
        .interface("org.freedesktop.DBus")
        .unwrap()
        .build(&())
        .unwrap();
    let hello_serial = wire::parse(hello.data()).unwrap().serial;

    s.write_all(b"BEGIN\r\n").await.unwrap();
    s.write_all(hello.data()).await.unwrap();

    let frame = read_message(&mut s, &mut pending).await;
    let h = wire::parse(&frame).expect("parse Hello reply");
    assert_eq!(h.msg_type, wire::MessageType::MethodReturn, "got {h:?}");
    assert_eq!(h.reply_serial, Some(hello_serial));
}

/// Two-step form: `AUTH EXTERNAL` with no initial response, the
/// server asks with `DATA`, the client answers `DATA <hex-uid>`.
#[tokio::test]
async fn auth_external_data_step_with_foreign_uid_succeeds() {
    let env = TestEnv::start().await.expect("env start");
    let mut s = UnixStream::connect(proxy_socket_path(&env)).await.unwrap();
    let mut pending = Vec::new();

    s.write_all(b"\0AUTH EXTERNAL\r\n").await.unwrap();
    let prompt = read_line(&mut s, &mut pending).await;
    assert!(
        prompt.starts_with("DATA"),
        "expected the server to prompt for the identity, got {prompt:?}"
    );

    s.write_all(format!("DATA {}\r\n", foreign_uid_hex()).as_bytes())
        .await
        .unwrap();
    let reply = read_line(&mut s, &mut pending).await;
    assert!(
        reply.starts_with("OK "),
        "identity sent via DATA must be substituted too; upstream said {reply:?}"
    );
}
