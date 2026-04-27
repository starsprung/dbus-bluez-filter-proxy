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

//! End-to-end pass-through tests.
//!
//! With no filter rules configured, the proxy must be transparent:
//! anything a client could do directly against `dbus-daemon` should
//! also work going through the proxy. These tests use real `zbus`
//! connections through the proxy to a real `dbus-daemon` upstream
//! (via the `helpers::TestEnv` harness).

mod helpers;

use helpers::TestEnv;
use std::time::Duration;

/// Smoke: the proxy can accept a client and forward enough of the
/// initial Hello() round-trip that zbus considers itself connected
/// and gets a unique name back from the bus.
#[tokio::test]
async fn client_gets_unique_name_through_proxy() {
    let env = TestEnv::start().await.expect("env start");
    let conn = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect through proxy");
    let name = conn.unique_name().expect("unique name assigned");
    assert!(
        name.as_str().starts_with(':'),
        "unique names must start with ':' (got {name:?})"
    );
}

/// Two sequential method calls on the same connection both work,
/// and their replies are routed back to the right caller.
#[tokio::test]
async fn sequential_method_calls_round_trip() {
    let env = TestEnv::start().await.expect("env start");
    let conn = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect through proxy");

    // ListNames() and GetId() are both no-arg DBus methods on the
    // org.freedesktop.DBus service. Calling them in series exercises
    // serial-number tracking through the relay.
    let proxy = zbus::fdo::DBusProxy::new(&conn).await.unwrap();
    let names = proxy.list_names().await.expect("list_names");
    assert!(
        names.iter().any(|n| n.as_str() == "org.freedesktop.DBus"),
        "bus daemon should advertise itself in ListNames"
    );
    let id = proxy.get_id().await.expect("get_id");
    assert!(!id.is_empty(), "GetId should return non-empty bus GUID");
}

/// Two clients connecting to the proxy simultaneously each get
/// distinct unique names — the relay handles concurrent sessions.
#[tokio::test]
async fn two_clients_get_distinct_unique_names() {
    let env = TestEnv::start().await.expect("env start");
    let a = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .unwrap();
    let b = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .unwrap();
    assert_ne!(a.unique_name(), b.unique_name());
}

/// A service registered (via the upstream socket directly) is
/// callable by a client connected through the proxy. Demonstrates
/// bidirectional pass-through: methods → upstream, replies → client,
/// no payload mutation.
#[tokio::test]
async fn service_registered_upstream_is_callable_via_proxy() {
    let env = TestEnv::start().await.expect("env start");

    // Register a tiny test service directly on the upstream bus.
    let server = zbus::ConnectionBuilder::address(env.upstream_addr())
        .unwrap()
        .name("com.example.Echo")
        .unwrap()
        .serve_at("/com/example/Echo", EchoService)
        .unwrap()
        .build()
        .await
        .expect("register echo service");

    // Client connects via the proxy and calls the service.
    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");

    let proxy_handle = zbus::Proxy::new(
        &client,
        "com.example.Echo",
        "/com/example/Echo",
        "com.example.Echo",
    )
    .await
    .unwrap();

    let reply: String = proxy_handle.call("Echo", &"hello".to_string()).await.unwrap();
    assert_eq!(reply, "hello");

    drop(server);
}

/// Disconnecting a client cleanly tears down the per-client relay
/// task on the proxy without affecting other connections.
#[tokio::test]
async fn dropping_one_client_does_not_disturb_another() {
    let env = TestEnv::start().await.expect("env start");
    let a = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .unwrap();
    let b = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .unwrap();

    drop(a);
    // Give the relay a moment to notice the closed half.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // b should still be functional.
    let proxy_b = zbus::fdo::DBusProxy::new(&b).await.unwrap();
    let names = proxy_b.list_names().await.expect("b still works");
    assert!(names.iter().any(|n| n.as_str() == "org.freedesktop.DBus"));
}

// ─── tiny test service definition ─────────────────────────────────

struct EchoService;

#[zbus::interface(name = "com.example.Echo")]
impl EchoService {
    fn echo(&self, msg: String) -> String {
        msg
    }
}
