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

//! BlueZ-aware method-call filtering.
//!
//! Configures the proxy with a list of allowed `/org/bluez/hciN`
//! paths. Any method call to a different `/org/bluez/hciM/...`
//! subtree returns `org.freedesktop.DBus.Error.AccessDenied` to the
//! client without reaching upstream. Calls outside the `org.bluez`
//! service are forwarded verbatim (default-pass).
//!
//! Tests register a tiny fake `org.bluez` impl on the upstream bus
//! exposing two adapters at `/org/bluez/hci0` and `/org/bluez/hci1`,
//! then exercise the proxy's filter from a `zbus` client.

mod helpers;

use helpers::{TestEnv, TestEnvBuilder};
use zbus::zvariant::OwnedObjectPath;

#[tokio::test]
async fn allowed_adapter_method_call_passes_through() {
    let env = TestEnvBuilder::new()
        .with_filter_allow_bluez_paths(vec!["/org/bluez/hci0".into()])
        .start()
        .await
        .expect("env start");
    register_fake_bluez(&env).await;

    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");

    // Echo on hci0 should succeed.
    let p = zbus::Proxy::new(
        &client,
        "org.bluez",
        "/org/bluez/hci0",
        "org.bluez.FakeAdapter",
    )
    .await
    .unwrap();
    let reply: String = p.call("Echo", &"hi".to_string()).await.expect("hci0 echo");
    assert_eq!(reply, "hi");
}

#[tokio::test]
async fn denied_adapter_method_call_returns_access_denied() {
    let env = TestEnvBuilder::new()
        .with_filter_allow_bluez_paths(vec!["/org/bluez/hci0".into()])
        .start()
        .await
        .expect("env start");
    register_fake_bluez(&env).await;

    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");

    // Echo on hci1 must be blocked by the proxy with AccessDenied,
    // not reach upstream.
    let p = zbus::Proxy::new(
        &client,
        "org.bluez",
        "/org/bluez/hci1",
        "org.bluez.FakeAdapter",
    )
    .await
    .unwrap();
    let result: zbus::Result<String> = p.call("Echo", &"hi".to_string()).await;
    let err = result.expect_err("hci1 call should have errored");
    let zbus::Error::MethodError(name, _, _) = &err else {
        panic!("expected MethodError, got {err:?}");
    };
    assert_eq!(
        name.as_str(),
        "org.freedesktop.DBus.Error.AccessDenied",
        "unexpected error name"
    );
}

#[tokio::test]
async fn root_org_bluez_path_is_forwarded_for_object_manager() {
    let env = TestEnvBuilder::new()
        .with_filter_allow_bluez_paths(vec!["/org/bluez/hci0".into()])
        .start()
        .await
        .expect("env start");
    register_fake_bluez(&env).await;

    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");

    // `/org/bluez` is a root path that ObjectManager.GetManagedObjects
    // is called on. The call itself must reach upstream — response
    // payload rewriting hides disallowed adapters, but denying the
    // call outright would break adapter enumeration entirely.
    //
    // Our fake bluez doesn't implement ObjectManager, so the call
    // will fail with UnknownInterface — but that error comes from
    // *upstream*, which is exactly what proves the proxy forwarded
    // it instead of synthesizing AccessDenied.
    let mgr = zbus::fdo::ObjectManagerProxy::builder(&client)
        .destination("org.bluez")
        .unwrap()
        .path("/org/bluez")
        .unwrap()
        .build()
        .await
        .unwrap();
    let err = mgr
        .get_managed_objects()
        .await
        .expect_err("fake service has no ObjectManager");
    let msg = format!("{err:?}");
    assert!(
        !msg.contains("AccessDenied"),
        "/org/bluez was blocked by the proxy when it should have been forwarded: {msg}"
    );
    let _ = OwnedObjectPath::default(); // keep the import
}

#[tokio::test]
async fn calls_to_other_services_are_forwarded() {
    let env = TestEnvBuilder::new()
        .with_filter_allow_bluez_paths(vec!["/org/bluez/hci0".into()])
        .start()
        .await
        .expect("env start");

    // Register a tiny non-bluez service.
    let _server = zbus::ConnectionBuilder::address(env.upstream_addr())
        .unwrap()
        .name("com.example.Echo")
        .unwrap()
        .serve_at("/com/example/Echo", helpers::EchoService)
        .unwrap()
        .build()
        .await
        .expect("register echo");

    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");

    let p = zbus::Proxy::new(
        &client,
        "com.example.Echo",
        "/com/example/Echo",
        "com.example.Echo",
    )
    .await
    .unwrap();
    // Default-pass: filter ignores anything outside org.bluez.
    let reply: String = p.call("Echo", &"hi".to_string()).await.expect("echo");
    assert_eq!(reply, "hi");
}

/// Regression test for issue #1: when the watcher publishes a new
/// allow-list (e.g. because the configured MAC moved from hci0 to
/// hci1 across an unplug/replug), in-flight relay tasks must pick
/// up the change on their very next message. This test fakes the
/// publish step directly via `TestEnv::set_filter` — it does not
/// exercise the dbus signal subscription, only the read-side ArcSwap
/// path that subscription drives.
#[tokio::test]
async fn live_filter_update_takes_effect_on_existing_client_connection() {
    let env = TestEnvBuilder::new()
        .with_filter_allow_bluez_paths(vec!["/org/bluez/hci0".into()])
        .start()
        .await
        .expect("env start");
    register_fake_bluez(&env).await;

    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");
    let hci0 = zbus::Proxy::new(
        &client,
        "org.bluez",
        "/org/bluez/hci0",
        "org.bluez.FakeAdapter",
    )
    .await
    .unwrap();
    let hci1 = zbus::Proxy::new(
        &client,
        "org.bluez",
        "/org/bluez/hci1",
        "org.bluez.FakeAdapter",
    )
    .await
    .unwrap();

    // Initial state: hci0 allowed, hci1 denied.
    let reply: String = hci0.call("Echo", &"a".to_string()).await.expect("hci0 ok");
    assert_eq!(reply, "a");
    let denied: zbus::Result<String> = hci1.call("Echo", &"a".to_string()).await;
    assert!(
        matches!(&denied, Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied"),
        "hci1 should be denied initially, got {denied:?}"
    );

    // Simulate the watcher detecting that our MAC moved from hci0 to
    // hci1 and publishing the new allow-list. The same long-lived
    // client connection should now see the flipped behaviour.
    env.set_filter(dbus_bluez_filter_proxy::filter::FilterConfig {
        bluez_allowed_adapter_paths: vec!["/org/bluez/hci1".into()],
    });

    let reply: String = hci1.call("Echo", &"b".to_string()).await.expect("hci1 ok after swap");
    assert_eq!(reply, "b");
    let denied: zbus::Result<String> = hci0.call("Echo", &"b".to_string()).await;
    assert!(
        matches!(&denied, Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied"),
        "hci0 should be denied after swap, got {denied:?}"
    );
}

// ─── helpers ──────────────────────────────────────────────────────

async fn register_fake_bluez(env: &TestEnv) {
    use std::sync::Mutex;
    static REGISTERED: Mutex<Vec<zbus::Connection>> = Mutex::new(Vec::new());

    let server = zbus::ConnectionBuilder::address(env.upstream_addr())
        .unwrap()
        .name("org.bluez")
        .unwrap()
        .serve_at("/org/bluez/hci0", FakeAdapter)
        .unwrap()
        .serve_at("/org/bluez/hci1", FakeAdapter)
        .unwrap()
        .build()
        .await
        .expect("register fake bluez");
    // Keep alive for the duration of the test process.
    REGISTERED.lock().unwrap().push(server);
}

struct FakeAdapter;

#[zbus::interface(name = "org.bluez.FakeAdapter")]
impl FakeAdapter {
    fn echo(&self, msg: String) -> String {
        msg
    }
}
