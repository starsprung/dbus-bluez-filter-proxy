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

//! Response/signal payload rewriting.
//!
//! `org.bluez`'s ObjectManager exposes one entry per adapter (and
//! per device under each adapter) in its `GetManagedObjects()` reply
//! and in its `InterfacesAdded`/`InterfacesRemoved` signals. Method
//! denial alone leaves these advertisements visible — apps that lock
//! onto the first adapter in the list and don't try alternatives
//! still get the wrong adapter and bail. The proxy makes disallowed
//! adapter subtrees *invisible* by stripping them from response
//! payloads and from signal payloads before they reach the client.

mod helpers;

use helpers::TestEnvBuilder;
use std::collections::HashMap;
use std::time::Duration;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

type GmoReply = HashMap<
    OwnedObjectPath,
    HashMap<
        zbus::zvariant::OwnedSignature, // interface name (signature-typed in zbus 4 GMO… actually OwnedInterfaceName)
        HashMap<String, OwnedValue>,
    >,
>;

#[tokio::test]
async fn get_managed_objects_response_strips_disallowed_adapters() {
    let env = TestEnvBuilder::new()
        .with_filter_allow_bluez_paths(vec!["/org/bluez/hci0".into()])
        .start()
        .await
        .expect("env start");

    // Register a fake org.bluez that replies to GMO with two adapters.
    register_fake_bluez_with_object_manager(&env).await;

    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");

    let mgr = zbus::fdo::ObjectManagerProxy::builder(&client)
        .destination("org.bluez")
        .unwrap()
        .path("/org/bluez")
        .unwrap()
        .build()
        .await
        .unwrap();

    let objs = mgr.get_managed_objects().await.expect("GMO");
    let paths: Vec<String> = objs.keys().map(|p| p.as_str().to_string()).collect();

    assert!(
        paths.iter().any(|p| p == "/org/bluez/hci0"),
        "allowed adapter must appear: {paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p == "/org/bluez/hci1"),
        "disallowed adapter MUST be stripped: {paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p.starts_with("/org/bluez/hci1/")),
        "disallowed adapter's children must also be stripped: {paths:?}"
    );
}

#[tokio::test]
async fn interfaces_added_for_disallowed_adapter_is_dropped() {
    let env = TestEnvBuilder::new()
        .with_filter_allow_bluez_paths(vec!["/org/bluez/hci0".into()])
        .start()
        .await
        .expect("env start");
    let server_conn = register_fake_bluez_with_object_manager(&env).await;

    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");

    let mgr = zbus::fdo::ObjectManagerProxy::builder(&client)
        .destination("org.bluez")
        .unwrap()
        .path("/org/bluez")
        .unwrap()
        .build()
        .await
        .unwrap();
    use futures_util::StreamExt;
    let mut added = mgr.receive_interfaces_added().await.unwrap();

    // Emit two InterfacesAdded signals: one for the allowed adapter's
    // device subtree, one for the disallowed adapter's. Client must
    // see only the allowed one.
    tokio::spawn(emit_interfaces_added(server_conn));

    let mut allowed_seen = false;
    let mut disallowed_seen = false;
    let deadline = tokio::time::sleep(Duration::from_millis(800));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            sig = added.next() => {
                let Some(sig) = sig else { break; };
                let args = sig.args().unwrap();
                let path: &str = args.object_path().as_str();
                if path.starts_with("/org/bluez/hci0/") { allowed_seen = true; }
                if path.starts_with("/org/bluez/hci1/") { disallowed_seen = true; }
            }
        }
    }
    assert!(allowed_seen, "allowed adapter's InterfacesAdded should pass");
    assert!(
        !disallowed_seen,
        "disallowed adapter's InterfacesAdded must be dropped"
    );
}

// ─── upstream fake ────────────────────────────────────────────────

async fn register_fake_bluez_with_object_manager(env: &helpers::TestEnv) -> zbus::Connection {
    use std::sync::Mutex;
    static REGISTERED: Mutex<Vec<zbus::Connection>> = Mutex::new(Vec::new());

    let conn = zbus::ConnectionBuilder::address(env.upstream_addr())
        .unwrap()
        .name("org.bluez")
        .unwrap()
        .serve_at("/org/bluez/hci0", FakeAdapter("hci0"))
        .unwrap()
        .serve_at("/org/bluez/hci1", FakeAdapter("hci1"))
        .unwrap()
        .serve_at("/org/bluez/hci0/dev_01", FakeDevice)
        .unwrap()
        .serve_at("/org/bluez/hci1/dev_01", FakeDevice)
        .unwrap()
        .build()
        .await
        .expect("register fake bluez");
    // zbus's ObjectServer doesn't auto-add ObjectManager support;
    // attach it explicitly at the bus root for /org/bluez.
    conn.object_server()
        .at("/org/bluez", zbus::fdo::ObjectManager)
        .await
        .expect("install ObjectManager");
    REGISTERED.lock().unwrap().push(conn.clone());
    conn
}

async fn emit_interfaces_added(conn: zbus::Connection) {
    use zbus::SignalContext;
    // Brief delay so the client's AddMatch round-trip has settled.
    tokio::time::sleep(Duration::from_millis(80)).await;
    let allowed_ctx = SignalContext::new(&conn, "/org/bluez").unwrap();
    let allowed = zbus::zvariant::ObjectPath::try_from("/org/bluez/hci0/dev_99").unwrap();
    let disallowed = zbus::zvariant::ObjectPath::try_from("/org/bluez/hci1/dev_99").unwrap();
    let empty: HashMap<zbus::names::InterfaceName, HashMap<&str, zbus::zvariant::Value>> =
        HashMap::new();
    let _ = zbus::fdo::ObjectManager::interfaces_added(&allowed_ctx, &allowed, &empty).await;
    let _ = zbus::fdo::ObjectManager::interfaces_added(&allowed_ctx, &disallowed, &empty).await;
}

struct FakeAdapter(&'static str);

#[zbus::interface(name = "org.bluez.Adapter1")]
impl FakeAdapter {
    #[zbus(property)]
    fn address(&self) -> String {
        match self.0 {
            "hci0" => "00:1A:7D:DA:71:08".into(),
            "hci1" => "8C:86:DD:AB:04:7D".into(),
            _ => "00:00:00:00:00:00".into(),
        }
    }
}

struct FakeDevice;

#[zbus::interface(name = "org.bluez.Device1")]
impl FakeDevice {
    #[zbus(property)]
    fn address(&self) -> String {
        "AA:BB:CC:DD:EE:FF".into()
    }
}

// silence unused-type warning while iterating
#[allow(dead_code)]
fn _gmo_type_ref(_: &GmoReply) {}
