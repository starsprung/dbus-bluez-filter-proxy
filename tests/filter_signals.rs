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

//! Generic signal-source filtering.
//!
//! Beyond `InterfacesAdded`/`InterfacesRemoved`, BlueZ also emits
//! per-adapter signals on the adapter's own object path — the
//! loudest of these is
//! `org.freedesktop.DBus.Properties.PropertiesChanged`. Without
//! filtering, a client subscribed through the proxy would still see
//! activity on disallowed adapters even though it can't act on
//! them. The proxy drops any signal whose `PATH` header is under a
//! disallowed `/org/bluez/<other>/...` subtree.

mod helpers;

use futures_util::StreamExt;
use helpers::TestEnvBuilder;
use std::time::Duration;
use zbus::SignalContext;

#[tokio::test]
async fn properties_changed_on_disallowed_adapter_is_dropped() {
    let env = TestEnvBuilder::new()
        .with_filter_allow_bluez_paths(vec!["/org/bluez/hci0".into()])
        .start()
        .await
        .expect("env start");

    // Register fake adapters at /hci0 and /hci1 — the interface impl
    // is irrelevant; we only need the paths to exist so PropertiesChanged
    // can be emitted from each.
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

    // Client subscribes to org.freedesktop.DBus.Properties.PropertiesChanged
    // for the org.bluez service via the proxy. Match rule is broad —
    // any path. The proxy must drop hci1 events.
    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");

    let dbus = zbus::fdo::DBusProxy::new(&client).await.unwrap();
    dbus.add_match_rule(
        "type='signal',interface='org.freedesktop.DBus.Properties',\
         member='PropertiesChanged',sender='org.bluez'"
            .try_into()
            .unwrap(),
    )
    .await
    .unwrap();

    let mut stream = zbus::MessageStream::from(client.clone());

    // Emit a PropertiesChanged on each adapter path.
    let server_for_emit = server.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        emit_props_changed(&server_for_emit, "/org/bluez/hci0").await;
        emit_props_changed(&server_for_emit, "/org/bluez/hci1").await;
    });

    let mut allowed_seen = false;
    let mut disallowed_seen = false;
    let deadline = tokio::time::sleep(Duration::from_millis(800));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            msg = stream.next() => {
                let Some(Ok(msg)) = msg else { break; };
                let header = msg.header();
                if header.message_type() != zbus::message::Type::Signal { continue; }
                let Some(path) = header.path() else { continue; };
                let path = path.as_str();
                if header.member().map(|m| m.as_str()) != Some("PropertiesChanged") { continue; }
                if path == "/org/bluez/hci0" { allowed_seen = true; }
                if path == "/org/bluez/hci1" { disallowed_seen = true; }
            }
        }
    }
    assert!(allowed_seen, "allowed adapter's PropertiesChanged should pass");
    assert!(
        !disallowed_seen,
        "disallowed adapter's PropertiesChanged must be dropped"
    );
    drop(server);
}

#[tokio::test]
async fn signal_on_non_bluez_path_is_default_pass() {
    let env = TestEnvBuilder::new()
        .with_filter_allow_bluez_paths(vec!["/org/bluez/hci0".into()])
        .start()
        .await
        .expect("env start");

    // Custom service on a non-bluez path emits a signal — must pass.
    let server = zbus::ConnectionBuilder::address(env.upstream_addr())
        .unwrap()
        .name("com.example.Pinger")
        .unwrap()
        .serve_at("/com/example/Pinger", PingService)
        .unwrap()
        .build()
        .await
        .expect("register pinger");

    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");

    let proxy = zbus::Proxy::new(
        &client,
        "com.example.Pinger",
        "/com/example/Pinger",
        "com.example.Pinger",
    )
    .await
    .unwrap();
    let mut sigs = proxy.receive_signal("Ping").await.unwrap();

    let server_for_emit = server.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        let ctx = SignalContext::new(&server_for_emit, "/com/example/Pinger").unwrap();
        let _ = PingService::ping(&ctx).await;
    });

    let arrived = tokio::time::timeout(Duration::from_millis(800), sigs.next()).await;
    assert!(
        matches!(arrived, Ok(Some(_))),
        "non-bluez signal must pass through unchanged"
    );
    drop(server);
}

// ─── fake services ────────────────────────────────────────────────

struct FakeAdapter;

#[zbus::interface(name = "org.bluez.Adapter1")]
impl FakeAdapter {
    #[zbus(property)]
    fn powered(&self) -> bool {
        true
    }
}

async fn emit_props_changed(conn: &zbus::Connection, path: &str) {
    use std::collections::HashMap;
    use zbus::zvariant::Value;
    let ctx = SignalContext::new(conn, zbus::zvariant::ObjectPath::try_from(path).unwrap())
        .expect("signal ctx");
    let changed: HashMap<&str, Value> = HashMap::new();
    let invalidated: &[&str] = &[];
    // Hand-emit org.freedesktop.DBus.Properties.PropertiesChanged
    // because zbus's high-level property-emit auto-routes through
    // ObjectServer's own properties; we want a raw signal on the
    // service's bus to test the proxy's path-based filter.
    let _ = conn
        .emit_signal(
            None::<&str>,
            path,
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &("org.bluez.Adapter1", &changed, invalidated),
        )
        .await;
    let _ = ctx; // silence unused on some zbus versions
}

struct PingService;

#[zbus::interface(name = "com.example.Pinger")]
impl PingService {
    #[zbus(signal)]
    async fn ping(ctx: &SignalContext<'_>) -> zbus::Result<()>;
}
