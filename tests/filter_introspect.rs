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

//! End-to-end test of Introspect XML payload rewriting.
//!
//! Locks in the busctl-tree-leak fix: a recursive introspection
//! through the proxy must not enumerate disallowed adapters as
//! `<node name="..."/>` children of `/org/bluez`.

mod helpers;

use helpers::TestEnvBuilder;

#[tokio::test]
async fn introspect_strips_disallowed_adapter_node_children() {
    let env = TestEnvBuilder::new()
        .with_filter_allow_bluez_paths(vec!["/org/bluez/hci0".into()])
        .start()
        .await
        .expect("env start");

    // Register a fake org.bluez with both adapters as ObjectServer
    // children. zbus auto-implements Introspectable for served
    // paths, so /org/bluez's Introspect XML lists hci0 + hci1.
    let _server = zbus::ConnectionBuilder::address(env.upstream_addr())
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

    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");

    let proxy = zbus::Proxy::new(
        &client,
        "org.bluez",
        "/org/bluez",
        "org.freedesktop.DBus.Introspectable",
    )
    .await
    .unwrap();
    let xml: String = proxy.call("Introspect", &()).await.expect("introspect");

    assert!(
        xml.contains(r#"name="hci0""#),
        "allowed adapter must be visible in introspection XML: {xml}"
    );
    assert!(
        !xml.contains(r#"name="hci1""#),
        "disallowed adapter MUST be stripped from introspection XML: {xml}"
    );
}

struct FakeAdapter;

#[zbus::interface(name = "org.bluez.Adapter1")]
impl FakeAdapter {
    #[zbus(property)]
    fn powered(&self) -> bool {
        true
    }
}
