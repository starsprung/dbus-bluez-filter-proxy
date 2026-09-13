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

//! Session teardown.
//!
//! A D-Bus connection is all-or-nothing: when one side goes away the
//! other must see it. That matters for BlueZ in particular — it keys
//! agents, advertisements, GATT applications and device connections
//! to the owning client's unique name and tears them down on
//! `NameOwnerChanged`. If the proxy keeps its upstream socket open
//! after the client has gone, none of that cleanup happens.
//!
//! Regression tests for the relay leaving the surviving direction's
//! task (and therefore both sockets) alive after the other direction
//! hit EOF.

mod helpers;

use futures_util::StreamExt;
use helpers::TestEnv;
use std::time::Duration;

/// Client disconnects → dbus-daemon must see the proxy's upstream
/// connection close, observed as `NameOwnerChanged` for the client's
/// unique name with an empty new owner.
#[tokio::test]
async fn client_disconnect_is_propagated_upstream() {
    let env = TestEnv::start().await.expect("env start");

    // Observer directly on the upstream bus.
    let observer = zbus::ConnectionBuilder::address(env.upstream_addr())
        .unwrap()
        .build()
        .await
        .unwrap();
    let dbus = zbus::fdo::DBusProxy::new(&observer).await.unwrap();
    let mut noc = dbus.receive_name_owner_changed().await.unwrap();

    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");
    let unique = client.unique_name().expect("unique name").to_owned();
    drop(client);

    let deadline = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => panic!(
                "upstream bus never saw {unique} disconnect within 2s: \
                 the proxy is holding the upstream connection open after the client left"
            ),
            sig = noc.next() => {
                let sig = sig.expect("NameOwnerChanged stream ended");
                let args = sig.args().unwrap();
                if args.name().as_str() == unique.as_str() && args.new_owner().is_none() {
                    return;
                }
            }
        }
    }
}

/// Upstream goes away → an idle client (one only waiting for signals,
/// never sending) must observe the disconnect rather than hang.
#[tokio::test]
async fn upstream_disconnect_is_propagated_to_idle_client() {
    let mut env = TestEnv::start().await.expect("env start");
    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");
    let mut stream = zbus::MessageStream::from(client.clone());

    env.kill_upstream().await;

    let observed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match stream.next().await {
                None => break "stream ended",
                Some(Err(_)) => break "stream errored",
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(
        observed.is_ok(),
        "idle client never observed upstream disconnect within 2s: \
         the proxy left the client socket open after upstream closed"
    );
}
