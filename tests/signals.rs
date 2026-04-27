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

//! Signal delivery through the relay.
//!
//! Asserts the upstream-to-client direction of pass-through is
//! honest: a signal emitted on the bus reaches a client subscribed
//! through the proxy.

mod helpers;

use helpers::TestEnv;
use futures_util::StreamExt;
use std::time::Duration;
use tokio::sync::oneshot;
use zbus::SignalContext;

#[tokio::test]
async fn signal_emitted_upstream_reaches_client_through_proxy() {
    let env = TestEnv::start().await.expect("env start");

    let server = zbus::ConnectionBuilder::address(env.upstream_addr())
        .unwrap()
        .name("com.example.Pinger")
        .unwrap()
        .serve_at("/com/example/Pinger", PingService)
        .unwrap()
        .build()
        .await
        .expect("register service");

    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");

    // Subscribe to the Ping signal as the client (through the proxy).
    let proxy = zbus::Proxy::new(
        &client,
        "com.example.Pinger",
        "/com/example/Pinger",
        "com.example.Pinger",
    )
    .await
    .unwrap();

    let mut stream = proxy.receive_signal("Ping").await.unwrap();

    // Have the server emit one. Done in a separate task so the
    // emit and the receive both happen on the live runtime.
    let server2 = server.clone();
    let (emitted_tx, emitted_rx) = oneshot::channel();
    tokio::spawn(async move {
        // Brief delay so the client's subscription is in place
        // (zbus' AddMatch round-trip).
        tokio::time::sleep(Duration::from_millis(50)).await;
        let ctx = SignalContext::new(&server2, "/com/example/Pinger").unwrap();
        PingService::ping(&ctx).await.expect("emit");
        let _ = emitted_tx.send(());
    });

    // Wait for the signal to reach us, with a generous timeout so
    // a flaky environment fails loud rather than hanging the suite.
    let recv = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("signal arrived within 2s");
    assert!(recv.is_some(), "stream returned None instead of a signal");

    emitted_rx.await.unwrap();
    drop(server);
}

struct PingService;

#[zbus::interface(name = "com.example.Pinger")]
impl PingService {
    #[zbus(signal)]
    async fn ping(ctx: &SignalContext<'_>) -> zbus::Result<()>;
}
