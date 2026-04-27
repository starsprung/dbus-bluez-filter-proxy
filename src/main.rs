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

//! `dbus-bluez-filter-proxy` binary entry point.
//!
//! Resolves a configured BT adapter MAC to its live `/org/bluez/hciN`
//! object path via `/sys/class/bluetooth`, then runs the relay
//! library against a downstream listen socket and an upstream
//! `dbus-daemon` socket. Filter rules are passed via flags.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use dbus_bluez_filter_proxy::{
    filter::FilterConfig,
    hci,
    proxy::{Proxy, ProxyConfig},
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about = "Filtering D-Bus proxy with BlueZ adapter scoping")]
struct Cli {
    /// Unix socket path the proxy listens on for downstream clients.
    #[arg(long, env = "DBUS_BLUEZ_FILTER_PROXY_LISTEN")]
    listen: PathBuf,

    /// Unix socket path of the upstream `dbus-daemon` (the system
    /// bus, typically `/run/dbus/system_bus_socket`).
    #[arg(
        long,
        env = "DBUS_BLUEZ_FILTER_PROXY_UPSTREAM",
        default_value = "/run/dbus/system_bus_socket"
    )]
    upstream: PathBuf,

    /// Expected uid of the connecting downstream peer (for SASL
    /// EXTERNAL). Defaults to whatever the proxy is running as,
    /// which is also the uid SASL EXTERNAL needs to match for the
    /// peer_uid == server_uid auth check to pass.
    #[arg(long, env = "DBUS_BLUEZ_FILTER_PROXY_PEER_UID")]
    peer_uid: Option<u32>,

    /// MAC address of the BT adapter the consumer is allowed to
    /// see/touch via `org.bluez`. Repeatable for multi-adapter
    /// scoping (rare). Resolved to `/org/bluez/hciN` on startup.
    /// Empty list = full pass-through (no BlueZ filter).
    ///
    /// Via env var: comma-separated list of MACs.
    #[arg(
        long = "bluez-allow-mac",
        env = "DBUS_BLUEZ_FILTER_PROXY_BLUEZ_ALLOW_MAC",
        value_name = "MAC",
        value_delimiter = ','
    )]
    bluez_allow_macs: Vec<String>,

    /// Seconds to wait for the configured adapter MAC(s) to
    /// appear in `/sys/class/bluetooth` before bailing out.
    #[arg(
        long,
        env = "DBUS_BLUEZ_FILTER_PROXY_ADAPTER_RESOLVE_TIMEOUT_SECS",
        default_value_t = 60
    )]
    adapter_resolve_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();

    let mut bluez_allowed: Vec<String> = Vec::new();
    for mac in &cli.bluez_allow_macs {
        let hci = wait_for_adapter(mac, Duration::from_secs(cli.adapter_resolve_timeout_secs))
            .with_context(|| format!("resolve adapter MAC {mac}"))?;
        let path = format!("/org/bluez/{hci}");
        tracing::info!("bluez allow: MAC {mac} -> {path}");
        bluez_allowed.push(path);
    }

    let peer_uid = cli
        .peer_uid
        .unwrap_or_else(|| nix::unistd::geteuid().as_raw());

    let cfg = ProxyConfig {
        listen: cli.listen.clone(),
        upstream: cli.upstream,
        peer_uid,
        filter: FilterConfig {
            bluez_allowed_adapter_paths: bluez_allowed,
        },
    };

    tracing::info!(
        "dbus-bluez-filter-proxy starting: listen={} peer_uid={}",
        cli.listen.display(),
        peer_uid
    );
    let proxy = Proxy::bind(cfg).await?;
    proxy.run().await
}

/// Resolve a BT adapter MAC to its kernel name (`hci0`, `hci1`, ...)
/// via `/sys/class/bluetooth`. Polls until the adapter appears or
/// the timeout elapses — covers cold-boot and USB-resume races.
fn wait_for_adapter(mac: &str, timeout: Duration) -> Result<String> {
    let target = mac.to_uppercase();
    let start = std::time::Instant::now();
    loop {
        if let Some(name) = lookup_adapter_once(&target)? {
            return Ok(name);
        }
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "no BT adapter with MAC {mac} appeared within {timeout:?}"
            ));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn lookup_adapter_once(target_upper: &str) -> Result<Option<String>> {
    // bindgen-generated bindings + raw HCIGETDEVINFO ioctl. Lives
    // in the hci module; no shelling out, no text parsing.
    let adapters = hci::list_adapters().context("HCIGETDEVINFO/HCIGETDEVLIST")?;
    Ok(adapters
        .into_iter()
        .find(|a| a.mac.to_uppercase() == target_upper)
        .map(|a| a.name))
}
