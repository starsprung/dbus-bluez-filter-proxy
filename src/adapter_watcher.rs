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

//! Background task that keeps `FilterConfig::bluez_allowed_adapter_paths`
//! in sync with the live MAC→hciN mapping.
//!
//! The kernel can reassign an adapter to a different `hciN` index
//! across unplug/replug (USB resume races, multiple-adapter reorder,
//! deauthorize/authorize cycles to unwedge a stuck adapter, etc.).
//! Without this watcher, the proxy's filter would either reject the
//! adapter at its new path (hiding the user's hardware) or — worse,
//! if another adapter took the old `hciN` — expose the wrong adapter
//! through the same allow-listed path.
//!
//! Wiring:
//!   1. Open a dedicated zbus connection to the proxy's configured
//!      upstream socket (NOT a client-relayed connection — the
//!      watcher is the proxy's own peer of `dbus-daemon`).
//!   2. Subscribe to BlueZ's `InterfacesAdded`/`InterfacesRemoved`
//!      on `/` (BlueZ's `ObjectManager` root).
//!   3. On each event, re-enumerate adapters via HCI ioctls and
//!      atomically swap an updated [`FilterConfig`] into the
//!      `ArcSwap` so in-flight relay tasks pick up the new
//!      allow-list on their very next message.
//!
//! If a configured MAC is currently absent, its entry is left out
//! of the allow-list (conservative: a different adapter that takes
//! the old `hciN` won't accidentally inherit the allow). When the
//! MAC reappears at any `hciN`, the next signal re-adds it.
//!
//! Reconnect logic: if the upstream connection drops (dbus-daemon
//! restart, transient I/O error) we log and retry with capped
//! exponential backoff. The watcher loop never exits — the task
//! lives as long as the proxy does.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use tracing::{debug, info, warn};

use crate::filter::{FilterConfig, SharedFilter};
use crate::hci::{self, Adapter};

/// Spawn the watcher. Returns immediately; the task runs forever
/// until the runtime shuts down. A no-op (returns a finished task)
/// if `macs` is empty, since with no configured MACs there's no
/// allow-list to maintain.
pub fn spawn(upstream: PathBuf, macs: Vec<String>, filter: SharedFilter) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if macs.is_empty() {
            debug!("adapter watcher: no MACs configured, watcher not started");
            return;
        }
        let mut backoff = Duration::from_millis(500);
        loop {
            match run_once(&upstream, &macs, &filter).await {
                Ok(()) => {
                    // run_once only returns Ok(()) on a clean shutdown,
                    // which today never happens — the inner loop runs
                    // forever. Treat as a defensive case anyway.
                    backoff = Duration::from_millis(500);
                }
                Err(e) => {
                    warn!(
                        "adapter watcher: lost connection ({e:#}); reconnecting in {backoff:?}"
                    );
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    })
}

async fn run_once(upstream: &Path, macs: &[String], filter: &SharedFilter) -> Result<()> {
    let address = format!("unix:path={}", upstream.display());
    let conn = zbus::ConnectionBuilder::address(address.as_str())?
        .build()
        .await
        .context("connect to upstream dbus for adapter watcher")?;

    let object_manager = zbus::fdo::ObjectManagerProxy::builder(&conn)
        .destination("org.bluez")?
        .path("/")?
        .build()
        .await
        .context("build ObjectManagerProxy on org.bluez /")?;

    let mut added = object_manager
        .receive_interfaces_added()
        .await
        .context("subscribe to InterfacesAdded")?;
    let mut removed = object_manager
        .receive_interfaces_removed()
        .await
        .context("subscribe to InterfacesRemoved")?;

    info!("adapter watcher: subscribed to org.bluez ObjectManager signals");

    // Reconcile once at startup. Closes the small window between
    // main()'s initial MAC→hciN resolution and the watcher coming
    // online — if an adapter moved in that gap, this catches it.
    reconcile(macs, filter);

    loop {
        tokio::select! {
            sig = added.next() => {
                if sig.is_none() {
                    anyhow::bail!("InterfacesAdded stream ended");
                }
                reconcile(macs, filter);
            }
            sig = removed.next() => {
                if sig.is_none() {
                    anyhow::bail!("InterfacesRemoved stream ended");
                }
                reconcile(macs, filter);
            }
        }
    }
}

/// Re-enumerate adapters and publish a new [`FilterConfig`] iff the
/// MAC→hciN mapping changed. No-op on HCI ioctl failure (we'd rather
/// keep the stale allow-list than blow it away on a transient error).
fn reconcile(macs: &[String], filter: &SharedFilter) {
    let adapters = match hci::list_adapters() {
        Ok(a) => a,
        Err(e) => {
            warn!("adapter watcher: HCI list_adapters failed: {e}; keeping current filter");
            return;
        }
    };
    let new_paths = compute_allowed_paths(macs, &adapters);
    let current = filter.load();
    if current.bluez_allowed_adapter_paths != new_paths {
        info!(
            "adapter watcher: bluez allow updated {:?} -> {:?}",
            current.bluez_allowed_adapter_paths, new_paths
        );
        filter.store(Arc::new(FilterConfig {
            bluez_allowed_adapter_paths: new_paths,
        }));
    } else {
        debug!("adapter watcher: signal received, mapping unchanged");
    }
}

/// Build the allow-list given the configured MACs and the current
/// kernel adapter list. Pure function: easy to unit-test, no I/O.
/// MACs whose adapters are currently absent are skipped — when they
/// reappear at any `hciN` a later reconcile() adds them back.
pub(crate) fn compute_allowed_paths(macs: &[String], adapters: &[Adapter]) -> Vec<String> {
    let mut out = Vec::with_capacity(macs.len());
    for mac in macs {
        let target = mac.to_uppercase();
        if let Some(a) = adapters.iter().find(|a| a.mac.to_uppercase() == target) {
            out.push(format!("/org/bluez/{}", a.name));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ad(name: &str, mac: &str) -> Adapter {
        Adapter {
            name: name.to_string(),
            mac: mac.to_string(),
        }
    }

    #[test]
    fn maps_present_macs_to_their_current_hci_paths() {
        let macs = vec!["AA:BB:CC:DD:EE:01".into(), "AA:BB:CC:DD:EE:02".into()];
        let adapters = vec![
            ad("hci2", "AA:BB:CC:DD:EE:01"),
            ad("hci0", "AA:BB:CC:DD:EE:02"),
        ];
        let paths = compute_allowed_paths(&macs, &adapters);
        assert_eq!(paths, vec!["/org/bluez/hci2", "/org/bluez/hci0"]);
    }

    #[test]
    fn skips_absent_macs() {
        // The configured second MAC has no live adapter — its entry
        // must be left out of the allow-list rather than mapped to
        // whatever happens to share the old hciN.
        let macs = vec!["AA:BB:CC:DD:EE:01".into(), "AA:BB:CC:DD:EE:02".into()];
        let adapters = vec![ad("hci0", "AA:BB:CC:DD:EE:01")];
        let paths = compute_allowed_paths(&macs, &adapters);
        assert_eq!(paths, vec!["/org/bluez/hci0"]);
    }

    #[test]
    fn mac_match_is_case_insensitive() {
        let macs = vec!["aa:bb:cc:dd:ee:ff".into()];
        let adapters = vec![ad("hci0", "AA:BB:CC:DD:EE:FF")];
        let paths = compute_allowed_paths(&macs, &adapters);
        assert_eq!(paths, vec!["/org/bluez/hci0"]);
    }

    #[test]
    fn replug_to_new_hci_updates_path() {
        // Same MAC, kernel reassigned it from hci1 to hci2. This is
        // the exact scenario from issue #1.
        let macs = vec!["AA:BB:CC:DD:EE:01".into()];
        let before = compute_allowed_paths(&macs, &[ad("hci1", "AA:BB:CC:DD:EE:01")]);
        let after = compute_allowed_paths(&macs, &[ad("hci2", "AA:BB:CC:DD:EE:01")]);
        assert_eq!(before, vec!["/org/bluez/hci1"]);
        assert_eq!(after, vec!["/org/bluez/hci2"]);
        assert_ne!(before, after, "reconcile should detect the hciN change");
    }

    #[test]
    fn different_adapter_taking_old_hci_does_not_inherit_allow() {
        // hci0 used to be our MAC. Now hci0 belongs to a different
        // physical adapter (MAC :02) and our MAC is gone. The
        // allow-list must be EMPTY — otherwise we'd be silently
        // exposing the wrong adapter to the consumer.
        let macs = vec!["AA:BB:CC:DD:EE:01".into()];
        let adapters = vec![ad("hci0", "AA:BB:CC:DD:EE:02")];
        let paths = compute_allowed_paths(&macs, &adapters);
        assert!(
            paths.is_empty(),
            "stale hci0 entry leaked through to allow list: {paths:?}"
        );
    }
}
