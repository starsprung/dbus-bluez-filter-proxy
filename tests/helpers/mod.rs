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

//! Integration-test harness.
//!
//! [`TestEnvBuilder`] / [`TestEnv`] spawns:
//!   * an isolated `dbus-daemon` listening on a tmpfile unix socket
//!     (acts as upstream for the proxy),
//!   * the filtering proxy in front of it on a second tmpfile socket,
//!   * cleans both up on drop.
//!
//! No host system bus, no real BlueZ, no production containers.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};

use dbus_bluez_filter_proxy::filter::FilterConfig;
use dbus_bluez_filter_proxy::proxy::{Proxy, ProxyConfig};

pub struct TestEnvBuilder {
    filter: FilterConfig,
}

impl TestEnvBuilder {
    pub fn new() -> Self {
        Self {
            filter: FilterConfig::default(),
        }
    }

    /// BlueZ adapter paths the filter should permit. Anything else
    /// under `/org/bluez/` gets `AccessDenied`. Empty list means
    /// `/org/bluez/*` is fully open (default pass-through).
    pub fn with_filter_allow_bluez_paths(mut self, paths: Vec<String>) -> Self {
        self.filter.bluez_allowed_adapter_paths = paths;
        self
    }

    pub async fn start(self) -> anyhow::Result<TestEnv> {
        TestEnv::start_with(self.filter).await
    }
}

impl Default for TestEnvBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TestEnv {
    _tmp: TempDir,
    upstream_addr: String,
    proxy_addr: String,
    _upstream: Child,
    proxy_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl TestEnv {
    /// Spin up upstream `dbus-daemon` + proxy with a permissive
    /// (default-pass) filter. Convenience for tests that don't
    /// care about filter rules.
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_with(FilterConfig::default()).await
    }

    async fn start_with(filter: FilterConfig) -> anyhow::Result<Self> {
        let tmp = tempfile::Builder::new()
            .prefix("dbus-bluez-filter-proxy-test-")
            .tempdir()?;
        let upstream_sock = tmp.path().join("upstream.sock");
        let proxy_sock = tmp.path().join("proxy.sock");
        let config_path = tmp.path().join("dbus.conf");

        let config = format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={path}</listen>
  <auth>EXTERNAL</auth>
  <allow_anonymous/>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
            path = upstream_sock.display()
        );
        tokio::fs::write(&config_path, config).await?;

        let upstream = Command::new("dbus-daemon")
            .arg("--nofork")
            .arg(format!("--config-file={}", config_path.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;

        wait_for_socket(&upstream_sock, Duration::from_secs(5)).await?;

        let cfg = ProxyConfig {
            listen: proxy_sock.clone(),
            upstream: upstream_sock.clone(),
            peer_uid: nix::unistd::geteuid().as_raw(),
            filter,
        };
        let proxy = Proxy::bind(cfg).await?;
        let proxy_handle = tokio::spawn(proxy.run());

        wait_for_socket(&proxy_sock, Duration::from_secs(5)).await?;

        Ok(Self {
            _tmp: tmp,
            upstream_addr: format!("unix:path={}", upstream_sock.display()),
            proxy_addr: format!("unix:path={}", proxy_sock.display()),
            _upstream: upstream,
            proxy_handle,
        })
    }

    pub fn proxy_addr(&self) -> &str {
        &self.proxy_addr
    }

    pub fn upstream_addr(&self) -> &str {
        &self.upstream_addr
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        self.proxy_handle.abort();
    }
}

async fn wait_for_socket(path: &PathBuf, timeout: Duration) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    loop {
        if path.exists() {
            if let Ok(mut stream) = tokio::net::UnixStream::connect(path).await {
                let _ = stream.shutdown().await;
                return Ok(());
            }
        }
        if start.elapsed() > timeout {
            anyhow::bail!(
                "socket {} did not come up within {timeout:?}",
                path.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// Shared test-service definition.

pub struct EchoService;

#[zbus::interface(name = "com.example.Echo")]
impl EchoService {
    fn echo(&self, msg: String) -> String {
        msg
    }
}
