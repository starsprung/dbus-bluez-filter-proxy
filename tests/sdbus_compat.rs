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

//! sd-bus compatibility — `busctl`, the canonical sd-bus client,
//! must connect through the proxy. This is the central regression
//! test for sd-bus's pipelined SASL fast-path: `xdg-dbus-proxy`
//! fails it ("Invalid message header read"), and that motivated
//! this whole proxy.
//!
//! Skipped (with a logged message) if `busctl` isn't on PATH so a
//! checkout without systemd installed doesn't fail spuriously.

mod helpers;

use helpers::TestEnv;
use std::process::Stdio;
use tokio::process::Command;

#[tokio::test]
async fn busctl_list_via_proxy_succeeds() {
    let busctl = match which("busctl") {
        Some(p) => p,
        None => {
            eprintln!("skipping: busctl not on PATH");
            return;
        }
    };

    let env = TestEnv::start().await.expect("env start");

    // `busctl --address=... list` connects, does AUTH, calls
    // ListNames, prints results. Round-trip exercise of the relay
    // *and* sd-bus's pipelined SASL.
    let trace = std::env::var("DBUS_FILTER_PROXY_STRACE").is_ok();
    let mut cmd = if trace {
        let mut c = Command::new("strace");
        c.arg("-fe").arg("trace=read,write,recvmsg,sendmsg,setsockopt,getsockopt,connect");
        c.arg(busctl.as_os_str());
        c
    } else {
        Command::new(busctl)
    };
    let out = cmd
        .arg(format!("--address={}", env.proxy_addr()))
        .arg("list")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn busctl");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "busctl failed (exit {:?}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
    // Confirm the bus's own service shows up in the listing — i.e.
    // a real method round-trip happened, not just AUTH.
    assert!(
        stdout.contains("org.freedesktop.DBus"),
        "busctl list output didn't mention org.freedesktop.DBus:\n{stdout}"
    );
}

fn which(cmd: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
