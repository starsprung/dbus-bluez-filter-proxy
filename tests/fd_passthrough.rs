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

//! End-to-end FD-passing through the proxy.
//!
//! `dbus-fast` (used by `bleak`) negotiates `AGREE_UNIX_FD` during
//! SASL when `negotiate_unix_fd=True`. Once that's in effect, BlueZ's
//! GATT fast-path methods (`AcquireWrite`, `AcquireNotify`) start
//! returning real file descriptors as `SCM_RIGHTS` ancillary data on
//! the method-return message. If the proxy reads/writes message bytes
//! with plain `read`/`write` (no `recvmsg`/`sendmsg` ancillary), those
//! FDs are silently dropped — the client receives a method-return
//! whose `UNIX_FDS` header field claims one FD but no FD arrives, and
//! attempting to use it surfaces as crashes deep inside whichever
//! protocol the FD was meant to carry.
//!
//! This test exercises the full path: a service registered directly
//! on the upstream bus returns a memfd containing a known byte
//! pattern; a client connected through the proxy receives the FD,
//! reads from it, and asserts the bytes round-tripped.

mod helpers;

use helpers::TestEnv;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use zbus::zvariant::OwnedFd as ZvOwnedFd;

const SENTINEL: &[u8] = b"FD-RELAYED-OK";

/// Service that creates a tempfile, writes [`SENTINEL`] into it,
/// rewinds, and returns the fd. Reading from the returned fd should
/// yield those exact bytes — only possible if the proxy preserved
/// the `SCM_RIGHTS` ancillary data on the method-return message.
/// If FDs are dropped, the client receives `UNIX_FDS=1` in the
/// header but no actual FD, and the call surfaces as a marshalling
/// error.
struct FdSource;

#[zbus::interface(name = "com.example.FdSource")]
impl FdSource {
    fn fetch(&self) -> zbus::fdo::Result<ZvOwnedFd> {
        let mut tmp = tempfile::tempfile()
            .map_err(|e| zbus::fdo::Error::Failed(format!("tempfile: {e}")))?;
        tmp.write_all(SENTINEL)
            .map_err(|e| zbus::fdo::Error::Failed(format!("write: {e}")))?;
        tmp.seek(SeekFrom::Start(0))
            .map_err(|e| zbus::fdo::Error::Failed(format!("seek: {e}")))?;
        let owned: OwnedFd = tmp.into();
        Ok(ZvOwnedFd::from(owned))
    }
}

#[tokio::test]
async fn fd_returned_from_upstream_arrives_through_proxy() {
    let env = TestEnv::start().await.expect("env start");

    // Register the FD-returning service directly on the upstream bus.
    let _server = zbus::ConnectionBuilder::address(env.upstream_addr())
        .unwrap()
        .name("com.example.FdSource")
        .unwrap()
        .serve_at("/com/example/FdSource", FdSource)
        .unwrap()
        .build()
        .await
        .expect("register fd-source service");

    // Client must opt into FD passing — the proxy can't deliver FDs
    // to a client that didn't negotiate AGREE_UNIX_FD.
    let client = zbus::ConnectionBuilder::address(env.proxy_addr())
        .unwrap()
        .build()
        .await
        .expect("connect via proxy");

    let proxy = zbus::Proxy::new(
        &client,
        "com.example.FdSource",
        "/com/example/FdSource",
        "com.example.FdSource",
    )
    .await
    .unwrap();

    let zfd: ZvOwnedFd = proxy
        .call("Fetch", &())
        .await
        .expect("Fetch call should succeed and deliver an FD through the proxy");
    let owned: OwnedFd = zfd.into();

    let mut file = std::fs::File::from(owned);
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("read memfd contents");
    assert_eq!(
        buf, SENTINEL,
        "memfd received via proxy should contain the sentinel bytes \
         (got {buf:?}); empty / wrong bytes mean SCM_RIGHTS was \
         dropped or replaced with an unrelated FD"
    );
}
