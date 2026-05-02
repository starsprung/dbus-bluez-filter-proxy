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

//! Async Unix-stream IO that preserves `SCM_RIGHTS` ancillary data.
//!
//! `tokio::net::UnixStream::read` / `write` use `read(2)` / `write(2)`,
//! which discard ancillary control data. D-Bus carries file
//! descriptors via `SCM_RIGHTS` — required for BlueZ's GATT fast
//! path (`AcquireWrite`, `AcquireNotify`) — so the message-aware
//! relay must use `recvmsg(2)` / `sendmsg(2)` instead. This module
//! wraps a raw `OwnedFd` in `tokio::io::unix::AsyncFd` and offers
//! `recv` / `send` methods that thread FDs through.
//!
//! Per-message FD pairing is the caller's responsibility: in any
//! given `recvmsg` call the kernel returns at most one sendmsg's
//! worth of ancillary, so callers should accumulate FDs into a
//! queue and pop the count declared by each message's `UNIX_FDS`
//! header field as full messages get parsed out of the byte stream.

use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use nix::sys::socket::{
    recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags,
};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;


/// Generous upper bound on the FDs we expect in a single recvmsg.
/// dbus-daemon's default `max_message_unix_fds` is 16; per-recvmsg
/// ancillary collects at most one sendmsg's worth, so 16 is the
/// practical ceiling. 32 leaves headroom for a misconfigured peer
/// without bloating the stack frame.
const MAX_FDS_PER_RECV: usize = 32;

/// Async, FD-passing-aware wrapper around a Unix stream socket.
///
/// `recv` and `send` are both `&self` so the same stream can be read
/// in one task and written in another concurrently — wrap the value
/// in an `Arc` and clone the handle for each task. tokio's `AsyncFd`
/// supports concurrent readiness for read and write, and `recvmsg` /
/// `sendmsg` are individually atomic at the syscall layer.
pub struct FdStream {
    fd: AsyncFd<OwnedFd>,
}

impl FdStream {
    /// Wrap a non-blocking `OwnedFd`. The caller is responsible for
    /// `O_NONBLOCK` — `AsyncFd` will spin if the fd is blocking.
    /// `tokio::net::UnixStream::into_std()` does not guarantee
    /// nonblocking mode after conversion, so callers should
    /// explicitly `set_nonblocking(true)` on the std stream first.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self {
            fd: AsyncFd::with_interest(fd, Interest::READABLE | Interest::WRITABLE)?,
        })
    }

    /// Receive bytes plus any `SCM_RIGHTS` FDs that arrived as
    /// ancillary data. Returns `(0, [])` on peer EOF.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
        loop {
            let mut guard = self.fd.readable().await?;
            // try_io drives one nonblocking syscall; on WouldBlock
            // it clears the readiness bit and we wait again.
            let res = guard.try_io(|inner| {
                let mut iov = [IoSliceMut::new(buf)];
                let mut cmsg = nix::cmsg_space!([RawFd; MAX_FDS_PER_RECV]);
                // MSG_CMSG_CLOEXEC: any FDs we receive should be
                // close-on-exec so child processes can't accidentally
                // inherit them. Matches dbus-daemon's behaviour.
                let r = recvmsg::<()>(
                    inner.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg),
                    MsgFlags::MSG_CMSG_CLOEXEC,
                )
                .map_err(io::Error::from)?;
                let n = r.bytes;
                let mut fds: Vec<OwnedFd> = Vec::new();
                for cm in r.cmsgs().map_err(io::Error::other)? {
                    if let ControlMessageOwned::ScmRights(raws) = cm {
                        for raw in raws {
                            // SAFETY: these FDs were just delivered
                            // by the kernel and we own them now.
                            fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
                        }
                    }
                }
                Ok((n, fds))
            });
            match res {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    /// Send bytes plus an optional batch of FDs as `SCM_RIGHTS`. The
    /// FDs are referenced by `BorrowedFd` so the caller can keep
    /// ownership across retries; they're dropped (closed) by the
    /// caller after a successful send.
    pub async fn send(&self, buf: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<usize> {
        // Build the ScmRights array from raw fds. ControlMessage
        // borrows the slice for the duration of sendmsg, so we
        // collect once and reuse across retries.
        let raw_fds: Vec<RawFd> = fds.iter().map(|f| f.as_raw_fd()).collect();
        loop {
            let mut guard = self.fd.writable().await?;
            let res = guard.try_io(|inner| {
                let iov = [IoSlice::new(buf)];
                if raw_fds.is_empty() {
                    sendmsg::<()>(inner.as_raw_fd(), &iov, &[], MsgFlags::empty(), None)
                        .map_err(io::Error::from)
                } else {
                    let cmsgs = [ControlMessage::ScmRights(&raw_fds)];
                    sendmsg::<()>(inner.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)
                        .map_err(io::Error::from)
                }
            });
            match res {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    /// Send `buf` in full; loop until every byte has been written.
    /// FDs are attached to the *first* sendmsg only — that pairs
    /// them with the start of the byte range, which is how
    /// dbus-daemon and every D-Bus client expect to read them.
    pub async fn send_all(&self, mut buf: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        let mut first = true;
        while !buf.is_empty() {
            let n = if first {
                first = false;
                self.send(buf, fds).await?
            } else {
                self.send(buf, &[]).await?
            };
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            buf = &buf[n..];
        }
        Ok(())
    }
}

/// Convenience: a shareable handle so reader and writer tasks can
/// hold the same `FdStream` concurrently.
pub type SharedFdStream = Arc<FdStream>;
