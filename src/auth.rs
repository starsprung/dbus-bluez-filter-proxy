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

//! Server-side D-Bus SASL AUTH state machine.
//!
//! Handles both the spec's back-and-forth flow and sd-bus's pipelined
//! "fast path", where the client crams everything into a single send
//! and doesn't wait for the server's `OK` before issuing `BEGIN`. A
//! typical sd-bus pipelined transmission looks like:
//!
//! ```text
//! \0AUTH EXTERNAL\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n
//! ```
//!
//! ...with the AUTH line carrying *no* hex-uid argument — sd-bus relies
//! exclusively on the SO_PEERCRED-derived uid the kernel attests on the
//! socket. The traditional flow with an explicit hex-uid is also
//! handled: if present, the FSM validates it against `peer_uid`.
//!
//! Design invariants:
//!   * The FSM does no I/O. The caller hands it bytes via [`feed`] and
//!     executes the returned [`Action`]s. This makes it cheap to test
//!     without sockets, async, or a real D-Bus daemon.
//!   * Pipelined input is fully supported: a single `feed` call may
//!     consume multiple SASL lines, accumulating the response. When
//!     `BEGIN` is parsed, the FSM emits [`Action::Accept`] along with
//!     any trailing message-stream bytes ([`Accept::carryover`]) so
//!     the caller can hand them straight to the relay.
//!   * `peer_uid` is the caller's responsibility to obtain (typically
//!     via SO_PEERCRED on the client socket); the FSM only ratifies
//!     the SASL-level claim when one is presented.

use std::fmt;

/// Driving the FSM by feeding bytes returns one of these.
///
/// The caller's loop is:
///
/// ```text
/// loop {
///     let buf = socket.read().await?;
///     match fsm.feed(&buf) {
///         Action::NeedMore       => continue,
///         Action::Send(reply)    => socket.write_all(&reply).await?,
///         Action::Accept(a)      => {
///             socket.write_all(&a.reply).await?;
///             forward_to_upstream(&a.carryover).await?;
///             break;
///         }
///         Action::Reject(reason) => { drop(socket); return Err(reason.into()); }
///     }
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Read more bytes from the client; nothing to send yet.
    NeedMore,
    /// Write these bytes to the client and loop back to `feed`.
    /// (Used during multi-step exchanges that haven't yet reached
    /// `BEGIN`. With pure pipelined sd-bus input, this variant is
    /// rarely hit because the FSM consumes everything up to `BEGIN`
    /// in one call and emits `Accept` directly.)
    Send(Vec<u8>),
    /// Handshake complete. Send `reply` to the client, then enter
    /// message-passing mode with `carryover` as the leading bytes.
    Accept(Accept),
    /// Reject the client; close the connection. Reason is for logs.
    Reject(RejectReason),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Accept {
    pub reply: Vec<u8>,
    pub carryover: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RejectReason {
    MissingNul,
    UnknownMechanism { line: String },
    InvalidUid,
    UidMismatch { expected: u32, got: u32 },
    UnexpectedCommand(String),
    MalformedHexUid,
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingNul => write!(f, "client did not send leading NUL"),
            Self::UnknownMechanism { line } => {
                write!(f, "unsupported AUTH mechanism: {line:?} (only EXTERNAL is accepted)")
            }
            Self::InvalidUid => write!(f, "uid not parseable from EXTERNAL hex argument"),
            Self::UidMismatch { expected, got } => write!(
                f,
                "uid mismatch: peer claims {got}, kernel says {expected}"
            ),
            Self::UnexpectedCommand(s) => write!(f, "unexpected SASL command: {s:?}"),
            Self::MalformedHexUid => write!(f, "EXTERNAL hex-uid had odd length or invalid chars"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    /// Haven't seen the leading NUL yet.
    AwaitNul,
    /// NUL received; waiting for `AUTH ...`.
    AwaitAuth,
    /// `AUTH EXTERNAL` (no hex-uid) received; we sent a `DATA`
    /// challenge and are waiting for the client's `DATA` response.
    /// This mirrors what real dbus-daemon does — sd-bus tools
    /// pre-emptively pipeline DATA after AUTH expecting this exact
    /// challenge/response.
    AwaitData,
    /// EXTERNAL accepted (OK sent); waiting for `BEGIN` (and
    /// optionally `NEGOTIATE_UNIX_FD` first).
    AwaitBegin,
    /// BEGIN received; handshake complete.
    Done,
    /// Rejected; the I/O layer should close the connection.
    Rejected,
}

/// Server-side handshake state machine. One per inbound connection.
#[derive(Debug)]
pub struct AuthFsm {
    state: State,
    /// Kernel-attested peer uid (from SO_PEERCRED). Authoritative.
    peer_uid: u32,
    server_guid: String,
    rxbuf: Vec<u8>,
    /// Accumulated reply for the next `Send` or `Accept` action.
    /// Pipelined input writes here as multi-line responses (e.g.
    /// `OK <guid>\r\nERROR\r\n` for AUTH+NEGOTIATE_UNIX_FD).
    pending_reply: Vec<u8>,
}

impl AuthFsm {
    pub fn new(peer_uid: u32, server_guid: impl Into<String>) -> Self {
        Self {
            state: State::AwaitNul,
            peer_uid,
            server_guid: server_guid.into(),
            rxbuf: Vec::with_capacity(64),
            pending_reply: Vec::with_capacity(64),
        }
    }

    /// Feed bytes from the wire. Returns the next [`Action`] to take.
    pub fn feed(&mut self, bytes: &[u8]) -> Action {
        self.rxbuf.extend_from_slice(bytes);
        loop {
            match self.state {
                State::AwaitNul => {
                    if self.rxbuf.is_empty() {
                        return self.flush_or_more();
                    }
                    if self.rxbuf[0] != 0 {
                        self.state = State::Rejected;
                        return Action::Reject(RejectReason::MissingNul);
                    }
                    self.rxbuf.remove(0);
                    self.state = State::AwaitAuth;
                }
                State::AwaitAuth => match self.take_line() {
                    None => return self.flush_or_more(),
                    Some(line) => {
                        if let Some(act) = self.handle_auth_line(&line) {
                            return act;
                        }
                    }
                },
                State::AwaitData => match self.take_line() {
                    None => return self.flush_or_more(),
                    Some(line) => {
                        if let Some(act) = self.handle_data_line(&line) {
                            return act;
                        }
                    }
                },
                State::AwaitBegin => match self.take_line() {
                    None => return self.flush_or_more(),
                    Some(line) => {
                        if let Some(act) = self.handle_begin_line(&line) {
                            return act;
                        }
                    }
                },
                State::Done => {
                    // Anything still in rxbuf is message-stream bytes
                    // for the relay. Hand them off via Accept.
                    let carryover = std::mem::take(&mut self.rxbuf);
                    let reply = std::mem::take(&mut self.pending_reply);
                    return Action::Accept(Accept { reply, carryover });
                }
                State::Rejected => return Action::NeedMore,
            }
        }
    }

    /// True if the FSM has accepted the client (BEGIN received).
    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    fn flush_or_more(&mut self) -> Action {
        if self.pending_reply.is_empty() {
            Action::NeedMore
        } else {
            let reply = std::mem::take(&mut self.pending_reply);
            Action::Send(reply)
        }
    }

    fn take_line(&mut self) -> Option<String> {
        let pos = self.rxbuf.windows(2).position(|w| w == b"\r\n")?;
        let line: Vec<u8> = self.rxbuf.drain(..pos).collect();
        self.rxbuf.drain(..2);
        String::from_utf8(line).ok()
    }

    /// Returns Some(action) to terminate the loop, or None to continue
    /// processing further lines from rxbuf in this same `feed` call.
    fn handle_auth_line(&mut self, line: &str) -> Option<Action> {
        // `AUTH EXTERNAL` — sd-bus form (no hex-uid; peer_uid is
        // authoritative from the kernel and that's what we use).
        // `AUTH EXTERNAL <hex-uid>` — libdbus form (hex-uid validated
        // against peer_uid as a defence-in-depth check).
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        match parts.as_slice() {
            ["AUTH", "EXTERNAL"] => {
                // No hex-uid: emit the DATA challenge that real
                // dbus-daemon sends. The client (sd-bus) responds
                // with its own DATA line — usually pre-emptively
                // pipelined — and we OK after that.
                self.pending_reply.extend_from_slice(b"DATA\r\n");
                self.state = State::AwaitData;
                None
            }
            ["AUTH", "EXTERNAL", hex_uid] => match decode_hex_uid(hex_uid) {
                Ok(claimed) if claimed == self.peer_uid => {
                    self.pending_reply
                        .extend_from_slice(format!("OK {}\r\n", self.server_guid).as_bytes());
                    self.state = State::AwaitBegin;
                    None
                }
                Ok(claimed) => {
                    self.state = State::Rejected;
                    Some(Action::Reject(RejectReason::UidMismatch {
                        expected: self.peer_uid,
                        got: claimed,
                    }))
                }
                Err(reason) => {
                    self.state = State::Rejected;
                    Some(Action::Reject(reason))
                }
            },
            ["AUTH"] => {
                // Bare `AUTH` is a probe: respond with available mechs.
                self.pending_reply
                    .extend_from_slice(b"REJECTED EXTERNAL\r\n");
                None
            }
            ["AUTH", _mech, ..] => {
                self.state = State::Rejected;
                Some(Action::Reject(RejectReason::UnknownMechanism {
                    line: line.to_string(),
                }))
            }
            _ => {
                self.state = State::Rejected;
                Some(Action::Reject(RejectReason::UnexpectedCommand(
                    line.to_string(),
                )))
            }
        }
    }

    fn handle_data_line(&mut self, line: &str) -> Option<Action> {
        // Expected: client's DATA response to our DATA challenge.
        // `DATA[ <hex>]` — payload is the SASL credentials, but for
        // EXTERNAL with kernel-attested SO_PEERCRED we don't actually
        // need any data. Accept empty or anything.
        if line == "DATA" || line.starts_with("DATA ") {
            self.pending_reply
                .extend_from_slice(format!("OK {}\r\n", self.server_guid).as_bytes());
            self.state = State::AwaitBegin;
            None
        } else if line == "CANCEL" {
            self.state = State::Rejected;
            Some(Action::Reject(RejectReason::UnexpectedCommand("CANCEL".into())))
        } else {
            self.state = State::Rejected;
            Some(Action::Reject(RejectReason::UnexpectedCommand(
                line.to_string(),
            )))
        }
    }

    fn handle_begin_line(&mut self, line: &str) -> Option<Action> {
        // A late `DATA` line in AwaitBegin (after we've already
        // sent OK) shouldn't normally happen — sd-bus pipelines DATA
        // before BEGIN, which we now consume in AwaitData. But if
        // some client emits DATA again post-OK, silently swallow it
        // rather than confusing the response stream.
        if let Some(rest) = line.strip_prefix("DATA") {
            if rest.is_empty() || rest.starts_with(' ') {
                return None;
            }
        }
        match line {
            "BEGIN" => {
                self.state = State::Done;
                None
            }
            "NEGOTIATE_UNIX_FD" => {
                // We don't pass FDs through the proxy. ERROR is the
                // libdbus way of saying "not supported"; sd-bus and
                // GDBus handle it gracefully and continue to BEGIN.
                self.pending_reply.extend_from_slice(b"ERROR\r\n");
                None
            }
            "CANCEL" => {
                self.state = State::Rejected;
                Some(Action::Reject(RejectReason::UnexpectedCommand(
                    "CANCEL".into(),
                )))
            }
            _ => {
                self.state = State::Rejected;
                Some(Action::Reject(RejectReason::UnexpectedCommand(
                    line.to_string(),
                )))
            }
        }
    }
}

fn decode_hex_uid(hex_uid: &str) -> Result<u32, RejectReason> {
    let bytes = hex::decode(hex_uid).map_err(|_| RejectReason::MalformedHexUid)?;
    let s = std::str::from_utf8(&bytes).map_err(|_| RejectReason::InvalidUid)?;
    s.parse::<u32>().map_err(|_| RejectReason::InvalidUid)
}
