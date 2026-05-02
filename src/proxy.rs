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

//! TCP-style relay between a downstream client and an upstream
//! D-Bus daemon, with a transparent SASL phase.
//!
//! Lifecycle of a client:
//!   1. Accept on the listen socket.
//!   2. Read kernel-attested peer uid via SO_PEERCRED. Reject early
//!      if it doesn't match the configured `peer_uid` — guards
//!      against another local user dialling the proxy socket.
//!   3. Connect to the upstream socket and send `\0` plus
//!      `SCM_CREDENTIALS` carrying the proxy's own creds (libdbus
//!      convention; dbus-daemon validates the ancillary creds against
//!      its allow-list before any AUTH bytes are read).
//!   4. Consume — and drop — the leading `\0` byte the downstream
//!      client must send. Its purpose is to ride along with peer
//!      credentials, but those credentials terminate at the proxy;
//!      upstream sees the proxy's creds, set in step 3, instead.
//!   5. Run a bidirectional byte-shuttle between client and upstream.
//!      Forward each `\r\n`-terminated SASL line verbatim in both
//!      directions until the line `BEGIN\r\n` is seen from the
//!      client. That line is forwarded too; anything in the same
//!      buffer past `BEGIN\r\n` is the post-SASL carryover (sd-bus's
//!      pipelined fast-path packs `BEGIN` and the first message into
//!      one syscall).
//!   6. Spawn two tasks: client→upstream and upstream→client. Each
//!      task parses message headers so the BlueZ filter rules can
//!      apply (method-call denial, GMO/Introspect response rewriting,
//!      signal filtering); message bodies that aren't being rewritten
//!      pass through untouched.
//!
//! Why transparent SASL forwarding rather than re-implementing the
//! handshake locally: the SASL `OK <guid>` line carries the upstream
//! daemon's bus GUID, and `NEGOTIATE_UNIX_FD` negotiates a real
//! capability between client and daemon. Re-implementing locally
//! means inventing a fake GUID and choosing a hard-coded answer to
//! `NEGOTIATE_UNIX_FD` that may not match upstream's truth — strict
//! clients (dbus-fast, used by `bleak`) treat any reply other than
//! `AGREE_UNIX_FD` as auth failure, so a hard-coded `ERROR` breaks
//! them outright. Forwarding keeps upstream's answers authoritative.
//!
//! Per-client failures don't tear down the listener; one bad client
//! disconnects and we keep accepting.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info};

use crate::filter::{Decision, FilterConfig, MethodCallInfo};
use crate::introspect;
use crate::wire::{self, MessageType};

/// Tracked outgoing method calls whose replies we want to rewrite.
/// Keyed by request serial; the variant carries any per-call state
/// the rewriter needs (e.g. the path that was introspected, so the
/// XML-filter can compute child paths).
#[derive(Debug, Clone)]
enum TrackedCall {
    GetManagedObjects,
    Introspect { object_path: String },
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen: PathBuf,
    pub upstream: PathBuf,
    /// Expected peer uid for downstream SASL EXTERNAL. Tests pass the
    /// running uid; production callers pass whatever uid the owning
    /// container is expected to connect as.
    pub peer_uid: u32,
    /// BlueZ filter rules. Empty default = full pass-through.
    pub filter: FilterConfig,
}

pub struct Proxy {
    listener: UnixListener,
    cfg: Arc<ProxyConfig>,
}

impl Proxy {
    /// Bind the listen socket. Caller owns the returned [`Proxy`] and
    /// drives it with [`Self::run`].
    pub async fn bind(cfg: ProxyConfig) -> Result<Self> {
        // Best-effort cleanup: stale socket files from prior runs would
        // make bind() fail with EADDRINUSE. Production has a privileged
        // ExecStartPre to handle this; tests get the same behaviour.
        let _ = tokio::fs::remove_file(&cfg.listen).await;
        let listener = UnixListener::bind(&cfg.listen)
            .with_context(|| format!("bind {}", cfg.listen.display()))?;
        Ok(Self {
            listener,
            cfg: Arc::new(cfg),
        })
    }

    /// Accept loop. Spawns a task per inbound connection; runs until
    /// the listener errors out.
    pub async fn run(self) -> Result<()> {
        loop {
            let (client, _) = match self.listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    error!("accept failed: {e}");
                    return Err(e.into());
                }
            };
            let cfg = Arc::clone(&self.cfg);
            tokio::spawn(async move {
                if let Err(e) = handle_client(client, cfg).await {
                    debug!("client session ended: {e:#}");
                }
            });
        }
    }
}

async fn handle_client(mut client: UnixStream, cfg: Arc<ProxyConfig>) -> Result<()> {
    // Validate peer uid via SO_PEERCRED before any bytes flow. Done
    // here rather than as part of SASL because the SASL phase is
    // forwarded transparently to upstream — this is the proxy's only
    // independent authorization decision.
    let observed_uid = peer_uid(&client).context("read SO_PEERCRED on client socket")?;
    if observed_uid != cfg.peer_uid {
        anyhow::bail!(
            "peer uid mismatch: SO_PEERCRED reports {observed_uid}, configured {}",
            cfg.peer_uid
        );
    }

    // Connect upstream and emit the proxy's own `\0` + SCM_CREDENTIALS
    // greeting. dbus-daemon reads ancillary creds on the leading NUL
    // and uses them as the kernel-attested identity for the
    // upstream-side SASL EXTERNAL exchange.
    let upstream_path = cfg.upstream.clone();
    let std_upstream =
        tokio::task::spawn_blocking(move || -> Result<std::os::unix::net::UnixStream> {
            sync_connect_upstream_with_creds(&upstream_path)
        })
        .await
        .context("spawn_blocking upstream connect")??;
    std_upstream.set_nonblocking(true).context("set nonblocking")?;
    let mut upstream = UnixStream::from_std(std_upstream)
        .context("std -> tokio UnixStream conversion")?;

    // Run the SASL phase transparently. Drops the client's leading
    // NUL (the proxy already sent its own upstream), then byte-
    // shuttles SASL lines until `BEGIN\r\n` is forwarded upstream.
    let carryover = forward_sasl(&mut client, &mut upstream)
        .await
        .context("transparent SASL forwarding")?;
    if std::env::var("DBUS_FILTER_PROXY_DEBUG").is_ok() {
        eprintln!("[proxy] SASL forwarded, carryover len={}", carryover.len());
    }
    info!("SASL handshake forwarded (peer uid {})", cfg.peer_uid);

    // Hand the carryover bytes (anything past BEGIN that came in the
    // same syscall — common with sd-bus's pipelined fast-path) to
    // upstream before starting the message-aware relay.
    if !carryover.is_empty() {
        upstream
            .write_all(&carryover)
            .await
            .context("forward carryover to upstream")?;
    }

    // Both directions are message-aware.
    //
    // c2u (client -> upstream): read full messages, parse headers,
    // ask the filter; forward, or synthesize an AccessDenied reply
    // back to the client (writes to cw under a lock shared with u2c).
    //
    // u2c (upstream -> client): same shape; on a `GetManagedObjects`
    // method_return whose reply_serial we tracked, parse the body
    // dict and strip non-allowed adapter paths before forwarding.
    // On `InterfacesAdded`/`InterfacesRemoved` signals from
    // `org.freedesktop.DBus.ObjectManager`, parse the first body
    // argument (the announced object path) and drop the message
    // entirely if that path falls outside the allow list.
    let debug = std::env::var("DBUS_FILTER_PROXY_DEBUG").is_ok();
    let filter = cfg.filter.clone();
    let inflight = std::sync::Arc::new(tokio::sync::Mutex::new(
        std::collections::HashMap::<u32, TrackedCall>::new(),
    ));
    let (mut cr, cw) = client.into_split();
    let cw_arc = std::sync::Arc::new(tokio::sync::Mutex::new(cw));
    let (mut ur, mut uw) = upstream.into_split();

    let cw_for_c2u = std::sync::Arc::clone(&cw_arc);
    let inflight_for_c2u = std::sync::Arc::clone(&inflight);
    let filter_for_c2u = filter.clone();
    let c2u = tokio::spawn(async move {
        relay_c2u(
            &mut cr,
            &mut uw,
            cw_for_c2u,
            inflight_for_c2u,
            &filter_for_c2u,
            debug,
        )
        .await
    });

    let cw_for_u2c = std::sync::Arc::clone(&cw_arc);
    let u2c = tokio::spawn(async move {
        relay_u2c(&mut ur, cw_for_u2c, inflight, &filter, debug).await
    });

    tokio::select! {
        r = c2u => if debug { eprintln!("[proxy] c2u exit: {r:?}"); },
        r = u2c => if debug { eprintln!("[proxy] u2c exit: {r:?}"); },
    }
    Ok(())
}

/// Message-aware client -> upstream relay.
///
/// The cw lock is shared with u2c so error-reply synthesis (which
/// writes to cw) can't collide with normal upstream-sourced writes.
/// `inflight` records outgoing method-call serials whose replies
/// the proxy needs to rewrite or post-process — `GetManagedObjects`
/// (subtree splice) and `Introspect` (XML node strip).
async fn relay_c2u(
    cr: &mut tokio::net::unix::OwnedReadHalf,
    uw: &mut tokio::net::unix::OwnedWriteHalf,
    cw: std::sync::Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
    inflight: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<u32, TrackedCall>>>,
    filter: &FilterConfig,
    debug: bool,
) -> std::io::Result<()> {
    let mut accum: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        // Make sure we have at least one full message in `accum`.
        let total_len = loop {
            if accum.len() >= wire::FIXED_HEADER_LEN {
                match wire::peek_message_size(&accum[..wire::FIXED_HEADER_LEN]) {
                    Ok(n) if accum.len() >= n => break n,
                    Ok(_) => {} // need more bytes for full message
                    Err(e) => {
                        if debug {
                            eprintln!("[proxy] c->u peek err: {e}");
                        }
                        return Ok(());
                    }
                }
            }
            let n = cr.read(&mut tmp).await?;
            if n == 0 {
                return Ok(());
            }
            accum.extend_from_slice(&tmp[..n]);
        };

        let msg_bytes: Vec<u8> = accum.drain(..total_len).collect();
        let header = match wire::parse(&msg_bytes) {
            Ok(h) => h,
            Err(e) => {
                if debug {
                    eprintln!("[proxy] c->u parse err: {e}; forwarding raw");
                }
                uw.write_all(&msg_bytes).await?;
                continue;
            }
        };

        match header.msg_type {
            MessageType::MethodCall => {
                let info = MethodCallInfo {
                    serial: header.serial,
                    destination: header.destination.as_deref(),
                    path: header.path.as_deref().unwrap_or(""),
                    sender: header.sender.as_deref(),
                };
                match filter.check_method_call(info) {
                    Decision::Forward => {
                        // Track method calls whose replies we want
                        // to rewrite on the way back. Only for
                        // org.bluez — non-bluez calls pass-through
                        // unmodified. Two cases today:
                        //
                        //   GetManagedObjects: strip disallowed
                        //   adapter entries from the dict.
                        //
                        //   Introspect: strip disallowed `<node>`
                        //   children from the XML.
                        if header.destination.as_deref() == Some("org.bluez") {
                            let kind = match (
                                header.interface.as_deref(),
                                header.member.as_deref(),
                            ) {
                                (
                                    Some("org.freedesktop.DBus.ObjectManager"),
                                    Some("GetManagedObjects"),
                                ) => Some(TrackedCall::GetManagedObjects),
                                (
                                    Some("org.freedesktop.DBus.Introspectable"),
                                    Some("Introspect"),
                                )
                                // libdbus also accepts Introspect on
                                // calls that omit the interface field.
                                | (None, Some("Introspect")) => header
                                    .path
                                    .clone()
                                    .map(|p| TrackedCall::Introspect { object_path: p }),
                                _ => None,
                            };
                            if let Some(k) = kind {
                                inflight.lock().await.insert(header.serial, k);
                            }
                        }
                        uw.write_all(&msg_bytes).await?;
                    }
                    Decision::DenyMethodCall { .. } => {
                        if debug {
                            eprintln!(
                                "[proxy] DENY {} {}.{}",
                                header.path.as_deref().unwrap_or(""),
                                header.interface.as_deref().unwrap_or(""),
                                header.member.as_deref().unwrap_or("")
                            );
                        }
                        let reply = build_access_denied_error(&msg_bytes)?;
                        let mut g = cw.lock().await;
                        g.write_all(&reply).await?;
                    }
                }
            }
            _ => {
                // Method returns / errors / signals from the client
                // pass through untouched; the filter rules only
                // apply to upstream-sourced traffic on the return path.
                uw.write_all(&msg_bytes).await?;
            }
        }
    }
}

/// Message-aware upstream -> client relay.
///
///   * `GetManagedObjects` method returns whose `reply_serial`
///     matches an `inflight` entry: parse body, strip non-allowed
///     adapter paths from the outer dict, re-marshal.
///   * `org.freedesktop.DBus.ObjectManager.{InterfacesAdded,
///     InterfacesRemoved}` signals: parse the leading object-path
///     argument; if the path falls outside the filter's allow list,
///     drop the message entirely.
///   * Anything else: forward verbatim.
async fn relay_u2c(
    ur: &mut tokio::net::unix::OwnedReadHalf,
    cw: std::sync::Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
    inflight: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<u32, TrackedCall>>>,
    filter: &FilterConfig,
    debug: bool,
) -> std::io::Result<()> {
    let mut accum: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let total_len = loop {
            if accum.len() >= wire::FIXED_HEADER_LEN {
                match wire::peek_message_size(&accum[..wire::FIXED_HEADER_LEN]) {
                    Ok(n) if accum.len() >= n => break n,
                    Ok(_) => {}
                    Err(e) => {
                        if debug {
                            eprintln!("[proxy] u->c peek err: {e}");
                        }
                        return Ok(());
                    }
                }
            }
            let n = ur.read(&mut tmp).await?;
            if n == 0 {
                return Ok(());
            }
            accum.extend_from_slice(&tmp[..n]);
        };

        let msg_bytes: Vec<u8> = accum.drain(..total_len).collect();
        let header = match wire::parse(&msg_bytes) {
            Ok(h) => h,
            Err(e) => {
                if debug {
                    eprintln!("[proxy] u->c parse err: {e}; forwarding raw");
                }
                cw.lock().await.write_all(&msg_bytes).await?;
                continue;
            }
        };

        let out_bytes: Option<Vec<u8>> = match header.msg_type {
            MessageType::MethodReturn => {
                let tracked = match header.reply_serial {
                    Some(rs) => inflight.lock().await.remove(&rs),
                    None => None,
                };
                match tracked {
                    Some(TrackedCall::GetManagedObjects) => {
                        match rewrite_gmo_reply(&msg_bytes, filter) {
                            Ok(rewritten) => {
                                if debug {
                                    eprintln!(
                                        "[proxy] GMO reply rewritten: {} -> {} bytes",
                                        msg_bytes.len(),
                                        rewritten.len()
                                    );
                                }
                                Some(rewritten)
                            }
                            Err(e) => {
                                if debug {
                                    eprintln!("[proxy] GMO rewrite failed ({e}); forwarding raw");
                                }
                                Some(msg_bytes)
                            }
                        }
                    }
                    Some(TrackedCall::Introspect { object_path }) => {
                        match rewrite_introspect_reply(&msg_bytes, &object_path, filter) {
                            Ok(rewritten) => {
                                if debug {
                                    eprintln!(
                                        "[proxy] Introspect({object_path}) reply rewritten: {} -> {} bytes",
                                        msg_bytes.len(),
                                        rewritten.len()
                                    );
                                }
                                Some(rewritten)
                            }
                            Err(e) => {
                                if debug {
                                    eprintln!(
                                        "[proxy] Introspect rewrite failed ({e}); forwarding raw"
                                    );
                                }
                                Some(msg_bytes)
                            }
                        }
                    }
                    None => Some(msg_bytes),
                }
            }
            MessageType::Signal => {
                // First filter: signal's own PATH header. Catches
                // PropertiesChanged on /org/bluez/<other>, custom
                // signals on adapter subtrees, etc. The signal's
                // PATH is where the emitter is — if that path is
                // disallowed, the consumer shouldn't see it at all.
                let path = header.path.as_deref().unwrap_or("");
                if !filter.is_path_visible(path) {
                    if debug {
                        eprintln!(
                            "[proxy] DROP signal {} on {path} (disallowed path)",
                            header.member.as_deref().unwrap_or("")
                        );
                    }
                    None
                } else {
                    // Second filter: ObjectManager.InterfacesAdded /
                    // InterfacesRemoved are emitted on /org/bluez (a
                    // root path, always visible) but announce a
                    // specific adapter via the body's first arg. Drop
                    // if that announced path is disallowed.
                    let is_objmgr = header.interface.as_deref()
                        == Some("org.freedesktop.DBus.ObjectManager");
                    let is_added_or_removed = matches!(
                        header.member.as_deref(),
                        Some("InterfacesAdded") | Some("InterfacesRemoved")
                    );
                    if is_objmgr && is_added_or_removed {
                        match peek_object_path_arg(&msg_bytes, &header) {
                            Ok(announced) if !filter.is_path_visible(&announced) => {
                                if debug {
                                    eprintln!(
                                        "[proxy] DROP signal {} announcing {announced}",
                                        header.member.as_deref().unwrap_or("")
                                    );
                                }
                                None
                            }
                            _ => Some(msg_bytes),
                        }
                    } else {
                        Some(msg_bytes)
                    }
                }
            }
            _ => Some(msg_bytes),
        };

        if let Some(b) = out_bytes {
            cw.lock().await.write_all(&b).await?;
        }
    }
}

/// Rewrite the body of a `GetManagedObjects` reply to drop entries
/// whose object-path key is a disallowed BlueZ adapter subtree.
///
/// Surgical wire-level splice: walk the outer `a{oa{sa{sv}}}` array,
/// find each top-level dict entry's byte range, copy through the
/// kept entries verbatim, drop the rest, patch the outer array
/// length and the message body_length. Output is byte-identical to
/// the upstream's original except for the deleted entries — no
/// re-marshaling of nested values, no HashMap-induced reordering,
/// no signature drift. (The earlier deserialise/filter/re-serialise
/// implementation occasionally produced wire bytes bluetoothctl
/// segfaulted on, despite zvariant + zbus accepting them as valid.)
fn rewrite_gmo_reply(msg_bytes: &[u8], filter: &FilterConfig) -> anyhow::Result<Vec<u8>> {
    let endian = match msg_bytes[0] {
        b'l' => zbus::zvariant::Endian::Little,
        b'B' => zbus::zvariant::Endian::Big,
        b => anyhow::bail!("invalid endian byte 0x{b:02x}"),
    };

    let body_start = align8(wire::FIXED_HEADER_LEN + read_u32_at(msg_bytes, 12, endian) as usize);
    let body = &msg_bytes[body_start..];

    let entries = parse_outer_dict_entries(body, endian)
        .map_err(|e| anyhow::anyhow!("parse GMO outer dict: {e}"))?;
    if entries.is_empty() {
        // No entries means nothing to filter; pass through.
        return Ok(msg_bytes.to_vec());
    }

    // Find the original array's offsets within `body`.
    // body[0..4] = uint32 outer-array length. The dict entries
    // start at the next 8-aligned offset.
    let array_data_start = align8(4);
    let mut new_body = Vec::with_capacity(body.len());
    new_body.extend_from_slice(&body[..array_data_start]);

    // `entry_end` for non-last upstream entries includes the
    // 8-align pad bytes between this entry and the next, which
    // dbus's ARRAY length counts as inter-element padding. For the
    // upstream-last entry, `entry_end == array_data_end` (no
    // trailing pad). When filtering drops the upstream-last entry
    // and a previously-non-last entry becomes the new last, its
    // trailing pad must NOT count toward `new_array_len` — dbus
    // ARRAY length excludes padding *after* the last element.
    // Track each kept entry's content end (`inner_end`) so the
    // splice can drop the new-last entry's trailing pad.
    let mut last_inner_end_in_new: Option<usize> = None;
    for (entry_start, entry_end, inner_end, path) in &entries {
        if !filter.is_path_visible(path) {
            continue;
        }
        let pre_len = new_body.len();
        new_body.extend_from_slice(&body[*entry_start..*entry_end]);
        // `inner_end <= entry_end`; offset by the same amount they
        // were apart in the source body.
        last_inner_end_in_new = Some(pre_len + (inner_end - entry_start));
    }
    if let Some(end) = last_inner_end_in_new {
        new_body.truncate(end);
    }
    let new_array_len = new_body.len() - array_data_start;

    // Patch the outer array length (the uint32 at body[0..4]).
    let arr_len_bytes = (new_array_len as u32).to_ne_bytes_endian(endian);
    new_body[0..4].copy_from_slice(&arr_len_bytes);

    // Build the full message: original header+fields, then new body.
    let mut out = Vec::with_capacity(body_start + new_body.len());
    out.extend_from_slice(&msg_bytes[..body_start]);
    out.extend_from_slice(&new_body);

    // Patch body_length in the fixed header (uint32 at offset 4).
    let body_len_bytes = (new_body.len() as u32).to_ne_bytes_endian(endian);
    out[4..8].copy_from_slice(&body_len_bytes);

    Ok(out)
}

/// Walk the outer dict of a GetManagedObjects body and return one
/// `(entry_start, entry_end, inner_end, path)` tuple per top-level
/// entry. All offsets are **byte offsets within the body**.
/// * `entry_start..entry_end` is the entry's full byte range
///   including any trailing alignment padding (i.e. through to the
///   next entry's 8-aligned start, or the array's end for the last
///   entry). Copying these ranges contiguously preserves inter-
///   entry struct alignment.
/// * `inner_end` is where the entry's actual content ends, i.e.
///   the end of the inner `a{sa{sv}}` array's payload, before any
///   trailing alignment pad. For the upstream-last entry,
///   `inner_end == entry_end`. For non-last entries `inner_end`
///   may be < `entry_end` by 1..7 bytes of dict-entry padding.
///   Splicers need this to know how much of the new last kept
///   entry to keep (the trailing pad must be trimmed because dbus
///   ARRAY length does not count pad after the last element).
fn parse_outer_dict_entries(
    body: &[u8],
    endian: zbus::zvariant::Endian,
) -> Result<Vec<(usize, usize, usize, String)>, &'static str> {
    if body.len() < 4 {
        return Err("body shorter than outer-array length field");
    }
    let array_len = read_u32_at(body, 0, endian) as usize;
    // After the uint32 length (4 bytes), pad to the alignment of
    // the array element type. DICT_ENTRY is struct-aligned (8).
    // Body itself starts at a message-offset that's already 8-
    // aligned, so position-in-body and position-in-message agree
    // on alignment.
    let array_data_start = align8(4);
    let array_data_end = array_data_start
        .checked_add(array_len)
        .ok_or("array length overflow")?;
    if body.len() < array_data_end {
        return Err("outer array length extends past body");
    }

    let mut entries = Vec::new();
    let mut cursor = array_data_start;
    while cursor < array_data_end {
        cursor = align8(cursor);
        if cursor >= array_data_end {
            break;
        }
        let entry_start = cursor;

        // Object path: uint32 length + utf8 + NUL terminator.
        if cursor + 4 > array_data_end {
            return Err("path length truncated");
        }
        let path_len = read_u32_at(body, cursor, endian) as usize;
        cursor += 4;
        let path_end = cursor
            .checked_add(path_len)
            .ok_or("path length overflow")?;
        if path_end > array_data_end {
            return Err("path content truncated");
        }
        let path = std::str::from_utf8(&body[cursor..path_end])
            .map_err(|_| "non-utf8 object path")?
            .to_owned();
        cursor = path_end + 1; // skip NUL terminator

        // Inner array `a{sa{sv}}`: align uint32-length to 4, then
        // align array contents to 8 (DICT_ENTRY alignment), then
        // skip `inner_len` content bytes.
        cursor = align4(cursor);
        if cursor + 4 > array_data_end {
            return Err("inner array length truncated");
        }
        let inner_len = read_u32_at(body, cursor, endian) as usize;
        cursor += 4;
        cursor = align8(cursor);
        let inner_end = cursor
            .checked_add(inner_len)
            .ok_or("inner array length overflow")?;
        if inner_end > array_data_end {
            return Err("inner array content truncated");
        }
        cursor = inner_end;

        // The entry ends at the next 8-aligned offset (where the
        // following dict entry would start), or at array_data_end
        // for the last entry. Including trailing padding in the
        // copied range is what preserves struct alignment when
        // splicing entries.
        let inner_end_offset = cursor;
        let entry_end = if cursor >= array_data_end {
            array_data_end
        } else {
            align8(cursor).min(array_data_end)
        };
        entries.push((entry_start, entry_end, inner_end_offset, path));
        cursor = entry_end;
    }
    Ok(entries)
}

trait U32EndianBytes {
    fn to_ne_bytes_endian(self, endian: zbus::zvariant::Endian) -> [u8; 4];
}
impl U32EndianBytes for u32 {
    fn to_ne_bytes_endian(self, endian: zbus::zvariant::Endian) -> [u8; 4] {
        match endian {
            zbus::zvariant::Endian::Little => self.to_le_bytes(),
            zbus::zvariant::Endian::Big => self.to_be_bytes(),
        }
    }
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Rewrite the body of an Introspect response so disallowed bluez
/// child paths are absent from the returned XML. Same surgical-
/// replacement strategy as `rewrite_gmo_reply`: parse via zbus's
/// Message::from_bytes for the typed body view, filter, re-marshal
/// at the original body offset, splice in, patch body_length.
fn rewrite_introspect_reply(
    msg_bytes: &[u8],
    object_path: &str,
    filter: &FilterConfig,
) -> anyhow::Result<Vec<u8>> {
    use zbus::message::Message;
    use zbus::zvariant::serialized::{Context, Data};
    use zbus::zvariant::{to_bytes, Endian as ZEndian};

    let endian = match msg_bytes[0] {
        b'l' => ZEndian::Little,
        b'B' => ZEndian::Big,
        b => anyhow::bail!("invalid endian byte 0x{b:02x}"),
    };
    let ctx_zero = Context::new_dbus(endian, 0);
    let data: Data<'_, '_> = Data::new(msg_bytes.to_vec(), ctx_zero);
    // SAFETY: msg_bytes was just successfully size-peeked + header-
    // parsed by our wire layer.
    let msg: Message = unsafe { Message::from_bytes(data) }?;

    let xml: String = msg.body().deserialize()?;
    let cfg = filter.clone();
    let filtered_xml =
        introspect::filter_xml(&xml, object_path, move |p| cfg.is_path_visible(p))?;

    let body_start = align8(wire::FIXED_HEADER_LEN + read_u32_at(msg_bytes, 12, endian) as usize);
    let body_ctx = Context::new_dbus(endian, body_start);
    let new_body_data = to_bytes(body_ctx, &filtered_xml)?;
    let new_body: &[u8] = &new_body_data;

    let mut out = Vec::with_capacity(body_start + new_body.len());
    out.extend_from_slice(&msg_bytes[..body_start]);
    out.extend_from_slice(new_body);

    let new_len = new_body.len() as u32;
    let bytes = match endian {
        ZEndian::Little => new_len.to_le_bytes(),
        ZEndian::Big => new_len.to_be_bytes(),
    };
    out[4..8].copy_from_slice(&bytes);
    Ok(out)
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

fn read_u32_at(bytes: &[u8], off: usize, endian: zbus::zvariant::Endian) -> u32 {
    let arr = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
    match endian {
        zbus::zvariant::Endian::Little => u32::from_le_bytes(arr),
        zbus::zvariant::Endian::Big => u32::from_be_bytes(arr),
    }
}

/// Decode the leading object-path argument of a signal message
/// body. Used for `InterfacesAdded`/`InterfacesRemoved` whose
/// signatures (`oa{sa{sv}}` / `oas`) both begin with an object path.
fn peek_object_path_arg(call_bytes: &[u8], header: &wire::Header) -> anyhow::Result<String> {
    let body_start = wire::FIXED_HEADER_LEN
        + header.fields_array_length as usize
        + padding_to_8(wire::FIXED_HEADER_LEN + header.fields_array_length as usize);
    if call_bytes.len() < body_start + 4 {
        anyhow::bail!("body too short for object path length");
    }
    let read_u32 = |off: usize| -> u32 {
        let arr = [
            call_bytes[off],
            call_bytes[off + 1],
            call_bytes[off + 2],
            call_bytes[off + 3],
        ];
        match header.endian {
            wire::Endian::Little => u32::from_le_bytes(arr),
            wire::Endian::Big => u32::from_be_bytes(arr),
        }
    };
    let n = read_u32(body_start) as usize;
    let path_start = body_start + 4;
    let path_end = path_start + n;
    if call_bytes.len() < path_end {
        anyhow::bail!("body truncated mid-object-path");
    }
    Ok(std::str::from_utf8(&call_bytes[path_start..path_end])?.to_owned())
}

fn padding_to_8(n: usize) -> usize {
    let r = n % 8;
    if r == 0 {
        0
    } else {
        8 - r
    }
}

/// Build an `org.freedesktop.DBus.Error.AccessDenied` reply to the
/// given method-call message. zbus's high-level builder needs a
/// parsed `Message` of the original call to wire reply-serial /
/// destination correctly, so we round-trip the raw bytes through
/// `Message::from_bytes` first.
fn build_access_denied_error(call_bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    use zbus::message::Message;
    use zbus::zvariant::serialized::{Context, Data};
    use zbus::zvariant::Endian as ZEndian;

    let endian = match call_bytes[0] {
        b'l' => ZEndian::Little,
        b'B' => ZEndian::Big,
        b => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid endian byte 0x{b:02x}"),
            ));
        }
    };
    let ctx = Context::new_dbus(endian, 0);
    let data: Data<'_, '_> = Data::new(call_bytes.to_vec(), ctx);
    // SAFETY: we just parsed `call_bytes` ourselves and verified
    // it's a well-formed D-Bus method call before reaching here.
    let call: Message = unsafe { Message::from_bytes(data) }
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("parse: {e}")))?;

    let body = "request blocked by dbus_bluez_filter_proxy: bluez object path is outside the configured allow-list".to_string();
    let reply = Message::method_error(&call, "org.freedesktop.DBus.Error.AccessDenied")
        .and_then(|b| b.build(&body))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("error msg build: {e}")))?;
    Ok(reply.data().to_vec())
}

/// Connect to the upstream socket and send the leading `\0` byte
/// with `SCM_CREDENTIALS` ancillary data carrying the proxy's own
/// uid/gid/pid. dbus-daemon binds those creds to the connection and
/// uses them as the kernel-attested identity for the SASL EXTERNAL
/// exchange that follows. Synchronous because the standard
/// `sendmsg(2)` API is sync-only and mixing raw `sendmsg` with the
/// tokio reactor is brittle; we run on a blocking thread instead.
fn sync_connect_upstream_with_creds(
    path: &std::path::Path,
) -> Result<std::os::unix::net::UnixStream> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, UnixCredentials};
    use std::io::IoSlice;
    use std::os::fd::{AsRawFd, BorrowedFd};

    let stream = std::os::unix::net::UnixStream::connect(path)
        .with_context(|| format!("connect upstream {}", path.display()))?;

    let creds = UnixCredentials::new();
    let nul = [0u8; 1];
    let iov = [IoSlice::new(&nul)];
    let cmsg = [ControlMessage::ScmCredentials(&creds)];
    // SAFETY: stream's fd outlives this BorrowedFd.
    let fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    sendmsg::<()>(fd.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
        .context("sendmsg with SCM_CREDENTIALS")?;

    Ok(stream)
}

/// Bidirectional byte-shuttle covering the SASL phase. The upstream
/// daemon's responses (`OK <guid>`, `AGREE_UNIX_FD`/`ERROR`, etc.)
/// pass back to the client verbatim — strict clients like dbus-fast
/// see exactly what they would from a direct connection.
///
/// The client→upstream direction is line-oriented so we can detect
/// `BEGIN\r\n` and split SASL bytes from any post-`BEGIN` carryover
/// that arrived in the same syscall (sd-bus pipelines `BEGIN` plus
/// the first message). Bytes after `BEGIN\r\n` are returned to the
/// caller, which feeds them to the message-aware relay.
///
/// The first byte from the client must be `\0` (D-Bus protocol
/// requires it). We consume and discard it: the proxy already sent
/// its own NUL+SCM_CREDENTIALS upstream, which is what binds the
/// upstream-side SASL identity. Forwarding the client's NUL would
/// have it parsed as either an extra leading-NUL (some daemons
/// reject) or, after the SASL phase, as a stray byte ahead of the
/// first message frame.
///
/// After `BEGIN\r\n` is forwarded the function does not return
/// immediately: it tracks how many response-expecting commands were
/// sent c→u (every command except `BEGIN`) and waits until upstream
/// has produced one `\r\n`-terminated reply for each. Without that
/// drain, a pipelined client (`\0AUTH…\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n`
/// in one syscall) would race upstream's SASL replies into the
/// message-aware relay, which would then misparse them as D-Bus
/// message frames.
async fn forward_sasl(
    client: &mut UnixStream,
    upstream: &mut UnixStream,
) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let debug = std::env::var("DBUS_FILTER_PROXY_DEBUG").is_ok();

    // Consume — and drop — the client's mandatory leading NUL.
    let mut nul = [0u8; 1];
    client
        .read_exact(&mut nul)
        .await
        .context("read client leading NUL")?;
    if nul[0] != 0 {
        anyhow::bail!(
            "expected leading NUL byte from client, got 0x{:02x}",
            nul[0]
        );
    }

    let mut c2u_pending: Vec<u8> = Vec::with_capacity(256);
    let mut u2c_pending: Vec<u8> = Vec::with_capacity(256);
    let mut carryover: Vec<u8> = Vec::new();
    // Each c→u line except BEGIN expects exactly one upstream reply
    // line per the SASL spec. Track the imbalance so we know when
    // the SASL phase is fully drained and the message-aware relay
    // can take over without misparsing a stray reply.
    let mut pending_replies: usize = 0;
    let mut begin_sent = false;
    // Separate buffers per direction: `tokio::select!` polls both
    // futures and the borrow checker treats them as live concurrently
    // even though only one wins. One buffer per arm sidesteps that.
    let mut c2u_tmp = [0u8; 1024];
    let mut u2c_tmp = [0u8; 1024];

    loop {
        if begin_sent && pending_replies == 0 {
            return Ok(carryover);
        }
        tokio::select! {
            // Stop reading from the client once BEGIN has been
            // forwarded — anything that arrives after is a message
            // frame for the post-SASL relay to consume.
            r = client.read(&mut c2u_tmp), if !begin_sent => {
                let n = r.context("read from client during SASL")?;
                if n == 0 {
                    anyhow::bail!("client EOF during SASL");
                }
                if debug {
                    eprintln!("[proxy] c->u SASL rx {n} bytes: {:?}", String::from_utf8_lossy(&c2u_tmp[..n]));
                }
                c2u_pending.extend_from_slice(&c2u_tmp[..n]);
                // Pop complete `\r\n`-terminated lines and forward
                // each one verbatim. `BEGIN` flips `begin_sent`; any
                // bytes still buffered after it are carryover.
                while let Some(crlf) = c2u_pending.windows(2).position(|w| w == b"\r\n") {
                    let line_end = crlf + 2;
                    upstream
                        .write_all(&c2u_pending[..line_end])
                        .await
                        .context("forward SASL line to upstream")?;
                    let is_begin = c2u_pending[..crlf] == *b"BEGIN";
                    c2u_pending.drain(..line_end);
                    if is_begin {
                        begin_sent = true;
                        carryover = std::mem::take(&mut c2u_pending);
                        break;
                    }
                    pending_replies += 1;
                }
            }
            r = upstream.read(&mut u2c_tmp) => {
                let n = r.context("read from upstream during SASL")?;
                if n == 0 {
                    anyhow::bail!("upstream EOF during SASL");
                }
                if debug {
                    eprintln!("[proxy] u->c SASL rx {n} bytes: {:?}", String::from_utf8_lossy(&u2c_tmp[..n]));
                }
                // Forward verbatim, but also count complete reply
                // lines so we know when upstream has answered every
                // outstanding command.
                client
                    .write_all(&u2c_tmp[..n])
                    .await
                    .context("forward SASL reply to client")?;
                u2c_pending.extend_from_slice(&u2c_tmp[..n]);
                while let Some(crlf) = u2c_pending.windows(2).position(|w| w == b"\r\n") {
                    u2c_pending.drain(..crlf + 2);
                    pending_replies = pending_replies.saturating_sub(1);
                }
            }
        }
    }
}

/// Look up the connecting peer's uid via `SO_PEERCRED`. The
/// kernel-attested uid is the proxy's only independent authorization
/// signal (the SASL handshake itself is forwarded transparently to
/// upstream), so the value returned here is compared against
/// [`ProxyConfig::peer_uid`] up front in [`handle_client`].
pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::fd::{AsRawFd, BorrowedFd};
    // SAFETY: `stream`'s fd outlives the BorrowedFd.
    let fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    let cred = getsockopt(&fd, PeerCredentials).context("SO_PEERCRED")?;
    Ok(cred.uid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::zvariant::Endian as ZEndian;

    /// Build the bytes of one outer dict entry:
    /// `{o = path, a{sa{sv}} = [{ "I" = a{sv} { "X" = byte(value) } }]}`.
    /// `with_trailing_pad` controls whether the entry's bytes include
    /// the 6 trailing pad bytes that 8-align the next entry — present
    /// for non-last entries in the upstream body, absent for the
    /// upstream-last entry.
    ///
    /// The fixture deliberately uses a 15-byte path and a single
    /// byte-typed property so the entry's `inner_end` lands at a
    /// non-8-aligned offset (50 bytes past the entry start), which
    /// is what makes the trailing-pad bug observable.
    fn build_entry(path: &str, value: u8, with_trailing_pad: bool) -> Vec<u8> {
        assert_eq!(
            path.len(),
            15,
            "test fixture hard-codes path length 15 for predictable alignment"
        );
        let mut e = Vec::with_capacity(56);
        // Object path: u32 length, content, NUL.
        e.extend_from_slice(&15u32.to_le_bytes());
        e.extend_from_slice(path.as_bytes());
        e.push(0);
        // offset 20 within entry — already 4-aligned.
        // Inner array `a{sa{sv}}`: u32 length, then 8-aligned content.
        e.extend_from_slice(&26u32.to_le_bytes()); // inner array byte length
                                                   // offset 24 — already 8-aligned.
                                                   // One `{sa{sv}}`: iface name, then a{sv}.
        e.extend_from_slice(&1u32.to_le_bytes()); // iface name length
        e.push(b'I');
        e.push(0); // NUL
                   // offset 30 — pad to 4 for next u32.
        e.extend_from_slice(&[0, 0]);
        e.extend_from_slice(&10u32.to_le_bytes()); // props_len
                                                   // offset 36 — pad to 8 for DICT_ENTRY of {sv}.
        e.extend_from_slice(&[0, 0, 0, 0]);
        // One `{sv}`: prop name, variant of byte.
        e.extend_from_slice(&1u32.to_le_bytes()); // prop name length
        e.push(b'X');
        e.push(0); // NUL
        e.push(1); // variant signature length
        e.push(b'y'); // signature 'y'
        e.push(0); // signature NUL
        e.push(value); // byte value
                       // Entry content ends here at offset 50. Total inner_array_len
                       // is 50 - 24 = 26, matching the u32 written above.
        if with_trailing_pad {
            e.extend_from_slice(&[0; 6]);
        }
        e
    }

    /// Wrap a sequence of entry-bytes into a valid
    /// `a{oa{sa{sv}}}` GMO method-return message. The last entry
    /// must be supplied without trailing pad — dbus ARRAY length
    /// excludes pad after the last element.
    fn build_gmo_message(entries: &[Vec<u8>]) -> Vec<u8> {
        let array_len: usize = entries.iter().map(|e| e.len()).sum();
        let mut body = Vec::with_capacity(8 + array_len);
        body.extend_from_slice(&(array_len as u32).to_le_bytes());
        body.extend_from_slice(&[0; 4]); // pad to 8 (DICT_ENTRY align)
        for e in entries {
            body.extend_from_slice(e);
        }
        let mut msg = Vec::with_capacity(16 + body.len());
        msg.extend_from_slice(&[b'l', 2 /* METHOD_RETURN */, 0, 1]);
        msg.extend_from_slice(&(body.len() as u32).to_le_bytes());
        msg.extend_from_slice(&1u32.to_le_bytes()); // serial
        msg.extend_from_slice(&0u32.to_le_bytes()); // fields_array_length
        msg.extend_from_slice(&body);
        msg
    }

    /// Regression test for the trailing-pad bug: when the filter
    /// drops the upstream-last entry and a previously-non-last
    /// entry becomes the new last, the rewriter must NOT include
    /// that entry's inter-element pad bytes in the new ARRAY
    /// length. The dbus spec excludes padding *after* the last
    /// element from `ARRAY` length, and strict parsers (sd-bus,
    /// dbus-fast, jeepney) reject bodies that include it — they
    /// loop one extra time and read past the body.
    #[test]
    fn rewrite_gmo_trims_trailing_pad_when_last_entry_dropped() {
        // Three bluez paths sorted as hci0 < hci1 < hci2 by
        // BTreeMap. The filter allows only `hci1`, dropping the
        // first and last upstream entries. `hci1`'s entry happens
        // to end at a non-8-aligned inner-array offset (its single
        // byte-typed property leaves inner_end at +50 from the
        // entry's 8-aligned start), so the rewriter has 6 bytes
        // of trailing pad to potentially leak into array_len.
        let upstream = build_gmo_message(&[
            build_entry("/org/bluez/hci0", 0x10, true),
            build_entry("/org/bluez/hci1", 0x11, true),
            build_entry("/org/bluez/hci2", 0x12, false), // upstream last: no trailing pad
        ]);
        let filter = FilterConfig {
            bluez_allowed_adapter_paths: vec!["/org/bluez/hci1".into()],
        };
        let out = rewrite_gmo_reply(&upstream, &filter).expect("rewrite");

        let body_start = align8(wire::FIXED_HEADER_LEN);
        let new_body = &out[body_start..];
        let endian = ZEndian::Little;
        let array_len = read_u32_at(new_body, 0, endian) as usize;
        let array_data_start = align8(4);
        let array_data_end = array_data_start + array_len;

        let kept = parse_outer_dict_entries(new_body, endian).expect("parse outer");
        assert_eq!(
            kept.len(),
            1,
            "filter should leave exactly one entry, got {kept:?}"
        );
        let (_es, _ee, inner_end, path) = &kept[0];
        assert_eq!(path, "/org/bluez/hci1");

        // The core spec invariant: the array's content boundary
        // must land exactly at the new last entry's content end.
        // Pre-fix, this fails by 1..7 bytes (the trailing pad).
        assert_eq!(
            array_data_end, *inner_end,
            "new ARRAY length must NOT include trailing pad after the new last entry \
             (array_data_end={array_data_end}, last entry inner_end={inner_end})"
        );

        // body_length in the fixed header must agree.
        let body_len = read_u32_at(&out, 4, endian) as usize;
        assert_eq!(
            body_len,
            new_body.len(),
            "body_length header field must match actual body length"
        );
        assert_eq!(
            body_len, array_data_end,
            "body_length must equal array_data_end for an `a{{oa{{sa{{sv}}}}}}` body \
             (no trailing pad in the body either)"
        );
    }

    /// Sanity check the other direction: when the kept-last entry
    /// IS the upstream-last entry, the rewriter's output is
    /// already correct — no trailing pad to trim — and the result
    /// is still well-formed. Guards against the fix accidentally
    /// over-trimming.
    #[test]
    fn rewrite_gmo_keeps_correct_length_when_last_entry_kept() {
        let upstream = build_gmo_message(&[
            build_entry("/org/bluez/hci0", 0x10, true),
            build_entry("/org/bluez/hci1", 0x11, false), // upstream last: no trailing pad
        ]);
        let filter = FilterConfig {
            bluez_allowed_adapter_paths: vec!["/org/bluez/hci1".into()],
        };
        let out = rewrite_gmo_reply(&upstream, &filter).expect("rewrite");
        let body_start = align8(wire::FIXED_HEADER_LEN);
        let new_body = &out[body_start..];
        let endian = ZEndian::Little;
        let array_len = read_u32_at(new_body, 0, endian) as usize;
        let array_data_end = align8(4) + array_len;

        let kept = parse_outer_dict_entries(new_body, endian).expect("parse outer");
        assert_eq!(kept.len(), 1);
        let (_es, _ee, inner_end, path) = &kept[0];
        assert_eq!(path, "/org/bluez/hci1");
        assert_eq!(array_data_end, *inner_end);
    }
}
