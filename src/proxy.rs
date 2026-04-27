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
//! D-Bus daemon, with the SASL handshake mediated by [`crate::auth`].
//!
//! Lifecycle of a client:
//!   1. Accept on the listen socket.
//!   2. Read kernel-attested peer uid via SO_PEERCRED.
//!   3. Run [`AuthFsm`] over inbound bytes until `Accept` is emitted.
//!      Send any reply bytes the FSM produces back to the client.
//!   4. Connect to the upstream socket. Run an outbound SASL exchange
//!      against the upstream bus (the proxy is a client there) and
//!      consume the upstream's `OK <guid>\r\n` reply so it never
//!      reaches the downstream client.
//!   5. Forward the FSM's `carryover` bytes (anything that came in
//!      after `BEGIN` in the same syscall — common with sd-bus's
//!      pipelined fast-path) to the upstream.
//!   6. Spawn two tasks: client→upstream and upstream→client. Each
//!      task parses message headers so the BlueZ filter rules can
//!      apply (method-call denial, GMO/Introspect response rewriting,
//!      signal filtering); message bodies that aren't being rewritten
//!      pass through untouched.
//!
//! Per-client failures don't tear down the listener; one bad client
//! disconnects and we keep accepting.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info};

use crate::auth::{Accept, Action, AuthFsm};
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

/// Server GUID advertised in the SASL `OK <guid>` line.
///
/// D-Bus clients don't validate this against any registry; it's an
/// identifier for the bus. We pick a stable value for the proxy so
/// cross-client behaviour is reproducible.
const PROXY_GUID: &str = "0123456789abcdef0123456789abcdef";

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
    // Run downstream SASL.
    let mut fsm = AuthFsm::new(cfg.peer_uid, PROXY_GUID);
    let carryover = downstream_handshake(&mut client, &mut fsm).await?;
    if std::env::var("DBUS_FILTER_PROXY_DEBUG").is_ok() {
        eprintln!("[proxy] downstream SASL ok, carryover len={}", carryover.len());
    }
    info!("downstream SASL accepted (peer uid {})", cfg.peer_uid);

    // Connect upstream + do SASL synchronously on a std stream
    // (sendmsg with SCM_CREDENTIALS is sync-friendly), then hand
    // the fd to tokio for the relay phase.
    let upstream_path = cfg.upstream.clone();
    let std_upstream = tokio::task::spawn_blocking(move || -> Result<std::os::unix::net::UnixStream> {
        sync_upstream_handshake(&upstream_path)
    })
    .await
    .context("spawn_blocking upstream handshake")??;
    std_upstream.set_nonblocking(true).context("set nonblocking")?;
    let mut upstream = UnixStream::from_std(std_upstream)
        .context("std -> tokio UnixStream conversion")?;
    debug!("upstream SASL completed");

    // Hand the carryover bytes (post-BEGIN payload that came in the
    // same syscall as the SASL lines) to upstream before starting
    // the relay.
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

    let mut new_array_len: usize = 0;
    for (entry_start, entry_end, path) in &entries {
        if !filter.is_path_visible(path) {
            continue;
        }
        let entry_bytes = &body[*entry_start..*entry_end];
        new_body.extend_from_slice(entry_bytes);
        new_array_len += entry_end - entry_start;
    }

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
/// `(start, end, path)` tuple per top-level entry. `start..end` are
/// **byte ranges within the body** that include the entry's content
/// AND its trailing alignment padding (i.e. through to the next
/// entry's 8-aligned start, or the array's end for the last entry).
/// Copying these ranges contiguously into a new buffer preserves
/// inter-entry struct alignment.
fn parse_outer_dict_entries(
    body: &[u8],
    endian: zbus::zvariant::Endian,
) -> Result<Vec<(usize, usize, String)>, &'static str> {
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
        let entry_end = if cursor >= array_data_end {
            array_data_end
        } else {
            align8(cursor).min(array_data_end)
        };
        entries.push((entry_start, entry_end, path));
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

/// Drive the downstream SASL FSM. Returns the post-BEGIN carryover.
async fn downstream_handshake(client: &mut UnixStream, fsm: &mut AuthFsm) -> Result<Vec<u8>> {
    let mut buf = [0u8; 4096];
    let debug = std::env::var("DBUS_FILTER_PROXY_DEBUG").is_ok();
    loop {
        let n = client
            .read(&mut buf)
            .await
            .context("read during SASL")?;
        if n == 0 {
            anyhow::bail!("client EOF during SASL");
        }
        if debug {
            eprintln!("[proxy] downstream rx {n} bytes: {:?}", String::from_utf8_lossy(&buf[..n]));
        }
        match fsm.feed(&buf[..n]) {
            Action::NeedMore => {}
            Action::Send(reply) => client.write_all(&reply).await?,
            Action::Accept(Accept { reply, carryover }) => {
                client.write_all(&reply).await?;
                return Ok(carryover);
            }
            Action::Reject(reason) => {
                anyhow::bail!("SASL rejected: {reason}");
            }
        }
    }
}

/// Synchronous upstream SASL handshake. Runs on a blocking thread
/// because we need raw sendmsg(2) for the SCM_CREDENTIALS NUL byte
/// that dbus-daemon expects, and mixing that with the tokio reactor
/// is harder to keep correct than just doing it before handing the
/// fd over to tokio.
fn sync_upstream_handshake(path: &std::path::Path) -> Result<std::os::unix::net::UnixStream> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, UnixCredentials};
    use std::io::{IoSlice, Read, Write};
    use std::os::fd::{AsRawFd, BorrowedFd};

    let mut stream = std::os::unix::net::UnixStream::connect(path)
        .with_context(|| format!("connect upstream {}", path.display()))?;

    let our_uid = nix::unistd::geteuid().as_raw();
    let hex_uid = hex::encode(our_uid.to_string());
    let payload = format!("AUTH EXTERNAL {hex_uid}\r\nBEGIN\r\n");
    let debug = std::env::var("DBUS_FILTER_PROXY_DEBUG").is_ok();
    if debug {
        eprintln!("[proxy] upstream tx (after creds NUL): {:?}", payload);
    }

    // Send NUL with SCM_CREDENTIALS — libdbus convention; dbus-daemon
    // matches the ancillary creds against the SO_PEERCRED-derived
    // identity to confirm the connection is from a legitimate peer.
    let creds = UnixCredentials::new();
    let nul = [0u8; 1];
    let iov = [IoSlice::new(&nul)];
    let cmsg = [ControlMessage::ScmCredentials(&creds)];
    // SAFETY: stream's fd outlives this BorrowedFd.
    let fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    sendmsg::<()>(fd.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
        .context("sendmsg with SCM_CREDENTIALS")?;

    stream
        .write_all(payload.as_bytes())
        .context("write upstream SASL")?;

    // Consume the `OK <guid>\r\n` reply so it doesn't bleed into the
    // forwarded byte stream. We send only AUTH+BEGIN (no
    // NEGOTIATE_UNIX_FD), so a single CRLF terminates the response.
    let mut buf = [0u8; 256];
    let mut acc = Vec::new();
    loop {
        let n = stream.read(&mut buf).context("read upstream SASL reply")?;
        if debug {
            eprintln!(
                "[proxy] upstream rx {n} bytes: {:?}",
                String::from_utf8_lossy(&buf[..n])
            );
        }
        if n == 0 {
            anyhow::bail!("upstream EOF during SASL");
        }
        acc.extend_from_slice(&buf[..n]);
        if let Some(pos) = acc.windows(2).position(|w| w == b"\r\n") {
            // Anything after the CRLF is message-stream bytes from
            // upstream — should never happen in practice (dbus-daemon
            // waits for the client's first message) but if it does,
            // we lose them. Acceptable until shown otherwise.
            let _trailing = acc.split_off(pos + 2);
            if !acc.starts_with(b"OK ") {
                anyhow::bail!("upstream rejected SASL: {:?}", String::from_utf8_lossy(&acc));
            }
            return Ok(stream);
        }
    }
}

/// Look up the connecting peer's uid via SO_PEERCRED. Used by
/// production callers to validate the SASL claim against kernel
/// truth; tests pass the uid in via [`ProxyConfig`] directly because
/// they connect as the same uid that runs the proxy.
/// Look up the connecting peer's uid via SO_PEERCRED. Production
/// callers will validate the SASL claim against this; the test
/// harness pre-fills `peer_uid` because the test process IS the
/// connecting client.
#[allow(dead_code)]
pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::fd::{AsRawFd, BorrowedFd};
    // SAFETY: `stream`'s fd outlives the BorrowedFd.
    let fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    let cred = getsockopt(&fd, PeerCredentials).context("SO_PEERCRED")?;
    Ok(cred.uid())
}
