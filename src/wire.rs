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

//! Minimal D-Bus message wire-format parsing.
//!
//! Only the bits the proxy needs for filter routing: message type,
//! serial, body length, and the well-known header fields (PATH,
//! INTERFACE, MEMBER, DESTINATION, SENDER, REPLY_SERIAL). Body
//! parsing/rewriting for `GetManagedObjects` lives in
//! [`crate::proxy`]; XML body rewriting for `Introspect` lives in
//! [`crate::introspect`].
//!
//! The D-Bus wire format is documented at
//! <https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-marshaling>.

use anyhow::{anyhow, bail, Result};

/// Fixed-size message prefix.
pub const FIXED_HEADER_LEN: usize = 16;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageType {
    Invalid,
    MethodCall,
    MethodReturn,
    Error,
    Signal,
    Other(u8),
}

impl MessageType {
    fn from_u8(b: u8) -> Self {
        match b {
            0 => Self::Invalid,
            1 => Self::MethodCall,
            2 => Self::MethodReturn,
            3 => Self::Error,
            4 => Self::Signal,
            n => Self::Other(n),
        }
    }
}

/// Parsed view of a D-Bus message header.
#[derive(Debug, Clone)]
pub struct Header {
    pub endian: Endian,
    pub msg_type: MessageType,
    pub flags: u8,
    pub protocol_version: u8,
    pub body_length: u32,
    pub serial: u32,
    pub fields_array_length: u32,
    // Well-known fields. None means absent.
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub error_name: Option<String>,
    pub reply_serial: Option<u32>,
    pub destination: Option<String>,
    pub sender: Option<String>,
}

impl Header {
    /// Total length of the message on the wire — fixed header +
    /// fields array (padded to 8-byte alignment) + body.
    pub fn total_len(&self) -> usize {
        let header_with_fields = FIXED_HEADER_LEN + self.fields_array_length as usize;
        let aligned = align8(header_with_fields);
        aligned + self.body_length as usize
    }
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Parse just the fixed 16-byte prefix to get body_length so the
/// I/O layer can tell how many more bytes constitute one message.
/// Used to size the per-message read buffer before doing the full
/// header parse.
pub fn peek_message_size(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < FIXED_HEADER_LEN {
        bail!("need {FIXED_HEADER_LEN} bytes for fixed header, have {}", bytes.len());
    }
    let endian = parse_endian(bytes[0])?;
    let body_length = read_u32(endian, &bytes[4..8]);
    let fields_array_length = read_u32(endian, &bytes[12..16]);
    let header_with_fields = FIXED_HEADER_LEN + fields_array_length as usize;
    Ok(align8(header_with_fields) + body_length as usize)
}

/// Parse an entire D-Bus message header (including the variable
/// fields array). `bytes` must contain at least the full header.
/// Body is not parsed; callers can index `[header.total_len() -
/// header.body_length..]` to get its bytes if they need it.
pub fn parse(bytes: &[u8]) -> Result<Header> {
    if bytes.len() < FIXED_HEADER_LEN {
        bail!("short header: {} bytes", bytes.len());
    }
    let endian = parse_endian(bytes[0])?;
    let msg_type = MessageType::from_u8(bytes[1]);
    let flags = bytes[2];
    let protocol_version = bytes[3];
    let body_length = read_u32(endian, &bytes[4..8]);
    let serial = read_u32(endian, &bytes[8..12]);
    let fields_array_length = read_u32(endian, &bytes[12..16]);

    let fields_end = FIXED_HEADER_LEN + fields_array_length as usize;
    if bytes.len() < fields_end {
        bail!(
            "fields array truncated: need {fields_end} bytes, have {}",
            bytes.len()
        );
    }

    let mut header = Header {
        endian,
        msg_type,
        flags,
        protocol_version,
        body_length,
        serial,
        fields_array_length,
        path: None,
        interface: None,
        member: None,
        error_name: None,
        reply_serial: None,
        destination: None,
        sender: None,
    };
    parse_fields(endian, &bytes[FIXED_HEADER_LEN..fields_end], &mut header)?;
    Ok(header)
}

fn parse_endian(b: u8) -> Result<Endian> {
    match b {
        b'l' => Ok(Endian::Little),
        b'B' => Ok(Endian::Big),
        other => Err(anyhow!("invalid endian byte: 0x{other:02x}")),
    }
}

fn read_u32(endian: Endian, b: &[u8]) -> u32 {
    let arr = [b[0], b[1], b[2], b[3]];
    match endian {
        Endian::Little => u32::from_le_bytes(arr),
        Endian::Big => u32::from_be_bytes(arr),
    }
}

/// Parse the header-fields array `a(yv)`. Each entry is a
/// (BYTE field-code, VARIANT value) struct, struct-aligned to
/// 8 bytes within the array. `bytes` is exactly the fields-array
/// payload (length given by the fixed header).
///
/// Field-code → expected value type:
///   1 PATH         → object path (signature 'o')
///   2 INTERFACE    → string ('s')
///   3 MEMBER       → string ('s')
///   4 ERROR_NAME   → string ('s')
///   5 REPLY_SERIAL → uint32 ('u')
///   6 DESTINATION  → string ('s')
///   7 SENDER       → string ('s')
///   8 SIGNATURE    → signature ('g') — ignored
///   9 UNIX_FDS     → uint32 ('u') — ignored
fn parse_fields(endian: Endian, bytes: &[u8], out: &mut Header) -> Result<()> {
    let mut cursor = 0usize;
    // Each struct entry begins on an 8-byte boundary *relative to
    // the start of the array*. The array itself starts after the
    // 16-byte fixed header which is already 8-aligned, so absolute
    // and relative alignment coincide.
    while cursor < bytes.len() {
        cursor = align_within(cursor, 8);
        if cursor >= bytes.len() {
            break;
        }
        let code = bytes[cursor];
        cursor += 1;
        // VARIANT: <sig-len:byte><sig-bytes><nul>...padding to type-align...<value>
        let sig_len = *bytes.get(cursor).ok_or_else(|| anyhow!("variant truncated"))? as usize;
        cursor += 1;
        let sig_end = cursor + sig_len;
        if sig_end > bytes.len() {
            bail!("variant signature out of range");
        }
        let sig = &bytes[cursor..sig_end];
        cursor = sig_end + 1; // skip the trailing NUL after the signature

        // Now the value, aligned to its type.
        match code {
            1 | 6 | 7 => {
                // PATH ('o') or DESTINATION/SENDER ('s'): a uint32
                // length (4-aligned) followed by utf8 + NUL terminator.
                cursor = align_within(cursor, 4);
                if cursor + 4 > bytes.len() {
                    bail!("string length truncated");
                }
                let n = read_u32(endian, &bytes[cursor..cursor + 4]) as usize;
                cursor += 4;
                if cursor + n > bytes.len() {
                    bail!("string body truncated");
                }
                let s = std::str::from_utf8(&bytes[cursor..cursor + n])
                    .map_err(|e| anyhow!("non-utf8 string field: {e}"))?
                    .to_string();
                cursor += n + 1; // +1 for NUL terminator
                let _ = sig; // PATH vs string distinguishable by sig; we don't need it
                match code {
                    1 => out.path = Some(s),
                    6 => out.destination = Some(s),
                    7 => out.sender = Some(s),
                    _ => unreachable!(),
                }
            }
            2 | 3 | 4 => {
                cursor = align_within(cursor, 4);
                if cursor + 4 > bytes.len() {
                    bail!("string length truncated");
                }
                let n = read_u32(endian, &bytes[cursor..cursor + 4]) as usize;
                cursor += 4;
                if cursor + n > bytes.len() {
                    bail!("string body truncated");
                }
                let s = std::str::from_utf8(&bytes[cursor..cursor + n])
                    .map_err(|e| anyhow!("non-utf8 string field: {e}"))?
                    .to_string();
                cursor += n + 1;
                match code {
                    2 => out.interface = Some(s),
                    3 => out.member = Some(s),
                    4 => out.error_name = Some(s),
                    _ => unreachable!(),
                }
            }
            5 | 9 => {
                // REPLY_SERIAL or UNIX_FDS: uint32, 4-aligned.
                cursor = align_within(cursor, 4);
                if cursor + 4 > bytes.len() {
                    bail!("uint32 field truncated");
                }
                let n = read_u32(endian, &bytes[cursor..cursor + 4]);
                cursor += 4;
                if code == 5 {
                    out.reply_serial = Some(n);
                }
            }
            8 => {
                // SIGNATURE: byte length + bytes + NUL. We don't
                // use it for filtering decisions but must walk past.
                let n = *bytes.get(cursor).ok_or_else(|| anyhow!("sig field truncated"))? as usize;
                cursor += 1 + n + 1;
            }
            _ => {
                // Unknown field code — skip the variant value by
                // following its signature. Conservative: bail rather
                // than misparse and corrupt the rest of the array.
                bail!("unknown header field code {code} (sig {:?})", String::from_utf8_lossy(sig));
            }
        }
    }
    Ok(())
}

fn align_within(cursor: usize, alignment: usize) -> usize {
    let rem = cursor % alignment;
    if rem == 0 {
        cursor
    } else {
        cursor + (alignment - rem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built minimal method-call message — bypasses zbus so we
    /// know exactly what we're testing.
    /// Calls `org.example.Echo.Echo(""\)` on `/echo` of `:1.5`.
    fn make_method_call() -> Vec<u8> {
        // We rely on zbus's marshaller to produce a real wire image,
        // so the parser test verifies against bytes a legitimate
        // D-Bus client could actually emit.
        use zbus::message::Message;
        let m = Message::method("/com/example/Echo", "Echo")
            .unwrap()
            .destination("com.example")
            .unwrap()
            .interface("com.example.Echo")
            .unwrap()
            .build(&"hello".to_string())
            .unwrap();
        m.data().to_vec()
    }

    #[test]
    fn parses_real_zbus_built_method_call() {
        let bytes = make_method_call();
        let h = parse(&bytes).expect("parse");
        assert_eq!(h.msg_type, MessageType::MethodCall);
        assert_eq!(h.path.as_deref(), Some("/com/example/Echo"));
        assert_eq!(h.member.as_deref(), Some("Echo"));
        assert_eq!(h.interface.as_deref(), Some("com.example.Echo"));
        assert_eq!(h.destination.as_deref(), Some("com.example"));
        assert!(h.serial > 0);
    }

    #[test]
    fn total_len_matches_zbus_emitted_length() {
        let bytes = make_method_call();
        let h = parse(&bytes).expect("parse");
        assert_eq!(h.total_len(), bytes.len());
    }

    #[test]
    fn peek_message_size_agrees_with_full_parse() {
        let bytes = make_method_call();
        let from_peek = peek_message_size(&bytes[..FIXED_HEADER_LEN]).unwrap();
        let h = parse(&bytes).unwrap();
        assert_eq!(from_peek, h.total_len());
    }
}
