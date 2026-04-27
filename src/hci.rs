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

//! Linux HCI ioctl helpers.
//!
//! Type/constant definitions are generated from `<bluetooth/hci.h>`
//! at build time via `bindgen` (see `build.rs`) — kernel/bluez
//! struct layouts auto-track upstream changes. The lookup logic
//! (open AF_BLUETOOTH socket, list adapters, query each) is a thin
//! wrapper around the generated bindings.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
// The bindgen output isn't terribly stylish but it's a one-shot
// drop and not the surface we read from elsewhere.

mod sys {
    include!(concat!(env!("OUT_DIR"), "/hci_bindings.rs"));
}

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// One adapter as reported by the kernel.
#[derive(Debug, Clone)]
pub struct Adapter {
    /// Kernel name: `hci0`, `hci1`, ...
    pub name: String,
    /// MAC in canonical hex-colon order (`XX:XX:XX:XX:XX:XX`).
    pub mac: String,
}

/// Enumerate every BT adapter the kernel knows about.
pub fn list_adapters() -> io::Result<Vec<Adapter>> {
    // bindgen renders `hci_dev_list_req`'s flexible-array-member
    // (`struct hci_dev_req dev_req[0]`) as `__IncompleteArrayField`
    // — sizeof(struct) is just the fixed prefix (4 bytes for
    // dev_num + padding). The kernel writes HCI_MAX_DEV entries
    // past the end, so we MUST allocate a backing buffer that
    // includes room for the FAM. A bare `mem::zeroed()` would
    // corrupt the stack on the ioctl.
    let fam_capacity = sys::HCI_MAX_DEV as usize;
    let total_bytes = std::mem::size_of::<sys::hci_dev_list_req>()
        + fam_capacity * std::mem::size_of::<sys::hci_dev_req>();
    let mut buf = vec![0u8; total_bytes];

    // SAFETY: buf lives for the entire ioctl + FAM walk; the cast
    // is to a `repr(C)` type whose first field is u16 followed by
    // a zero-sized FAM marker, both populated by the kernel.
    unsafe {
        let sk = libc::socket(
            sys::AF_BLUETOOTH as libc::c_int,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            sys::BTPROTO_HCI as libc::c_int,
        );
        if sk < 0 {
            return Err(io::Error::last_os_error());
        }
        let sk = OwnedFd::from_raw_fd(sk);

        // HCIGETDEVLIST — kernel reads dev_num as the requested
        // capacity and writes back the actual count + entries.
        let dl_ptr = buf.as_mut_ptr() as *mut sys::hci_dev_list_req;
        (*dl_ptr).dev_num = fam_capacity as u16;
        let rc = libc::ioctl(
            sk.as_raw_fd(),
            sys::HCI_IOCTL_GETDEVLIST as libc::c_ulong,
            dl_ptr,
        );
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let dev_num = (*dl_ptr).dev_num as usize;
        let dev_req_ptr = (*dl_ptr).dev_req.as_ptr();
        let mut out = Vec::with_capacity(dev_num);
        for i in 0..dev_num {
            let dev_id = (*dev_req_ptr.add(i)).dev_id;
            let mut di: sys::hci_dev_info = std::mem::zeroed();
            di.dev_id = dev_id;
            let rc = libc::ioctl(
                sk.as_raw_fd(),
                sys::HCI_IOCTL_GETDEVINFO as libc::c_ulong,
                &mut di as *mut _,
            );
            if rc < 0 {
                // Skip per-adapter failures (e.g. adapter removed
                // mid-enumeration) rather than aborting.
                continue;
            }
            // bindgen exposes name as `[c_char; 8]`. c_char is i8 on
            // Linux x86_64; cast to bytes for str::from_utf8.
            let name_bytes: &[u8] = std::slice::from_raw_parts(
                di.name.as_ptr() as *const u8,
                di.name.len(),
            );
            let name_end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            let Ok(name) = std::str::from_utf8(&name_bytes[..name_end]) else {
                continue;
            };
            // bdaddr_t.b is a [u8; 6]; bindgen names the inner field
            // `b`. Kernel stores LE so we reverse for canonical fmt.
            out.push(Adapter {
                name: name.to_owned(),
                mac: format_bdaddr(&di.bdaddr.b),
            });
        }
        Ok(out)
    }
}

fn format_bdaddr(b: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        b[5], b[4], b[3], b[2], b[1], b[0]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bdaddr_formats_in_canonical_reverse_byte_order() {
        let raw: [u8; 6] = [0x08, 0x71, 0xDA, 0x7D, 0x1A, 0x00];
        assert_eq!(format_bdaddr(&raw), "00:1A:7D:DA:71:08");
    }

    #[test]
    fn ioctl_constants_resolved_from_bindgen() {
        // _IOR('H', 210, int) = (2<<30) | (4<<16) | ('H'<<8) | 210.
        let expected_list: u64 = (2u64 << 30) | (4u64 << 16) | (b'H' as u64) << 8 | 210;
        let expected_info: u64 = (2u64 << 30) | (4u64 << 16) | (b'H' as u64) << 8 | 211;
        assert_eq!(sys::HCI_IOCTL_GETDEVLIST as u64, expected_list);
        assert_eq!(sys::HCI_IOCTL_GETDEVINFO as u64, expected_info);
    }
}
