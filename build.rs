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

//! Build-time codegen.
//!
//! Generates Rust ffi bindings for the small subset of
//! `<bluetooth/hci.h>` types/constants the proxy uses to enumerate
//! HCI adapters. The generated `hci_bindings.rs` lands in `OUT_DIR`
//! and is `include!`'d from `src/hci.rs`.
//!
//! Build deps required on the build host:
//!   * `libbluetooth-dev` (Debian) — provides the BlueZ headers.
//!   * `libclang-dev` — bindgen drives clang to parse the headers.

fn main() {
    println!("cargo:rerun-if-changed=src/hci_wrapper.h");

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let bindings = bindgen::Builder::default()
        .header("src/hci_wrapper.h")
        // Allowlist exactly what we touch — anything else from the
        // BT/socket headers stays out of the generated module.
        .allowlist_type("hci_dev_info")
        .allowlist_type("hci_dev_list_req")
        .allowlist_type("hci_dev_req")
        .allowlist_type("hci_dev_stats")
        .allowlist_var("HCI_MAX_DEV")
        .allowlist_var("AF_BLUETOOTH")
        .allowlist_var("BTPROTO_HCI")
        // Re-exposed ioctl request numbers from hci_wrapper.h
        .allowlist_var("HCI_IOCTL_GETDEVLIST")
        .allowlist_var("HCI_IOCTL_GETDEVINFO")
        .derive_default(true)
        .derive_debug(false)
        .derive_copy(true)
        // Rust-style names: hci_dev_info → HciDevInfo etc. Kept as
        // C names instead — they're internal to the hci module and
        // matching upstream is more useful when reading kernel docs.
        .layout_tests(true)
        .generate()
        .expect("bindgen failed");

    bindings
        .write_to_file(out_dir.join("hci_bindings.rs"))
        .expect("write hci_bindings.rs");
}
