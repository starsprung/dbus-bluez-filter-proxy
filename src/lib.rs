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

//! Filtering D-Bus proxy.
//!
//! Acts as a D-Bus relay between a client (typically a containerised
//! consumer) and the host's system bus. Default behaviour is pure
//! pass-through; targeted filter rules narrow what the client can see
//! or call on the `org.bluez` service so a container can be scoped to
//! a single Bluetooth adapter without leaking visibility of others.
//!
//! Compatible with the standard SASL handshake flow, sd-bus's
//! pipelined "fast path", and clients that negotiate FD passing
//! (libdbus, sd-bus/`busctl`, gdbus, zbus, dbus-fast/`bleak`) — the
//! proxy forwards SASL bytes between client and upstream verbatim
//! during the handshake, so whatever the upstream daemon supports is
//! what the client sees.

pub mod filter;
pub mod hci;
pub mod introspect;
pub mod proxy;
pub mod wire;
