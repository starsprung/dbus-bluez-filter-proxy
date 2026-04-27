/*
 * dbus-bluez-filter-proxy: BlueZ-aware filtering D-Bus proxy.
 * Copyright (C) 2026 Shaun Starsprung
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Wrapper header for bindgen.
 *
 * <bluetooth/hci.h> defines the ioctl request codes via the
 * `_IOR(type, nr, size)` function-like macro, which bindgen can't
 * directly translate to Rust constants. We re-expose them as plain
 * `const` integers so bindgen sees value-typed names it can emit.
 *
 * The struct types (hci_dev_info, hci_dev_list_req, ...) are
 * regular C structs and bindgen translates them straight from the
 * upstream header — no wrappers needed. If kernel/bluez ever bumps
 * the layout (appends fields, etc.), the next build picks up the
 * new shape automatically.
 */
/* sys/ioctl.h must come first — bluetooth/hci.h uses _IOR(...) at
 * file scope and clang errors out without the macro. The bluez
 * headers don't include it themselves; their build assumes the
 * caller has pulled it in. */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

/* Re-exposed ioctl request numbers. Names prefixed so they don't
 * clash with the upstream macros bindgen also sees. */
const unsigned long HCI_IOCTL_GETDEVLIST = HCIGETDEVLIST;
const unsigned long HCI_IOCTL_GETDEVINFO = HCIGETDEVINFO;
