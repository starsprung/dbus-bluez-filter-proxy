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

//! BlueZ-aware filter rules.
//!
//! Default behaviour is pass-through: any message goes through
//! the proxy unmodified. The filter narrows visibility for the
//! `org.bluez` service only, so a downstream client can be scoped
//! to a single Bluetooth adapter.
//!
//! Filter dimensions, all keyed off the same allowed-adapter list:
//!   * method-call denial — calls whose object path is under
//!     `/org/bluez/<other>/...` get an `AccessDenied` error reply
//!     synthesized by the proxy and never reach upstream.
//!   * response payload rewriting — `GetManagedObjects` replies
//!     have disallowed adapter subtrees spliced out.
//!   * signal payload filtering — `InterfacesAdded`/`Removed` and
//!     any signal whose source path is under a disallowed adapter
//!     are dropped.
//!   * Introspect XML rewriting — `<node name="hciN"/>` entries for
//!     disallowed adapters are stripped from `Introspect` responses.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FilterConfig {
    /// Object paths under `/org/bluez/` the consumer is allowed to
    /// touch. Each entry is an exact path like `/org/bluez/hci0`;
    /// the path itself and anything under it (e.g. device subtrees)
    /// pass through. Other `/org/bluez/hciN/...` subtrees are
    /// rejected with AccessDenied.
    ///
    /// Empty list disables BlueZ-side filtering — full pass-through.
    pub bluez_allowed_adapter_paths: Vec<String>,
}

/// Decision the filter makes for a single message.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Forward the message to the other side unchanged.
    Forward,
    /// Synthesize an `AccessDenied` error reply to the sender;
    /// don't forward upstream. Carries the rejected method-call's
    /// serial so the reply can be wired back to the right request.
    DenyMethodCall {
        request_serial: u32,
        client_unique_name: Option<String>,
    },
}

impl FilterConfig {
    /// Decide what to do with an outbound (client → upstream) method
    /// call. Returns [`Decision::Forward`] for non-bluez destinations
    /// and bluez paths that aren't filtered.
    pub fn check_method_call(&self, info: MethodCallInfo<'_>) -> Decision {
        if self.bluez_allowed_adapter_paths.is_empty() {
            return Decision::Forward;
        }
        // Anything not destined for org.bluez falls through.
        if info.destination != Some("org.bluez") {
            return Decision::Forward;
        }
        if path_is_allowed(info.path, &self.bluez_allowed_adapter_paths) {
            Decision::Forward
        } else {
            Decision::DenyMethodCall {
                request_serial: info.serial,
                client_unique_name: info.sender.map(str::to_owned),
            }
        }
    }
}

/// Parsed header fields the filter needs to make a method-call
/// decision. Built by the proxy from the raw header bytes.
#[derive(Debug, Clone, Copy)]
pub struct MethodCallInfo<'a> {
    pub serial: u32,
    pub destination: Option<&'a str>,
    pub path: &'a str,
    pub sender: Option<&'a str>,
}

impl FilterConfig {
    /// True if `path` is exactly an allowed adapter, or a descendant
    /// of one, or a non-bluez path. False for disallowed
    /// `/org/bluez/<other>/...` subtrees. Used by the response/signal
    /// path filter — root paths like `/org/bluez` itself return true
    /// here too because they're not adapter subtrees.
    pub fn is_path_visible(&self, path: &str) -> bool {
        if self.bluez_allowed_adapter_paths.is_empty() {
            return true;
        }
        path_is_allowed(path, &self.bluez_allowed_adapter_paths)
    }
}

/// True if `path` is exactly an allowed adapter, or a descendant
/// of one (device / service / characteristic subtrees), or one of
/// the BlueZ "root" paths needed for ObjectManager enumeration to
/// work at all. False for `/org/bluez/<other>/...`.
fn path_is_allowed(path: &str, allowed: &[String]) -> bool {
    // Root paths are always permitted: the consumer needs to call
    // ObjectManager.GetManagedObjects on `/org/bluez` and reach the
    // root for introspection. Filtering at the *response* layer is
    // what hides the disallowed adapters from those calls.
    if matches!(path, "/" | "/org" | "/org/bluez") {
        return true;
    }
    if !path.starts_with("/org/bluez/") {
        // Outside the BlueZ object tree entirely; not our concern.
        return true;
    }
    for allowed_path in allowed {
        if path == allowed_path {
            return true;
        }
        // Descendant: e.g. `/org/bluez/hci0/dev_AA_BB_..`
        if path.starts_with(allowed_path)
            && path.as_bytes().get(allowed_path.len()) == Some(&b'/')
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(allowed: &[&str]) -> FilterConfig {
        FilterConfig {
            bluez_allowed_adapter_paths: allowed.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn call<'a>(path: &'a str, dest: Option<&'a str>) -> MethodCallInfo<'a> {
        MethodCallInfo {
            serial: 1,
            destination: dest,
            path,
            sender: None,
        }
    }

    #[test]
    fn empty_allow_list_lets_everything_through() {
        let c = cfg(&[]);
        let d = c.check_method_call(call("/org/bluez/hci1", Some("org.bluez")));
        assert_eq!(d, Decision::Forward);
    }

    #[test]
    fn allowed_adapter_root_passes() {
        let c = cfg(&["/org/bluez/hci0"]);
        assert_eq!(
            c.check_method_call(call("/org/bluez/hci0", Some("org.bluez"))),
            Decision::Forward
        );
    }

    #[test]
    fn allowed_adapter_descendant_passes() {
        let c = cfg(&["/org/bluez/hci0"]);
        assert_eq!(
            c.check_method_call(call("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF", Some("org.bluez"))),
            Decision::Forward
        );
    }

    #[test]
    fn disallowed_adapter_is_denied() {
        let c = cfg(&["/org/bluez/hci0"]);
        let d = c.check_method_call(call("/org/bluez/hci1", Some("org.bluez")));
        assert!(matches!(d, Decision::DenyMethodCall { .. }), "got {d:?}");
    }

    #[test]
    fn disallowed_adapter_descendant_is_denied() {
        let c = cfg(&["/org/bluez/hci0"]);
        let d = c.check_method_call(call("/org/bluez/hci1/dev_99", Some("org.bluez")));
        assert!(matches!(d, Decision::DenyMethodCall { .. }));
    }

    #[test]
    fn root_paths_pass_for_object_manager() {
        let c = cfg(&["/org/bluez/hci0"]);
        for p in ["/", "/org", "/org/bluez"] {
            assert_eq!(
                c.check_method_call(call(p, Some("org.bluez"))),
                Decision::Forward,
                "path {p} should pass for ObjectManager"
            );
        }
    }

    #[test]
    fn other_destinations_are_default_pass() {
        let c = cfg(&["/org/bluez/hci0"]);
        assert_eq!(
            c.check_method_call(call("/whatever", Some("org.example"))),
            Decision::Forward
        );
    }

    #[test]
    fn similar_prefix_does_not_match_descendant() {
        // Path `/org/bluez/hci10` must NOT be considered a descendant
        // of allowed `/org/bluez/hci1` — adapter naming is hci0/1/2…
        // but a substring-only check would match wrongly.
        let c = cfg(&["/org/bluez/hci1"]);
        // hci10 has '0' at the position where '/' would be in a real
        // descendant; filter must treat it as a different adapter.
        let d = c.check_method_call(call("/org/bluez/hci10", Some("org.bluez")));
        assert!(matches!(d, Decision::DenyMethodCall { .. }), "got {d:?}");
    }
}
