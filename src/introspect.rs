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

//! `org.freedesktop.DBus.Introspectable.Introspect` response filter.
//!
//! Closes the visibility leak that `busctl tree` surfaces: bluez's
//! introspection XML enumerates every child object as
//! `<node name="..."/>`, including disallowed adapter subtrees.
//! GMO/InterfacesAdded filtering doesn't touch this surface, so
//! recursive introspection would otherwise still list disallowed
//! adapters under `/org/bluez`.
//!
//! Implementation: streaming XML rewrite. Read the response body
//! (a single `s` containing the introspect XML), drop direct
//! `<node name="..."/>` children whose computed full path is hidden
//! by the filter, copy everything else through unchanged.

use anyhow::{anyhow, Result};
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;
use std::io::Cursor;

/// Filter the body of an Introspect response.
///
/// `current_path` is the object path the response describes — its
/// direct `<node>` children advertise sub-objects at
/// `current_path/<name>`. `is_visible` decides whether each
/// computed full path should appear in the output.
pub fn filter_xml(
    xml: &str,
    current_path: &str,
    is_visible: impl Fn(&str) -> bool,
) -> Result<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Cursor::new(Vec::<u8>::new()));

    // Depth counts opened-but-not-closed elements. The outer <node>
    // sits at depth 0 when its Start fires; after we write it,
    // depth becomes 1 — its direct children fire their events at
    // depth==1.
    let mut depth: i32 = 0;
    loop {
        let event = reader
            .read_event()
            .map_err(|e| anyhow!("xml parse: {e}"))?;
        match event {
            Event::Start(e) => {
                if e.name().as_ref() == b"node" && depth == 1 {
                    if !child_is_visible(&e, current_path, &is_visible)? {
                        skip_until_close(&mut reader)?;
                        continue;
                    }
                }
                writer.write_event(Event::Start(e.into_owned()))?;
                depth += 1;
            }
            Event::End(e) => {
                writer.write_event(Event::End(e.into_owned()))?;
                depth -= 1;
            }
            Event::Empty(e) => {
                if e.name().as_ref() == b"node" && depth == 1 {
                    if !child_is_visible(&e, current_path, &is_visible)? {
                        continue;
                    }
                }
                writer.write_event(Event::Empty(e.into_owned()))?;
            }
            Event::Eof => break,
            other => writer.write_event(other.into_owned())?,
        }
    }

    let bytes = writer.into_inner().into_inner();
    Ok(String::from_utf8(bytes)?)
}

fn child_is_visible(
    e: &BytesStart,
    current_path: &str,
    is_visible: &impl Fn(&str) -> bool,
) -> Result<bool> {
    let name = e
        .attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == b"name")
        .and_then(|a| String::from_utf8(a.value.into_owned()).ok());
    let Some(name) = name else {
        // <node/> without a name advertises the *current* object;
        // those don't hide sub-paths so just keep them.
        return Ok(true);
    };
    let full_path = if current_path == "/" {
        format!("/{name}")
    } else {
        format!("{current_path}/{name}")
    };
    Ok(is_visible(&full_path))
}

fn skip_until_close(reader: &mut Reader<&[u8]>) -> Result<()> {
    let mut inner_depth = 1i32;
    while inner_depth > 0 {
        match reader
            .read_event()
            .map_err(|e| anyhow!("xml parse during skip: {e}"))?
        {
            Event::Start(_) => inner_depth += 1,
            Event::End(_) => inner_depth -= 1,
            Event::Eof => anyhow::bail!("unexpected EOF mid-element"),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::filter::FilterConfig;

    /// Helper: lift the production filter into a closure for tests.
    /// Mirrors how proxy.rs invokes filter_xml in production.
    fn allow<'a>(paths: &[&str]) -> impl Fn(&str) -> bool + use<> {
        let cfg = FilterConfig {
            bluez_allowed_adapter_paths: paths.iter().map(|s| s.to_string()).collect(),
        };
        move |p| cfg.is_path_visible(p)
    }

    #[test]
    fn drops_disallowed_direct_child_self_closing() {
        let xml = r#"<node>
  <node name="hci0"/>
  <node name="hci1"/>
</node>"#;
        let out = filter_xml(xml, "/org/bluez", allow(&["/org/bluez/hci0"])).unwrap();
        assert!(out.contains(r#"name="hci0""#));
        assert!(!out.contains(r#"name="hci1""#));
    }

    #[test]
    fn drops_disallowed_direct_child_with_close_tag() {
        let xml = r#"<node>
  <node name="hci0"></node>
  <node name="hci1"></node>
</node>"#;
        let out = filter_xml(xml, "/org/bluez", allow(&["/org/bluez/hci0"])).unwrap();
        assert!(out.contains(r#"name="hci0""#));
        assert!(!out.contains(r#"name="hci1""#));
    }

    #[test]
    fn keeps_interface_and_method_descriptors() {
        let xml = r#"<node>
  <interface name="org.bluez.Adapter1">
    <method name="StartDiscovery"/>
  </interface>
  <node name="hci0"/>
</node>"#;
        let out = filter_xml(xml, "/org/bluez", allow(&["/org/bluez/hci0"])).unwrap();
        assert!(out.contains("org.bluez.Adapter1"));
        assert!(out.contains("StartDiscovery"));
    }

    #[test]
    fn does_not_filter_nested_node_advertisements() {
        // The outer object happens to be /org/bluez/hci0 (allowed).
        // Children are devices like dev_XX. They should pass.
        let xml = r#"<node>
  <node name="dev_AA_BB_CC_DD_EE_FF"/>
</node>"#;
        let out = filter_xml(
            xml,
            "/org/bluez/hci0",
            allow(&["/org/bluez/hci0"]),
        )
        .unwrap();
        assert!(out.contains("dev_AA_BB_CC_DD_EE_FF"));
    }

    #[test]
    fn handles_root_object_path() {
        // Introspect on "/" — child names join with single "/".
        let xml = r#"<node><node name="org"/></node>"#;
        let out = filter_xml(xml, "/", allow(&["/org/bluez/hci0"])).unwrap();
        // /org isn't a bluez disallowed path → kept.
        assert!(out.contains(r#"name="org""#));
    }

    #[test]
    fn passes_through_unrelated_xml_unchanged() {
        // Non-bluez introspect (e.g. systemd1 service): all paths
        // visible because allow-list is irrelevant outside bluez.
        let xml = r#"<node>
  <node name="manager"/>
</node>"#;
        let out = filter_xml(xml, "/org/freedesktop/systemd1", |_| true).unwrap();
        assert!(out.contains(r#"name="manager""#));
    }

    #[test]
    fn preserves_outer_node_attributes() {
        let xml = r#"<node name="self">
  <node name="hci1"/>
</node>"#;
        let out = filter_xml(xml, "/org/bluez", allow(&["/org/bluez/hci0"])).unwrap();
        assert!(out.contains(r#"<node name="self">"#));
        assert!(!out.contains(r#"name="hci1""#));
    }
}
