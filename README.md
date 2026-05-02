# dbus-bluez-filter-proxy

A D-Bus proxy that scopes a downstream client to an allowlisted set of
Bluetooth adapters. Adapters not on the allowlist are *invisible*: they don't
appear in `ObjectManager.GetManagedObjects` results, `InterfacesAdded`
signals, or `Introspect` XML. From the client's point of view, only the
allowlisted adapters exist.

The binary, the package, and the repo are all named `dbus-bluez-filter-proxy`.
The "bluez" qualifier is in the name because the only filter rules shipped
are BlueZ-specific; everything else passes through unchanged.

## Use case

You run two or more Bluetooth applications in containers and want each to
have exclusive use of one specific adapter on the host. Common reasons:

- One container scans for advertisements, another runs a BLE peripheral.
- A development environment shouldn't see the adapter assigned to a
  production service running on the same machine.
- A third-party tool enumerates `org.bluez` adapters and grabs the first one
  it finds — you need it to find only the adapter you've assigned to it.

BlueZ exposes a single `org.bluez` service on the host's system bus, so
sharing the host's D-Bus socket between containers gives every container
visibility of every adapter. This proxy lets you give each consumer its own
filtered view of `org.bluez`.

## Why not xdg-dbus-proxy

[xdg-dbus-proxy](https://github.com/flatpak/xdg-dbus-proxy) can deny method
calls on specific object paths but only filters *requests*. The disallowed
adapter is still visible: `bluetoothctl show` lists it,
`ObjectManager.GetManagedObjects` returns it, `InterfacesAdded` signals fire
for it, and `busctl tree org.bluez` enumerates it. Tools that enumerate
adapters and pick the first one will pick the wrong one even though they
can't actually use it.

xdg-dbus-proxy also doesn't speak sd-bus's pipelined SASL fast-path, so
`busctl` and other systemd-stack tools can't connect through it.

`dbus-bluez-filter-proxy` rewrites response payloads (not just requests), strips
disallowed paths from `Introspect` XML, drops signals for hidden adapters,
and supports both libdbus and sd-bus SASL handshakes.

## What it filters

When at least one `--bluez-allow-mac` is specified, the proxy applies these
rules to the `org.bluez` service. Everything else (other services, the
message bus itself, etc.) is forwarded byte-for-byte.

| Message | Action |
|---|---|
| `org.bluez` method call to a disallowed adapter path | Denied with an `AccessDenied` error |
| `GetManagedObjects` response | Disallowed adapter subtrees spliced out at the wire level |
| `InterfacesAdded` / `InterfacesRemoved` signal | Dropped if the path is under a disallowed adapter |
| Other signals from `org.bluez` | Dropped if the source path is under a disallowed adapter |
| `Introspect` response on `/org/bluez` | `<node name="hciN"/>` entries for disallowed adapters stripped from the XML |
| Anything else | Forwarded unchanged |

If `--bluez-allow-mac` is omitted entirely, the proxy is a pure pass-through.

Adapter scoping is by MAC address. The proxy resolves each MAC to its current
kernel index (`hci0`, `hci1`, ...) at startup using HCI ioctls, so the rules
stay correct across reboots even if Linux reorders the adapters.

## Authentication: peer UID matching

D-Bus on Linux uses SASL EXTERNAL authentication, which is satisfied by the
server reading the client's UID from the Unix socket via `SO_PEERCRED`. The
server then checks that the peer UID matches an expected value.

The proxy plays the server role for downstream clients. **It will only
accept connections from a client running as the UID specified by
`--peer-uid` (defaults to the UID the proxy itself is running as).**

This has practical consequences:

- If the consumer is a container running as root (UID 0), run the proxy as
  root. This is the common case.
- If the consumer runs as a non-root UID — for example a container with
  `user: 1000:1000` in its compose file, or any host process running as a
  service user — either run the proxy as that same UID, or pass
  `--peer-uid <UID>` to make the proxy expect a specific peer UID.
- Mixing UIDs without telling the proxy will fail with an authentication
  error during connection setup.

The proxy's own connection upstream to `dbus-daemon` is authenticated as the
proxy's UID. The system bus accepts connections from any UID by default, so
this is normally not a constraint, but per-method Polkit rules on the host
will see the proxy's UID, not the original client's.

## Usage

```
dbus-bluez-filter-proxy \
    --listen <socket-path> \
    [--upstream <bus-socket>] \
    [--peer-uid <UID>] \
    [--bluez-allow-mac <MAC> [--bluez-allow-mac <MAC> ...]] \
    [--adapter-resolve-timeout-secs <SECS>]
```

| Flag | Default | Notes |
|---|---|---|
| `--listen` | required | Path where the proxy will create its Unix socket. Bind-mount this into the consumer container. |
| `--upstream` | `/run/dbus/system_bus_socket` | Path to the real system bus socket on the host. |
| `--peer-uid` | proxy's own UID | UID the downstream client must connect as (SASL EXTERNAL). |
| `--bluez-allow-mac` | none (full pass-through) | MAC of an adapter the consumer is allowed to see. Repeatable on the CLI; comma-separated when set via env. |
| `--adapter-resolve-timeout-secs` | `60` | How long to wait for `--bluez-allow-mac` adapters to appear at startup before bailing out. |

Every flag also reads from a matching environment variable: take the flag
name, uppercase it, replace `-` with `_`, and prefix `DBUS_BLUEZ_FILTER_PROXY_`.
So `--peer-uid` is `DBUS_BLUEZ_FILTER_PROXY_PEER_UID`, `--bluez-allow-mac`
is `DBUS_BLUEZ_FILTER_PROXY_BLUEZ_ALLOW_MAC`, and so on. This makes systemd
template units clean — the `ExecStart=` line stays canonical and
per-instance configuration goes in an `EnvironmentFile=` or an
`Environment=` drop-in.

## Setup walkthrough: Docker Compose

Two containers, each scoped to its own adapter.

### 1. Run a proxy instance per consumer on the host

A systemd template unit makes this clean. One unit per consumer, parameterised
by instance name:

```ini
# /etc/systemd/system/dbus-bluez-filter-proxy@.service
[Unit]
Description=Filtering D-Bus proxy for %i
After=dbus.service bluetooth.service
Requires=dbus.service

[Service]
Type=simple
EnvironmentFile=/etc/dbus-bluez-filter-proxy/%i.conf
UMask=0000
ExecStartPre=+/bin/rm -f ${SOCKET_PATH}
ExecStart=/usr/local/bin/dbus-bluez-filter-proxy \
    --listen ${SOCKET_PATH} \
    --upstream /run/dbus/system_bus_socket \
    --bluez-allow-mac ${ADAPTER_MAC}
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Per-instance config files set the socket path, adapter MAC, and any other
flag-equivalent env vars. The unit's `EnvironmentFile=` directive loads the
matching one based on the instance name (`%i`) — that's how `scanner` and
`peripheral` get different configuration from one shared unit file.

```ini
# /etc/dbus-bluez-filter-proxy/scanner.conf
SOCKET_PATH=/run/dbus-proxy/scanner/system_bus_socket
ADAPTER_MAC=AA:BB:CC:DD:EE:FF
```

```ini
# /etc/dbus-bluez-filter-proxy/peripheral.conf
SOCKET_PATH=/run/dbus-proxy/peripheral/system_bus_socket
ADAPTER_MAC=11:22:33:44:55:66
```

This is where any per-instance configuration goes. Need to override the
upstream socket path or peer UID for one instance? Add the corresponding
`DBUS_BLUEZ_FILTER_PROXY_*` line to that instance's `.conf` file. The
template unit file stays untouched.

Enable each:

```sh
systemctl enable --now dbus-bluez-filter-proxy@scanner.service
systemctl enable --now dbus-bluez-filter-proxy@peripheral.service
```

### 2. Bind-mount the proxy socket into each container

```yaml
# compose.yml
services:
  scanner:
    volumes:
      - /run/dbus-proxy/scanner:/run/dbus:ro
    environment:
      DBUS_SYSTEM_BUS_ADDRESS: unix:path=/run/dbus/system_bus_socket

  peripheral:
    volumes:
      - /run/dbus-proxy/peripheral:/run/dbus:ro
    environment:
      DBUS_SYSTEM_BUS_ADDRESS: unix:path=/run/dbus/system_bus_socket
```

Inside `scanner`, BlueZ exposes only `AA:BB:CC:DD:EE:FF`. Inside
`peripheral`, only `11:22:33:44:55:66`. Each container is unaware of the
other adapter's existence.

### 3. Match UIDs (if your container isn't root)

If your application inside the container runs as a non-root user
(`USER 1000` in a Dockerfile, or `user: 1000:1000` in compose) you have to
tell the proxy which UID to expect — otherwise the SASL EXTERNAL handshake
(see "Authentication: peer UID matching" above) rejects the connection.

#### Why this matters

When a process inside the container connects to the proxy's Unix socket, the
host kernel records the process's UID on the socket. The proxy reads that UID
via `SO_PEERCRED` and compares it against the UID it expects (defaulting to
its own UID). If the two don't match, the proxy refuses the connection during
the auth handshake — which manifests as a hard-to-diagnose connection failure
on the client side.

There's nothing Bluetooth-specific about this; it's how D-Bus authentication
works on Unix sockets in general.

For typical Docker setups (no user-namespace remapping), the UID inside the
container is the same as the UID the host kernel sees on the socket. So if
your container runs as UID 1000, the proxy will see peer UID 1000 and needs
to be configured to accept that.

#### Two ways to fix it

**Option A — keep the proxy as root, override the expected peer UID.** Add
the env var to that instance's `.conf` file:

```ini
# /etc/dbus-bluez-filter-proxy/scanner.conf
SOCKET_PATH=/run/dbus-proxy/scanner/system_bus_socket
ADAPTER_MAC=AA:BB:CC:DD:EE:FF
DBUS_BLUEZ_FILTER_PROXY_PEER_UID=1000
```

The proxy still runs as root upstream, so host-side Polkit rules see the
proxy as root. Useful when the proxy needs root privileges upstream (e.g. for
adapter management calls that go through Polkit) but the consumer can't run
as root. This is usually what you want.

**Option B — run the proxy itself as the matching UID.** This needs a
systemd unit *drop-in*, because `User=` is a unit-level directive (it
controls what user systemd starts the process as) and isn't an env var the
binary can read:

```ini
# /etc/systemd/system/dbus-bluez-filter-proxy@scanner.service.d/user.conf
[Service]
User=1000
Group=1000
```

A drop-in is a small unit fragment that's merged into the template unit
without modifying it. Now the proxy runs as UID 1000, the client connects
as UID 1000, the SASL EXTERNAL check passes by default. Side-effect: the
proxy's connection upstream to the host's `dbus-daemon` is *also* as UID
1000, so any host-side Polkit rules will see the proxy as UID 1000 rather
than root — pick this if that's what you want.

If your container runs as root (UID 0), neither option is needed — the
default of "expect peer UID = my own UID" works as long as the proxy is also
running as root, which is the default.

## Building

Requires Rust stable, `libbluetooth-dev`, and `libclang-dev` (for bindgen):

```sh
cargo build --release --locked
```

The binary links dynamically against `libbluetooth` and requires a
BlueZ-capable kernel for the HCI ioctls used to resolve adapter MACs.

## Tests

```sh
./run-tests.sh                    # full suite in a Docker container
./run-tests.sh --test passthrough # one suite
cargo test                        # locally (needs the build deps above)
```

The container test setup spins up a real `dbus-daemon` and a stub `org.bluez`
service so the integration tests exercise the full SASL handshake and
filter pipeline against a working bus.

## Code layout

| Path | Notes |
|---|---|
| `src/proxy.rs` | Async relay: splice loop, call tracking, GMO/Introspect rewriting; SASL phase forwards bytes verbatim between client and upstream |
| `src/filter.rs` | BlueZ filter rules (adapter visibility, method-call policy) |
| `src/wire.rs` | D-Bus wire message header parser |
| `src/introspect.rs` | Streaming XML filter for Introspect responses |
| `src/hci.rs` | HCI ioctl adapter enumeration (MAC → hciN index) |
| `build.rs` | bindgen invocation for `<bluetooth/hci.h>` |

## License

Licensed under the GNU General Public License, version 3 or later
([GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html)). See the
[`LICENSE`](LICENSE) file for the full text.
