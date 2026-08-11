# iptime-cli

An experimental, agent-friendly macOS CLI for reading and changing settings on
ipTIME routers without automating the canvas-rendered web UI.

`iptime-cli` talks to the same local HTTP RPC endpoint used by recent ipTIME web
interfaces. It does **not** modify router firmware, install anything on the
router, or send data to a cloud service.

> [!WARNING]
> This is an unofficial interoperability project. It is not affiliated with or
> endorsed by EFM Networks or ipTIME. Firmware updates may change the private
> protocol without notice. Use it only on routers you own or administer.

[한국어 문서](README.ko.md)

## Current scope

- macOS on Apple silicon and Intel
- JSON output suitable for scripts and AI agents
- Router probe, product/network status, connected clients, DHCP, Wi-Fi, and
  port-forward reads
- Secret-redacted output by default
- macOS Keychain integration without placing passwords in command arguments
- Config backup export with mode `0600`
- Dry-run-first Wi-Fi and port-forward changes
- Conservative raw RPC access with read/write risk classification

This project is beta software. Authenticated behavior is covered by synthetic
tests, but compatibility still varies by model and firmware.

Grouped read commands keep successful results when another firmware-specific
method returns an RPC error and mark the JSON response as `partial:true` with
only a sanitized error code for that item. Authentication and transport
failures—and a group with no successful item—still stop the command.

## Install from source

Requirements: macOS and Go 1.25 or newer.

```sh
git clone https://github.com/IJEMIN/iptime-cli.git
cd iptime-cli
go build -o ./bin/iptime ./cmd/iptime
install -m 0755 ./bin/iptime /usr/local/bin/iptime
```

If your shell cannot write to `/usr/local/bin`, install into a directory on
your `PATH` instead.

## Quick start

Global options must appear before the command.

```sh
# Does not require a login.
iptime --router http://192.168.0.1 probe

# Let the macOS security tool store the password through its own hidden prompt.
iptime --router http://192.168.0.1 credential set

iptime --router http://192.168.0.1 status
iptime --router http://192.168.0.1 clients
iptime --router http://192.168.0.1 dhcp
iptime --router http://192.168.0.1 wifi show
iptime --router http://192.168.0.1 port-forward list
```

The router URL defaults to `http://192.168.0.1`. You can also set the
non-secret values `IPTIME_ROUTER`, `IPTIME_INTERFACE`, and `IPTIME_USERNAME`.
There is intentionally no password environment variable or `--password`
option. `--timeout` limits DNS resolution and each router request. Time spent on
an interactive Keychain approval, password prompt, or captcha prompt is not
counted against that network timeout.

### Multiple active interfaces

If a Mac has Wi-Fi and Ethernet on the same subnet, bind the request explicitly:

```sh
iptime --interface <interface-name> status
```

You may use `--source-address <local-ip>` instead. The two options are mutually
exclusive.

### Captcha

If the router requires a login security code, retry with the global option:

```sh
iptime --captcha login
```

The temporary captcha image is opened with macOS and deleted after the attempt.

## Safe changes

Changes are dry runs unless `--yes` is present.

Immediately before an actual change, the CLI saves a full config backup under
`~/Library/Application Support/iptime-cli/backups/<router-id>/`. The opaque ID is
derived from the router origin so backups from multiple routers remain separate
without putting an address in the filename. The directory and files use modes
`0700` and `0600`. Backups can contain credentials, are never uploaded, and are
not deleted automatically; review and remove old files locally. If the router
cannot create a decodable, plausibly sized backup, the change stops.
`--no-backup` is an explicit escape hatch for a change you have independently
protected. This sanity check cannot prove that a firmware-specific backup is
restorable, so keep an independently tested recovery path for critical changes.

### Wi-Fi

First find the firmware-specific BSS identifier:

```sh
iptime wifi show
```

Then update only selected fields. The CLI reads the current object, sends only
the type-checked fields used by the observed web-UI schema, and verifies the
complete transmitted state after applying it. If a secure network's existing
password is hidden or malformed, read-modify-write fails closed unless the same
command supplies a replacement password.

```sh
iptime wifi set --bss <bss-id> --ssid ExampleWiFi
iptime wifi set --bss <bss-id> --ssid ExampleWiFi --yes

# The new Wi-Fi password is read through a hidden prompt.
iptime wifi set --bss <bss-id> --set-password --yes
```

Changing the network currently used by your Mac may disconnect the CLI. Prefer
a wired management connection for Wi-Fi or LAN changes.

### Port forwarding

```sh
iptime port-forward add \
  --name example-web \
  --target 192.168.0.10 \
  --protocol tcp \
  --external-port 8443 \
  --internal-port 443

# Review the JSON plan, then repeat with --yes.
iptime port-forward add \
  --name example-web \
  --target 192.168.0.10 \
  --protocol tcp \
  --external-port 8443 \
  --internal-port 443 \
  --yes

iptime port-forward delete --name example-web
iptime port-forward delete --name example-web --yes
```

Port forwarding exposes a service beyond the LAN. Review the target service's
authentication and patch status before applying a rule.

## Low-level RPC

Known read methods use `call`:

```sh
iptime call product/info
iptime call --params '"lan"' dhcpd/lease/show
```

State-changing methods use `apply`, which prints a redacted plan by default:

```sh
printf '%s\n' '"Example Router"' | iptime apply --params-stdin system/name
printf '%s\n' '"Example Router"' | iptime apply --params-stdin --yes system/name
```

High-risk and unknown methods require an additional acknowledgement. Arbitrary
command execution, factory reset, config restore, administrator credential
changes, firmware changes, and raw backup output are blocked entirely in this
release. Explicit JSON `null` params are rejected because the wire protocol
cannot distinguish them from omitted params. Secret-like JSON—and all raw write
params—must be supplied with `--params-stdin`, never as a shell argument. When
`--params-stdin` and the global `--password-stdin` are combined, stdin is
consumed in this fixed order: one JSON params line, then one router-password
line. Keychain is less error-prone for automated use. See
[the protocol notes](docs/protocol.md) before adding a method to the classifier.

## Backups

Router backup files can contain administrator and Wi-Fi credentials. They are
never printed, are created with mode `0600`, and are ignored by this repository.

```sh
iptime backup --output "$HOME/Desktop/router-backup.config"
```

The command refuses to overwrite an existing file.

## Privacy and security model

- No telemetry, analytics, background service, or cloud API
- Typed passwords and credentials are read from macOS Keychain, a hidden prompt,
  or an explicit stdin pipe; raw write params are stdin-only
- Session cookies live only in process memory and the CLI logs out after the
  operation
- Public IP targets are rejected unless `--allow-public-host` is explicit
- HTTP redirects are rejected and hostname resolutions are pinned per process
- Password-like response fields are redacted unless `--show-secrets` is explicit
- Config backups, HAR/PCAP files, router dumps, and local diagnostics are ignored

Normal status output can still contain private IP addresses, MAC addresses,
hostnames, SSIDs, and device names because those values are necessary for router
administration. Do not paste raw output into a public issue. Use `iptime doctor`,
which emits a narrower privacy-redacted report.

Many routers expose their admin UI over plaintext HTTP. In that case the login
password also travels over the local network as it does in the web UI. Use a
trusted LAN or router HTTPS when available. `--insecure` disables HTTPS
certificate verification and should be used only after independently confirming
the router address and certificate situation on a trusted LAN.

## Development

```sh
make check
```

Tests use only hand-written synthetic responses. Do not commit real router
responses, backups, firmware, UI bundles, screenshots, HAR files, or packet
captures. Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md)
before reporting a problem.

## License

MIT
