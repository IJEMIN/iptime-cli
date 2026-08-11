# Protocol notes

This document records the minimum independently observed behavior needed for
interoperability. The repository contains no ipTIME firmware or UI source.

## Transport

Recent canvas-rendered web interfaces use an HTTP POST endpoint:

```text
/cgi/service.cgi
```

The request is JSON-RPC-like but is not JSON-RPC 2.0:

```json
{
  "method": "product/info"
}
```

The `params` member is omitted when absent. Depending on the method, it can be an
object, array, string, number, or boolean. A successful HTTP response normally
contains one of these envelopes:

```json
{"result": {}, "error": null}
```

```json
{"result": null, "error": {"code": -31998, "message": "Unauthenticated"}}
```

HTTP status and RPC error status are handled separately.

The current client rejects an explicit JSON `null` parameter because its request
builder uses `nil` to mean that the `params` member is absent.

## Authentication

`session/login` accepts an object containing `id` and `pw`, plus optional captcha
or link-session fields. A successful login returns `"done"` and establishes an
HTTP cookie. Subsequent requests use that in-memory cookie. `session/logout` is
called when the CLI operation finishes.

Captcha support uses `captcha/new`, downloads the same-origin image to a temporary
mode-`0600` file, opens it on macOS, and sends `{text,url}` with the login.

## Supported read families

The initial classifier covers selected exact methods in these families (the
source allowlist remains authoritative):

- selected `product/*`, `system/*`, and interface status methods
- `network/interface/lan/stations`
- `dhcpd/config/get`, `dhcpd/status`, and `dhcpd/lease/show`
- selected `wireless/*/show`, `wireless/*/info`, and channel capability reads
- `portforward/config`, `portforward/get`, and `portforward/max`
- config backups through the dedicated file-only `backup` command (raw RPC
  output remains blocked)

Read results are kept as generic JSON values so unknown firmware fields survive.
Password-like fields are redacted only at the output boundary.
Grouped reads retain successful items if another method returns an RPC error and
mark the result partial. Transport and authentication failures, or a group with
no successful item, still stop the operation.

## Changes

Known state-changing methods are routed through `apply` or a typed command. Typed
Wi-Fi changes perform a read-modify-write of the known BSS fields used by the
observed UI serializer and set `commit:true`. Missing, mistyped, or unsafe
required values fail closed; output-only or unknown fields are not sent back to
the router. Post-write verification compares the complete transmitted state,
not only the user-edited field.

The safety classifier has four non-read outcomes:

- `write`: requires `--yes`
- `high-risk`: also requires `--force-high-risk`
- `unknown`: also requires `--force-unknown`
- `blocked`: cannot be invoked; arbitrary command execution, factory reset,
  restore, raw backup output, administrator credential changes, and firmware changes stay
  behind typed or future workflows

Actual changes first save a decodable, plausibly sized configuration backup in
a private, router-specific local directory unless `--no-backup` is explicit.
Because the backup format is firmware-private, this is a sanity gate rather
than proof that a restore will succeed.

This is a client-side safety boundary, not a router transaction. A LAN IP, WAN,
or Wi-Fi change can still disconnect the client before verification.

## Compatibility contributions

Add hand-written synthetic fixtures and fake-server tests. Never record or submit
real traffic. A useful compatibility report states only the product family,
firmware version, method name, expected schema shape, and sanitized error code.
