# Contributing

Contributions are welcome, especially synthetic compatibility tests for
additional firmware families.

## Privacy boundary

Never commit or attach data captured from a real router. This includes responses,
backups, logs, screenshots, firmware, JavaScript/UI bundles, HAR/PCAP files,
cookies, network identifiers, and device names.

Fixtures must be written from scratch with unmistakably synthetic values such as:

- `ExampleWiFi`
- `example-device`
- `02:00:00:00:00:01`
- `192.0.2.10` and `2001:db8::1` in non-networking tests
- `not-a-real-password`

Do not start with a real response and attempt to anonymize it. It is too easy to
miss nested identifiers or credentials.

## Workflow

```sh
gofmt -w ./cmd ./internal
go vet ./...
go test -race ./...
```

Keep changes small and preserve these invariants:

- no typed password command-line argument or password environment variable;
  raw write params remain stdin-only
- no persistent session cookie
- no redirects or public router targets by default
- no raw request/response logging
- state changes are dry-run-first
- unknown methods require explicit acknowledgement
- `command` remains blocked

New method classifications should cite the behavior in the pull request without
uploading proprietary source or captured private data.
