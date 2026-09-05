# FeGrid IEC 60870

A sans-IO IEC 60870-5 protocol stack in Rust with CS 101 / CS 104 transports, a typed ASDU codec, a sans-IO file-transfer state machine, IEC 62351-5 secure-auth scaffolding, and a tokio async runtime.

The stack targets IEC 60870-5-101 (FT 1.2 serial) and IEC 60870-5-104 (TCP / TLS) conformance.

## Install

```toml
[dependencies]
fegrid-iec60870 = { version = "0.1", features = ["tokio"] }
```

Default features are `tokio`. Additional transports and tooling are gated behind feature flags:

- `serial` — FT 1.2 serial port transport
- `tls` — TLS over TCP (CS 104)
- `file` — IEC 60870-5 file-transfer service
- `secauth` — IEC 62351-5 secure-authentication scaffolding

## Build

```sh
cargo build --workspace
```

For the full set of transports and tooling:

```sh
cargo build --workspace --features "tokio serial tls file secauth"
```

## Test

```sh
cargo test --workspace --no-fail-fast
```

## Crates

### Sans-IO core (no_std-friendly)

- `fegrid-iec60870-core` — common types: Type IDs, COT, qualifiers, time tags, IOA.
- `fegrid-iec60870-asdu` — ASDU encoding, decoding, dispatch, and file-transfer SM.
- `fegrid-iec60870-cs101` — FT 1.2 link-layer codec + sans-IO master/slave runtime.
- `fegrid-iec60870-cs104` — APCI typestate engine, watchdog, raw message handlers.

### Drivers and tooling

- `fegrid-iec60870-tokio` — async driver over TCP, TLS, and serial.
- `fegrid-iec60870-file` — IEC 60870-5 file-transfer service surface.
- `fegrid-iec60870-secauth` — IEC 62351-5 secure-authentication scaffolding.
- `fegrid-iec60870-conformance` — PICS XML + 30-item F-CONF-* report.
- `fegrid-iec60870-fixtures` — canonical corpus of captured IEC 60870 traffic.
- `fegrid-iec60870` — umbrella crate re-exporting the above.

## Conformance

The `fegrid-iec60870-conformance` crate exercises the ASDU codec, the CS 101 FT 1.2 link FSM, the CS 104 APCI typestate engine, and the secure-auth surface against captured IEC 60870 traffic.

## License

Dual-licensed under either of:

- [MIT](LICENSE-MIT)
- [Apache-2.0](LICENSE-APACHE)

at your option.
