# fegrid-iec60870

Pure-Rust IEC 60870-5 protocol stack: typed ASDU codec, CS 101 / CS 104 transport,
file-transfer service, IEC 62351-5 secure-auth scaffolding, and a tokio async
runtime.

## Crates

| Crate                             | What it does                                      |
| --------------------------------- | ------------------------------------------------- |
| `fegrid-iec60870-core`        | Type IDs, COT, qualifiers, time tags, IOA         |
| `fegrid-iec60870-asdu`        | ASDU encode/decode + dispatch + file-transfer SM  |
| `fegrid-iec60870-cs101`       | FT 1.2 link-layer codec + master/slave runtime    |
| `fegrid-iec60870-cs104`       | APCI typestate engine, watchdog, raw handlers     |
| `fegrid-iec60870-tokio`       | Async transport over tokio (TCP, TLS, server)     |
| `fegrid-iec60870-file`        | File-transfer service (F_FR / F_SG / F_DR)        |
| `fegrid-iec60870-secauth`     | IEC 62351-5 secure-authentication scaffolding     |
| `fegrid-iec60870-conformance` | PICS XML + 30-item F-CONF-* report                |
| `fegrid-iec60870`             | Umbrella: re-exports + plugin system              |

## Quickstart

```toml
[dependencies]
fegrid-iec60870 = { version = "0.1", features = ["tokio"] }
```

```rust
use fegrid_iec60870::core::{AppLayerParameters, TypeId};
use fegrid_iec60870::asdu::{Asdu, InformationObject, InformationValue};

let params = AppLayerParameters::default();
let asdu = Asdu::interrogation_command(1, 0xFFFF /* QOI station */);
let bytes = asdu.encode(&params)?;
```

## Examples

```
cargo run -p fegrid-iec60870-tokio --example cs104_session_probe
cargo run -p fegrid-iec60870-tokio --example echo_master
```

## Build / test

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
```

## Workspace tasks (`just`)

```
just            # list recipes
just test       # nextest run --workspace
just lint       # clippy -D warnings
just coverage   # cargo llvm-cov
```

## License

MIT OR Apache-2.0
