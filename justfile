set shell := ["bash", "-uc"]
default:
    @just --list

test    := "cargo nextest run --workspace"
lint    := "cargo clippy --workspace --all-targets -- -D warnings"
fmt     := "cargo fmt --all"

check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo nextest run --workspace

# Publish the crate family to crates.io, in dependency order.
# Needs `cargo login` (or CARGO_REGISTRY_TOKEN) first. `--dry-run` is not
# useful here: cargo resolves inter-member deps against crates.io, so a
# member can only be verified after its dependencies are published.
publish:
    cargo publish -p fegrid-iec60870-core
    cargo publish -p fegrid-iec60870-asdu
    cargo publish -p fegrid-iec60870-cs101
    cargo publish -p fegrid-iec60870-cs104
    cargo publish -p fegrid-iec60870-secauth
    cargo publish -p fegrid-iec60870-file
    cargo publish -p fegrid-iec60870-tokio
    cargo publish -p fegrid-iec60870

fuzz target:
    cd fuzz && cargo +nightly fuzz run {{target}}

# Line-coverage heatmap (HTML + lcov + summary). Requires cargo-llvm-cov.
coverage:
    CARGO_TARGET_DIR={{justfile_directory()}}/target \
        cargo llvm-cov test --workspace \
            --html
    CARGO_TARGET_DIR={{justfile_directory()}}/target \
        cargo llvm-cov report \
            --lcov --output-path {{justfile_directory()}}/target/llvm-cov/lcov.info

coverage-open:
    xdg-open coverage/html/index.html

coverage-clean:
    cargo llvm-cov clean --workspace
    rm -rf coverage/

# Live integration tests against real products on the lab network.
# Target list: FEGRID_LIVE_TARGETS="name=host[:port],..." (port default 2404).
# Without the env var these tests skip; run this recipe only from a host
# that can reach the listed products.
live-test:
    FEGRID_LIVE_TARGETS="rm_t501_gen1=10.25.0.21" \
        cargo nextest run -p fegrid-iec60870-tokio --test live104_rm_t501 --nocapture

# Live compliance tests against real products. Default = strict (any
# vendor gap fails the run); set FEGRID_LIVE_STRICT=0 for lenient
# (notes printed, exit green) when re-running against an under-conforming
# product whose gaps are already tracked.
live-test-compliance:
    FEGRID_LIVE_TARGETS="rm_t501_gen1=10.25.0.21" \
        cargo nextest run -p fegrid-iec60870-tokio --test live104_rm_t501_compliance --nocapture
# Same as live-test, but lenient: documents vendor non-conformance
# without failing the run. Use for ad-hoc sweeps against under-conforming
# products; CI defaults to the strict recipe.
live-test-lenient:
    FEGRID_LIVE_TARGETS="rm_t501_gen1=10.25.0.21" FEGRID_LIVE_STRICT=0 \
        cargo nextest run -p fegrid-iec60870-tokio --test live104_rm_t501_compliance --nocapture