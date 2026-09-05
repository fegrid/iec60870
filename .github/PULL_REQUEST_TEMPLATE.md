## Summary

<!-- One paragraph: what changed and why. Cite the issue or design doc. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (call out below)
- [ ] Documentation / CI / tooling only
- [ ] Refactor (no behavior change)

## Crates affected

<!-- List every workspace crate touched. Examples:
- [ ] fegrid-iec60870
- [ ] fegrid-iec60870-tokio
- [ ] all runtime crates
- [ ] none (docs / CI only)
-->

## Public API impact

<!-- Describe any change to the published surface:
- new symbols, types, modules, feature flags
- renamed or removed items
- changed default features
- changed dependency requirements
If nothing changes, write "None."
-->

## Breaking change

<!-- Required if this PR is breaking. Otherwise delete this section.
Explain what consumers must do to upgrade and link to a migration note.
-->

## Verification

<!-- Tick what you ran locally. -->
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo nextest run --workspace`
- [ ] `cargo build --workspace --all-features`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
- [ ] `cargo deny check`
- [ ] `cargo audit`

## Release notes

<!-- Optional. A short note that release tooling can pick up if this lands.
If you leave this blank the maintainers will write the release note. -->
