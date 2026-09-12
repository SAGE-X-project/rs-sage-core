# Changelog

## Unreleased

### Removed
- `handshake` (four-phase protocol superseded by the HPKE profile), `transport`
  (reqwest-based manager; the gateway owns transport) and `blockchain`
  (alloy / solana clients; on-chain resolution lives in the Go core) modules,
  their examples, benches and integration tests, and the `blockchain` feature.
  This drops `reqwest`, `alloy*`, `solana-*` and the `h2` / `rustls-webpki` /
  `rustls-pemfile` advisories they pulled in.

### Changed
- Toolchain pinned to Rust 1.88.0 (`rust-toolchain.toml`, `rust-version`);
  CI runs one stable toolchain instead of stable/beta/nightly.
- `cargo fmt` and `clippy -D warnings` are clean on all targets and features.
- `uuid` enables the `js` feature so the `wasm32-unknown-unknown` build works.
- RUSTSEC-2023-0071 (`rsa` Marvin side channel, no fix) is acknowledged in
  `deny.toml` and `.cargo/audit.toml` until RSA support is removed.
- Doc examples for `X25519KeyPair::diffie_hellman` unwrap the result.
