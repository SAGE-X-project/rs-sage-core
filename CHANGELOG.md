# Changelog

## Unreleased

### Changed (sage-spec alignment, crypto)
- secp256k1 signatures follow the Ethereum convention of sage-spec 01-crypto:
  Keccak-256 digest, RFC 6979, low-S, 65-byte `r || s || v` on the wire
  (64-byte `r || s` and DER accepted on input, high-S normalised on verify).
- secp256k1 and P-256 public keys are stored and exported as 65-byte
  uncompressed SEC1 points (33-byte compressed accepted on input); key ids
  are computed over that encoding. `PublicKey::to_compressed_bytes` and
  `PublicKey::ethereum_address` (lower-case hex) added.
- P-256 signatures are raw 64-byte `r || s`, low-S normalised.
- RFC 9421 `alg` for secp256k1 is `es256k`.
- `Signature::from_bytes(key_type, bytes)` is the single signature parser;
  `Signature` stores raw wire bytes for the ECDSA curves.
- secp256k1 JWK export implemented; `k256` 0.13.
- The `jcs` module implements RFC 8785; `tests/spec_vectors.rs` runs the
  sage-spec `jcs` and `crypto` suites (8/8 pass).

### Removed
- RSA support (`rsa` module, `KeyType::Rsa2048/Rsa4096`, RSA formats and
  RFC 9421 identifiers): optional in sage-spec, not covered by vectors, and
  the only remaining `cargo audit` finding (RUSTSEC-2023-0071).
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
- Doc examples for `X25519KeyPair::diffie_hellman` unwrap the result.
