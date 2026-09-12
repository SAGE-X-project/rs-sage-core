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

### Changed (sage-spec alignment, session)
- `session` rewritten to `05-session.md`: ChaCha20-Poly1305 records
  `be64(seq) || nonce[12] || ciphertext` with a random nonce and the sequence
  number authenticated as AAD, a 1024-slot replay window, key rotation every
  `rekey_interval` records (`sage-session-rekey-v1 || direction || be64(gen)`),
  the HKDF key schedule (`sage-session-keys-v1`, `sage-directional-keys-v1`,
  salt = session id), seed and id derivation (`derive_session_seed`,
  `compute_session_id`), directional and AAD entry points
  (`encrypt_outbound`, `decrypt_inbound`, `encrypt_with_aad`,
  `decrypt_with_aad`) and the HMAC path over the signing keys.
  `SecureSession::new(id, seed, config)` derives the shared keys;
  `SecureSession::with_role` adds the directional ones. The manager uses the
  HPKE exporter as the seed and derives the id from it. Default
  `max_messages` is 1000. `aes-gcm` replaced by `chacha20poly1305`.
- `tests/spec_vectors.rs` runs the sage-spec `session` suite (3/3): the Go
  core's records at seq 0 and 256 (rotated key) and the directional/AAD
  records decrypt here.

### Changed (sage-spec alignment, RFC 9421)
- `rfc9421` rewritten to the sage-spec profile: `Signature` members are RFC
  8941 byte sequences (`sig1=:base64:`), any label is accepted (first
  lexicographically by default), `Content-Digest` (`sha-256=:…:`) is added
  when a body is given and checked on verify, every request carries a `nonce`
  and verifiers keep a per-`keyid` replay guard, `created` is bounded by a
  freshness window, `keyid` carries the agent DID (`HttpSigner::with_key_id`,
  `VerifyOptions::expected_did`, `X-SAGE-DID` consistency), responses bind
  the request with `;req` components (`sign_response`, `verify_response`),
  `@query-param` is supported, and `alg` must match the key type.
  `VerifyOptions::strict_request` / `strict_response` mirror the Go core.
  `HttpSigner::sign_request` now takes the body; `sign_response` and
  `verify_response` take the request.
- `tests/spec_vectors.rs` runs the sage-spec `rfc9421` suite (4/4).

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
