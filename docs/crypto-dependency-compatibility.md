# Curve dependency compatibility

The curve dependencies use `k256` and `p256` 0.14, with a direct
`crypto-bigint` requirement of at least 0.7.8 for patched curve arithmetic
following [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
Cargo can retain older versions for a consumer's other dependencies. This
minimum requirement therefore does not establish that an entire consumer
graph is free of affected packages: audit its complete resolved lockfile.
The library's minimum supported Rust version remains 1.88.

SAGE's public key and signature bytes retain their existing formats:
uncompressed SEC1 public keys, low-S 65-byte secp256k1 signatures including
the recovery ID, and low-S 64-byte P-256 signatures. The existing protocol
profiles, FFI representation and algorithm identifiers are unchanged.

Rust applications that directly use the concrete `k256` types returned by
`crypto::secp256k1` helpers must align their dependency with `k256` 0.14.
The upstream point encoding APIs use `to_sec1_point` / `ToSec1Point`, and
`normalize_s` returns a signature directly. Applications using SAGE's
`KeyPair`, `PublicKey`, `Signature` and byte interfaces retain those APIs.
Ed25519 still uses its own signature traits; import the traits for the
corresponding algorithm when using upstream types directly.

Compatibility checks include the existing SAGE vectors, the RFC 6979
Appendix A.2.5 P-256 sample through both SAGE signing interfaces, existing
low-S and recovery checks, native unit and integration tests, FFI example
execution, and the WASM build. The security job prints the resolved reverse
dependency tree before running the unchanged advisory checks. Test results
must be assessed for the exact commit under review.
