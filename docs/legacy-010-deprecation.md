# Legacy APIs and the SAGE 0.10.0 deprecation plan

Status: preparation (phase P0). No item is newly marked `#[deprecated]` by this
document. It classifies public APIs that predate the SAGE 0.10.0 protocol,
names their 0.10.0 replacements, records known callers at `f464a5a`, and orders
the work needed before marking them. The Go core keeps a matching plan in
`sage/docs/LEGACY_010_DEPRECATION.md`.

Legacy APIs remain available and keep their historical behavior. They are not
0.10.0 conformance subjects: Inspector observations of 0.10.0 cases must call
the 0.10.0 entry points. The crate is `0.x`, so a minor release may remove a
deprecated item; a changed C header signature is a minor bump.

## Why preparation comes before marking

- **CI denies warnings.** `cargo clippy --all-targets --all-features -- -D warnings`
  turns every in-crate use of a `#[deprecated]` item into a failure, including
  tests, benches, examples and the `ffi`/`wasm` features. There is no
  `#[allow(deprecated)]` in the crate today.
- **0.10.0 code used the legacy JCS entry point.** `hpke/completion010.rs`,
  `hpke/derivation010.rs` and `hpke/completion010/record010.rs` called
  `jcs::canonicalize`. P1 added the crate-private `jcs::canonical`, which
  these modules now call; `jcs::canonicalize` delegates to it. `guard010` and
  `registry010` build on `jcs::parse` and `jcs::to_string`, which stay.
- **FFI and WASM expose legacy APIs as stable surface:** `sage_jcs_canonicalize`,
  `sage_did_validate` (`parse_did`), key proof-of-possession, legacy session
  identifiers and a `SecureSession`-backed session.

## Classification

### A. Deprecate after preparation (a 0.10.0 replacement exists)

| Legacy | 0.10.0 replacement | Behavioral difference |
|---|---|---|
| `did::parse_did`, `did::validate_did`, `did::parse_chain` | `did::parse_did_010`, `did::parse_did_url_010` | Legacy accepts only `ethereum`/`eth`/`solana`/`sol` and rejects canonical `web` and `eip155` DIDs |
| `jcs::canonicalize` (lenient entry point) | `guard010::canonicalize` | Legacy normalizes `-0` and has no size, member or depth limits |
| `hpke::combine_secrets` | `hpke::combine_secrets_010` | v1 combiner versus transcript-bound 0.10.0 schedule |
| `hpke::make_ack_tag`, `verify_ack_tag` | `make_ack_tag_010`, `verify_ack_tag_010` | v1 labels |
| `hpke::derive_traffic_keys`, v1 label constants, `DefaultInfoBuilder`, `InfoBuilder` | `build_domains_010`; record keys inside `RecordSession010` | v1 labels |
| `HpkeClient*`, `HpkeServer*`, `NonceStore` | `hpke::completion010::CompletionEndpoint010` (`new`, `new_protected`), `ReplayStore010`, `ReplayJournal010` | Legacy handshake without the 0.10.0 authenticated completion, replay and current-key gates |
| `session::SecureSession`, `Session`, `SessionConfig`, `derive_session_seed`, `compute_session_id` | `session::RecordSession010` (via `CompletionEndpoint010`) | Historical wire format and derivation (README) |

### B. Keep (shared building blocks, not deprecated)

- `jcs::parse`, `jcs::to_string`, `jcs::Value`, `number_to_string`: used by
  `guard010` and `registry010`.
- `kem_seal`, `kem_open`, `hmac_expand`, `sha256_hash*`.

### C. Legacy with no 0.10.0 replacement (decision needed before deprecating)

| API | Note |
|---|---|
| `rfc9421` general signer/verifier, canonicalizers, replay guard | 0.10.0 only provides session-bound HTTP (`completion010` HTTP methods) |
| `did` resolvers, `DIDResolver`, key resolvers | `registry010::Gate` needs a trusted Source; it is not a network resolver |
| `did` key proof-of-possession (`pop_challenge`, `generate_key_pop`, `verify_key_pop`) | `registry010::pop_challenge010` builds challenge bytes only |
| `A2AAgentCard` proof | No 0.10.0 card verifier |
| `SessionManager` | No one-to-one replacement |
| FFI/WASM legacy functions | Need a C/JS surface decision and a minor-version bump |

Class C items must not be marked until a replacement exists or the owners decide
to retire the feature.

## Phases

1. **P0 (this document).** Classify, list callers and replacements.
2. **P1. Decouple and migrate inside this crate, without behavior change.**
   - Done: 0.10.0 modules call the crate-private `jcs::canonical`; output is
     unchanged because `jcs::canonicalize` delegates to it.
   - Move examples, benches and tests that demonstrate 0.10.0 behavior to the
     0.10.0 APIs; keep legacy tests explicitly labeled legacy.
   - Decide the FFI/WASM surface (keep with `#[allow(deprecated)]`, or add
     0.10.0 entry points first).
3. **P2. Mark class A** with `#[deprecated(since = "…", note = "use …")]`,
   add a CHANGELOG Deprecated section, and add scoped
   `#[allow(deprecated)]` only on intentional legacy callers.
4. **P3. Consumers.** Update sage-inspector harness adapters to route 0.10.0
   cases to 0.10.0 entry points; legacy routes stay labeled legacy.
5. **Removal** in a later minor release after consumers move.

## Verification for each phase

- `cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`,
  `cargo test --all-features`.
- 0.10.0 vectors and Inspector observations unchanged by P1.
