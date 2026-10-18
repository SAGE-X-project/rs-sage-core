# Authenticated HTTP application metadata

`AuthenticatedCompletion010::into_http_application(endpoint, target)` consumes
an unused session into a non-cloneable `HTTPApplicationOwner010` for an exact
trusted HTTPS target. It implements the existing SAGE 0.10.0 envelope metadata
field, without a new wire version, transport listener or execution authorization.
Matching ordinary and HTTP-bound handshakes are supported, including provisional
responder receive. Used, closed, mismatched-target or wrong-endpoint acquisition
fails. Unlike Go's retryable failed transfer, **Rust failure consumes and closes
the original session**. The private inner owner preserves lifecycle and history;
Drop closes it. There is no inner-session export or non-HTTP conversion.

`seal_request`/`open_request` and `seal_response`/`open_response` exchange owned
accepted views. Content, metadata and sender/recipient/signing-key/session fields
come from accepted envelopes. Response metadata is independently authenticated and
need not equal request metadata. A view and a response's `success` are data, never
a portable grant for local effects. Safe Rust immutable borrows keep input wire
bytes stable during providers; common HTTP admission precedes its proof copy.
This does not place a new global length cap on a trusted configured target.

Metadata is optional: `None` is absent, `Some(empty)` is a present empty object.
Present null is rejected by a raw object visitor, as are duplicate decoded keys,
nonstring values, invalid UTF-8 and unpaired surrogate escapes. At most 32 keys
match `[a-z][a-z0-9_]{0,31}`; each value is at most 1024 UTF-8 bytes and metadata JCS
is at most 4096 bytes. Send metadata is checked/cloned before Clock or other
providers. Incoming metadata admission occurs after local clock/HTTP preparation
but before Source, cryptographic record acceptance or replay publication. Values
never select a signing key, Registry authority or canonical identity.

The same full signature, record AAD and complete signed-request hash bind metadata.
**Complete AAD remains at most 4033 bytes**, including participant and response
correlation fields. Valid metadata alone can therefore exceed a particular
request/response budget. Envelope32768, record16384 and plaintext16348 byte bounds
remain. Optional task fields and full chapter 08 large-message support are not
implemented by this API. Existing bare/non-HTTP and ordinary HTTP APIs still
reject every metadata member, including `{}`, instead of decrypting and dropping it.

The owner reuses the original endpoint identity, lifetime mirror, panic handling
and ordered clock samples. `participants` returns local/peer identifiers;
`local_now`, `observe` and `check` retain their diagnostic/current-observation
boundaries and do not authorize dispatch. The final mirror sample may fail
**after replay/sequence/terminal acceptance**. Such an error releases no view and
retires the owner, but retains acceptance/denial; it does not roll back storage or
restore a retry right. No temporary-memory zeroization claim follows from dropping
a failed result. The configured Source and custody retain their existing trust,
history and bounded-provider responsibilities.

Rust currently has no Context/cancellation token on these APIs. Go's Context check
at its final publication callback is a separate implemented boundary; this Rust
API does not inherit it, preempt blocked providers or predict later cancellation.
Actual transport cancellation and final-send/dispatch checks remain explicit
integration work. Neither a clock sample nor a fresh observation is a portable
permit; a final callback does not claim a second Source read.

The safe owned TLS fixture uses only public deterministic test keys/certificates
and inert content. The leaf private-key seed is byte09 repeated32, never deployment
custody; public DER certificates are under tests/fixtures. The root and leaf were
generated for localhost tests and expire in2036. TLS sockets use timeouts and only
an already-paired loopback connection. The test reconstructs method/target/Host,
status/headers/content from TLS HTTP bytes and counts an inert fixture handler.
Only normal exchange and unavailable configured authority are runtime cases.
Signature/AAD/schema changes remain in owned-key unit tests.

This fixture is not the production ADK TransportOwner or A2A server. Real adapters
must enforce trusted routing/TLS/framing, no redirect/retry/downgrade, final checks
after blocking setup and before first application bytes, and actual ingress and
execution policy. Core-valid but A2A-invalid metadata is an application rejection
after crypto/replay acceptance and cannot undo replay denial. These tests do not
close arbitrary peer-document/alias protected-verifier cases, attest an operating
Registry deployment or certify whole-protocol conformance.
