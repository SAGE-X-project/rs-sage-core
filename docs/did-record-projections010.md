# Native checked SAGE DID views

The SAGE 0.10.0 normative design is sage-spec
`06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b`, chapters 09 and 10. Earlier frozen
execution evidence keeps its original revision and scope.

## Architecture and use

Keep Snapshot and RegistryGate for protected-operation key decisions. Add an
owned RecordSnapshot/RecordReader boundary and RecordObserver for the complete
record and local provenance needed by DID views. Eip155 reads carry one finalized
block identity for record, keys and services. Web reads carry the bounded REG-08
envelope from an authenticated configured origin. A reader performs a fresh
read and validates source/history; ready/validated flags are not remote proofs.

The observer checks shape and every proof, persists the complete canonical
record digest and version, and rechecks freshness after storage. Web envelope
lifetime is also checked at the final gate. Expired keys can resolve for display
but never appear as verification methods. The private ObservedRecord fields
prevent substituting unchecked record bytes after observation.

The native didsource010 projector emits the Core 1.0 and DID 1.1 formats from
one record, including controller/state/version/source/block or issued/completion
metadata, all key roles and same-record services. No Go FFI or new production
dependency is required. Accept selection here chooses a bare document only.
DocumentView is not a standard DID Resolution algorithm result: a generic DID
resolver, standard deactivation/error handling and network HTTP negotiation
remain distinct integration work. No full DID or deployment conformance is
claimed by these helpers. Protected operations still need their own Gate read.

## Trust and unfinished bindings

No actual RPC/ABI, TLS origin/root, deployed contract, operational clock or
storage isolation is selected. The caller's reader must authenticate its
binding, finality/readiness, immutable history and historical KEM signers.
Record version persistence is not proof that an unspecified disk cannot roll
back. Actual registry deployment qualification stays in program stage 8.
IdentityAndReadiness remains NOT_BOUND and deployed controls remain NOT_RUN.
Known local size/invalid/stale reader errors retain their codes; unknown or
transport failures mean unreachable. Authenticated absence mapping is still open.

Units and safe child-process comparison are bounded fixtures, not operating
Source evidence. Cross-language equality proves only the compared view scope,
not organizationally independent audit or general interoperability.

## Verification scope

`cargo test --test did_record_projection010` checks observation binding,
all four proof suites, exact numeric spellings, clock and envelope deadlines,
reader diagnostic codes, durable restart denial, and both projections.
It also checks active records with every signing key expired, with or without
an otherwise live KEM. Such a public view grants no operation authority.

`python3 scripts/check_did_record_views010.py` builds separate local Rust and
Go fixture processes. Its 12 public signed records cover both registry profiles,
active/created/deactivated states, revoked historical KEM endorsers, partial
expiry and empty services. Both produce 24 views checked against independently
assembled normative expected documents and typed metadata. Rust's canonical
bytes are checked by the units; cross-language comparison normalizes JSON
object ordering, preserving all members and array order. The Go reference is
pinned to core `4c7bad17ce176088f7bbc22c94814a0631cd8776`; it is a test-only
module, never a production Rust dependency.

Eip155 reference execution exercises the complete Go Source. Web reference
execution checks the signed envelope and typed projection, not HTTP/TLS origin
binding. That public Go envelope checker still requires usable signing keys;
therefore the all-signing-expired boundary is native Rust unit evidence only.
Neither reference claims standard resolution-envelope encoding, HTTP negotiation,
authenticated absence, actual controller/history authority, or deployed readiness.

The DID Record Views CI job runs units and the separate reference processes.
It enforces at least 90% LLVM line coverage for **each** new production file
(`didsource010.rs`, `record_observer010.rs`), without including test source lines.
This is a line metric, not a claim of 90% branch/region or whole-core coverage.
Existing library units also exercise the shared record shape/proof helpers.

Local validation on Rust 1.88.0 and Go 1.26.8 passed: 767 Rust tests
(15 pre-existing ignored doctests), strict comparison parser checks,
formatting, and all-target/all-feature Clippy. The new projection and observer
files reached 90.12% and 96.36% line coverage respectively. Read-only independent
LLM review found reader-error masking and a weak JSON comparison; both were
fixed and re-reviewed without remaining findings. This review is not an
organizationally independent external audit.
