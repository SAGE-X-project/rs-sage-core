# Native single-observation DID pairs

`didsource010::observe_views(&mut RecordObserver, did)` implements the existing
[SAGE 0.10.0 DIDP-03 single-observation rule](https://github.com/SAGE-X-project/sage-spec/blob/06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b/spec/10-resolution.md#8-projection-equivalence--didp-03-r-4-r-14).
It obtains one owned `ObservedRecord` and returns independently owned `core10`
and `did11` members of `DocumentViews`. Each contains a document, media type and
observation metadata. A new invocation observes again; no cached pair is reused.

The configured observer retains responsibility for source identity, profile,
proofs, readiness, freshness, version continuity and durable history. The API
neither chooses operating trust nor accepts a peer document or alias as authority.
The same checked immutable observation is passed to both existing projectors.
If observation or projection fails, no pair is returned. This does not undo an
observer's journal advance, and no retry is attempted. Rust's existing synchronous
observer has no new cancellation interface. Per-document bounds, state/key expiry
projection rules and existing single-view functions remain unchanged. A pair is
not an HTTP envelope, DID resolver or protected-operation authorization result.

Public integration tests exercise all twelve original independently authored
web/eip155 fixture expectations with one source read per pair. A changing normal
source advances active version 7 to terminal deactivated version 8 at a different
finalized block; the next unavailable read must fail rather than return cached
views. Mutating one returned document/metadata cannot affect the other member or
the next call. Malformed identifiers, unavailable readers and unready/unvalidated
observations retain the existing refusal boundaries. These are ordinary bounded
fixtures, not operating-chain evidence or attack reproduction.

The test-only Rust executable now invokes this public operation directly. The
public Go reference invokes `advanced/sage.ObserveViews`, passing the core's
complete EIP155Source for eip155. Its web source is explicitly a fixture that
checks signed envelopes and typed projection material, without claiming operating
TLS/controller/history authority. Both programs assert one source call per case;
raw independent expected documents remain unchanged. Metadata is serialized from
the returned actual types, not reconstructed maps.

CI retains the three focused public Rust test results, source/revision/tree,
file-level LLVM coverage, exact public Go dependency selection, raw oracle-free
input and both native outputs. The shared comparison checker seals the Rust
executable source as well as the production and Go reference sources. Existing
unit, platform, audit and per-file coverage requirements stay enabled.
Reported binary digests are provenance, not compiled-byte attestation. Neither
these results nor the single-observation API close the peer-document/alias
verifier cases, protected A2A ingress or operating source qualification.
