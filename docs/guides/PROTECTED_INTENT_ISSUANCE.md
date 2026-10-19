# Protected intent issuance

Native Linux/macOS hosts can use `guard010::IntentIssuer` to authorize and issue
one root or downstream operation. The API leaves the 0.10.0 intent encoding,
Ed25519 domain, transport profiles and existing Client journal unchanged.

Construct `IssuerServices` from trusted `ClientServices`, full
`IssuancePolicy`, immutable `IntentMeasurement`, protected `IntentSigner` and
exact issuer-owned active Ed25519 `key_id`. Keep all providers and their
capabilities outside model/plugin control. `approve_intent` must evaluate the
entire canonical intent, including allowed target and current readiness,
policy epoch, captured original and exact final arguments. Hashing a component
alone does not establish the identity of the loaded instance.

`IntentIssuer::new` consumes a protected `RootCapture` and trusted services.
`authorize` accepts an `IntentProposal` containing only a registered tool,
fully resolved JSON object and lifetime from 1 through 300 seconds. Identity,
commitments, issuance time, fresh call ID and nonce are host/core owned. The
returned `AuthorizedIntent` has no constructor, clone or wire serialization.
`issue` consumes that issuer-bound decision before callbacks, rechecks current
policy/measurement/key/time and returns only a journaled `Client`. It does not
send or dispatch an effect, or expose an arbitrary-message signing method.

Each stable operation path has a permanent `.issuance` fence synced before
private-key use. Protect this fence, the Client journal and their directory
against deletion, rollback, substitution and unmediated concurrent writers.
A failure preserves consumed approval and any fence; an automatic retry at a
new path or with a new call ID is forbidden. Reconstruct a fresh issuer with
the same protected capture/configuration and call `reopen` to resume exact
journaled bytes without signing. Missing, partial or inconsistent state needs
protected reconciliation. Client services transfer once on issue/reopen;
that issuer cannot create another operation afterward.

`new_hop` requires a fresh local capture of the exact authenticated inbound
intent and protected upstream `HopServices`. The downstream decision is
independent, binds the parent call ID and rechecks admitted parent authority
before signing. The returned hop Client checks that authority again before
actual transport handoff.

`retire` permanently invalidates pending issuance decisions. It does not
revoke an already journaled request or undo an effect. The host must separately
retire policy at affected receivers and manage live Clients/DispatchGates.
Bounded callback deadlines, immutable loading, key custody, complete route
mediation and deployment evidence remain host obligations. The API does not
expose a protected C/WASM ABI or complete non-HTTP MCP owner assembly.

Scenario tests cover malformed proposals, denied policy, changed measurements,
inactive keys, expiry, retirement, foreign/reused decisions, signer failure,
invalid proof, final checks, root/hop issuance and separate-process journal
restart. The process tests use fixed public fixture keys and isolated temporary
storage; they provide bounded core runtime evidence, not a deployment verdict.
