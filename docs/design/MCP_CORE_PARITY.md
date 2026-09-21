# Non-HTTP MCP core implementation comparison

This is a source comparison and implementation work list, not protocol conformance
or a replacement for historical Inspector reports. Inputs are Go
`872307563416f144cc863d26b594b0ce7da1f2bd`, Rust baseline
`65b6d8c3d95ac9f57c8ef6ea8bc0fe88b71ca639`, and this Rust owner lifecycle change.
The normative reference is sage-spec `520e5ed9a896ff8ba8ade776484f41084957aaa2`,
`profiles/non-http-mcp-security.md`.

| Capability | Go internal implementation | Rust implementation |
| --- | --- | --- |
| Authenticated handshake and signed encrypted records | Present | Present |
| Exclusive unused non-HTTP session ownership | Present | Present through consuming ownership |
| Local time sampling and fresh registry observation | Present | Present; exclusive endpoint access remains required |
| Authenticated initialize, initialized and discovery lifecycle | Present | Internal setup adapter with bounded owner registration and independent deadline closure |
| Lifetime setup and protected request-ID history | Present | Shared setup and protected request history on both server and client |
| Owner-aware durable admission and execution queue | Present | Internal gate added: authenticated owner, durable fence, final checks, bounded shared queue and single-consumer claim |
| Protected reply publication and owned client delivery | Present | Internal one-shot protected replies and durable owned-client exchanges added |
| Fixed workers and independent deadline cancellation | Present | Gate workers plus registered setup/session/client lifetime monitoring; transport cleanup ownership pending |
| Bounded stream, connection and listener ownership | Present | Pending; loopback test carriage is not a production binding |

Go's implementations remain internal integrations under bounded trusted-provider
assumptions. Their existence does not prove immutable component loading, deployed
registry validation or whole-host mediation. Rust's clock, registry and endpoint
APIs currently use exclusive mutable access. An independent cancellation scheduler
must not wait for that same access behind a provider call; the ownership primitive
does not solve that scheduling requirement alone. The gate monitor uses its own
bounded local clock and shared close state without borrowing that endpoint.

The internal admission gate pins its authority, policy and executor for its lifetime.
It creates server setup with the gate coordinator already attached; an earlier close
handle cannot become detached. Lock order is execution mutex, shared coordinator,
then short-lived owner/queue leaf locks. Storage, registry work and effects run
outside the coordinator. The bounded local clock is the only provider sampled there.
All endpoint, registry and worker clocks must use the same trusted monotonic domain.

Admission authenticates through the existing sole request-ID history, reserves a
shared capacity slot before providers, persists EXECUTING, revalidates and inserts
once. A duplicate receives a diagnostic snapshot without enqueueing effects. A
closed owner cannot insert; later transport closure does not undo historical admission.
Storage unavailability and permanent retirement prevent further claims. An expired
claim bound cancels conservatively. Capacity remains occupied through actual executor
termination and result/UNKNOWN persistence. The executor must encompass actual work,
not detach another worker. Queue entries are never reconstructed from recovered rows.

The server now retains the sole response permit inside the authenticated owner.
It sends the stored signed result once with exact inner/outer correlation, then
rechecks result authority, session validity and the fixed request deadline before
releasing the invocation. The gate bounds concurrent reply work across owners and
retains its quota until I/O and cleanup end. Failed sends and oversized RPC output
preserve durable execution and exact terminal bytes. A pending reply retires only
that transport invocation; the worker remains charged until it actually finishes.
Old worker deadline observations cannot close a newer poll on the same connection.

The private owned client consumes a negotiated initiator and uses the existing durable
client journal with a private synchronous sender. No alternate sender, raw reply,
reusable send permit or session export is exposed by this adapter. Submission reserves
IDs in the same setup history. Receive authenticates outer correlation and status,
consumes the durable invocation, then checks fresh result/session evidence under the
shared pool coordinator before returning output. A failure after terminal persistence
can lose delivery, but reopen cannot redeliver it. Preparation and exchange quotas
survive owner closure until journal, provider and dependency cleanup actually end.

The gate scheduler starts exactly the configured number of effect/cleanup workers
and one independent monitor before any protected work. Worker signers are pinned at
construction, duplicate attachment and external manual claims are rejected, and no
request spawns a worker. Active admission, queued/running work and active reply
callbacks retain bounded monitor records. Claim expiry cancels an unclaimed job;
worker expiry requests cooperative cancellation. Request expiry closes only the
matching transport operation. Running work can still publish its exact first outcome.
The monitor never acquires execution, registry, endpoint, signer or storage locks.
Clock failure or rollback retires the gate. Cancellation retains quota until the
actual callback and durable cleanup end. Stop reports timeout without unlocking the
ledger; callers can wait again, then close storage after all charged work ends.

A separate owner monitor now attaches once to an unused gate/client pool and
registers each owner before setup I/O. Shared capacity survives logical closure and
reconnect: a registration is released only after the owner and, for an owned client,
its journal and provider fields are destroyed. Failed constructor cleanup is charged
as well. The monitor covers the original setup deadline, current protected deadline
including pending reply permits between callbacks, absolute/idle session lifetime,
pinned key expiry and responder confirmation lifetime. Record acceptance alone
advances idle activity; local clock sampling and registry observation do not.

The mirror and endpoint share a monotonic/UTC watermark. Local clock sampling and
mirror publication are serialized so an earlier sampled time cannot overwrite a newer
monitor observation. The monitor does not borrow the endpoint or wait for registry,
journal or transport callbacks. Its only callback is the trusted bounded local clock.
Clock failure closes registered owners and denies new registrations. Closing one owner
does not retire healthy peers. Stop closes logically before waiting; timeout retains
the monitor and registration capacity until actual owner destruction. Gate execution
workers have a separate stop/cleanup lifecycle and admitted work may still finish.

This provides independent logical lifetime closure, not remote registry revocation
polling, forced provider termination, immediate key destruction or automatic socket
cleanup. The owning host must drop closed owners and clients after their actual work
ends. Production stream/connection/listener ownership and pre-handshake resource
quotas remain pending. Blocking providers must remain bounded
and non-reentrant; an active synchronous callback can retain quota until it returns.
Retained quota is fail-closed degradation, not proof of timely cleanup. Administrative
replacement requires retiring and cleaning the old gate before reopening its durable
scope. No in-place configuration replacement or public owner reset is exposed.

Next add owned transport and cleanup orchestration, then cross-core Inspector
adapters. Local tests cover real encrypted sessions and journals, completed/pending
responses, polling without re-execution, old worker completion during a newer poll,
closure after durable acceptance, reopen without redelivery, invalid result authority,
failed/oversized replies, 5000/5001 ms observation age, shared quotas through blocked
receive and failed constructor cleanup, and bounded TCP request/response exchanges.
Scheduling regressions use inert callbacks and bounded local threads: blocked
component validation and reply send, independent worker/request deadline equality,
queue expiry, clock rollback, stop timeout/retry and old-operation isolation.
Owner lifecycle tests additionally cover blocked setup/client receive, idle versus
absolute expiry, pinned key expiry, responder confirmation, shared clock rollback,
retired poll deadlines, owner isolation, late attachment rejection, and registration
retention through failed construction and blocking dependency destructors.
These are implementation tests, not catalog PASS results or a production binding.

## Inspector disposition

Inspector's historical `docs/mcp-owner-core-review.md` and
`docs/mcp-consolidated-catalog.md` pin earlier inputs. Preserve those reports.
The consolidated catalog's 71 cases remain NOT_RUN, and its model/checker results
are not actual protocol execution. This change neither executes those catalog
cases nor promotes the 26 mandatory child obligations to PASS. Rust compile-time
ownership checks, unit tests and local TCP exchanges are separate implementation
evidence. No full binding, Go/Rust interoperability or deployment conformance is
claimed from this change.
