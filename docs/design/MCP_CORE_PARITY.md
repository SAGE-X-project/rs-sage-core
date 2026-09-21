# Non-HTTP MCP core implementation comparison

This is a source comparison and implementation work list, not protocol conformance
or a replacement for historical Inspector reports. Inputs are Go
`872307563416f144cc863d26b594b0ce7da1f2bd`, Rust baseline
`64531b658f28b069772b0c88d5148eb1dbec807c`, and this Rust admission change.
The normative reference is sage-spec `520e5ed9a896ff8ba8ade776484f41084957aaa2`,
`profiles/non-http-mcp-security.md`.

| Capability | Go internal implementation | Rust implementation |
| --- | --- | --- |
| Authenticated handshake and signed encrypted records | Present | Present |
| Exclusive unused non-HTTP session ownership | Present | Present through consuming ownership |
| Local time sampling and fresh registry observation | Present | Present; exclusive endpoint access remains required |
| Authenticated initialize, initialized and discovery lifecycle | Present | Internal setup adapter added; host integration remains pending |
| Lifetime setup and protected request-ID history | Present | Setup and server protected-input history added; client submission integration remains pending |
| Owner-aware durable admission and execution queue | Present | Internal gate added: authenticated owner, durable fence, final checks, bounded shared queue and single-consumer claim |
| Protected reply publication and owned client delivery | Present | Pending; existing MCP record helpers do not establish this boundary |
| Fixed workers and independent deadline cancellation | Present | Pending |
| Bounded stream, connection and listener ownership | Present | Pending; loopback test carriage is not a production binding |

Go's implementations remain internal integrations under bounded trusted-provider
assumptions. Their existence does not prove immutable component loading, deployed
registry validation or whole-host mediation. Rust's clock, registry and endpoint
APIs currently use exclusive mutable access. An independent cancellation scheduler
must not wait for that same access behind a provider call; the ownership primitive
introduced here does not solve that scheduling requirement.

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

This private API does not yet provide protected replies, client delivery, a host
worker pool or an independent cancellation scheduler. An owner stays occupied after
admission until the future reply integration or closure; no public reset exists.
Workers observe request expiry at claim and completion and close the owner without
claiming rollback. A blocked provider still needs the future independent scheduler;
retained quota is fail-closed degradation, not proof of timely cleanup. Administrative
replacement requires retiring and cleaning the old gate before reopening the durable
scope; no in-place configuration replacement is exposed here.

Next add response/client publication, scheduling and owned transport. Validate each
boundary with inert unit schedules and benign runtime exchanges before building
cross-core Inspector adapters. The admission tests cover real encrypted sessions and
ledger files, cross-thread closure during post-fence verification, shared capacity
through actual worker exit, duplicates, unavailable storage, signer failure with
queued work, clock rollback, freshness at 5000/5001 ms, request/claim deadline equality,
and a bounded loopback TCP request. These are implementation tests, not catalog PASS
results or a production transport binding.

## Inspector disposition

Inspector's historical `docs/mcp-owner-core-review.md` and
`docs/mcp-consolidated-catalog.md` pin earlier inputs. Preserve those reports.
The consolidated catalog's 71 cases remain NOT_RUN, and its model/checker results
are not actual protocol execution. This change neither executes those catalog
cases nor promotes the 26 mandatory child obligations to PASS. Rust compile-time
ownership checks, unit tests and local TCP exchanges are separate implementation
evidence. No full binding, Go/Rust interoperability or deployment conformance is
claimed from this change.
