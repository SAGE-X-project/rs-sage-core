# Non-HTTP MCP core implementation comparison

This is a source comparison and implementation work list, not protocol conformance
or a replacement for historical Inspector reports. Inputs are Go
`872307563416f144cc863d26b594b0ce7da1f2bd`, Rust baseline
`76dfd4247a030280aff475711fd4c2c5549d7934`, and this Rust setup change.
The normative reference is sage-spec `520e5ed9a896ff8ba8ade776484f41084957aaa2`,
`profiles/non-http-mcp-security.md`.

| Capability | Go internal implementation | Rust implementation |
| --- | --- | --- |
| Authenticated handshake and signed encrypted records | Present | Present |
| Exclusive unused non-HTTP session ownership | Present | Present through consuming ownership |
| Local time sampling and fresh registry observation | Present | Present; exclusive endpoint access remains required |
| Authenticated initialize, initialized and discovery lifecycle | Present | Internal setup adapter added; host integration remains pending |
| Lifetime setup and protected request-ID history | Present | Setup and server protected-input history added; client submission integration remains pending |
| Owner-aware durable admission and execution queue | Present | Pending; existing dispatch gate is a separate API |
| Protected reply publication and owned client delivery | Present | Pending; existing MCP record helpers do not establish this boundary |
| Fixed workers and independent deadline cancellation | Present | Pending |
| Bounded stream, connection and listener ownership | Present | Pending; loopback test carriage is not a production binding |

Go's implementations remain internal integrations under bounded trusted-provider
assumptions. Their existence does not prove immutable component loading, deployed
registry validation or whole-host mediation. Rust's clock, registry and endpoint
APIs currently use exclusive mutable access. An independent cancellation scheduler
must not wait for that same access behind a provider call; the ownership primitive
introduced here does not solve that scheduling requirement.

Integrate Rust owner-aware admission next, consuming authenticated setup and
protected-input history without creating a second authoritative ID set. Then add
response/client publication, scheduling and owned transport. Validate each boundary with inert unit schedules and benign
runtime exchanges before building cross-core Inspector adapters.

## Inspector disposition

Inspector's historical `docs/mcp-owner-core-review.md` and
`docs/mcp-consolidated-catalog.md` pin earlier inputs. Preserve those reports.
The consolidated catalog's 71 cases remain NOT_RUN, and its model/checker results
are not actual protocol execution. This change neither executes those catalog
cases nor promotes the 26 mandatory child obligations to PASS. Rust compile-time
ownership checks, unit tests and local TCP exchanges are separate implementation
evidence. No full binding, Go/Rust interoperability or deployment conformance is
claimed from this change.
