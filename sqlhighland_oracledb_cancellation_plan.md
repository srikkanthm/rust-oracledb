# SQLHighland + Oracle Rust Driver Query Cancellation Plan

**Date:** September 11, 2026  
**Target project:** SQLHighland  
**Primary upstream:** Oracle `rust-oracledb`  
**Goal:** Add safe, user-triggered cancellation of long-running Oracle queries while retaining the benefits of the modern pure-Rust Oracle driver.

---

## 1. Executive Summary

SQLHighland needs a real **Cancel Query** capability. The current Oracle-maintained `oracledb` Rust driver provides call timeouts, but it does not expose a public `Connection::cancel()` / `break_execution()` API suitable for a GUI cancel button.

The recommended approach is **not** to move SQLHighland to the older OCI-based `oracle` crate merely to obtain cancellation. Instead:

1. Keep Oracle's modern `rust-oracledb` driver as the base.
2. Fork it for SQLHighland.
3. Implement cancellation as a small, focused driver extension.
4. Start with **Unix + plain TCP** cancellation using Oracle's break mechanism and a separately usable socket/control path.
5. Reuse the driver's existing interrupt/reset recovery logic wherever possible.
6. Initially treat **TCPS/TLS and Windows as separate follow-up milestones** rather than weakening the first implementation with an overly broad design.
7. Keep the fork very close to upstream so the cancellation patch can be rebased and later removed if Oracle accepts an equivalent public API.

The long-term desired result is a public API similar to:

```rust
let cancel = conn.cancel_handle();

// query runs on worker thread/task
// ...

cancel.cancel()?;
```

or, if the driver architecture supports it safely:

```rust
conn.cancel()?;
```

---

## 2. Why We Should Not Immediately Switch Drivers

The older `oracle` crate exposes `Connection::break_execution()`, which is attractive for SQLHighland because it supports user-triggered cancellation. However, it is based on Oracle's client/OCI stack and does not align as well with SQLHighland's goal of using a modern pure-Rust driver.

Oracle's official `rust-oracledb` project is actively maintained and is the better long-term foundation. The missing piece is the public cancellation API, not the general suitability of the driver.

Therefore the preferred strategy is:

```text
Oracle rust-oracledb
        |
        v
SQLHighland fork
        |
        +---- cancellation patch
        |
        +---- SQLHighland integration
        |
        v
Keep rebasing on Oracle upstream
        |
        v
Remove/reduce patch when Oracle ships native cancellation
```

---

## 3. Important Source-Code Finding

An earlier investigation appeared to show a `CancelHandle` and transport-level out-of-band break support in `oracledb`. Further tracing established that the prominent `CancelHandle` documentation came from an **older/different driver lineage**, not the current Oracle-maintained implementation being targeted for SQLHighland.

For the current Oracle driver, the relevant architecture is approximately:

```text
Connection
   |
   v
ConnImpl
   |
   v
Arc<Mutex<Client>>
   |
   v
Transport
   |
   +--> TcpStream
   |
   +--> optional TLS stream
```

Normal query execution eventually reaches a blocking socket read.

The critical problem is therefore not knowing how an Oracle interrupt works. The driver already has timeout/error recovery concepts. The difficult part is allowing another thread to trigger cancellation **without waiting on the same client mutex that the running query owns**.

---

## 4. Current Query Execution Flow

The relevant conceptual call path is:

```text
Connection::query()
      |
      v
ConnImpl / statement execution
      |
      v
Client round trip
      |
      +--> send request
      |
      v
receive response
      |
      v
Transport::receive_packet()
      |
      v
blocking socket read
```

While the query is waiting in the socket read, another cancellation operation cannot simply lock the same `Client` mutex and send a break.

That would result in a design like:

```text
Query thread:
    lock Client
       |
       +--> blocking read

Cancel thread:
    lock Client  <---- waits forever while query owns it
```

Therefore cancellation must have an independent control path.

---

## 5. Oracle Cancellation Model

Oracle cancellation is based on an **interrupt/break** sent to the active connection, followed by protocol recovery so the connection can be reused safely.

Conceptually:

```text
BREAK / INTERRUPT
       |
       v
Oracle stops current operation
       |
       v
driver receives cancellation response
       |
       v
RESET / recovery
       |
       v
connection becomes usable again
```

This is fundamentally different from killing the Rust worker thread.

### Important rule

**Do not cancel a query by forcibly terminating its Rust thread/task.**

The goal is to interrupt Oracle at the protocol level and allow the query execution path to unwind normally.

---

## 6. Proposed Driver Architecture

Introduce a cancellation/control object independent from the main `Client` mutex.

Conceptually:

```text
                         +------------------+
                         |      Client      |
                         |                  |
Query thread ---------->| Transport        |
                         |     |            |
                         |     +-- read     |
                         +------------------+
                                  ^
                                  |
                           CancelHandle
                                  ^
                                  |
                         SQLHighland GUI
```

Possible API:

```rust
pub struct CancelHandle {
    control: Arc<CancelControl>,
}
```

And:

```rust
impl CancelHandle {
    pub fn cancel(&self) -> Result<(), Error> {
        // signal cancellation through independent control path
    }
}
```

Potential connection API:

```rust
impl Connection {
    pub fn cancel_handle(&self) -> CancelHandle;
}
```

This is preferable to exposing socket implementation details to SQLHighland.

---

## 7. First Implementation Target: Unix + Plain TCP

The first milestone should intentionally be narrow:

- macOS
- Linux
- plain Oracle TCP connections

The initial design can use a separately accessible copy/reference to the underlying TCP socket so cancellation does not need to acquire the main client mutex.

Conceptually:

```text
Query thread
    |
    +--> original TcpStream
    |        |
    |        +--> blocking Oracle read
    |
    |
Cancel thread
    |
    +--> cancellation socket/control path
             |
             +--> Oracle BREAK / OOB interrupt
```

On Unix-like systems, a low-level socket operation can be used where appropriate to send Oracle's break signal independently of the query thread's normal client state.

The exact socket abstraction should be kept behind the transport/control layer rather than exposed to the public crate API.

---

## 8. Cancellation State Machine

The fork should explicitly model cancellation state rather than relying only on a boolean.

Suggested conceptual states:

```text
Idle
  |
  v
Running
  |
  +---- cancel() ----> Cancelling
                         |
                         v
                      Recovering
                         |
                         v
                      Cancelled
                         |
                         v
                        Idle
```

### Race cases to handle

#### A. Cancel while query is running

Expected result:

```text
Running
   |
   v
send BREAK
   |
   v
receive server response
   |
   v
RESET/recover
   |
   v
return cancellation error
```

#### B. Query finishes just before cancel()

The cancellation call should be safe and should not corrupt the next operation. A no-op result or a well-defined "nothing running" result is preferable.

#### C. Cancel called twice

The second call should be idempotent or return a well-defined already-cancelling/already-cancelled state.

#### D. Connection becomes unusable during recovery

The driver must report the connection as broken rather than silently returning it to a pool in an unsafe state.

---

## 9. Reuse Existing Interrupt/Reset Recovery

A major advantage of using Oracle's current driver as the base is that timeout/error handling already contains recovery concepts.

The new user-triggered cancellation should reuse those existing mechanisms instead of creating an independent reset implementation.

The desired relationship is:

```text
                    +------------------+
                    | Cancellation     |
                    | trigger          |
                    +---------+--------+
                              |
                              v
                     Oracle interrupt
                              |
                              v
                    existing recovery
                         /         \
                        /           \
                 reset path      fatal error
                     |               |
                     v               v
                connection       connection
                  usable           broken
```

This reduces the amount of protocol logic that must be maintained in the fork.

---

## 10. TCPS / TLS Is a Separate Problem

Plain TCP and TCPS should not be treated as identical during the first implementation.

For plain TCP, an out-of-band socket operation can potentially bypass the normal client mutex.

For TCPS, the Oracle connection is wrapped in TLS. Raw TCP payloads cannot simply be injected as if they were unencrypted Oracle protocol data.

Therefore:

```text
Plain TCP
    -> implement first

TCPS/TLS
    -> dedicated design/testing milestone
```

Oracle's other drivers demonstrate that different transport paths may be needed depending on platform and whether OOB is available.

### Initial SQLHighland capability model

```rust
enum CancellationCapability {
    Supported,
    Unsupported,
}
```

For the first release:

```text
Unix + plain TCP    -> Supported
TCPS/TLS            -> Unsupported initially
Windows             -> Unsupported initially
```

The UI should be able to detect the capability and present the appropriate behavior.

---

## 11. Windows Should Be a Separate Milestone

Windows socket semantics and out-of-band behavior differ from Unix-like systems.

Do not make the first cancellation implementation depend on a complicated cross-platform abstraction that is not yet validated.

Initial target:

```text
macOS   ✅
Linux   ✅
Windows ⏳
TCPS    ⏳
```

Once Unix behavior is stable, evaluate the Windows implementation independently.

---

## 12. SQLHighland Integration

SQLHighland should hide the driver-specific cancellation API behind its own database abstraction.

For example:

```rust
trait DatabaseConnection {
    async fn execute(&self, sql: &str) -> Result<QueryResult, DbError>;

    fn cancellation(&self) -> CancellationSupport;
}
```

Or, for a concrete cancellation token abstraction:

```rust
trait QueryCancellation: Send + Sync {
    fn cancel(&self) -> Result<(), DbError>;
}
```

Then the Oracle implementation can use the forked driver's `CancelHandle` without leaking Oracle-specific socket semantics into the rest of SQLHighland.

---

## 13. Recommended SQLHighland Query Lifecycle

```text
User opens SQL editor
        |
        v
Press Run
        |
        v
Create/query execution context
        |
        +--> CancelHandle
        |
        v
Execute query on worker
        |
        +-------------------------------+
        |                               |
        | query completes               | user clicks Cancel
        |                               |
        v                               v
Return result                    CancelHandle.cancel()
                                        |
                                        v
                              Oracle BREAK / interrupt
                                        |
                                        v
                                 driver recovery
                                        |
                                        v
                              return cancellation error
```

The UI should distinguish:

```text
Success
Error
Cancelled
```

instead of presenting cancellation as a generic database failure.

---

## 14. Initial Test Strategy

Cancellation must be tested as a protocol feature, not merely as a unit-test mock.

### Test database query

Use a deterministic long-running Oracle operation, such as:

```sql
BEGIN
    DBMS_SESSION.SLEEP(60);
END;
/
```

Or a deliberately expensive SQL query when appropriate.

### Core test

1. Open a connection.
2. Start the long-running query on a worker.
3. Wait until the query is definitely running.
4. Call `cancel()` from another thread.
5. Verify the query returns promptly with a cancellation-related error/result.
6. Run a second query on the same connection.
7. Verify the second query succeeds.

That final step is critical.

### Success criteria

```text
Cancel works
        AND
Query stops
        AND
No deadlock
        AND
No leaked worker
        AND
Connection remains reusable
```

---

## 15. Race and Stress Tests

Add tests for:

- Cancel immediately after query starts.
- Cancel near query completion.
- Cancel twice.
- Multiple sequential cancellations.
- Query timeout followed by cancellation.
- Cancellation followed by another statement.
- Cancellation while fetching rows from a long-running cursor.
- Connection close during cancellation.
- Connection returned to a pool after cancellation.
- Server/network failure during cancellation recovery.
- Repeated cancellation under load.

Also test that a cancellation on one connection cannot affect another connection.

---

## 16. Error Semantics

SQLHighland should not have to parse vendor-specific strings to decide that a query was cancelled.

The driver should ideally expose a recognizable cancellation condition, for example:

```rust
enum Error {
    // ...
    Cancelled,
}
```

or a dedicated error classification/utility:

```rust
error.is_cancelled()
```

The exact API should be chosen to fit the driver's existing error model and Oracle's conventions.

The SQLHighland layer can then map it cleanly:

```text
Oracle driver cancelled
        |
        v
SQLHighland QueryStatus::Cancelled
```

---

## 17. Fork Strategy

Keep the fork as small and upstream-friendly as possible.

### Repository model

```text
upstream
  |
  +--> oracle/rust-oracledb
  |
  v
origin
  |
  +--> SQLHighland fork
```

Maintain an `upstream` remote and periodically rebase/merge Oracle changes.

### Branches

Suggested:

```text
main
feature/query-cancellation
upstream-sync
```

Avoid mixing unrelated SQLHighland-specific changes into the driver fork.

---

## 18. Dependency Strategy During Development

Use the fork directly from Git initially:

```toml
[dependencies]
oracledb = { git = "https://github.com/<your-org>/rust-oracledb", rev = "<commit>" }
```

Once stable, publish a clearly named forked package only if SQLHighland needs reproducible releases independent of Git references.

Prefer pinning to a commit/tag for SQLHighland releases so a driver update cannot silently change cancellation behavior.

---

## 19. Upstream Contribution Strategy

The desired end state is for SQLHighland's cancellation work to become an Oracle upstream feature.

A good upstream contribution should be:

1. Small in scope.
2. Well isolated from SQLHighland.
3. Thoroughly tested against a real Oracle database.
4. Explicit about connection reuse after cancellation.
5. Clear about platform limitations.
6. Designed around a public API rather than exposing socket internals.

Potential upstream API:

```rust
impl Connection {
    pub fn cancel(&self) -> Result<(), Error>;
}
```

or:

```rust
impl Connection {
    pub fn cancel_handle(&self) -> CancelHandle;
}
```

The `CancelHandle` approach may be preferable if the connection can be shared with a GUI/worker architecture without taking the main client mutex.

---

## 20. Version Migration Plan When Oracle Adds Native Cancellation

When Oracle eventually ships an official public cancellation API:

```text
1. Update SQLHighland to Oracle upstream version
2. Compare semantics and error types
3. Replace forked CancelHandle with Oracle API
4. Remove fork-specific transport changes
5. Remove temporary capability workarounds
6. Run full cancellation/reuse stress suite
7. Retire the fork
```

The SQLHighland abstraction should remain unchanged so only the Oracle adapter needs modification.

---

## 21. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Socket cancellation races with normal query completion | High | Explicit cancellation state machine + race tests |
| Connection left in bad protocol state | High | Reuse existing interrupt/reset recovery and test connection reuse |
| Deadlock around `Client` mutex | High | Cancellation control path must bypass the main mutex |
| TCPS behaves differently | High | Keep TCPS out of first milestone; design separately |
| Windows behavior differs | Medium/High | Target Unix first and add Windows-specific implementation later |
| Fork diverges from Oracle upstream | Medium | Keep patch isolated and rebase frequently |
| Oracle changes transport internals | Medium | Minimize invasive changes and maintain integration tests |
| Cancellation API leaks driver internals into SQLHighland | Medium | Hide behind SQLHighland cancellation abstraction |
| Cancellation fails but connection is incorrectly pooled | High | Mark connection broken whenever recovery cannot prove safety |

---

## 22. Recommended Implementation Milestones

### Milestone 1 — Repository and architecture

- Fork Oracle `rust-oracledb`.
- Add `CancelControl` / `CancelHandle` abstraction.
- Keep API private initially.
- Add instrumentation/logging around query execution and cancellation state.

### Milestone 2 — Unix/plain TCP cancellation

- Add independent socket/control path.
- Implement Oracle break operation.
- Connect it to existing interrupt/reset recovery.
- Implement a public cancellation API in the fork.

### Milestone 3 — Real database integration tests

- Add `DBMS_SESSION.SLEEP` cancellation test.
- Verify cancellation latency.
- Verify connection reuse.
- Add race and stress cases.

### Milestone 4 — SQLHighland integration

- Add `QueryStatus::Cancelled`.
- Add Cancel button handling.
- Disable/enable UI correctly based on query state.
- Ensure cancellation does not block the UI thread.

### Milestone 5 — TCPS

- Investigate in-band cancellation and TLS-safe transport control.
- Add TCPS-specific capability detection.
- Expand integration tests.

### Milestone 6 — Windows

- Determine correct Windows socket/Oracle break behavior.
- Add platform-specific implementation and CI coverage.

### Milestone 7 — Upstream proposal

- Extract fork changes into a minimal upstream PR.
- Provide tests and documentation.
- Work with Oracle maintainers on API shape.

---

## 23. Definition of Done for the First Production Version

The first SQLHighland release should not be considered complete until all of the following are true:

```text
[ ] User can cancel a running Oracle query.
[ ] Cancellation can be initiated from a different thread than query execution.
[ ] No deadlock occurs.
[ ] The query actually stops on Oracle.
[ ] Cancellation returns promptly.
[ ] The connection is reusable after successful cancellation.
[ ] Broken recovery marks the connection unusable.
[ ] UI distinguishes Cancelled from Failed.
[ ] Capability is known for the current transport/platform.
[ ] Automated integration test covers real Oracle cancellation.
[ ] Race/stress tests are passing.
[ ] Fork remains close to Oracle upstream.
```

---

## 24. Final Recommendation

**Keep SQLHighland on Oracle's modern `rust-oracledb` codebase and fork it temporarily rather than switching to the older OCI `oracle` crate.**

The key technical observation is that the missing feature is primarily a **concurrency/control-path problem**, not a need to replace Oracle's protocol implementation altogether.

The most practical first target is:

```text
Oracle rust-oracledb
        |
        +--> CancelHandle
        |       |
        |       +--> independent cancellation control path
        |       |
        |       +--> Oracle BREAK
        |
        +--> existing query execution
                |
                +--> existing recovery/reset machinery

Target 1:
  macOS + Linux + plain TCP

Later:
  TCPS/TLS
  Windows

Eventually:
  upstream to Oracle
```

This gives SQLHighland a real Cancel button without prematurely locking the project into a legacy OCI dependency, while keeping the fork temporary and upstreamable.

---

## References

- Oracle Rust driver: https://github.com/oracle/rust-oracledb
- Oracle Rust driver crate: https://crates.io/crates/oracledb
- Rust driver API docs: https://docs.rs/oracledb/latest/oracledb/
- Legacy OCI-based Rust driver: https://crates.io/crates/oracle
- Legacy driver API docs: https://docs.rs/oracle/latest/oracle/
- Oracle Python driver repository: https://github.com/oracle/python-oracledb
- Oracle Node driver repository: https://github.com/oracle/node-oracledb

> **Note:** This plan reflects the driver state and source-code investigation performed on September 11, 2026. Before implementing, re-check Oracle's current `main` branch and release notes because the cancellation API or transport architecture may change between releases.
