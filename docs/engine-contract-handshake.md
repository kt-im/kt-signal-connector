# Engine contract handshake (O1)

- Status: closed on both sides. The connector gate lives in
  `src/engine_contract.rs`; the engine landed
  `engine.protocolCapabilities.contractRevision` and reports `1.285`
  (`kt-signal-engine`), so a deployed pair classifies as `match` — the
  `legacy` row below remains the compatibility path for pre-handshake engines
  only, not the expected state of the shipped bundle.
- Contract revision: 1.285 (§4.269 in the implementation plan).
- Scope: connector only. No engine, desktop, or release-service change rides
  this batch.

## 1. Why

The connector and the engine are one runtime bundle but two independently
released binaries. The connector pins the engine's JSON-RPC method names and
error anchors as fixed literals; nothing at runtime proved *which* contract
revision the engine implements. The release service already declares an
`engineContractRevision` interval per component
(`data/components/signal-runtime/catalog.json`), but the declaration was
advisory: two mismatched binaries would talk until something failed deeper in
the account pipeline.

O1 turns that declaration into a startup gate: ask the engine who it is and
which revision it implements, then either serve it, degrade it explicitly, or
refuse it with a structured, non-retryable fatal.

## 2. The handshake

Once per engine landing — boot `runtime.start`, watchdog recovery, and each
per-account pool slot wake — and before any account-shaped side effect
(contacts resync, history import, unknown-outcome reconcile, configuration
gate sync, offline-queue drain):

1. `version` (read-only, empty params, **5 s budget**) — the engine's own
   identity `{name, version}`.
2. `engine.protocolCapabilities` (read-only, empty params, **5 s budget**) —
   the self-certification face; an engine that carries it may state
   `contractRevision`.

The handshake runs **unconditionally**. There is no environment switch that
skips it: a shipping env bypass is the one deployment that would serve an
unverified engine forever, which is exactly the drift the gate exists to catch.
Debugging and tests drive the handshake rows through the fake engine's own
fixture parameters (`KT_FAKE_ENGINE_CONTRACT_REVISION`,
`KT_FAKE_ENGINE_NO_CAPABILITIES`, `KT_FAKE_ENGINE_VERSION_ERROR`,
`KT_FAKE_ENGINE_VERSION_DELAY_MS` in `tests/fixtures/fake-engine.py`), never
through a production-facing variable.

The revision is a revision of the shared connector contract numbering. The
connector's half of the release declaration is pinned in code:

```text
ENGINE_CONTRACT_MIN_REVISION = "1.200"
ENGINE_CONTRACT_MAX_REVISION = "1.285"
SUPPORTED_ENGINE_CONTRACT_RANGE = "1.200-1.285"
```

Closed interval, `major.minor[.patch]` numeric comparison. Malformed
revisions are refused (never compared lexicographically).

## 3. Decision table

| Observation | Verdict | Runtime | `runtime.start` |
| --- | --- | --- | --- |
| `version` states identity, revision in range | `match` | served | ok |
| `version` states identity, no revision anywhere | `legacy` | served (degraded) | ok |
| `version` answers an error / no usable identity | `mismatch` (`version_missing`) | killed, latched | `ENGINE_CONTRACT_MISMATCH`, `retryable:false` |
| revision outside the interval | `mismatch` (`revision_out_of_range`) | killed, latched | same |
| revision not `major.minor[.patch]` | `mismatch` (`revision_malformed`) | killed, latched | same |
| `version` times out / engine exited / invalid protocol output | retryable startup failure | killed, not latched | `RUNTIME_START_FAILED`, `retryable:true` |
| `engine.protocolCapabilities` answers the upstream error class | `legacy` | served | ok |
| `engine.protocolCapabilities` transport failure | retryable startup failure | killed, not latched | same |

Why `legacy` and not a fatal: the self-certification face landed 2026-10-10
and the engine now states `contractRevision` (`1.285`), so the row is no
longer the expected state of the shipped bundle — it is the compatibility
path for an engine that predates the face (an older runtime bundle left on
disk). Failing closed on a missing revision would brick those engines with no
repair path. `legacy` is the compatibility ledger's degradation: the identity
is known, the revision is unknown, and the doctor says so.

A **mismatch** has no such degradation: an engine that states a revision
outside `1.200-1.285`, states something unparsable, or answers no identity is
always the non-retryable fatal. Nothing about the launch (flags, environment,
doctor state) softens it.

## 4. The fatal

The supervisor writes one byte-stable line to stderr at the moment the fault
is latched — the same launcher channel the store's fatal classes use:

```text
KT_FATAL code=ENGINE_CONTRACT_MISMATCH retryable=false engine=<v> supported=<range>
```

`engine=unknown` exactly when the engine failed to state its identity (never a
fabricated version). The host wire answer carries the same facts structurally:

```json
{"code":"ENGINE_CONTRACT_MISMATCH","message":"...","retryable":false,
 "data":{"retryable":false,"engine":"<v>","supported":"1.200-1.285",
         "reason":"revision_out_of_range"}}
```

## 5. Retry and latch

- **Retryable**: the engine did not answer inside the budget (timeout, exit,
  queue backpressure, invalid protocol output). The supervisor kills the
  child and returns `EngineError::StartFailed`; `runtime.start` maps it to
  `RUNTIME_START_FAILED` (`retryable:true`) and the watchdog may retry with
  its ordinary backoff.
- **Not retryable**: a mismatch latches on the supervisor for the process
  lifetime. `start`, `restart_engine`, and `watchdog_request_restart` all
  short-circuit to `EngineError::ContractMismatch` without spawning; the
  watchdog clears its deferred-restart backstop instead of re-arming it. The
  same binary answers the same revision on restart, so retrying can only burn
  the launcher's restart budget.
- A refused engine is force-killed before it ever lands in the engine slot, so
  no account-shaped pass can run against it; in legacy mode the other groups
  are stopped and the runtime is marked not running, and in full-pool mode
  all slots are stopped, because one engine binary backs every slot.

## 6. Surfaces

- `runtime.doctor` `groups[].engine`: `engineVersion`,
  `engineContractRevision`, `engineContractStatus`,
  `engineContractReason` (see `docs/doctor-contract.md`).
- Metrics: the periodic snapshot line carries `engine_version`,
  `engine_name`, `engine_contract_revision`, `engine_contract_status` and
  four counters (`engine_contract_checks_total`,
  `engine_contract_mismatches_total`,
  `engine_contract_probe_failures_total`, `engine_contract_legacy_total`);
  a per-slot `engine contract metrics` line rides beside the RSS sample.

## 7. Tests

- `src/engine_contract.rs` unit suite: the whole decision table, both closed
  endpoints, malformed revisions, the byte-exact fatal line, the structured
  `data` shape, and state projections.
- `src/metrics.rs`: the metrics snapshot projection for match / legacy /
  mismatch.
- `tests/engine_contract.rs` (end to end over the real socket + fake engine):
  matching start + doctor visibility, mismatch fatal + non-self-healing retry
  + stderr line + killed engine, version-probe timeout retryable with no
  fatal, and the legacy (no capabilities) degradation.
- The removed bypass stays removed: with `KT_DISABLE_CONTRACT_PROBE` set, a
  matching engine is still probed (the verdict reaches the doctor) and an
  out-of-range engine is still the non-retryable fatal
  (`the_removed_probe_bypass_env_cannot_skip_the_handshake`). No shipping
  launch path reads that variable any more, so an operator who sets it gets
  the real gate, not a silently unverified engine.

## 8. Engine-side status

Closed. The engine states `contractRevision` on
`engine.protocolCapabilities` and reports `1.285` — the same number as the
connector's `ENGINE_CONTRACT_MAX_REVISION` and the release service's
`engineContractRevision` declaration (`min == max`), so a runtime bundle
built from both heads classifies as `match` and the probe records
`engineVersion` + `engineContractRevision` on the doctor/metrics faces.

The engine may carry the revision on the `version` answer as well; the
connector accepts either face and prefers the capabilities one.

Future engine batches only have to keep two things aligned, both on the engine
side:

- the stated `contractRevision` stays inside the connector's pinned interval,
  or the connector's interval moves in the same release;
- the release declaration keeps `engineContractRevision.min == max` equal to
  that revision.

A pairing outside the interval classifies as `mismatch` and is refused at
start — refused, never degraded: there is no supported "talk anyway" mode.
