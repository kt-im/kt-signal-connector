# `runtime.doctor` — the read-only diagnostic face

Contract revisions 1.97 (§4.79), 1.101 (§4.82), 1.133 (§4.116), and 1.163
(§4.161) of `docs/implementation-plan.md` are the normative specification; this
document is the field-level quick reference for consumers (the desktop support
surface). The method answers the whole diagnostic payload in one Control-lane
call.

## Call

- Method: `runtime.doctor`, Control lane, non-mutating, params `{}` exactly —
  any other params answer `INVALID_REQUEST` (retryable=false). No new error
  codes, no new capability token: the method rides the handshake's method-list
  advertisement like every other `runtime.*` face.
- Available for the single kt-engine runtime; the engine faces degrade
  honestly where the engine does not carry a probe.
- Advertised through the standard method enumeration; a caller that does not
  know the method simply never calls it.

## Read-only discipline

The doctor never acts. Concretely:

- it never starts or stops an engine (`runtime.start`/`runtime.stop` remain
  the only lifecycle writers);
- it never removes, truncates, or breaks a lock — the occupancy probe takes
  the kernel lock and drops it immediately (`LOCK_EX|LOCK_NB`, then unlock);
- it writes nothing: the data-directory probe is `access(2)` + `statvfs(2)`,
  the lock-file read is capped at 32 bytes, and the engine is asked only
  through its existing read face with a 3-second budget (a wedged engine
  cannot hold a diagnostic anywhere near the ordinary 15 s request timeout);
- it makes no network request beyond the three declared service-plane probes
  below (read-only GETs to fixed compile-time URLs, 3-second budget each,
  through the launcher's SOCKS proxy environment when present; the third is
  the 1.163 system-trust leg).

The report is a snapshot: by the time the caller reads a field the process
may have moved on. Nothing in the answer is a lease or a reservation.

## Answer shape

```jsonc
{
  "connector": { "version", "apiVersion", "pid" },
  "groups": [ {
    "groupId",
    "engine":   { "state", "pid"?, "rssBytes"?, "resourcePressure",
                  "reachable", "unreachableReason"?,
                  "version"?:            { "present", "face"?|, "reason"? },
                  "protocolCapabilities"?: { "present", "face"?|, "reason"? },
                  "perfMetrics"?:        { "present", "face"?*, "reason"? },
                  "engineVersion"?,
                  "engineContractRevision"?,
                  "engineContractStatus",
                  "engineContractReason"? },
    "dataDir":  { "path", "exists", "writable", "freeBytes"?, "totalBytes"? },
    "lock":     { "present", "held", "pid"?, "holderAlive"?, "classification" },
    "credentials": { "state" }
  } ],
  "network":      { "watchdogRestartsTotal", "receiveDroppedTotal" },
  "recentErrors": { "window", "recordedTotal",
                    "families": [ { "source", "family", "retryable",
                                    "count", "lastAtUnixMs" } ] },
  "service":      { "proxyConfigured",
                    "chat":    { "classification", "status"?, "latencyMs"? },
                    "storage": { "classification", "status"?, "latencyMs"? },
                    "systemTrust"?: { "classification", "status"?, "latencyMs"? } }
}
```

`groups` lists every launch-plan group in launcher order. Keys marked `?` are
absent (not null) when the value does not apply. `face?|` is the engine's own
answer verbatim; `face?*` (the `perfMetrics` face, contract 1.133) is the
connector's allowlist projection — see the perf-metrics face below.
`systemTrust?` (contract 1.163) is present exactly when `proxyConfigured` is
true — see the service face below.

## Engine face

`engine` mirrors the supervisor's status view (`state` the live lifecycle
state, `pid`/`rssBytes` present only
for a live process). `reachable` is the doctor's own probe result: whether the
engine answered a read call during this diagnostic.

When `reachable` is false, `unreachableReason` carries a static, content-free
classification — exactly one of:

| `state`     | `unreachableReason`                                                                  |
| ----------- | ------------------------------------------------------------------------------------ |
| `stopped`   | `engine is stopped: not started since connector boot, or stopped by runtime.stop`    |
| `exited`    | `engine exited: the process ended on its own; start it with runtime.start`           |
| `faulted`   | `engine faulted: the process crashed or failed to start; the watchdog may restart it` |

The one transitional case has its own string, independent of `state`: the
engine was `running` but its live handle vanished mid-probe —
`the engine is transitioning: the live handle vanished mid-probe`.

Each method face (`version`, `protocolCapabilities`, `perfMetrics`) is mutually
exclusive by construction:

- `present: true` — the engine answered; `face` is the engine's own JSON answer
  passed through **verbatim**. The connector never re-derives, re-keys, or
  normalizes it (the kt-engine self-certification face keeps its upstream
  spelling, including `profiles_v2`). The `perfMetrics` face is the one
  deliberate exception — its `face` is the allowlist projection (next
  section).
- `present: false` — the engine did not answer; `reason` is a static string:
  the `unreachableReason` above when the engine is not running, or
  - `the engine stopped answering mid-probe` (timeout / not-running /
    exited / backpressure during the probe),
  - `the engine answered an error for the version method …`,
  - `the engine answered an error for the self-certification method …`
    (an engine without the kt-engine self-certification face; the full
    string carries the error class),
  - `the engine answered an error for the perf-metrics method …`
    (an engine predating the `engine.perfMetrics` face; the full string
    carries the error class).

Absent engine answers are the designed degradation — a diagnostic never fails
as a whole because one engine face could not answer.

## Engine contract face (O1)

Four additive fields fold the supervisor's startup handshake into the same
group face (they are the parsed counterpart of the two verbatim method faces
above, never a re-encoded answer):

| field | meaning |
| ----- | ------- |
| `engineVersion?` | the engine's own `version` string, verbatim. Present when the live probe answered it or a previous handshake recorded it. |
| `engineContractRevision?` | the contract revision the engine states (`engine.protocolCapabilities.contractRevision`, the `version` answer as fallback), verbatim. Absent for a legacy engine — absence stays absence. |
| `engineContractStatus` | `match` \| `legacy` \| `mismatch` \| `unverified` \| `unreachable`. The supervisor's verdict — the gate that decided whether the account pipeline may run. |
| `engineContractReason?` | for `mismatch`: `version_missing` \| `revision_out_of_range` \| `revision_malformed`. |

The precedence is deliberately split: the two values prefer this diagnostic's
live probe answers (freshest truth) and fall back to the recorded handshake
verdict when the engine cannot answer now; the status reads the verdict
itself, because that is what actually gated the runtime. A latched refusal
wins over `unreachable` so a killed engine still explains why.

`match` means the stated revision is inside the connector's closed supported
interval; `legacy` means the engine states no revision (a pre-handshake
build) and is served degraded; `mismatch` means the engine was refused and
never enters the account pipeline (`runtime.start` answers
`ENGINE_CONTRACT_MISMATCH`, `retryable: false`).

## Perf-metrics face

`perfMetrics` (contract 1.133, §4.116) carries the engine's own read-only
`engine.perfMetrics` snapshot — the S2a baseline layer the engine slice
landed (a closed 31-key vocabulary: 12 timing series, 19 counters). Unlike
the two faces above it is **not** a verbatim passthrough: the connector
projects the answer through its own pinned copy of the engine vocabulary
(`perfMetrics.face`), and everything the projection cannot vouch for drops
and counts:

- known `timings` entries (object-valued) and known `counters` entries
  (numeric) pass with the engine's own content verbatim;
- unknown top-level keys, unknown section entries, and malformed entries
  (`uptimeMs`/`unknownKeyDropped` not `u64`, a non-object series value, a
  non-numeric counter) drop; the face always carries `connectorDroppedKeys`
  — the number of dropped keys, `0` when the projection was lossless — so a
  consumer can tell a clean snapshot from a lossy one without diffing key
  sets;
- a future engine may grow its vocabulary: those keys stay dropped (and
  counted) until the connector's allowlist is widened by a contract batch.
  The connector never forwards an unbounded key space.

The probe rides the same reachability gate, the same 3-second read-only
diagnostic budget, and the same degradation family as the other method
faces: an engine predating `engine.perfMetrics` answers `present: false`
with the upstream-error-class reason; a
wedged engine answers `the engine stopped answering mid-probe`. Read-only
end to end: the engine's metric registry is process-internal state, the
probe sends `{}` and writes nothing.

## Credentials face

`credentials` (contract 1.101, §4.82) is the per-group credential state — the
doctor's one account-authenticated probe and the layer the unauthenticated
service probes below cannot see: `chat`'s 401 is the healthy edge answer for a
probe with no credentials, while a dead linked-device credential is only
observable through an authenticated call. One read-only `getUserStatus` ride
through the group's own live engine for the watchdog's ping-target account,
under the same 3-second diagnostic budget, folding into exactly one fixed
literal:

| `state`              | meaning |
| -------------------- | ------- |
| `healthy`            | the engine answered the registered face |
| `credentialsInvalid` | the engine answered the credential-death face — the same classification the `ACCOUNT_UNLINKED` chain rides; the account state converges exactly like any other request's |
| `indeterminate`      | the engine answered a different error — honestly unclassifiable at this boundary (the engine-side websocket-upgrade 401 gap, §4.82), never a guessed verdict |
| `unreachable`        | no live engine to probe through (the engine face carries the granular reason) |
| `noAccount`          | live engine, but the group has no account to probe |

The report carries only the literal: the probe target (an account number) rides
only into the engine call params and never enters the report, and no error text,
URL, or timing is carried. On the `credentialsInvalid` literal the desktop
should render the independent credential-invalid state (relink needed), not the
retryable network-error family.

## Lock face

The `.kt-signal-connector.lock` occupancy, in the contract's classification:

| `classification` | `present` | `held` | meaning |
| ---------------- | --------- | ------ | ------- |
| `none`     | false | false | no lock file |
| `held`     | true  | true  | a kernel lock is held — by construction the holder is alive (the kernel releases it on any exit); `holderAlive: true` is a kernel guarantee |
| `stale`    | true  | false | the recorded pid is dead — a crashed holder's remnant |
| `released` | true  | false | the recorded pid is alive or unknown — the designed post-release remnant; the lock file is deliberately never deleted, so this is the normal state after a clean connector exit |

- `pid` is the decimal pid the connector wrote into the lock file at acquire
  time; absent for files written by pre-face connectors or corrupted content.
- `holderAlive` is `true` whenever `held`; otherwise it is the recorded pid's
  liveness (`kill(pid, 0)`), absent when no pid is known.
- The probe is observational only: open read-only, `flock(LOCK_EX|LOCK_NB)`,
  unlock, close. A `held` verdict means someone else holds it; the doctor
  never waits for, breaks, or removes a lock.

## Data-directory face

`path` is the launcher-configured signal data directory (the authenticated
launcher already knows it; it never enters logs). `exists` is a stat;
`writable` is access-based (`access(2)` `W_OK`) — the directory's own
writability without writing anything. `freeBytes`/`totalBytes` come from
`statvfs(2)` and are absent when the directory does not exist. On Windows the
writability check falls back to the read-only attribute — best effort there
until a Windows test host exists; every other field behaves identically.

## Recent-error ring

`recentErrors` aggregates the process's classified failures:

- `window` is the ring's fixed capacity (64) — the newest 64 recorded events
  are the aggregation basis.
- `recordedTotal` counts every event ever recorded this process; when it
  exceeds `window`, the families below cover only the newest slice.
- `families` merges two sources: `source: "host"` (a host dispatch answered a
  structured error; `family` is the wire error code, `retryable` the code's
  retryability) and `source: "protocol"` (an engine protocol warning;
  `family` is the warning kind). Sorted by `count`, descending;
  `lastAtUnixMs` is the newest event's unix-millisecond timestamp.
- The ring is in-memory only: it resets with the process and holds no message
  content — codes, kinds, counts, timestamps.

## Service face

`service` is the doctor's only outbound network surface — read-only HTTPS GETs
through the launcher's SOCKS proxy environment, on a deliberate dual track
(contract 1.163):

- `proxyConfigured` is whether the process environment carries a well-formed
  `KT_SIGNAL_SOCKS_PROXY` (`host:port`, the variable the engine child inherits;
  an explicit `socks5(h)://` prefix is tolerated). Per-group proxy plans are
  deliberately not consulted: the probe reflects the process-wide launch
  environment, so a flag-only proxy reads as unconfigured. When false, both
  strict probes answer `not_configured`, `systemTrust` is absent (no probe
  ran — absence, never a literal, is how the wire says so), and no request is
  attempted at all.
- The **strict pair** `chat` (`GET
  https://chat.signal.org/v1/accounts/whoami`, unauthenticated — read the link
  healthy at the service edge's own 401) and `storage` (`GET
  https://storage.signal.org/` — any HTTP response is a healthy link) ride one
  client built fresh per diagnostic: HTTPS only, the vendored Signal
  production root CA as the **only** trust anchor (the kt-engine's
  tls_certs_only attitude — the probe validates exactly the TLS reality the
  engine's own traffic meets), the launcher proxy as a `socks5h://` route
  (remote DNS, matching the engine's `ALL_PROXY` mapping), 3-second connect
  and overall budgets, redirects off.
- The **system-trust leg** `systemTrust` (contract 1.163, §4.161) probes the
  same chat target through the same route on its own client — the platform
  trust store with **no** custom anchor: on macOS the Security.framework
  trust settings across the user, admin, and system domains (a user-installed
  CA included), the official desktop's own posture (Chromium + system store),
  and the same roots the connector's CDN attachment-download client rides.
  Present exactly when `proxyConfigured` is true; independent of the strict
  pair by construction (each side builds its own client and either verdict
  stands alone).

**The dual-track consumption contract** (the desktop's proxy self-check reads
this; the implementation batch lives on the desktop side): `chat`/`storage`
classifying `tls_failed` while `systemTrust` classifies `http` means the
pinned-anchor plane fails but the system-trust plane works end to end — the
*official-equivalent usable* verdict. The official desktop under the same
proxy stays silent (its Chromium trusts what the user's system trusts), so the
banner must not scream: treat that combination as passing (a non-blocking
notice at most). Only when `systemTrust` also fails to reach (`tls_failed`/
`timeout`/`socks_refused`) is the link genuinely broken and the blocking
warning honest. `systemTrust` absent (pre-1.163 connector or unconfigured
face) keeps the pre-1.163 reading of the strict legs.

Each probe's `classification` is exactly one fixed literal (the same
vocabulary on both tracks — no new literal was invented):

| `classification`  | meaning |
| ----------------- | ------- |
| `http`            | the service edge answered; the only classification carrying `status` (the HTTP status code) and `latencyMs` |
| `timeout`         | the 3-second connect or overall budget was exhausted |
| `socks_refused`   | the SOCKS-routed link was refused at or below the proxy hop (proxy down, proxy refused, upstream refused through the tunnel) |
| `tls_failed`      | the link reached the TLS handshake and failed — a trust mismatch (pinned CA rejecting, or the platform store empty/rejecting on the system leg), distinct from a dead route; also the fold for a system-trust client build failure (zero valid platform roots found) |
| `not_configured`  | no proxy environment — the probe never ran (strict legs only; `systemTrust` is absent instead) |

The mapping is a pure function over the transport error's own kind flags and a
source-chain marker walk; it is pinned by unit tests with no network. The red
line: the report carries only the fixed literals plus a status code and a
latency — never upstream error text, never request content, never a URL, never
a proxy endpoint.

## Network face

`watchdogRestartsTotal` and `receiveDroppedTotal` are the two existing
counters (`metrics::record_watchdog_restart`,
`metrics::record_receive_drop`) read out as-is — the network face adds no new
instrumentation, and the service-plane probes above are the doctor's only
outbound requests.
