#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

# run-cargo-gates.sh — run the AGENTS.md cargo gates inside a throwaway
# process group and reap the whole group on timeout, gate failure, and even
# after a clean cargo exit, so no runner/cargo/test-binary/connector/fixture
# process can orphan into launchd/init and hang a host.
#
# Background: the hang investigation (read-only probe batch 758) found that
# gate timeouts killed cargo but not the test binaries cargo had spawned —
# two sampled orphans still had Parent Process: launchd [1]. P0 (40e2248)
# turned in-harness hangs into evidenced failures; this wrapper is P1 and
# removes the orphan class itself: everything the gate spawns (test binaries,
# the kt-signal-connector binary, the fake-engine.py fixture) inherits the
# wrapper's fresh process group and dies with it.
#
# Usage:
#   scripts/run-cargo-gates.sh                # all gates: fmt, clippy, test, build --release
#   scripts/run-cargo-gates.sh test           # one gate: fmt|clippy|test|build|all
#   GATE_TIMEOUT_SECS=900 scripts/run-cargo-gates.sh test
#
# Exit codes: the failing gate's own exit code, or 124 when the timeout fired.
#
# Platform note (setsid): macOS ships no util-linux setsid(1). The wrapper
# calls POSIX::setsid(3) through perl instead — perl ships with macOS and with
# ubuntu-latest CI alike. setsid makes the child a session leader, so its pid
# is its process-group id; `pgrep -g` plus explicit kills then cover the whole
# tree including grandchildren (cargo -> test binary -> connector -> fixture).
# On Linux this is exactly what setsid(1) does.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMEOUT_SECS="${GATE_TIMEOUT_SECS:-1800}"
MODE="${1:-all}"
# 剩余参数透传给 cargo（CI 传 `test --lib`，只跑 lib 单测：集成测试依赖的
# python fixture 在 runner 上起不来，见 issue #7）。原先只取 $1，--lib 静默
# 丢掉；run_gate 里虽然支持 "$@" 透传，但调用方也没传过去——两处一起修。
shift || true
EXTRA_ARGS=("$@")

cd "$ROOT"

die() { printf '[gate] ERROR: %s\n' "$*" >&2; exit 2; }

case "$MODE" in
  fmt)    GATES=(fmt) ;;
  clippy) GATES=(clippy) ;;
  test)   GATES=(test) ;;
  build)  GATES=(build) ;;
  all)    GATES=(fmt clippy test build) ;;
  *)      die "unknown gate '$MODE' (want: fmt|clippy|test|build|all)" ;;
esac

# Live (non-zombie) members of a process group, one pid per line. pgrep also
# matches zombies, which are already dead and only await reaping, so filter
# the ps stat column: both BSD ps (macOS) and procps (Linux) mark them Z.
group_pids() {
  local pgid="$1" pid stat
  pgrep -g "$pgid" '.' 2>/dev/null | while IFS= read -r pid; do
    stat="$(ps -o stat= -p "$pid" 2>/dev/null || true)"
    case "$stat" in
      Z*|"") ;;
      *) printf '%s\n' "$pid" ;;
    esac
  done
  return 0
}

# TERM with a short grace, then KILL. On a timed-out gate no cleanup is
# meaningful; a graceful-shutdown path that would hang gets KILLed anyway.
reap_group() {
  local pgid="$1" pids
  pids="$(group_pids "$pgid")"
  [[ -n "$pids" ]] || return 0
  printf '[gate] reaping process group %d: %s\n' "$pgid" "$(printf '%s ' $pids)" >&2
  # shellcheck disable=SC2086  # pgrep output: one bare pid per line
  kill -TERM $pids 2>/dev/null || true
  sleep 0.2
  pids="$(group_pids "$pgid")"
  if [[ -n "$pids" ]]; then
    # shellcheck disable=SC2086
    kill -KILL $pids 2>/dev/null || true
    sleep 0.2
    pids="$(group_pids "$pgid")"
    if [[ -n "$pids" ]]; then
      printf '[gate] WARNING: group %d still holds after KILL: %s\n' "$pgid" "$(printf '%s ' $pids)" >&2
    fi
  fi
}

run_gate() {
  local gate="$1"; shift
  local -a cargo_args=()
  case "$gate" in
    fmt)    cargo_args=(fmt --check) ;;
    clippy) cargo_args=(clippy --all-targets --all-features -- -D warnings) ;;
    # 额外参数透传（CI 在 Linux 上只跑 `test --lib`：集成测试依赖的 python
    # fixture 在 runner 上起不来，追踪 issue #7）。原先这里写死 `test`，
    # 调用方传的 --lib 被静默丢掉。
    test)   cargo_args=(test "$@") ;;
    build)  cargo_args=(build --release) ;;
  esac
  printf '[gate] >>> cargo %s\n' "${cargo_args[*]}"

  # Spawn cargo as the leader of a brand-new session (see header): its pid is
  # the process-group id reaped below. exec keeps that pid for cargo itself,
  # so bash's job pid doubles as the pgid with no pidfile.
  local pgid status waited=0
  set +e
  perl -MPOSIX=setsid -e '
    defined setsid() or do { print STDERR "setsid: $!\n"; exit 125 };
    exec { $ARGV[0] } @ARGV or do { print STDERR "exec $ARGV[0]: $!\n"; exit 127 };
  ' cargo "${cargo_args[@]}" &
  pgid=$!
  while kill -0 "$pgid" 2>/dev/null; do
    if (( waited >= TIMEOUT_SECS )); then
      status=124
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  if [[ -z "${status:-}" ]]; then
    wait "$pgid"
    status=$?
  fi
  # Reap unconditionally: on timeout it is the whole point, after a failure it
  # stops half-torn-down trees, and after success it is a no-op unless a test
  # leaked a process into the group — which is exactly what must not survive.
  (( status == 124 )) && printf '[gate] TIMEOUT after %ss — killing process group %d\n' "$TIMEOUT_SECS" "$pgid" >&2
  reap_group "$pgid"
  set -e

  if (( status == 124 )); then
    printf '[gate] FAILED (timeout): cargo %s\n' "${cargo_args[*]}" >&2
    return 124
  elif (( status != 0 )); then
    printf '[gate] FAILED (exit %d): cargo %s\n' "$status" "${cargo_args[*]}" >&2
    return "$status"
  fi
  printf '[gate] ok: cargo %s\n' "${cargo_args[*]}"
}

for gate in "${GATES[@]}"; do
  # bash 4.4+ 安全展开空数组；macOS 自带 3.2 用 ${arr[@]+...} 形式。
  if (( ${#EXTRA_ARGS[@]} )); then
    run_gate "$gate" "${EXTRA_ARGS[@]}"
  else
    run_gate "$gate"
  fi
done

printf '[gate] all gates passed (%s)\n' "$MODE"
