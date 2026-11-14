#!/usr/bin/env bash
# Start single-use GitHub runners for queued Voalack CI jobs, one disposable microVM per job.
#
# Deterministic, bounded and on demand: run it after a push, or from the session's periodic
# check. It is not a service. For each queued job that needs the `voalack` label it:
#   1. creates a fresh smolvm VM and installs a checksum-verified runner;
#   2. mints a one-hour registration token on the host and passes it into the VM as a secret
#      environment variable for the single configuration command (never printed or stored);
#   3. registers an --ephemeral --disableupdate runner, which takes one job and exits;
#   4. deletes the runner registration if still present and the VM, and verifies both are gone.
#
# Admission: every run with a queued `voalack` job must be a push event whose head repository is
# exactly the launcher's repository. A queued `voalack` job from a pull request, a fork or a run
# whose event or head repository is missing refuses the whole poll before anything starts
# (audit 2026-11-08, finding 1). This vets the queue as polled; it does not bind the runner to a
# particular job, and a job queued after the poll is not vetted.
#
# Exit status: 0 idle or all jobs handled; 2 GitHub unavailable (poll failed; nothing started);
# 3 a launch step or the runner process failed (resources cleaned up and verified; a job may
# not have completed); 4 cleanup unresolved (resources
# may remain; recorded under $STATE/unresolved; no further launches until `--cleanup` succeeds);
# 5 an untrusted `voalack` job is queued (nothing started).
#
# Usage: launch.sh [--cleanup] [owner/repo]     (default steliosx/voalack)
# Env:   MAX_JOBS (default 5); STATE (default ~/.local/state/voalack-ci); SMOLVM, GH (commands)
set -uo pipefail
CLEANUP_ONLY=0
[ "${1:-}" = --cleanup ] && { CLEANUP_ONLY=1; shift; }
REPO="${1:-steliosx/voalack}"
MAX_JOBS="${MAX_JOBS:-5}"
STATE="${STATE:-$HOME/.local/state/voalack-ci}"
SMOLVM="${SMOLVM:-smolvm}"
GH="${GH:-gh}"
RUNNER_VERSION=2.337.0
RUNNER_SHA256=70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613
IMAGE=ubuntu:24.04
LABEL=voalack
LOG="$STATE/launcher.log"
UNRESOLVED="$STATE/unresolved"

mkdir -p "$UNRESOLVED" || exit 4
exec 9>"$STATE/launcher.lock"
flock -n 9 || { echo "another launcher is running"; exit 0; }
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }

# --- GitHub queue -------------------------------------------------------------------------
# Prints the number of queued jobs needing $LABEL. A run that is already in progress can still
# hold queued jobs (one runner at a time serves a multi-job workflow), so both queued and
# in-progress runs are inspected. Returns 1 if any query fails or a response is malformed (never
# reports idle on a failed or partial query), and 3 if a run holding a queued $LABEL job is not a
# push of this repository (see Admission above).
queued_jobs() {
  local runs="" found total=0 run n status id event head
  for status in queued in_progress; do
    found=$("$GH" api "repos/$REPO/actions/runs?status=$status&per_page=100" \
            --jq '.workflow_runs[] | [.id, (.event // "-"), (.head_repository.full_name // "-")] | @tsv') || return 1
    runs="$runs$found"$'\n'
  done
  runs=$(sed '/^$/d' <<<"$runs" | sort -u)
  while IFS=$'\t' read -r id event head; do
    [ -n "$id" ] || continue
    [[ "$id" =~ ^[0-9]+$ ]] || return 1
    n=$("$GH" api "repos/$REPO/actions/runs/$id/jobs?per_page=100" \
        --jq "[.jobs[] | select(.status==\"queued\" and (.labels | index(\"$LABEL\")))] | length") || return 1
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    [ "$n" -gt 0 ] || continue
    if [ "$event" != push ] || [ "$head" != "$REPO" ]; then
      log "untrusted $LABEL job: run $id event=${event:--} head=${head:--}" >&2
      return 3
    fi
    total=$((total + n))
  done <<<"$runs"
  echo "$total"
}

# --- Cleanup ------------------------------------------------------------------------------
# Every step is attempted even if an earlier one fails; each resource is verified gone.
# Returns 0 only if both the runner registration and the VM are verified absent.
runner_ids() {  # prints IDs of runners named $1 in repository $2; non-zero if the query fails
  "$GH" api "repos/$2/actions/runners?per_page=100" --jq ".runners[] | select(.name==\"$1\") | .id"
}
vm_present() {  # 0 present, 1 absent, 2 unknown
  local names
  names=$("$SMOLVM" machine ls -q) || return 2
  grep -qxF "$1" <<<"$names" && return 0 || return 1
}
cleanup() {  # cleanup VM RUNNER [REPO]; REPO defaults to the launcher's repository
  local vm="$1" name="$2" repo="${3:-$REPO}" ok=1 ids id
  if ids=$(runner_ids "$name" "$repo"); then
    for id in $ids; do "$GH" api -X DELETE "repos/$repo/actions/runners/$id" >/dev/null || log "runner $name: delete failed"; done
    if ids=$(runner_ids "$name" "$repo"); then
      [ -z "$ids" ] && log "runner $name: absent (verified)" || { log "runner $name: still registered"; ok=0; }
    else log "runner $name: verification query failed"; ok=0; fi
  else log "runner $name: lookup failed"; ok=0; fi
  "$SMOLVM" machine stop --name "$vm" >/dev/null 2>&1 || log "vm $vm: stop failed or not running"
  "$SMOLVM" machine delete --name "$vm" --force >/dev/null 2>&1 || log "vm $vm: delete failed"
  vm_present "$vm"; case $? in
    1) log "vm $vm: absent (verified)";;
    0) log "vm $vm: still present"; ok=0;;
    *) log "vm $vm: verification query failed"; ok=0;;
  esac
  if [ "$ok" = 1 ]; then rm -f "$UNRESOLVED/$vm"; return 0; fi
  printf 'vm=%s\nrunner=%s\nrepo=%s\nat=%s\n' "$vm" "$name" "$repo" "$(date -u +%FT%TZ)" > "$UNRESOLVED/$vm"
  log "cleanup UNRESOLVED for $vm (recorded; run --cleanup)"
  return 1
}

retry_unresolved() {  # 0 if nothing is left unresolved
  local f vm runner repo left=0
  for f in "$UNRESOLVED"/*; do
    [ -e "$f" ] || continue
    vm=$(sed -n 's/^vm=//p' "$f"); runner=$(sed -n 's/^runner=//p' "$f"); repo=$(sed -n 's/^repo=//p' "$f")
    # Use the repository recorded with the resource, never the current invocation's default.
    if [ -z "$vm" ] || [ -z "$runner" ] || [[ ! "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
      log "unresolved record $f is malformed; leaving it for manual review"; left=1; continue
    fi
    log "retrying cleanup of $vm (repository $repo)"
    cleanup "$vm" "$runner" "$repo" || left=1
  done
  return "$left"
}

# --- Main ---------------------------------------------------------------------------------
if ! retry_unresolved; then log "unresolved cleanup remains; not launching"; exit 4; fi
[ "$CLEANUP_ONLY" = 1 ] && { log "cleanup complete"; exit 0; }

VM=""; NAME=""; TOKEN=""
on_exit() {
  local rc=$?
  TOKEN=""; unset VO_REG_TOKEN 2>/dev/null || true
  if [ -n "$VM" ]; then cleanup "$VM" "$NAME" || rc=4; fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

fail() {  # a launch step failed: clean up now; exit 3 if verified clean, 4 otherwise
  log "launch step failed: $1"
  TOKEN=""
  if cleanup "$VM" "$NAME"; then VM=""; exit 3; else VM=""; exit 4; fi
}

for _ in $(seq "$MAX_JOBS"); do
  pending=$(queued_jobs); qrc=$?
  if [ "$qrc" = 3 ]; then log "untrusted $LABEL job queued; nothing started"; exit 5; fi
  if [ "$qrc" != 0 ]; then log "GitHub unavailable: queue query failed; nothing started"; exit 2; fi
  [ "$pending" -gt 0 ] || { log "no queued $LABEL jobs (query succeeded)"; exit 0; }
  VM="voalack-ci-$(date -u +%Y%m%d%H%M%S)-$RANDOM"; NAME="$VM"
  log "queued=$pending starting $VM"
  "$SMOLVM" machine create --net --net-backend virtio-net --cpus 2 --mem 2048 --image "$IMAGE" --name "$VM" >/dev/null || fail "create"
  "$SMOLVM" machine start --name "$VM" >/dev/null || fail "start"
  "$SMOLVM" machine exec -i --name "$VM" --timeout 10m -- sh -s >/dev/null <<GUEST || fail "provision"
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends curl ca-certificates tar git openssl libicu74 python3 python3-venv
useradd -m -s /bin/bash runner
mkdir -p /home/runner/r && cd /home/runner/r
curl -fsSL -o r.tgz https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-linux-x64-$RUNNER_VERSION.tar.gz
echo "$RUNNER_SHA256  r.tgz" | sha256sum -c -
tar xzf r.tgz && rm r.tgz
chown -R runner:runner /home/runner/r
GUEST
  TOKEN=$("$GH" api -X POST "repos/$REPO/actions/runners/registration-token" --jq .token) || fail "token"
  [ -n "$TOKEN" ] || fail "token empty"
  VO_REG_TOKEN="$TOKEN" "$SMOLVM" machine exec --name "$VM" --timeout 5m --secret-env RUNNER_TOKEN=VO_REG_TOKEN -- sh -c \
    "cd /home/runner/r && runuser -u runner -- ./config.sh --url https://github.com/$REPO --token \"\$RUNNER_TOKEN\" \
     --name $NAME --labels $LABEL --ephemeral --disableupdate --unattended --work _work >/dev/null" || fail "configure"
  TOKEN=""
  log "runner $NAME registered"
  "$SMOLVM" machine exec --name "$VM" --timeout 30m -- sh -c "cd /home/runner/r && runuser -u runner -- ./run.sh" >/dev/null 2>&1
  rc=$?
  log "runner $NAME exited rc=$rc"
  # A crashed or timed-out runner is an infrastructure failure, not a handled job.
  [ "$rc" = 0 ] || fail "runner process (rc=$rc)"
  if cleanup "$VM" "$NAME"; then VM=""; else VM=""; log "stopping: cleanup unresolved"; exit 4; fi
done
log "stopped after MAX_JOBS=$MAX_JOBS"
