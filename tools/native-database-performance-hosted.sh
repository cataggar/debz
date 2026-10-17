#!/usr/bin/env bash
# One matched pair on one disposable hosted runner; never a shared-host driver.
set -euo pipefail
umask 077

capture_body() {
  awk '
    /^fn captureDatabaseSnapshotInto\(/ { selected = 1; found++ }
    selected && /^\) !package_database.Snapshot \{/ { body = 1; next }
    body {
      if (first++ == 0 && $0 == "    _ = observer;") next
      print
      if ($0 == "}") { body = selected = 0 }
    }
    END { if (found != 1 || selected || body) exit 2 }
  '
}
mask_capture_body() {
  awk '
    /^fn captureDatabaseSnapshotInto\(/ { selected = 1; found++ }
    selected && /^\) !package_database.Snapshot \{/ { print; body = 1; next }
    body {
      if ($0 == "}") { print; body = selected = 0 }
      next
    }
    { print }
    END { if (found != 1 || selected || body) exit 2 }
  '
}
if [[ ${1:-} == --emit-control-source ]]; then
  [[ $# == 3 && -f $2 && ! -L $2 && -f $3 && ! -L $3 ]] || exit 2
  # Emit source only; the hosted driver independently binds the original body
  # to accepted Git bytes and proves all remaining source is identical.
  awk '
    FNR == NR {
      if (/^fn captureDatabaseSnapshotInto\(/) { original_selected = 1; found++ }
      if (original_selected && /^\) !package_database.Snapshot \{/) { original_body = 1; next }
      if (original_body) {
        original[++count] = $0
        if ($0 == "}") { original_body = original_selected = 0; original_complete++ }
      }
      next
    }
    /^fn captureDatabaseSnapshotInto\(/ { selected = 1; candidate_found++ }
    selected && /^\) !package_database.Snapshot \{/ {
      print
      print "    _ = observer;"
      for (i = 1; i <= count; i++) print original[i]
      body = 1
      next
    }
    body {
      if ($0 == "}") { body = selected = 0; candidate_complete++ }
      next
    }
    { print }
    END {
      if (found != 1 || original_complete != 1 || original_selected || original_body ||
          candidate_found != 1 || candidate_complete != 1 || count == 0 || selected || body) exit 2
    }
  ' "$2" "$3"
  exit "$?"
fi
validate_values() {
  [[ $1 == amd64 || $1 == arm64 ]] &&
    [[ $2 == Debug || $2 == ReleaseSafe ]] &&
    [[ $3 == capture || $3 == overhead ]] &&
    [[ $4 == AB || $4 == BA ]] &&
    [[ $5 =~ ^[1-9][0-9]?$ ]]
}
if [[ ${1:-} == --validate-values ]]; then
  [[ $# == 6 ]] || exit 2
  validate_values "$2" "$3" "$4" "$5" "$6"
  exit "$?"
fi
[[ $# == 12 && $(id -u) == 0 && $(id -g) == 0 &&
  ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
  ${GITHUB_RUN_ID:-} =~ ^[0-9]+$ && ${GITHUB_RUN_ATTEMPT:-} =~ ^[0-9]+$ ]] || {
  echo "requires a disposable GitHub-hosted root-owned orchestration checkout" >&2
  echo "usage: $0 ORCHESTRATOR ARCH MODE capture|overhead AB|BA SAMPLE CANDIDATE CONTROL CANDIDATE_BUNDLE CONTROL_BUNDLE URI SUITE" >&2
  exit 2
}
orchestrator=$1 architecture=$2 optimize=$3 comparison=$4 order=$5 sample=$6
candidate=$7 control=$8 candidate_bundle=$9 control_bundle=${10} uri=${11} suite=${12}
validate_values "$architecture" "$optimize" "$comparison" "$order" "$sample"
[[ $candidate =~ ^[0-9a-f]{40}$ && $control =~ ^[0-9a-f]{40}$ ]]
[[ "$orchestrator" == "/srv/debz-protected/native-ci-$GITHUB_RUN_ID-${GITHUB_RUN_ATTEMPT}0-$architecture" ]]
checkout=$orchestrator/checkout
[[ $(realpath -- "${BASH_SOURCE[0]}") == "$checkout/tools/native-database-performance-hosted.sh" ]]
export PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0
unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH ZIG_LIB_DIR
test "$(git -C "$checkout" rev-parse HEAD)" = "$candidate"
test -z "$(git -C "$checkout" status --porcelain)"
require_protected_path() {
  local current=$1
  [[ $current == /* ]] || exit 2
  while :; do
    [[ ! -L "$current" && -e "$current" && $(stat -c '%u:%g' "$current") == 0:0 ]] || exit 2
    local mode
    mode=$(stat -c '%a' "$current")
    (( (8#$mode & 0022) == 0 )) || exit 2
    [[ $current != / ]] || break
    current=$(dirname -- "$current")
  done
}
[[ -d "$checkout" && ! -L "$checkout" ]]
require_protected_path "$checkout"
require_protected_path "$candidate_bundle"
require_protected_path "$control_bundle"
bash "$checkout/tools/real-snapshot-acceptance.sh" --validate-values "$uri" "$suite" "$architecture"
for bundle in "$candidate_bundle" "$control_bundle"; do
  [[ $bundle == "$orchestrator/"* && -f $bundle && ! -L $bundle &&
    $(stat -c %h "$bundle") == 1 ]]
done
pair_git=$orchestrator/pair-$sample.git
[[ ! -e $pair_git && ! -L $pair_git ]]
git init --quiet --bare "$pair_git"
git --git-dir="$pair_git" bundle verify "$candidate_bundle"
git --git-dir="$pair_git" bundle verify "$control_bundle"
git --git-dir="$pair_git" fetch --quiet "$candidate_bundle" HEAD:refs/heads/candidate
git --git-dir="$pair_git" fetch --quiet "$control_bundle" HEAD:refs/heads/control
test "$(git --git-dir="$pair_git" rev-parse refs/heads/candidate)" = "$candidate"
test "$(git --git-dir="$pair_git" rev-parse refs/heads/control)" = "$control"
git --git-dir="$pair_git" fsck --full --no-dangling
if [[ $comparison == capture ]]; then
  # Restore only original capture traversal, never unrelated later authority
  # changes, common instrumentation or the surrounding state machine.
  accepted=06af4d875cf036abd113e6d0e5ef640be6956309
  [[ "$candidate" != "$control" ]]
  git --git-dir="$pair_git" merge-base --is-ancestor "$accepted" "$candidate"
  cmp <(git --git-dir="$pair_git" show "$control:src/native_unpack.zig" | capture_body) \
    <(git --git-dir="$pair_git" show "$accepted:src/native_unpack.zig" | capture_body)
  cmp <(git --git-dir="$pair_git" show "$control:src/native_unpack.zig" | mask_capture_body) \
    <(git --git-dir="$pair_git" show "$candidate:src/native_unpack.zig" | mask_capture_body)
  while IFS= read -r path; do
    [[ $path == src/native_unpack.zig || $path == security/native-only-production-policy.json ||
      $path == security/digest-inventory-v1.tsv ]]
  done < <(git --git-dir="$pair_git" diff --name-only "$control" "$candidate")
  cmp <(git --git-dir="$pair_git" show "$candidate:security/native-only-production-policy.json" |
    jq -S 'del(.reviewed_fingerprints["src/native_unpack.zig"])') \
    <(git --git-dir="$pair_git" show "$control:security/native-only-production-policy.json" |
    jq -S 'del(.reviewed_fingerprints["src/native_unpack.zig"])')
  cmp <(git --git-dir="$pair_git" show "$candidate:security/digest-inventory-v1.tsv" |
    grep -v $'^src/native_unpack\\.zig\t') \
    <(git --git-dir="$pair_git" show "$control:security/digest-inventory-v1.tsv" |
    grep -v $'^src/native_unpack\\.zig\t')
else
  [[ "$control" == "$candidate" ]]
fi

output=$orchestrator/pair-$sample-$comparison-$optimize
[[ ! -e $output && ! -L $output ]]
install -d -m 0700 "$output"
{
  printf 'schema=https://debz.dev/schema/native-database-performance-pair-v1\n'
  printf 'workflow_source_commit=%s\ncandidate=%s\ncontrol=%s\n' "$GITHUB_SHA" "$candidate" "$control"
  printf 'run_id=%s\nrun_attempt=%s\njob=%s\nrunner_name=%s\n' \
    "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$GITHUB_JOB" "$RUNNER_NAME"
  printf 'architecture=%s\noptimization=%s\ncomparison=%s\norder=%s\nsample=%s\n' \
    "$architecture" "$optimize" "$comparison" "$order" "$sample"
  printf 'workload_packages=177\ncache_policy=new-protected-cache-per-slot\n'
  sha256sum "$candidate_bundle" "$control_bundle"
  uname -a
  cat /proc/cpuinfo
  cat /proc/meminfo
  cat /proc/loadavg
} >"$output/pair-identity.txt"

run_slot() {
  local slot=$1 source=$candidate measured=1 status=0 reference_status=0 collect_status=0
  if [[ $slot == A && $comparison == capture ]]; then source=$control; fi
  if [[ $slot == A && $comparison == overhead ]]; then measured=0; fi
  local index=1 bundle=$candidate_bundle
  [[ $slot == A ]] || index=2
  [[ $source != "$control" || $comparison != capture ]] || bundle=$control_bundle
  # The numeric filesystem slot is distinct from the genuine run_attempt,
  # which is retained verbatim in invocation-identity.txt and pair-identity.
  local tree="/srv/debz-protected/native-ci-$GITHUB_RUN_ID-${GITHUB_RUN_ATTEMPT}${sample}${index}-$architecture"
  [[ ! -e $tree && ! -L $tree ]] || return 1
  install -d -m 0700 "$tree" || return 1
  git init --quiet --bare "$tree/bare.git" || return 1
  git --git-dir="$tree/bare.git" fetch --quiet "$bundle" HEAD:refs/heads/protected || return 1
  test "$(git --git-dir="$tree/bare.git" rev-parse refs/heads/protected)" = "$source" || return 1
  git --git-dir="$tree/bare.git" symbolic-ref HEAD refs/heads/protected || return 1
  git clone --quiet --no-hardlinks "file://$tree/bare.git" "$tree/checkout" || return 1
  test "$(git -C "$tree/checkout" rev-parse HEAD)" = "$source" || return 1
  printf 'tree=%s\nsource=%s\ntelemetry=%s\n' "$tree" "$source" "$measured" >"$output/slot-$slot.txt" || return 1
  DEBZ_NATIVE_SNAPSHOT_OPTIMIZE="$optimize" \
    bash "$tree/checkout/tools/real-snapshot-reference-protected-ci.sh" --stage-native \
    "$tree" "$architecture" "$source" >"$output/slot-$slot-staging.log" 2>&1 || status=$?
  if (( status == 0 )); then
    GITHUB_SHA="$source" DEBZ_NATIVE_PHASE_TELEMETRY="$measured" \
      DEBZ_NATIVE_PERFORMANCE_EXPECT_PACKAGES=177 \
      bash "$tree/checkout/tools/real-snapshot-protected-native-ci.sh" native \
      "$tree" "$architecture" "$source" "$uri" "$suite" \
      >"$output/slot-$slot-native.log" 2>&1 || status=$?
    if (( status == 0 )); then
      bash "$tree/checkout/tools/real-snapshot-protected-native-ci.sh" reference \
        "$tree" "$architecture" "$source" >"$output/slot-$slot-reference.log" 2>&1 || reference_status=$?
    else
      reference_status=1
    fi
    NATIVE_STEP_OUTCOME="$([[ $status == 0 ]] && echo success || echo failure)" \
      bash "$tree/checkout/tools/real-snapshot-protected-native-ci.sh" collect \
      "$tree" "$architecture" "$source" >"$output/slot-$slot-collect.log" 2>&1 || collect_status=$?
  fi
  printf 'native_status=%s\nreference_status=%s\ncollection_status=%s\n' \
    "$status" "$reference_status" "$collect_status" >>"$output/slot-$slot.txt"
  (( status == 0 && reference_status == 0 && collect_status == 0 ))
}

status=0
for slot in "${order:0:1}" "${order:1:1}"; do
  run_slot "$slot" || status=1
done
if (( status == 0 )); then
  a="/srv/debz-protected/native-ci-$GITHUB_RUN_ID-${GITHUB_RUN_ATTEMPT}${sample}1-$architecture/checkout"
  b="/srv/debz-protected/native-ci-$GITHUB_RUN_ID-${GITHUB_RUN_ATTEMPT}${sample}2-$architecture/checkout"
  ae=$a/.real-snapshot/$architecture/evidence
  be=$b/.real-snapshot/$architecture/evidence
  cmp "$ae/ubuntu-minimal.lock.json" "$be/ubuntu-minimal.lock.json" || status=1
  cmp "$ae/status-after-create" "$be/status-after-create" || status=1
  "$b/zig-out/bin/real-snapshot-comparator" compare "$ae/native.snapshot.json" \
    "$be/native.snapshot.json" "$output/cross-slot-root-comparison.json" || status=1
  for field in initial_database_generation_sha256 final_database_generation_sha256 \
    exact_lock_sha256 artifact_evidence_sha256 final_state_sha256 trigger_evidence_sha256 \
    progress_record_count recovered_phase_count; do
    cmp <(jq -S --arg field "$field" '.[$field]' "$ae/create-native-transaction-provenance-v2.json") \
      <(jq -S --arg field "$field" '.[$field]' "$be/create-native-transaction-provenance-v2.json") || status=1
  done
  if [[ $comparison == capture ]]; then
    for phase in capture import hash mutation fsync progress_serialization; do
      cmp <(jq --arg phase "$phase" '[.invocations[].counters[] | select(.phase == $phase) | .count] | add' \
        "$ae/create-native-phase-summary-v1.json") \
        <(jq --arg phase "$phase" '[.invocations[].counters[] | select(.phase == $phase) | .count] | add' \
        "$be/create-native-phase-summary-v1.json") || status=1
    done
  fi
fi
printf 'pair_checks_status=%s\nacceptance=requires-original-cohort-recovery-and-matched-series-review\n' \
  "$status" >"$output/pair-result.txt"
sync -f "$output"
echo "paired original evidence: $output"
echo "retain both named native-upload directories; always clean all named trees on the disposable runner"
exit "$status"
