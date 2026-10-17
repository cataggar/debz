#!/usr/bin/env bash
# The full native/reference wrapper, not the separate small protected proof.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root
unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH ZIG_LIB_DIR

[[ $# -ge 4 && $(id -u) == 0 && $(id -g) == 0 ]] || {
  echo "usage (as root): $0 native|reference|collect TREE ARCHITECTURE COMMIT [URI SUITE]" >&2
  exit 2
}
operation=$1 tree=$2 architecture=$3 commit=$4
[[ $tree =~ ^/srv/debz-protected/native-ci-[0-9]+-[0-9]+-(amd64|arm64)$ &&
  ${BASH_REMATCH[1]} == "$architecture" && $commit =~ ^[0-9a-f]{40}$ ]]
checkout=$tree/checkout
[[ $(realpath -- "${BASH_SOURCE[0]}") == "$checkout/tools/real-snapshot-protected-native-ci.sh" ]]
cd "$checkout"
test "$(git rev-parse HEAD)" = "$commit"
"$checkout/zig-out/bin/debz-reference-paths" ancestry "$tree"
"$checkout/zig-out/bin/debz-reference-paths" protected \
  "$checkout/tools/real-snapshot-protected-native-ci.sh" \
  "$checkout/tools/real-snapshot-acceptance.sh" \
  "$checkout/tools/real-snapshot-reference.sh" \
  "$checkout/tools/real-snapshot-reference-paths.zig" \
  "$checkout/zig-out/bin/debz-reference-paths" \
  "$checkout/zig-out/bin/debz-vendor-snapshot-tools" \
  "$checkout/zig-out/bin/debz-native-outcome" \
  "$checkout/zig-out/bin/debz-native-phase-summary" \
  "$checkout/zig-out/bin/debz-exec-audit" \
  "$checkout/zig-out/bin/debz" \
  "$checkout/zig-out/bin/native-differential" \
  "$checkout/zig-out/bin/real-snapshot-comparator"
work=$checkout/.real-snapshot/$architecture
evidence=$work/evidence
upload=$tree/native-upload

if [[ $operation != collect ]]; then
  "$checkout/zig-out/bin/debz-reference-paths" protected "$tree/native-inputs.args"
  mapfile -t inputs <"$tree/native-inputs.args"
  [[ ${#inputs[@]} == 3 ]]
  "$checkout/zig-out/bin/debz-reference-paths" protected "$tree/native-optimize.txt"
  mapfile -t optimize <"$tree/native-optimize.txt"
  [[ ${#optimize[@]} == 1 && ( ${optimize[0]} == Debug || ${optimize[0]} == ReleaseSafe ) ]]
  export DEBZ_NATIVE_SNAPSHOT_OPTIMIZE=${optimize[0]}
  export DEBZ_ZIG=${inputs[0]} REFERENCE_DPKG=${inputs[1]} DEBZ_REAL_SNAPSHOT_KEYRING=${inputs[2]}
  export ZIG_GLOBAL_CACHE_DIR=$tree/zig-global ZIG_LOCAL_CACHE_DIR=$checkout/.zig-cache
fi

case "$operation" in
  native)
    [[ $# == 6 ]]
    export DEBZ_REAL_SNAPSHOT_TRACE=1
    exec bash "$checkout/tools/real-snapshot-acceptance.sh" "$checkout/zig-out/bin/debz" \
      "$5" "$6" "$architecture" "$work"
    ;;
  reference)
    [[ $# == 4 ]]
    exec bash tools/real-snapshot-reference.sh "$REFERENCE_DPKG" \
      "$evidence/ubuntu-minimal.lock.json" "$work/cache" "$architecture" "$work"
    ;;
  collect)
    [[ $# == 4 ]]
    ;;
  *) echo "unknown protected native operation: $operation" >&2; exit 2 ;;
esac

install -d -o root -g root -m 0700 "$evidence" "$upload"
capture_status=0 differential_status=0 forbidden_exec_status=0 outcome_status=0 copy_status=0 coordination_status=0
if [[ -d "$work/root/var/lib/dpkg/info" ]]; then
  timeout --signal=TERM --kill-after=30s 5m zig-out/bin/debz-vendor-snapshot-tools capture \
    --reference-root "$work/root" --architecture "$architecture" \
    --output "$evidence/vendor-state-inventory-v1.json" || capture_status=$?
else
  printf 'captured=false\nreason=no-candidate-dpkg-database\n' >"$evidence/vendor-state-capture-skipped.txt"
fi
timeout --signal=TERM --kill-after=30s 5m zig-out/bin/native-differential capture \
  --root "$work/root" --exclude dev/null \
  --output "$evidence/native.snapshot.json" || differential_status=$?
if [[ -f "$evidence/reference.snapshot.json" && -f "$evidence/native.snapshot.json" ]]; then
  zig-out/bin/real-snapshot-comparator compare "$evidence/reference.snapshot.json" \
    "$evidence/native.snapshot.json" "$evidence/comparison-summary-v1.json" || differential_status=$?
else
  differential_status=1
  printf 'compared=false\nreference_snapshot_present=%s\nnative_snapshot_present=%s\n' \
    "$([[ -f "$evidence/reference.snapshot.json" ]] && echo true || echo false)" \
    "$([[ -f "$evidence/native.snapshot.json" ]] && echo true || echo false)" \
    >"$evidence/comparison-unavailable.txt"
fi
PATH=/no-host-interpreters zig-out/bin/debz-native-outcome "$evidence" "${NATIVE_STEP_OUTCOME:-unavailable}" \
  >"$evidence/acceptance-outcome-v1.json" || outcome_status=$?

allowed_script_dpkg_exec=0 allowed_script_dpkg_divert_exec=0 allowed_script_dpkg_statoverride_exec=0
: >"$evidence/exec-reaudit.txt"
for trace in "$evidence"/*.execve; do
  [[ -f "$trace" && ! -L "$trace" ]] || continue
  audit_status=0
  bash tools/real-snapshot-acceptance.sh --audit-exec-trace \
    "$trace" "$work/root" "$architecture" "$checkout/zig-out/bin/debz" \
    >"$evidence/exec-reaudit.part" || audit_status=$?
  {
    printf 'trace=%s\naudit_status=%s\n' "${trace##*/}" "$audit_status"
    cat "$evidence/exec-reaudit.part"
  } >>"$evidence/exec-reaudit.txt"
  allowed=$(sed -n 's/^allowed_script_dpkg_exec=\([0-9][0-9]*\)$/\1/p' "$evidence/exec-reaudit.part")
  allowed_script_dpkg_exec=$((allowed_script_dpkg_exec + ${allowed:-0}))
  allowed=$(sed -n 's/^allowed_script_dpkg_divert_exec=\([0-9][0-9]*\)$/\1/p' "$evidence/exec-reaudit.part")
  allowed_script_dpkg_divert_exec=$((allowed_script_dpkg_divert_exec + ${allowed:-0}))
  allowed=$(sed -n 's/^allowed_script_dpkg_statoverride_exec=\([0-9][0-9]*\)$/\1/p' "$evidence/exec-reaudit.part")
  allowed_script_dpkg_statoverride_exec=$((allowed_script_dpkg_statoverride_exec + ${allowed:-0}))
  [[ $audit_status == 0 ]] || forbidden_exec_status=1
done
rm -f -- "$evidence/exec-reaudit.part"
if [[ $forbidden_exec_status != 0 ]]; then
  if ! grep -h '^forbidden_exec' "$evidence/exec-reaudit.txt" >"$evidence/forbidden-exec.txt"; then
    printf 'audit_failed_without_forbidden_exec_record=true\n' >"$evidence/forbidden-exec.txt"
  fi
fi
printf '%s exec re-audit: %s read-only dpkg, %s dpkg-divert, %s dpkg-statoverride; forbidden_status=%s\n' \
  "$architecture" "$allowed_script_dpkg_exec" "$allowed_script_dpkg_divert_exec" \
  "$allowed_script_dpkg_statoverride_exec" "$forbidden_exec_status" >"$evidence/exec-reaudit-summary.txt"
cat "$evidence/exec-reaudit-summary.txt"

copy_optional() {
  local source=$1 target=$2
  [[ -e "$source" && ! -L "$source" ]] || return 0
  cp -a -- "$source" "$target" || copy_status=$?
}
copy_optional "$work/state" "$evidence/state"
copy_optional "$work/root/var/lib/dpkg/status" "$evidence/status-final"
copy_optional "$work/root/var/lib/dpkg/diversions" "$evidence/diversions-final"
copy_optional "$work/root/var/lib/dpkg/statoverride" "$evidence/statoverride-final"
copy_optional "$tree/reference-dpkg/usr/bin/dpkg" "$evidence/reference-dpkg"
copy_optional "$tree/reference-dpkg/usr/bin/dpkg-deb" "$evidence/reference-dpkg-deb"
copy_optional "$tree/reference-dpkg/reference-receipt-v1.json" "$evidence/reference-receipt-v1.json"
copy_optional "$tree/evidence" "$evidence/staging"
copy_optional "$tree/native-inputs.args" "$evidence/native-inputs.args"
copy_optional "$tree/native-optimize.txt" "$evidence/native-optimize.txt"
"$checkout/zig-out/bin/debz-reference-paths" capture-coordination "$work/root" "$evidence" \
  >"$evidence/native-coordination-capture.log" 2>&1 || coordination_status=$?
du -sh "$work" >"$evidence/disk-usage-final.txt" || copy_status=$?
printf 'commit=%s\narchitecture=%s\ncapture_status=%s\ndifferential_status=%s\nexec_audit_status=%s\noutcome_status=%s\ncopy_status=%s\ncoordination_status=%s\n' \
  "$commit" "$architecture" "$capture_status" "$differential_status" \
  "$forbidden_exec_status" "$outcome_status" "$copy_status" "$coordination_status" >"$evidence/collection-result.txt"

# Export only bounded regular evidence, never transfer ownership of the
# protected checkout, tools or live roots to the runner.
"$checkout/zig-out/bin/debz-reference-paths" export-evidence "$evidence" "$upload"
(( capture_status == 0 && differential_status == 0 && forbidden_exec_status == 0 && outcome_status == 0 && copy_status == 0 && coordination_status == 0 ))
