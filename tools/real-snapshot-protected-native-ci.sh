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
python3 -I tools/real-snapshot-reference-tree-check.py ancestry "$tree"
python3 -I - "$checkout/tools" "$checkout" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import protected
checkout = Path(sys.argv[2])
for relative in ("tools/real-snapshot-protected-native-ci.sh",
                 "tools/real-snapshot-acceptance.sh",
                 "tools/real-snapshot-reference.sh",
                 "tools/capture-vendor-state.py",
                 "tools/real_snapshot_reference_paths.py",
                 "tools/real_snapshot_outcome.py",
                 "zig-out/bin/debz", "zig-out/bin/native-differential",
                 "zig-out/bin/real-snapshot-comparator"):
    protected(checkout / relative)
PY
work=$checkout/.real-snapshot/$architecture
evidence=$work/evidence
upload=$tree/native-upload

if [[ $operation != collect ]]; then
  python3 -I - "$checkout/tools" "$tree/native-inputs.args" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import protected
protected(Path(sys.argv[2]))
PY
  mapfile -t inputs <"$tree/native-inputs.args"
  [[ ${#inputs[@]} == 3 ]]
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
capture_status=0 differential_status=0 forbidden_exec_status=0 outcome_status=0 copy_status=0
if [[ -d "$work/root/var/lib/dpkg/info" ]]; then
  timeout --signal=TERM --kill-after=30s 5m python3 tools/capture-vendor-state.py \
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
python3 -I tools/real_snapshot_outcome.py "$evidence" "${NATIVE_STEP_OUTCOME:-unavailable}" \
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
du -sh "$work" >"$evidence/disk-usage-final.txt" || copy_status=$?
printf 'commit=%s\narchitecture=%s\ncapture_status=%s\ndifferential_status=%s\nexec_audit_status=%s\noutcome_status=%s\ncopy_status=%s\n' \
  "$commit" "$architecture" "$capture_status" "$differential_status" \
  "$forbidden_exec_status" "$outcome_status" "$copy_status" >"$evidence/collection-result.txt"

# Export only bounded regular evidence, never transfer ownership of the
# protected checkout, tools or live roots to the runner.
python3 -I - "$evidence" "$upload" <<'PY'
import hashlib
import os
from pathlib import Path
import shutil
import stat
import sys

source, target = map(Path, sys.argv[1:])
entries = []
total = 0
try:
    for root, directories, files in os.walk(source, followlinks=False):
        for name in directories + files:
            path = Path(root) / name
            meta = path.lstat()
            if stat.S_ISDIR(meta.st_mode):
                continue
            if not stat.S_ISREG(meta.st_mode) or meta.st_size > 128 * 1024 * 1024:
                raise ValueError(f"unsafe or oversized evidence member: {path}")
            total += meta.st_size
            if total > 512 * 1024 * 1024:
                raise ValueError("evidence exceeds 512 MiB")
            entries.append(path)
    for path in entries:
        destination = target / path.relative_to(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "rb", opener=lambda name, flags: os.open(name, flags | os.O_NOFOLLOW)) as src:
            with destination.open("xb") as dst:
                shutil.copyfileobj(src, dst)
    (target / "artifact-summary.txt").write_text(f"bytes_before_index={total}\n")
except (OSError, ValueError) as error:
    (target / "export-failure.txt").write_text(str(error) + "\n")
    raise
finally:
    lines = []
    for path in sorted(target.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(target)}")
    (target / "SHA256SUMS").write_text("\n".join(lines) + "\n")
PY
(( capture_status == 0 && differential_status == 0 && forbidden_exec_status == 0 && outcome_status == 0 && copy_status == 0 ))
