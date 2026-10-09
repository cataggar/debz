#!/usr/bin/env bash
# Fresh signed source and replay roots, separate from the small protected proof.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C
unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH ZIG_LIB_DIR

[[ $# == 4 && $(id -u) == 0 && $(id -g) == 0 && $(uname -m) == x86_64 ]] || {
  echo "usage (as root on amd64): $0 PROTECTED_ZIG PROTECTED_DEBZ PINNED_DPKG NEW_WORKSPACE" >&2
  exit 2
}
checkout=$(pwd -P)
zig=$1 debz=$2 pinned=$3 workspace=$4
[[ "$workspace" == "$checkout/.real-snapshot/python3-amd64" &&
  ! -e "$workspace" && ! -L "$workspace" ]]
[[ -n ${DEBZ_REAL_SNAPSHOT_KEYRING:-} ]]
python3 -B -I - "$checkout/tools" "$checkout" "$zig" "$debz" "$pinned" \
  "$DEBZ_REAL_SNAPSHOT_KEYRING" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import protected, toolchain
checkout = Path(sys.argv[2])
for relative in ("tools/real-snapshot-python3-protected-stage.sh",
                 "tools/real-snapshot-python3-reference.sh",
                 "tools/real-snapshot-signed-proc-bindings.sh",
                 "tools/real-snapshot-signed-proc-prestates.sh",
                 "tools/real-snapshot-reference-order.py",
                 "tools/real_snapshot_python_fixtures.py",
                 "tools/real_snapshot_less_fixtures.py",
                 "tools/real_snapshot_reference_paths.py"):
    protected(checkout / relative)
protected(checkout / ".real-snapshot", directory=True)
toolchain(Path(sys.argv[3]))
for argument in sys.argv[4:]:
    protected(Path(argument))
PY
bash "$checkout/tools/real-snapshot-reference-protected-ci.sh" \
  --check-keyring "$DEBZ_REAL_SNAPSHOT_KEYRING" >/dev/null
export DEBZ_ZIG=$zig PYTHONDONTWRITEBYTECODE=1
fixture() {
  python3 -B -I - "$checkout/tools" "$@" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from real_snapshot_python_fixtures import dispatch
dispatch(sys.argv[2:])
PY
}

# Reuse the authenticated full closure and its existing pinned-dpkg scheduler;
# capture before Python configure, without changing configure semantics.
bash tools/real-snapshot-signed-proc-bindings.sh "$debz" "$workspace"
bash tools/real-snapshot-signed-proc-prestates.sh --python3 "$pinned" "$workspace"
source=$workspace/prestates/python3
evidence=$workspace/evidence
fixture directory "$workspace" evidence
read -r bytes _ < <(du -sb "$source")
(( bytes <= 512 * 1024 * 1024 ))

copy_root() {
  [[ ! -e "$2" && ! -L "$2" ]]
  cp -a --reflink=auto --one-file-system -- "$1" "$2"
}
before=$workspace/empty-0600
before_0644=$workspace/empty-0644
copy_root "$source" "$before"
# This is a new disposable fixture, not a native-root repair. Never follow
# the captured root's null/proc aliases while preparing its empty sink.
fixture empty "$before"
copy_root "$before" "$before_0644"
fixture mode "$before_0644" 0644
lock=$workspace/snapshot/evidence/ubuntu-minimal.lock.json
archive_digest=$(jq -er '.packages[] | select(.name == "python3" and .architecture == "amd64") |
  .archive_identity.digests[] | select(.algorithm == "sha512") | .digest' "$lock")
archive=$workspace/snapshot/cache/packages-v2/objects/sha512-$archive_digest
after=$workspace/after-0600
after_0644=$workspace/after-0644
for mode in 0600 0644; do
  input=$before output=$after
  [[ $mode == 0600 ]] || { input=$before_0644; output=$after_0644; }
  fixture capture "$workspace" "evidence/replay-$mode.txt" "evidence/replay-$mode.stderr" \
    timeout --signal=TERM --kill-after=30s 10m \
    bash tools/real-snapshot-python3-reference.sh "$pinned" "$input" "$lock" "$archive" \
    "$output" "$workspace/dpkg-$mode"
done
for name in html link shadow null null-0640 root script proc; do
  copy_root "$before" "$workspace/bad-$name"
done
fixture basic "$workspace/bad-html" "$workspace/bad-link" "$workspace/bad-shadow" \
  "$workspace/bad-null" "$workspace/bad-null-0640" "$workspace/bad-root" \
  "$workspace/bad-script" "$workspace/bad-proc"

printf '%s\n' \
  "-Dpython3-reference-root=$before" \
  "-Dpython3-reference-after=$after" \
  "-Dpython3-reference-root-0644=$before_0644" \
  "-Dpython3-reference-after-0644=$after_0644" \
  "-Dpython3-reference-root-py3compile=$after-py3compile-before" \
  "-Dpython3-reference-after-py3compile=$after-py3compile-after" \
  "-Dpython3-reference-bad-html=$workspace/bad-html" \
  "-Dpython3-reference-bad-link=$workspace/bad-link" \
  "-Dpython3-reference-bad-shadow=$workspace/bad-shadow" \
  "-Dpython3-reference-bad-null=$workspace/bad-null" \
  "-Dpython3-reference-bad-null-0640=$workspace/bad-null-0640" \
  "-Dpython3-reference-bad-root=$workspace/bad-root" \
  "-Dpython3-reference-bad-script=$workspace/bad-script" \
  "-Dpython3-reference-bad-proc=$workspace/bad-proc" \
  "-Dpython3-reference-bad-py3compile-hash=$after-py3compile-bad-hash" \
  "-Dpython3-reference-bad-py3compile-mode=$after-py3compile-bad-mode" \
  "-Dpython3-reference-bad-minimal-postinst=$after-py3compile-bad-postinst" \
  "-Dpython3-reference-bad-minimal-compiler=$after-py3compile-bad-compiler" \
  "-Dpython3-reference-inputs-proof=$evidence/inputs-proof.txt" \
  "-Dpython3-reference-alternatives-proof=$evidence/alternatives-proof.txt" \
  | python3 -B -I -c '
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import protected
from real_snapshot_less_fixtures import create_exclusive
root = Path(sys.argv[2])
protected(root, directory=True)
content = sys.stdin.buffer.read(16385)
if len(content) > 16384:
    raise ValueError("Python arguments exceed bound")
create_exclusive(root, "evidence/python3-reference.args", content, 0o600)
' "$checkout/tools" "$workspace"
read -r bytes _ < <(du -sb "$workspace")
(( bytes <= 16 * 1024 * 1024 * 1024 ))
echo "Python source and all 18 root coordinates staged; Zig verification has not executed"
