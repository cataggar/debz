#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C PYTHONDONTWRITEBYTECODE=1
unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH ZIG_LIB_DIR
[[ $# == 3 && $(id -u) == 0 && $(id -g) == 0 && $(uname -m) == aarch64 ]] || {
  echo "usage (as root on arm64): $0 PROTECTED_ZIG PROTECTED_DEBZ NEW_WORKSPACE" >&2
  exit 2
}
checkout=$(pwd -P)
zig=$1 debz=$2 workspace=$3
[[ "$workspace" == "$checkout/.real-snapshot/less-arm64" &&
  ! -e "$workspace" && ! -L "$workspace" && -n ${DEBZ_REAL_SNAPSHOT_KEYRING:-} ]]
python3 -B -I - "$checkout/tools" "$checkout" "$zig" "$debz" "$DEBZ_REAL_SNAPSHOT_KEYRING" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import protected, toolchain
for name in ("real-snapshot-less-protected-stage.sh", "real-snapshot-less-reference.sh",
             "real_snapshot_less_stage.py", "real_snapshot_less_fixtures.py",
             "real-snapshot-reference-protected-stage.sh"):
    protected(Path(sys.argv[2]) / "tools" / name)
toolchain(Path(sys.argv[3]))
for argument in sys.argv[4:]:
    protected(Path(argument))
PY
bash "$checkout/tools/real-snapshot-reference-protected-ci.sh" \
  --check-keyring "$DEBZ_REAL_SNAPSHOT_KEYRING" >/dev/null
bash tools/real-snapshot-reference-protected-stage.sh --arm64-less-source "$zig" "$debz" "$workspace"
source=$workspace/source
[[ ! -e "$source" && ! -L "$source" ]]
cp -a --reflink=auto --one-file-system -- "$workspace/template" "$source"
lock=$workspace/evidence/runtime.lock.json
cache=$workspace/snapshot/cache/packages-v2/objects
pinned=$workspace/dpkg/usr/bin/dpkg
python3 -B -I tools/real_snapshot_less_stage.py prepare "$source" "$lock" "$cache" "$pinned" \
  "$workspace/evidence/less.lock.json" "$workspace/evidence/dash.lock.json" "$workspace/evidence/util-linux.lock.json"
# Obtain a genuine unpacked database/control state from pinned dpkg. Only the
# unchanged signed inert less preinst runs; no configure/trigger authority.
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$source" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      /var/lib/dpkg/producer-dpkg --root=/ --force-not-root --force-bad-path \
      --force-depends --no-triggers --unpack /var/lib/dpkg/producer-less.deb
  '
python3 -B -I tools/real_snapshot_less_stage.py seal "$source"
read -r bytes _ < <(du -sb "$source")
(( bytes <= 512 * 1024 * 1024 ))
less_lock=$workspace/evidence/less.lock.json
dash_lock=$workspace/evidence/dash.lock.json
digest=$(jq -er '.packages[] | select(.name == "less" and .architecture == "arm64") |
  .archive_identity.digests[] | select(.algorithm == "sha512") | .digest' "$less_lock")
timeout --signal=TERM --kill-after=30s 15m \
  bash tools/real-snapshot-less-reference.sh "$pinned" "$source" "$lock" "$cache/sha512-$digest" \
  "$workspace/script-after" "$workspace/dpkg-after" "$zig" "$less_lock" "$dash_lock" \
  >"$workspace/evidence/less-replay.txt" 2>"$workspace/evidence/less-replay.stderr"
read -r bytes _ < <(du -sb "$workspace")
(( bytes <= 8 * 1024 * 1024 * 1024 ))
echo "signed arm64 less source and fifteen replay roots staged; required receipt verification remains"
