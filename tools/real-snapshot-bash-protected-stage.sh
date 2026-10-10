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
[[ "$workspace" == "$checkout/.real-snapshot/bash-arm64" &&
  ! -e "$workspace" && ! -L "$workspace" && -n ${DEBZ_REAL_SNAPSHOT_KEYRING:-} ]]
python3 -B -I - "$checkout/tools" "$checkout" "$zig" "$debz" "$DEBZ_REAL_SNAPSHOT_KEYRING" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import protected, toolchain
for name in ("real-snapshot-bash-protected-stage.sh", "real_snapshot_less_stage.py",
             "real_snapshot_less_fixtures.py", "real-snapshot-reference-protected-stage.sh"):
    protected(Path(sys.argv[2]) / "tools" / name)
toolchain(Path(sys.argv[3]))
for argument in sys.argv[4:]:
    protected(Path(argument))
PY
bash "$checkout/tools/real-snapshot-reference-protected-ci.sh" \
  --check-keyring "$DEBZ_REAL_SNAPSHOT_KEYRING" >/dev/null
bash tools/real-snapshot-reference-protected-stage.sh --arm64-bash-source "$zig" "$debz" "$workspace"
source=$workspace/source
[[ ! -e "$source" && ! -L "$source" ]]
cp -a --reflink=auto --one-file-system -- "$workspace/template" "$source"
lock=$workspace/evidence/runtime.lock.json
cache=$workspace/snapshot/cache/packages-v2/objects
pinned=$workspace/dpkg/usr/bin/dpkg
python3 -B -I tools/real_snapshot_less_stage.py prepare-bash "$source" "$lock" "$cache" "$pinned" \
  "$workspace/evidence/bash.lock.json" "$workspace/evidence/dash.lock.json" "$workspace/evidence/util-linux.lock.json" \
  "$workspace/evidence/libc-bin.lock.json"
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$source" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      /var/lib/dpkg/producer-dpkg --root=/ --force-not-root --force-bad-path \
      --force-depends --no-triggers --unpack /var/lib/dpkg/producer-libtinfo6.deb /var/lib/dpkg/producer-bash.deb
  '
python3 -B -I tools/real_snapshot_less_stage.py seal-bash "$source"
[[ ! -e "$source/etc/ld.so.cache" && ! -L "$source/etc/ld.so.cache" ]]
{
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$source" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      /var/lib/dpkg/producer-ldconfig -i -X -C /etc/ld.so.cache -f /dev/null /usr/lib/aarch64-linux-gnu
  '
} >"$workspace/evidence/bash-cache-producer.stdout" 2>"$workspace/evidence/bash-cache-producer.stderr"
install -m 0644 "$source/etc/ld.so.cache" "$workspace/evidence/bash-source-ld.so.cache"
[[ $(dpkg-query --admindir="$source/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' bash) == '5.3-2ubuntu1 arm64 install ok unpacked' ]]
read -r bytes _ < <(du -sb "$source")
(( bytes <= 512 * 1024 * 1024 ))
zenv=(env "TMPDIR=$checkout/.zig-cache/data")
"${zenv[@]}" "$zig" build test-real-snapshot-arm64-bash-source-protected \
  "-Darm64-bash-source-root=$source" \
  "-Darm64-bash-source-proof=$workspace/evidence/bash-source-proof.txt" \
  -Doptimize=ReleaseSafe -j2 --summary all
grep -Fx "signed arm64 bash source guard executed without skips" "$workspace/evidence/bash-source-proof.txt"
for name in native dpkg-after bad-script bad-mode bad-tool bad-alias bad-prestate bad-cache; do
  destination=$workspace/$name
  [[ ! -e "$destination" && ! -L "$destination" ]]
  cp -a --reflink=auto --one-file-system -- "$source" "$destination"
done
python3 -B -I - "$checkout/tools" "$workspace" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from real_snapshot_less_fixtures import (
    chmod_regular, create_exclusive, overwrite_regular, read_regular, replace_symlink,
)
root = Path(sys.argv[2])
relative = "var/lib/dpkg/info/bash.postinst"
script = read_regular(root / "bad-script", relative, 1024)
overwrite_regular(root / "bad-script", relative, script + b"\nunreviewed callback\n")
chmod_regular(root / "bad-mode", relative, 0o644)
overwrite_regular(root / "bad-tool", "usr/bin/update-alternatives", b"foreign alternatives tool\n")
replace_symlink(root / "bad-alias", "usr/lib/aarch64-linux-gnu/libtinfo.so.6", "libtinfo.so.6.6", "foreign-tinfo")
create_exclusive(root / "bad-prestate", "usr/bin/update-menus", b"#!/bin/sh\nexit 0\n", 0o755)
cache = read_regular(root / "bad-cache", "etc/ld.so.cache", 1024 * 1024)
if b"/lib/aarch64-linux-gnu/libc.so.6" not in cache:
    raise ValueError("original ldconfig cache omitted the libc provider")
overwrite_regular(root / "bad-cache", "etc/ld.so.cache",
                  cache.replace(b"/lib/aarch64-linux-gnu/libc.so.6", b"/bad/aarch64-linux-gnu/libc.so.6"))
PY
{
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$workspace/dpkg-after" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      /var/lib/dpkg/producer-dpkg --root=/ --force-not-root --force-bad-path \
      --force-depends --no-triggers --configure bash
  '
} >"$workspace/evidence/bash-reference.stdout" 2>"$workspace/evidence/bash-reference.stderr"
[[ $(dpkg-query --admindir="$workspace/dpkg-after/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' bash) == '5.3-2ubuntu1 arm64 install ok installed' ]]
[[ $(dpkg-query --admindir="$source/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' bash) == '5.3-2ubuntu1 arm64 install ok unpacked' ]]
read -r bytes _ < <(du -sb "$workspace")
(( bytes <= 8 * 1024 * 1024 * 1024 ))
echo "signed arm64 bash cached source and nine replay roots staged; required native receipt remains"
