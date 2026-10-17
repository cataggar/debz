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
for name in ("real-snapshot-bash-protected-stage.sh", "real-snapshot-stage.zig",
             "real-snapshot-reference-protected-stage.sh"):
    protected(Path(sys.argv[2]) / "tools" / name)
protected(Path(sys.argv[2]) / "zig-out/bin/debz-reference-stage")
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
zig-out/bin/debz-reference-stage prepare-bash "$source" "$lock" "$cache" "$pinned" \
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
zig-out/bin/debz-reference-stage seal-bash "$source"
stage_ldconfig_cache() {
  local root=$1 prefix=$2
  [[ ! -e "$root/etc/ld.so.cache" && ! -L "$root/etc/ld.so.cache" ]]
  {
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      /var/lib/dpkg/producer-ldconfig -i -X -C /etc/ld.so.cache -f /dev/null /usr/lib/aarch64-linux-gnu
  '
  } >"$workspace/evidence/$prefix-cache-producer.stdout" 2>"$workspace/evidence/$prefix-cache-producer.stderr"
  install -m 0644 "$root/etc/ld.so.cache" "$workspace/evidence/$prefix-source-ld.so.cache"
}
stage_ldconfig_cache "$source" bash
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
"${zenv[@]}" "$zig" build test-real-snapshot-arm64-util-linux-source-protected \
  "-Darm64-util-linux-source-root=$source" \
  "-Darm64-util-linux-source-postinst=$workspace/evidence/util-linux-original-native.postinst" \
  "-Darm64-util-linux-source-proof=$workspace/evidence/util-linux-source-proof.txt" \
  -Doptimize=ReleaseSafe -j2 --summary all
grep -Fx "signed arm64 util-linux original archive source validated without callback admission or skips" "$workspace/evidence/util-linux-source-proof.txt"
timeout --signal=TERM --kill-after=5s 60s \
  /usr/bin/dpkg-deb --ctrl-tarfile "$source/var/lib/dpkg/producer-util-linux.deb" |
  /usr/bin/tar -xOf - ./postinst >"$workspace/evidence/util-linux-original-dpkg.postinst"
cmp "$workspace/evidence/util-linux-original-native.postinst" "$workspace/evidence/util-linux-original-dpkg.postinst"
for name in native dpkg-after bad-script bad-mode bad-tool bad-alias bad-prestate bad-cache; do
  destination=$workspace/$name
  [[ ! -e "$destination" && ! -L "$destination" ]]
  cp -a --reflink=auto --one-file-system -- "$source" "$destination"
done
zig-out/bin/debz-reference-stage bash-mutate-negatives "$workspace"
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
util_workspace=$workspace/util-linux
util_source=$util_workspace/source
install -d -o root -g root -m 0700 "$util_workspace"
[[ ! -e "$util_source" && ! -L "$util_source" ]]
cp -a --reflink=auto --one-file-system -- "$workspace/template" "$util_source"
zig-out/bin/debz-reference-stage prepare-util-linux "$util_source" "$lock" "$cache" "$pinned" \
  "$workspace/evidence/less.lock.json" "$workspace/evidence/dash.lock.json" "$workspace/evidence/util-linux.lock.json" \
  "$workspace/evidence/libc-bin.lock.json" "$workspace/evidence/init-system-helpers.lock.json" \
  "$workspace/evidence/perl-base.lock.json"
{
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$util_source" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    setpriv --bounding-set=-sys_admin --no-new-privs \
      /var/lib/dpkg/producer-dpkg --root=/ --force-not-root --force-bad-path \
      --force-depends --no-triggers --unpack \
      /var/lib/dpkg/producer-perl-base.deb \
      /var/lib/dpkg/producer-libtinfo6.deb \
      /var/lib/dpkg/producer-less.deb \
      /var/lib/dpkg/producer-util-linux.deb
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      /var/lib/dpkg/producer-dpkg --root=/ --force-not-root --force-bad-path \
      --force-depends --no-triggers --configure less
  '
} >"$workspace/evidence/util-linux-source-producer.stdout" 2>"$workspace/evidence/util-linux-source-producer.stderr"
zig-out/bin/debz-reference-stage seal-util-linux "$util_source"
stage_ldconfig_cache "$util_source" util-linux
[[ $(dpkg-query --admindir="$util_source/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' util-linux) == '2.41.3-3ubuntu2.2 arm64 install ok unpacked' ]]
[[ $(dpkg-query --admindir="$util_source/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' less) == '668-1build1 arm64 install ok installed' ]]
for util_name in native dpkg-after bad-script bad-mode bad-tool bad-alias bad-prestate bad-cache; do
  destination=$util_workspace/$util_name
  [[ ! -e "$destination" && ! -L "$destination" ]]
  cp -a --reflink=auto --one-file-system -- "$util_source" "$destination"
done
zig-out/bin/debz-reference-stage util-linux-mutate-negatives "$util_workspace"
{
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$util_workspace/dpkg-after" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      /var/lib/dpkg/producer-dpkg --root=/ --force-not-root --force-bad-path \
      --force-depends --no-triggers --configure util-linux
  '
} >"$workspace/evidence/util-linux-reference.stdout" 2>"$workspace/evidence/util-linux-reference.stderr"
[[ $(dpkg-query --admindir="$util_workspace/dpkg-after/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' util-linux) == '2.41.3-3ubuntu2.2 arm64 install ok installed' ]]
[[ $(dpkg-query --admindir="$util_source/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' util-linux) == '2.41.3-3ubuntu2.2 arm64 install ok unpacked' ]]
read -r bytes _ < <(du -sb "$workspace")
(( bytes <= 8 * 1024 * 1024 * 1024 ))
echo "signed arm64 bash cached source and nine replay roots staged; required native receipt remains"
