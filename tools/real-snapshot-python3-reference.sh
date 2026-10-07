#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

[[ $# == 6 && $(id -u) == 0 ]] || {
  echo "usage (as root): $0 PINNED_DPKG PROTECTED_SOURCE_ROOT SIGNED_LOCK SIGNED_ARCHIVE NEW_SCRIPT_COPY NEW_DPKG_COPY" >&2
  exit 2
}

require_protected_path() {
  local path=$1 current=/ remainder=${1#/} component metadata owner mode
  [[ "$path" == /* ]] || return 2
  while :; do
    [[ -d "$current" && ! -L "$current" ]] || return 2
    metadata=$(stat -c '%u:%a' -- "$current")
    owner=${metadata%%:*}
    mode=${metadata#*:}
    [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] &&
      (( (8#$mode & 022) == 0 )) || return 2
    [[ -n "$remainder" ]] || break
    component=${remainder%%/*}
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 2
    current="${current%/}/$component"
    if [[ "$remainder" == "$component" ]]; then
      remainder=
    else
      remainder=${remainder#*/}
    fi
  done
}

require_protected_file() {
  require_protected_path "$(dirname -- "$1")"
  [[ -f "$1" && ! -L "$1" ]] || return 2
  local metadata owner mode
  metadata=$(stat -c '%u:%a' -- "$1")
  owner=${metadata%%:*}
  mode=${metadata#*:}
  [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] &&
    (( (8#$mode & 022) == 0 ))
}

checkout=$(pwd -P)
[[ $(realpath -- "${BASH_SOURCE[0]}") == "$checkout/tools/real-snapshot-python3-reference.sh" ]]
require_protected_file "$checkout/tools/real-snapshot-python3-reference.sh"
require_protected_file "$checkout/tools/prepare-native-dpkg.py"
require_protected_file "$checkout/src/fixtures/ubuntu-resolute-python3.preinst"
require_protected_path "$checkout/.real-snapshot"
[[ $(stat -c '%u:%g:%a' "$checkout/.real-snapshot") == 0:0:700 ]]

pinned=$(realpath -- "$1")
source_root=$(realpath -- "$2")
lock=$(realpath -- "$3")
archive=$(realpath -- "$4")
script_root=$(realpath -m -- "$5")
dpkg_root=$(realpath -m -- "$6")
py3compile_before="${script_root}-py3compile-before"
py3compile_after="${script_root}-py3compile-after"
py3compile_dpkg="${dpkg_root}-py3compile"
py3compile_bad_hash="${script_root}-py3compile-bad-hash"
py3compile_bad_mode="${script_root}-py3compile-bad-mode"
py3compile_bad_postinst="${script_root}-py3compile-bad-postinst"
py3compile_bad_compiler="${script_root}-py3compile-bad-compiler"
for file in "$pinned" "$lock" "$archive"; do require_protected_file "$file"; done
require_protected_path "$source_root"
[[ $(stat -c '%u:%g:%a' "$source_root") == 0:0:700 ]]
for path in "$pinned" "$source_root" "$lock" "$archive" "$script_root" "$dpkg_root" \
  "$py3compile_before" "$py3compile_after" "$py3compile_dpkg" \
  "$py3compile_bad_hash" "$py3compile_bad_mode" \
  "$py3compile_bad_postinst" "$py3compile_bad_compiler"; do
  case "$path" in "$checkout"/.real-snapshot/*) ;; *) exit 2 ;; esac
done
[[ "$source_root" != "$script_root" && "$source_root" != "$dpkg_root" &&
   "$script_root" != "$dpkg_root" ]]
for path in "$script_root" "$dpkg_root" \
  "$py3compile_before" "$py3compile_after" "$py3compile_dpkg" \
  "$py3compile_bad_hash" "$py3compile_bad_mode" \
  "$py3compile_bad_postinst" "$py3compile_bad_compiler"; do
  require_protected_path "$(dirname -- "$path")"
  [[ ! -e "$path" && ! -L "$path" ]]
  case "$path" in "$source_root"/*) exit 2 ;; esac
done
python3 tools/prepare-native-dpkg.py --architecture amd64 --verify-only "$pinned"
[[ $(sha256sum "$pinned" | cut -d' ' -f1) == \
  0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5 ]]

digest=616bc16aa40a486075b987804a735a7c9e1873ad151564d057452761e31377b93451f00d2f82fcbccd6b2edd32dbaaeba14e6862a6a5192229a37e66fe61f6aa
[[ $(jq -r '.packages[] | select(.name == "python3" and .version == "3.14.3-0ubuntu2" and .architecture == "amd64") | .archive_identity.digests[] | select(.algorithm == "sha512") | .digest' "$lock") == "$digest" ]]
[[ $(jq -r '.packages[] | select(.name == "python3" and .version == "3.14.3-0ubuntu2" and .architecture == "amd64") | .declared_size' "$lock") == 22938 ]]
[[ $(stat -c '%s' "$archive") == 22938 ]]
[[ $(sha512sum "$archive" | cut -d' ' -f1) == "$digest" ]]
require_protected_file "$source_root/var/lib/dpkg/info/python3.preinst"
require_protected_file "$source_root/var/lib/dpkg/info/python3-minimal.postinst"
require_protected_file "$source_root/var/lib/dpkg/info/python3-minimal.list"
require_protected_file "$source_root/usr/bin/py3compile"
require_protected_file "$source_root/usr/bin/update-alternatives"
require_protected_file "$source_root/dev/null"
[[ $(sha256sum "$source_root/usr/bin/update-alternatives" | cut -d' ' -f1) == \
  023e1c2eef9f323f6f2c2f53aa22092cd118b1f087349ce133a677f94a03ed45 ]]
[[ $(stat -c '%u:%g:%a:%s:%h' "$source_root/var/lib/dpkg/info/python3-minimal.list") == \
  0:0:644:781:1 ]]
[[ $(sha256sum "$source_root/var/lib/dpkg/info/python3-minimal.list" | cut -d' ' -f1) == \
  82003099685ad735bdf486d434276cdb0b82b88f269330f87504a5739008f519 ]]
[[ -L "$source_root/usr/bin/python3" &&
   $(readlink "$source_root/usr/bin/python3") == python3.14 ]]
[[ $(stat -c '%u:%g:%a:%s:%h' "$source_root/var/lib/dpkg/info/python3.preinst") == 0:0:755:856:1 ]]
[[ $(sha256sum "$source_root/var/lib/dpkg/info/python3.preinst" | cut -d' ' -f1) == \
  115f972bfeb85d083537b4d7fc59261979c6a2511d85b84407c7d7da38c9a85f ]]
[[ $(stat -c '%u:%g:%a:%s:%h' "$source_root/var/lib/dpkg/info/python3-minimal.postinst") == 0:0:755:117:1 ]]
[[ $(sha256sum "$source_root/var/lib/dpkg/info/python3-minimal.postinst" | cut -d' ' -f1) == \
  be10656c9edf975f5dfe48fe5819172e905e14dcd4ff372af5d8b45b26168edd ]]
[[ $(stat -c '%u:%g:%a:%s:%h' "$source_root/usr/bin/py3compile") == 0:0:755:13312:1 ]]
[[ $(sha256sum "$source_root/usr/bin/py3compile" | cut -d' ' -f1) == \
  a94b6fd8fb7f801f564da4dbb3e2d646b54713b58349d725c650885a5a0c6ccc ]]
[[ $(jq -r '.packages[] | select(.name == "python3-minimal" and .version == "3.14.3-0ubuntu2" and .architecture == "amd64") | .archive_identity.digests[] | select(.algorithm == "sha512") | .digest' "$lock") == \
  e45a8b4d3ee89c9c30f3c2a31af1dfc5600dd4a541f4fcf42abb4946870076ad2dfa3a629699aa204d77db9d17ae58529eee5202cd6e89f8af14a5a9ec9b96a5 ]]
[[ $(jq -r '.packages[] | select(.name == "python3-minimal" and .version == "3.14.3-0ubuntu2" and .architecture == "amd64") | .declared_size' "$lock") == 25808 ]]
cmp "$source_root/var/lib/dpkg/info/python3.preinst" \
  "$checkout/src/fixtures/ubuntu-resolute-python3.preinst"
require_protected_file "$checkout/src/fixtures/ubuntu-resolute-python3-minimal.postinst"
cmp "$source_root/var/lib/dpkg/info/python3-minimal.postinst" \
  "$checkout/src/fixtures/ubuntu-resolute-python3-minimal.postinst"
[[ $(dpkg-query --admindir="$source_root/var/lib/dpkg" -W \
  -f='${Version} ${Status}' python3) == '3.14.3-0ubuntu2 install ok unpacked' ]]
[[ $(dpkg-query --admindir="$source_root/var/lib/dpkg" -W \
  -f='${Version} ${Status}' python3-minimal) == '3.14.3-0ubuntu2 install ok installed' ]]
[[ $(stat -c '%u:%g:%a:%s:%h' "$source_root/dev/null") == 0:0:600:0:1 ||
   $(stat -c '%u:%g:%a:%s:%h' "$source_root/dev/null") == 0:0:644:0:1 ]]
[[ -d "$source_root/proc" && ! -L "$source_root/proc" &&
   -z $(find "$source_root/proc" -mindepth 1 -print -quit) ]]
[[ ! -e "$source_root/usr/share/doc/python3/html" ]]

alternatives_fingerprint() {
  local root=$1
  [[ $(find "$root/var/lib/dpkg/alternatives" -mindepth 1 -maxdepth 1 -type f | wc -l) == 14 ]]
  [[ $(find "$root/etc/alternatives" -mindepth 1 -maxdepth 1 -type l | wc -l) == 76 ]]
  (
    cd "$root"
    find var/lib/dpkg/alternatives -mindepth 1 -maxdepth 1 -type f -print0 |
      sort -z | xargs -0 sha256sum
    find etc/alternatives -mindepth 1 -maxdepth 1 -type l -printf '%P %l\n' | sort
    readlink usr/bin/python3
  ) | sha256sum | cut -d' ' -f1
}
before=$(alternatives_fingerprint "$source_root")
cp -a --reflink=auto -- "$source_root" "$script_root"
cp -a --reflink=auto -- "$source_root" "$dpkg_root"
require_protected_path "$script_root"
require_protected_path "$dpkg_root"

timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --pid --fork --kill-child=SIGKILL --propagation private -- \
  chroot "$script_root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    test -z "$(find /proc -mindepth 1 -print -quit)"
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      /bin/sh /var/lib/dpkg/info/python3.preinst install
  '
[[ $(alternatives_fingerprint "$script_root") == "$before" ]]
[[ $(sha256sum "$script_root/dev/null" | cut -d' ' -f1) == \
  3b74c3d36b39899791526ce6546cf74a38d042c28ebdd023828d17b100cdccbc ]]
[[ $(stat -c '%s' "$script_root/dev/null") == 96 ]]

[[ -d "$dpkg_root/tmp" && ! -L "$dpkg_root/tmp" ]]
[[ -d "$dpkg_root/usr/local/sbin" && ! -L "$dpkg_root/usr/local/sbin" ]]
install -o root -g root -m0755 "$pinned" "$dpkg_root/usr/local/sbin/dpkg"
install -o root -g root -m0644 "$archive" "$dpkg_root/tmp/python3.deb"
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --pid --fork --kill-child=SIGKILL --propagation private -- \
  chroot "$dpkg_root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    test -z "$(find /proc -mindepth 1 -print -quit)"
    exec setpriv --bounding-set=-sys_admin --no-new-privs /bin/sh -ec '\''
      env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
        DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
        /usr/local/sbin/dpkg --root=/ --force-not-root --force-bad-path \
        --force-depends --no-triggers --purge python3
      env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
        DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
        /usr/local/sbin/dpkg --root=/ --force-not-root --force-bad-path \
        --force-confold --no-triggers --unpack /tmp/python3.deb
    '\'' sh
  '
[[ $(dpkg-query --admindir="$dpkg_root/var/lib/dpkg" -W \
  -f='${Version} ${Status}' python3) == '3.14.3-0ubuntu2 install ok unpacked' ]]
[[ $(alternatives_fingerprint "$dpkg_root") == "$before" ]]
cmp "$script_root/dev/null" "$dpkg_root/dev/null"
[[ $(stat -c '%u:%g:%a:%s' "$script_root/dev/null") == \
   "$(stat -c '%u:%g:%a:%s' "$dpkg_root/dev/null")" ]]
[[ ! -e "$script_root/proc/sys" && ! -e "$dpkg_root/proc/sys" ]]

# Generate the 20-byte prestate by running its signed producer, not by seeding bytes.
cp -a --reflink=auto -- "$source_root" "$py3compile_before"
require_protected_path "$py3compile_before"
chmod 0644 "$py3compile_before/dev/null"
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --pid --fork --kill-child=SIGKILL --propagation private -- \
  chroot "$py3compile_before" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    test -z "$(find /proc -mindepth 1 -print -quit)"
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      /bin/sh /var/lib/dpkg/info/python3-minimal.postinst configure ""
  '
[[ $(stat -c '%u:%g:%a:%s:%h' "$py3compile_before/dev/null") == 0:0:644:20:1 ]]
[[ $(sha256sum "$py3compile_before/dev/null" | cut -d' ' -f1) == \
  e212fd644ebc9508a5494c1d69e26c62e23b5695d797588603dd870af154751e ]]
[[ $(alternatives_fingerprint "$py3compile_before") == "$before" ]]
cp -a --reflink=auto -- "$py3compile_before" "$py3compile_after"
cp -a --reflink=auto -- "$py3compile_before" "$py3compile_dpkg"
for path in "$py3compile_after" "$py3compile_dpkg"; do require_protected_path "$path"; done
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --pid --fork --kill-child=SIGKILL --propagation private -- \
  chroot "$py3compile_after" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    test -z "$(find /proc -mindepth 1 -print -quit)"
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      /bin/sh /var/lib/dpkg/info/python3.preinst install
  '
install -o root -g root -m0755 "$pinned" "$py3compile_dpkg/usr/local/sbin/dpkg"
require_protected_path "$py3compile_dpkg/var/lib/dpkg"
[[ ! -e "$py3compile_dpkg/var/lib/dpkg/python3-probe.deb" &&
   ! -L "$py3compile_dpkg/var/lib/dpkg/python3-probe.deb" ]]
install -o root -g root -m0644 "$archive" "$py3compile_dpkg/var/lib/dpkg/python3-probe.deb"
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --pid --fork --kill-child=SIGKILL --propagation private -- \
  chroot "$py3compile_dpkg" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    test -z "$(find /proc -mindepth 1 -print -quit)"
    exec setpriv --bounding-set=-sys_admin --no-new-privs /bin/sh -ec '\''
      env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
        DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
        /usr/local/sbin/dpkg --root=/ --force-not-root --force-bad-path \
        --force-depends --no-triggers --purge python3
      env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
        DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
        /usr/local/sbin/dpkg --root=/ --force-not-root --force-bad-path \
        --force-confold --no-triggers --unpack /var/lib/dpkg/python3-probe.deb
    '\'' sh
  '
[[ $(stat -c '%u:%g:%a:%s:%h' "$py3compile_after/dev/null") == 0:0:644:96:1 ]]
[[ $(sha256sum "$py3compile_after/dev/null" | cut -d' ' -f1) == \
  3b74c3d36b39899791526ce6546cf74a38d042c28ebdd023828d17b100cdccbc ]]
cmp "$py3compile_after/dev/null" "$py3compile_dpkg/dev/null"
[[ $(stat -c '%u:%g:%a:%s:%h' "$py3compile_dpkg/dev/null") == 0:0:644:96:1 ]]
[[ $(dpkg-query --admindir="$py3compile_dpkg/var/lib/dpkg" -W \
  -f='${Version} ${Status}' python3) == '3.14.3-0ubuntu2 install ok unpacked' ]]
[[ $(alternatives_fingerprint "$py3compile_after") == "$before" &&
   $(alternatives_fingerprint "$py3compile_dpkg") == "$before" ]]
for path in "$py3compile_after" "$py3compile_dpkg"; do
  [[ -d "$path/proc" && ! -L "$path/proc" &&
     -z $(find "$path/proc" -mindepth 1 -print -quit) ]]
done
for path in "$py3compile_bad_hash" "$py3compile_bad_mode" \
  "$py3compile_bad_postinst" "$py3compile_bad_compiler"; do
  cp -a --reflink=auto -- "$py3compile_before" "$path"
  require_protected_path "$path"
done
printf '/usr/bin/py3compile ' > "$py3compile_bad_hash/dev/null"
chmod 0600 "$py3compile_bad_mode/dev/null"
sed -i 's/which/false/' "$py3compile_bad_postinst/var/lib/dpkg/info/python3-minimal.postinst"
printf 'stale compiler\n' > "$py3compile_bad_compiler/usr/bin/py3compile"
printf 'DEBZ_REQUIRE_SIGNED_PYTHON3_PREINST_ROOT_PY3COMPILE=%s\nDEBZ_REQUIRE_SIGNED_PYTHON3_PREINST_AFTER_PY3COMPILE=%s\nDEBZ_REQUIRE_SIGNED_PYTHON3_BAD_NULL_PY3COMPILE_HASH=%s\nDEBZ_REQUIRE_SIGNED_PYTHON3_BAD_NULL_PY3COMPILE_MODE=%s\nDEBZ_REQUIRE_SIGNED_PYTHON3_BAD_MINIMAL_POSTINST=%s\nDEBZ_REQUIRE_SIGNED_PYTHON3_BAD_MINIMAL_COMPILER=%s\n' \
  "$py3compile_before" "$py3compile_after" "$py3compile_bad_hash" \
  "$py3compile_bad_mode" "$py3compile_bad_postinst" "$py3compile_bad_compiler"
printf 'signed_python3_preinst=115f972bfeb85d083537b4d7fc59261979c6a2511d85b84407c7d7da38c9a85f\npinned_dpkg=1.22.22\nsigned_archive_sha512=%s\nscript_exit=0\ndpkg_unpack_exit=0\npreinst_args=install\nalternatives_fingerprint=%s\nnull_bytes=96\nnull_sha256=3b74c3d36b39899791526ce6546cf74a38d042c28ebdd023828d17b100cdccbc\n' "$digest" "$before"
