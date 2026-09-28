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
require_protected_file "$checkout/src/fixtures/ubuntu-stonking-python3-3.14.7-3.preinst"
require_protected_path "$checkout/.real-snapshot"
[[ $(stat -c '%u:%g:%a' "$checkout/.real-snapshot") == 0:0:700 ]]

pinned=$(realpath -- "$1")
source_root=$(realpath -- "$2")
lock=$(realpath -- "$3")
archive=$(realpath -- "$4")
script_root=$(realpath -m -- "$5")
dpkg_root=$(realpath -m -- "$6")
for file in "$pinned" "$lock" "$archive"; do require_protected_file "$file"; done
require_protected_path "$source_root"
[[ $(stat -c '%u:%g:%a' "$source_root") == 0:0:700 ]]
for path in "$pinned" "$source_root" "$lock" "$archive" "$script_root" "$dpkg_root"; do
  case "$path" in "$checkout"/.real-snapshot/*) ;; *) exit 2 ;; esac
done
[[ "$source_root" != "$script_root" && "$source_root" != "$dpkg_root" &&
   "$script_root" != "$dpkg_root" ]]
for path in "$script_root" "$dpkg_root"; do
  require_protected_path "$(dirname -- "$path")"
  [[ ! -e "$path" && ! -L "$path" ]]
  case "$path" in "$source_root"/*) exit 2 ;; esac
done
python3 tools/prepare-native-dpkg.py --architecture amd64 --verify-only "$pinned"
[[ $(sha256sum "$pinned" | cut -d' ' -f1) == \
  0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5 ]]

digest=1943e1345282b90dffed86d986d467e3d81e266a9925e8a12524bd853c8ef3a7f531a296d93772bfa3d86e04dd97600b66bd3c22e382be48627326998975c6b6
[[ $(jq -r '.packages[] | select(.name == "python3" and .version == "3.14.7-3" and .architecture == "amd64") | .archive_identity.digests[] | select(.algorithm == "sha512") | .digest' "$lock") == "$digest" ]]
[[ $(jq -r '.packages[] | select(.name == "python3" and .version == "3.14.7-3" and .architecture == "amd64") | .declared_size' "$lock") == 23672 ]]
[[ $(stat -c '%s' "$archive") == 23672 ]]
[[ $(sha512sum "$archive" | cut -d' ' -f1) == "$digest" ]]
require_protected_file "$source_root/var/lib/dpkg/info/python3.preinst"
require_protected_file "$source_root/var/lib/dpkg/info/python3-minimal.list"
require_protected_file "$source_root/usr/bin/update-alternatives"
[[ $(sha256sum "$source_root/usr/bin/update-alternatives" | cut -d' ' -f1) == \
  3e5fbdcf3b36bcfb7af1b406152c3a088acccc27c7b3e42d59ca0527a6259d9d ]]
[[ $(stat -c '%u:%g:%a:%s:%h' "$source_root/var/lib/dpkg/info/python3-minimal.list") == \
  0:0:644:781:1 ]]
[[ $(sha256sum "$source_root/var/lib/dpkg/info/python3-minimal.list" | cut -d' ' -f1) == \
  a0d9c1023aeef88ea89781862449be6b65cf84157b7d894aacd0c536b0940ba8 ]]
[[ -L "$source_root/usr/bin/python3" &&
   $(readlink "$source_root/usr/bin/python3") == python3.14 ]]
[[ $(stat -c '%u:%g:%a:%s:%h' "$source_root/var/lib/dpkg/info/python3.preinst") == 0:0:755:856:1 ]]
[[ $(sha256sum "$source_root/var/lib/dpkg/info/python3.preinst" | cut -d' ' -f1) == \
  115f972bfeb85d083537b4d7fc59261979c6a2511d85b84407c7d7da38c9a85f ]]
cmp "$source_root/var/lib/dpkg/info/python3.preinst" \
  "$checkout/src/fixtures/ubuntu-stonking-python3-3.14.7-3.preinst"
[[ $(dpkg-query --admindir="$source_root/var/lib/dpkg" -W \
  -f='${Version} ${Status}' python3) == '3.14.7-3 install ok unpacked' ]]
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
  -f='${Version} ${Status}' python3) == '3.14.7-3 install ok unpacked' ]]
[[ $(alternatives_fingerprint "$dpkg_root") == "$before" ]]
cmp "$script_root/dev/null" "$dpkg_root/dev/null"
[[ $(stat -c '%u:%g:%a:%s' "$script_root/dev/null") == \
   "$(stat -c '%u:%g:%a:%s' "$dpkg_root/dev/null")" ]]
[[ ! -e "$script_root/proc/sys" && ! -e "$dpkg_root/proc/sys" ]]
printf 'signed_python3_preinst=115f972bfeb85d083537b4d7fc59261979c6a2511d85b84407c7d7da38c9a85f\npinned_dpkg=1.22.22\nsigned_archive_sha512=%s\nscript_exit=0\ndpkg_unpack_exit=0\npreinst_args=install\nalternatives_fingerprint=%s\nnull_bytes=96\nnull_sha256=3b74c3d36b39899791526ce6546cf74a38d042c28ebdd023828d17b100cdccbc\n' "$digest" "$before"
