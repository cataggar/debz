#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

[[ $# == 3 ]] || {
  echo "usage: $0 PINNED_DPKG DISPOSABLE_SOURCE_ROOT NEW_PROOF_ROOT" >&2
  exit 2
}
[[ $(id -u) == 0 ]] || {
  echo "the pinned reference requires root" >&2
  exit 2
}

require_protected_path() {
  local path=$1 current=/ remainder=${1#/} component owner mode metadata
  [[ "$path" == /* ]] || return 2
  while :; do
    [[ -d "$current" && ! -L "$current" ]] || {
      echo "reference path is not a real directory: $current" >&2
      return 2
    }
    metadata=$(stat -c '%u:%a' -- "$current")
    owner=${metadata%%:*}
    mode=${metadata#*:}
    [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] &&
      (( (8#$mode & 022) == 0 )) || {
      echo "reference path is writable by an unprivileged user: $current" >&2
      return 2
    }
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
  local path=$1 metadata owner mode
  require_protected_path "$(dirname -- "$path")"
  [[ -f "$path" && ! -L "$path" ]] || return 2
  metadata=$(stat -c '%u:%a' -- "$path")
  owner=${metadata%%:*}
  mode=${metadata#*:}
  [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] &&
    (( (8#$mode & 022) == 0 )) || {
    echo "reference file is writable by an unprivileged user: $path" >&2
    return 2
  }
}

repository_root=$(pwd -P)
script_path=$(realpath -- "${BASH_SOURCE[0]}")
[[ "$script_path" == "$repository_root/tools/real-snapshot-udev-reference.sh" ]] || {
  echo "run the protected reference script from its checkout root" >&2
  exit 2
}
require_protected_file "$script_path"
require_protected_file "$repository_root/tools/prepare-native-dpkg.py"
require_protected_path "$repository_root/.real-snapshot"
[[ $(stat -c '%u:%g:%a' "$repository_root/.real-snapshot") == 0:0:700 ]] || {
  echo "the reference fixture directory must be root-owned and mode 0700" >&2
  exit 2
}
pinned=$(realpath -- "$1")
source_root=$(realpath -- "$2")
proof_root=$(realpath -m -- "$3")
require_protected_file "$pinned"
require_protected_path "$source_root"
require_protected_path "$(dirname -- "$proof_root")"
for path in "$pinned" "$source_root" "$proof_root"; do
  case "$path" in
    "$repository_root"/.real-snapshot/*) ;;
    *) echo "reference inputs must be beneath this checkout's .real-snapshot" >&2; exit 2 ;;
  esac
done
[[ "$source_root" != "$proof_root" ]]
case "$proof_root" in "$source_root"/*) echo "proof root must not nest in source" >&2; exit 2 ;; esac
[[ -d "$source_root" && ! -L "$2" && ! -e "$proof_root" && ! -L "$proof_root" ]]
[[ $(stat -c '%u:%g:%a' "$source_root") == 0:0:700 ]]
[[ $(stat -c '%u:%g:%a' "$source_root/proc") == 0:0:755 ]]
[[ ! -L "$source_root/proc" && -z $(find "$source_root/proc" -mindepth 1 -print -quit) ]]
for control in \
  'var/lib/dpkg/info/udev.postinst:2578:755:b7892e975bcce896c4938c2219a244fa03863d5eff37cd2eb66d2b8540f14606' \
  'usr/bin/dpkg:322728:755:972003a11f3ae0f5b2556dce1d2c2721fb5119818b9bbef1124293024fdb6517' \
  'usr/bin/systemd-tmpfiles:121544:755:13f968f41bac6dfdca7dc4fb346551b8a02e5ff148da3384f48fe04d37246fb4' \
  'usr/lib/tmpfiles.d/static-nodes-permissions.conf:798:644:ca4849c27428fd648f6377dd51a3ab0eb79de69fce1bdc910670012c0cf26f85' \
  'usr/lib/sysusers.d/debian-udev.conf:143:644:e9493928a4ed5399c5619cee0559644099f0625075606baca35b40533286b5e0'; do
  IFS=: read -r name size mode digest <<<"$control"
  file="$source_root/$name"
  require_protected_file "$file"
  [[ $(stat -c '%u:%g:%s:%a:%h' "$file") == "0:0:$size:$mode:1" ]]
  [[ $(sha256sum "$file" | cut -d' ' -f1) == "$digest" ]]
done
require_protected_file "$source_root/var/lib/dpkg/status"
[[ $(dpkg-query --admindir="$source_root/var/lib/dpkg" \
  -W -f='${Version} ${Status}' udev) == \
  '259.5-0ubuntu3.4 install ok half-configured' ]]
python3 tools/prepare-native-dpkg.py --architecture amd64 --verify-only "$pinned"

cp -a --reflink=auto -- "$source_root" "$proof_root"
[[ -d "$proof_root/usr/local/sbin" && ! -L "$proof_root/usr/local/sbin" ]]
install -o root -g root -m 0755 "$pinned" "$proof_root/usr/local/sbin/dpkg"
[[ $(sha256sum "$proof_root/usr/local/sbin/dpkg" | cut -d' ' -f1) == \
  0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5 ]]

result=0
unshare --mount --pid --fork --kill-child=SIGKILL --propagation private -- \
  chroot "$proof_root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    test ! -L /proc
    test -z "$(find /proc -mindepth 1 -print -quit)"
    mount -t proc -o ro,nosuid,nodev,noexec,hidepid=2,subset=pid proc /proc
    test "$(stat -f -c %T /proc)" = proc
    test ! -e /proc/sys
    test ! -e /proc/sys/kernel/random/boot_id
    test "$(stat -Lc %d:%i /proc/1/root)" = "$(stat -Lc %d:%i /)"
    exec setpriv --bounding-set=-sys_admin --no-new-privs /bin/sh -c '\''
      set -eu
      for field in CapEff CapBnd; do
        hex=$(sed -n "s/^$field:[[:space:]]*//p" /proc/self/status)
        test $((0x$hex & 0x200000)) -eq 0
      done
      test "$(sed -n "s/^NoNewPrivs:[[:space:]]*//p" /proc/self/status)" -eq 1
      test ! -e /proc/sys
      exec env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
        DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true \
        DPKG_COLORS=never /usr/local/sbin/dpkg --root=/ --force-not-root \
        --force-bad-path --force-confold --no-triggers --configure udev
    '\'' sh
  ' || result=$?
printf 'pinned_dpkg_exit=%d udev_status=%s\n' "$result" \
  "$(dpkg-query --admindir="$proof_root/var/lib/dpkg" -W -f='${Status}' udev)"
[[ ! -e "$proof_root/proc/sys" ]]
exit "$result"
