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
    echo "reference program is writable by an unprivileged user: $path" >&2
    return 2
  }
}

repository_root=$(pwd -P)
script_path=$(realpath -- "${BASH_SOURCE[0]}")
[[ "$script_path" == "$repository_root/tools/real-snapshot-systemd-proc-reference.sh" ]] || {
  echo "run the protected reference script from its checkout root" >&2
  exit 2
}
require_protected_file "$script_path"
require_protected_file "$repository_root/tools/prepare-native-dpkg.py"
require_protected_path "$repository_root/.real-snapshot"
[[ $(stat -c '%u:%a' "$repository_root/.real-snapshot") == 0:700 ]] || {
  echo "the reference fixture directory must be root-owned and mode 0700" >&2
  exit 2
}
pinned=$(realpath "$1")
source_root=$(realpath "$2")
proof_root=$(realpath -m "$3")
require_protected_path "$source_root"
require_protected_path "$(dirname -- "$proof_root")"
for path in "$source_root" "$proof_root"; do
  case "$path" in
    "$repository_root"/.real-snapshot/*) ;;
    *) echo "proof roots must be beneath this worktree's .real-snapshot" >&2; exit 2 ;;
  esac
done
[[ "$source_root" != "$proof_root" ]]
[[ -d "$source_root" && ! -L "$2" && ! -e "$proof_root" && ! -L "$proof_root" ]]
[[ $(stat -c '%u:%g:%a' "$source_root") == 0:0:700 ]]
[[ $(stat -c '%u:%g:%a' "$source_root/proc") == 0:0:755 ]]
[[ ! -L "$source_root/proc" && -z $(find "$source_root/proc" -mindepth 1 -print -quit) ]]
[[ $(sha256sum "$source_root/var/lib/dpkg/info/systemd.postinst" | cut -d' ' -f1) == \
  d9df6a03ccb6b557c16ac1c674557a66c1db290f3c6d3cadbef335e0ce74e31d ]]
[[ $(dpkg-query --admindir="$source_root/var/lib/dpkg" \
  -W -f='${Version} ${Status}' systemd) == \
  '261.2-1ubuntu2 install ok half-configured' ]]
python3 tools/prepare-native-dpkg.py --architecture amd64 --verify-only "$pinned"
boot_id=$(cat /proc/sys/kernel/random/boot_id)
[[ "$boot_id" =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]]

cp -a --reflink=auto -- "$source_root" "$proof_root"
install -o root -g root -m 0755 "$pinned" "$proof_root/usr/bin/dpkg"
[[ $(sha256sum "$proof_root/usr/bin/dpkg" | cut -d' ' -f1) == \
  0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5 ]]

result=0
unshare --mount --pid --fork --kill-child=SIGKILL --propagation private -- \
  chroot "$proof_root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    test ! -L /proc
    test ! -e /proc/sys
    mount -t proc -o ro,nosuid,nodev,noexec,hidepid=2 proc /proc
    mount -t tmpfs -o nosuid,nodev,noexec,mode=0700,size=64k tmpfs /proc/sys
    mkdir -p /proc/sys/kernel/random
    printf "%s\n" "$1" >/proc/sys/kernel/random/boot_id
    chmod 0555 /proc/sys/kernel /proc/sys/kernel/random
    chmod 0444 /proc/sys/kernel/random/boot_id
    mount -o remount,ro,nosuid,nodev,noexec /proc/sys
    test "$(cat /proc/sys/kernel/random/boot_id)" = "$1"
    test "$(find /proc/sys -mindepth 1 | wc -l)" -eq 3
    test ! -e /proc/sys/net
    test ! -e /proc/sys/vm
    test ! -e /proc/sys/kernel/random/uuid
    test ! -e /proc/sys/kernel/pid_max
    test "$(stat -f -c %T /proc)" = proc
    test "$(stat -f -c %T /proc/sys)" = tmpfs
    test "$(stat -Lc %d:%i /proc/1/root)" = "$(stat -Lc %d:%i /)"
    if touch /proc/sys/extra 2>/dev/null; then exit 1; fi
    exec setpriv --bounding-set=-sys_admin --no-new-privs /bin/sh -c '\''
      set -eu
      for field in CapEff CapBnd; do
        hex=$(sed -n "s/^$field:[[:space:]]*//p" /proc/self/status)
        test $((0x$hex & 0x200000)) -eq 0
      done
      test "$(sed -n "s/^NoNewPrivs:[[:space:]]*//p" /proc/self/status)" -eq 1
      exec env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
        DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true \
        DPKG_COLORS=never /usr/bin/dpkg --root=/ --force-not-root \
        --force-bad-path --force-confold --no-triggers --configure systemd
    '\'' sh
  ' sh "$boot_id" || result=$?
printf 'pinned_dpkg_exit=%d systemd_status=%s\n' "$result" \
  "$(dpkg-query --admindir="$proof_root/var/lib/dpkg" -W -f='${Status}' systemd)"
[[ ! -e "$proof_root/proc/sys" ]]
exit "$result"
