#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

[[ $# == 3 && $(id -u) == 0 ]] || {
  echo "usage (as root): $0 PINNED_DPKG PROTECTED_PRE_SUDO_ROOT NEW_PROOF_ROOT" >&2
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
[[ "$script_path" == "$repository_root/tools/real-snapshot-sudo-reference.sh" ]] || {
  echo "run the protected reference script from its checkout root" >&2
  exit 2
}
require_protected_file "$script_path"
require_protected_file "$repository_root/tools/prepare-native-dpkg.py"
require_protected_path "$repository_root/.real-snapshot"
[[ $(stat -c '%u:%g:%a' "$repository_root/.real-snapshot") == 0:0:700 ]] || {
  echo "reference fixture directory must be root-owned and mode 0700" >&2
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
case "$proof_root" in "$source_root"/*) exit 2 ;; esac
[[ -d "$source_root" && ! -L "$2" && ! -e "$proof_root" && ! -L "$proof_root" ]]
[[ $(stat -c '%u:%g:%a' "$source_root") == 0:0:700 ]]
[[ $(stat -c '%u:%g:%a' "$source_root/proc") == 0:0:755 ]]
[[ ! -L "$source_root/proc" && -z $(find "$source_root/proc" -mindepth 1 -print -quit) ]]

for control in \
  'var/lib/dpkg/info/sudo.postinst:1927:755:e766407bf70ad03d8006de9f3f8700f7ed22b532d8e299ac88e522e2c80a2cb8' \
  'var/lib/dpkg/info/sudo.list:2376:644:92f90d6a92f5c697cce3057db0b0b6ed3d831af950b1b6a2e2704f32410d483f' \
  'usr/bin/dpkg:322728:755:6587ef9e2ef69b1a0426d69d667bfd7cbcec6c3be5f0560cc4c219f95d65739f' \
  'usr/bin/dpkg-maintscript-helper:21123:755:1cd744cc0b6371329a6a5dbcf459329a08f8632b5f71e18463d0f0749fd0265d' \
  'usr/share/dpkg/sh/dpkg-error.sh:3228:644:d4d4fd7712da692dbb21a10795f7e62046c90b506338768b5a93cf9f1897f528' \
  'usr/bin/update-alternatives:59864:755:3e5fbdcf3b36bcfb7af1b406152c3a088acccc27c7b3e42d59ca0527a6259d9d' \
  'usr/lib/tmpfiles.d/sudo.conf:27:644:eed7eb9d7ddaccb3ae13d3225de1302a96754938fea4dc305c43b64cbcb5d0bc'; do
  IFS=: read -r name size mode digest <<<"$control"
  file="$source_root/$name"
  require_protected_file "$file"
  [[ $(stat -c '%u:%g:%s:%a:%h' "$file") == "0:0:$size:$mode:1" ]]
  [[ $(sha256sum "$file" | cut -d' ' -f1) == "$digest" ]]
done
require_protected_file "$source_root/var/lib/dpkg/status"
require_protected_file "$source_root/var/lib/dpkg/alternatives/sudo"
[[ $(stat -c '%u:%g:%s:%a:%h' "$source_root/var/lib/dpkg/alternatives/sudo") == 0:0:464:644:1 ]]
[[ $(sha256sum "$source_root/var/lib/dpkg/alternatives/sudo" | cut -d' ' -f1) == \
  4f50d77a8e6f76e51745762486caec36324433ea7b09aac48274624c70e46da6 ]]
[[ $(dpkg-query --admindir="$source_root/var/lib/dpkg" -W \
  -f='${Version} ${Status}' sudo) == '1.9.17p2-7ubuntu3 install ok unpacked' ]]
[[ $(dpkg-query --admindir="$source_root/var/lib/dpkg" -W \
  -f='${Version} ${Status}' sudo-rs) == '0.2.14-1ubuntu2 install ok installed' ]]
for link in 'usr/bin/sudoedit:sudo.ws' \
  'usr/share/man/man8/sudoedit.8.gz:sudo.ws.8.gz'; do
  IFS=: read -r name target <<<"$link"
  [[ -L "$source_root/$name" && $(readlink -- "$source_root/$name") == "$target" ]]
  [[ $(stat -c '%u:%g:%a:%h' -- "$source_root/$name") == 0:0:777:1 ]]
done
python3 tools/prepare-native-dpkg.py --architecture amd64 --verify-only "$pinned"

cp -a --reflink=auto -- "$source_root" "$proof_root"
[[ -d "$proof_root/usr/local/sbin" && ! -L "$proof_root/usr/local/sbin" ]]
install -o root -g root -m 0755 "$pinned" "$proof_root/usr/local/sbin/dpkg"
[[ $(sha256sum "$proof_root/usr/local/sbin/dpkg" | cut -d' ' -f1) == \
  0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5 ]]

timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --pid --fork --kill-child=SIGKILL --propagation private -- \
  chroot "$proof_root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    test -z "$(find /proc -mindepth 1 -print -quit)"
    mount -t proc -o ro,nosuid,nodev,noexec,hidepid=2,subset=pid proc /proc
    test "$(stat -f -c %T /proc)" = proc
    test ! -e /proc/sys
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
        --force-bad-path --force-confold --no-triggers --configure sudo
    '\'' sh
  '
[[ $(dpkg-query --admindir="$proof_root/var/lib/dpkg" -W \
  -f='${Version} ${Status}' sudo) == '1.9.17p2-7ubuntu3 install ok installed' ]]
[[ $(stat -c '%u:%g:%s:%a:%h' "$proof_root/var/lib/dpkg/alternatives/sudo") == 0:0:658:644:1 ]]
[[ $(sha256sum "$proof_root/var/lib/dpkg/alternatives/sudo" | cut -d' ' -f1) == \
  c583a377d2d7bc241422c91f43738f8e278e159e8e3bb2aa53d5bdeaf782e845 ]]
for link in 'usr/bin/sudoedit:/etc/alternatives/sudoedit' \
  'usr/share/man/man8/sudoedit.8.gz:/etc/alternatives/sudoedit.8.gz'; do
  IFS=: read -r name target <<<"$link"
  [[ -L "$proof_root/$name" && $(readlink -- "$proof_root/$name") == "$target" ]]
done
[[ ! -e "$proof_root/proc/sys" && -z $(find "$proof_root/proc" -mindepth 1 -print -quit) ]]
[[ $(dpkg-query --admindir="$source_root/var/lib/dpkg" -W \
  -f='${Version} ${Status}' sudo) == '1.9.17p2-7ubuntu3 install ok unpacked' ]]
printf 'pinned_dpkg_exit=0 sudo_status=installed sudo_record_bytes=658 sudo_record_sha256=%s proc_sys=absent\n' \
  "$(sha256sum "$proof_root/var/lib/dpkg/alternatives/sudo" | cut -d' ' -f1)"
