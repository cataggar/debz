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
[[ "$script_path" == "$repository_root/tools/real-snapshot-chrony-reference.sh" ]] || {
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
[[ -d "$source_root" && ! -L "$2" && ! -e "$proof_root" && ! -L "$proof_root" ]]
[[ $(stat -c '%u:%g:%a' "$source_root") == 0:0:700 ]]
[[ $(stat -c '%u:%g:%a' "$source_root/proc") == 0:0:755 ]]
[[ ! -L "$source_root/proc" && -z $(find "$source_root/proc" -mindepth 1 -print -quit) ]]
for control in \
  'chrony.postinst:6993:755:5629c0b5bc1601ae9e8f0f8cc7b660d4df659af55db2b90c7960f1e40c5c9272' \
  'chrony.config:204:755:77661a87b10380b637663d35d01f334c99887ba0dfb625f0c3cc14d995dd83f0' \
  'chrony.templates:698:644:1f0ffe9e66ddc6593446ef924cf6dc80a445b161f0e1876ffac417f0a32841cf'; do
  IFS=: read -r name size mode digest <<<"$control"
  file="$source_root/var/lib/dpkg/info/$name"
  require_protected_file "$file"
  [[ $(stat -c '%u:%g:%s:%a:%h' "$file") == "0:0:$size:$mode:1" ]]
  [[ $(sha256sum "$file" | cut -d' ' -f1) == "$digest" ]]
done
[[ $(dpkg-query --admindir="$source_root/var/lib/dpkg" \
  -W -f='${Version} ${Status}' chrony) == \
  '4.8-4ubuntu2 install ok half-configured' ]]
python3 tools/prepare-native-dpkg.py --architecture amd64 --verify-only "$pinned"

cp -a --reflink=auto -- "$source_root" "$proof_root"
install -o root -g root -m 0755 "$pinned" "$proof_root/usr/bin/dpkg"
[[ $(sha256sum "$proof_root/usr/bin/dpkg" | cut -d' ' -f1) == \
  0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5 ]]

result=0
unshare --mount --pid --fork --kill-child=SIGKILL --propagation private -- \
  setpriv --bounding-set=-sys_admin --no-new-privs -- \
  chroot "$proof_root" /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
    DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true \
    DPKG_COLORS=never /usr/bin/dpkg --root=/ --force-not-root \
    --force-bad-path --force-confold --no-triggers --configure chrony || result=$?
printf 'pinned_dpkg_exit=%d chrony_status=%s\n' "$result" \
  "$(dpkg-query --admindir="$proof_root/var/lib/dpkg" -W -f='${Status}' chrony)"
[[ ! -e "$proof_root/proc/sys" ]]
exit "$result"
