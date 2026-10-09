#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PYTHONDONTWRITEBYTECODE=1

[[ ( $# == 7 || $# == 9 ) && $(id -u) == 0 ]] || {
  echo "usage (as root): $0 PINNED_DPKG PROTECTED_SOURCE_ROOT SIGNED_LOCK LESS_ARCHIVE NEW_SCRIPT_ROOT NEW_DPKG_ROOT ZIG [LESS_LOCK DASH_LOCK]" >&2
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
    if [[ "$remainder" == "$component" ]]; then remainder=; else remainder=${remainder#*/}; fi
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
[[ $(realpath -- "${BASH_SOURCE[0]}") == "$checkout/tools/real-snapshot-less-reference.sh" ]]
for file in tools/real-snapshot-less-reference.sh tools/prepare-native-dpkg.py \
  tools/real_snapshot_less_fixtures.py tools/real_snapshot_reference_paths.py \
  src/fixtures/ubuntu-resolute-less.preinst; do require_protected_file "$checkout/$file"; done
require_protected_path "$checkout/.real-snapshot"
[[ $(stat -c '%u:%g:%a' "$checkout/.real-snapshot") == 0:0:700 ]]
pinned=$(realpath -- "$1")
source_root=$(realpath -- "$2")
lock=$(realpath -- "$3")
archive=$(realpath -- "$4")
script_root=$(realpath -m -- "$5")
dpkg_root=$(realpath -m -- "$6")
zig=$(realpath -- "$7")
less_lock=$lock dash_lock=$lock
if [[ $# == 9 ]]; then
  less_lock=$(realpath -- "$8")
  dash_lock=$(realpath -- "$9")
fi
for file in "$pinned" "$lock" "$less_lock" "$dash_lock" "$archive" "$zig"; do require_protected_file "$file"; done
require_protected_path "$source_root"
[[ $(stat -c '%u:%g:%a' "$source_root") == 0:0:700 ]]
for path in "$pinned" "$source_root" "$lock" "$less_lock" "$dash_lock" "$archive" "$script_root" "$dpkg_root"; do
  case "$path" in "$checkout"/.real-snapshot/*) ;; *) exit 2 ;; esac
done
[[ "$source_root" != "$script_root" && "$source_root" != "$dpkg_root" &&
   "$script_root" != "$dpkg_root" ]]
bad_script="${script_root}-bad-script"
bad_mode="${script_root}-bad-mode"
bad_tool="${script_root}-bad-tool"
bad_alias="${script_root}-bad-alias"
bad_prestate="${script_root}-bad-prestate"
for path in "$script_root" "$dpkg_root" "$bad_script" "$bad_mode" \
  "$bad_tool" "$bad_alias" "$bad_prestate"; do
  require_protected_path "$(dirname -- "$path")"
  [[ ! -e "$path" && ! -L "$path" ]]
  case "$path" in "$source_root"/*) exit 2 ;; esac
done
python3 tools/prepare-native-dpkg.py --architecture arm64 --verify-only "$pinned"
for source in "$lock" "$less_lock" "$dash_lock"; do
  [[ $(jq -r '.target_architecture' "$source") == arm64 ]]
done
require_lock_artifact() {
  local name=$1 version=$2 size=$3 sha512=$4 observed source=${5:-$lock}
  observed=$(jq -r --arg name "$name" --arg version "$version" \
    '.packages[] | select(.name == $name and .version == $version and .architecture == "arm64" and .origin.type == "authenticated_repository" and .archive_identity.primary == "sha512") | [.declared_size, (.archive_identity.digests[] | select(.algorithm == "sha512") | .digest)] | @tsv' "$source")
  [[ "$observed" == "$size"$'\t'"$sha512" ]]
}
digest=f3d538070be0217eec1c5e747f0b6ed05b08b22a006001dafac6c87747ab46e9055fb8bf1985aed2d4010f57d597108dbff22ed73f92959703fffa57ec84e0e8
require_lock_artifact less 668-1build1 171138 "$digest" "$less_lock"
require_lock_artifact dash 0.5.12-12ubuntu3 95716 c4a44690b1541936c4c85956f8e5bef0c915ce05afe6618230b70f4906803f8710b314b9093b451787b995bcd7b25a3947f51c8efa03dbda16c7eac720f93c6e "$dash_lock"
require_lock_artifact dpkg 1.23.7ubuntu1 1260980 824a6a3f33837c16dedb4faff92bd15b0dbe82d27dd9b25403f87ec4572acc6332159a6374558185ca503e18de6f637d2a79e7db9fafaab3ccae4ac77427eee5
require_lock_artifact libc6 2.43-2ubuntu2.4 1642036 865127bc2d7d9218e2a3482b7e0b5ae3649c31bcac82d0437a7231c798f56a1939f0f18fc664111a7c446eef6f9864176c040ad78b7aac1a6a3afe4d4b9cbeb7
[[ $(stat -c '%s' "$archive") == 171138 &&
   $(sha512sum "$archive" | cut -d' ' -f1) == "$digest" ]]
[[ $(dpkg-query --admindir="$source_root/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' less) == '668-1build1 arm64 install ok unpacked' ]]
require_protected_file "$source_root/var/lib/dpkg/info/less.preinst"
cmp "$source_root/var/lib/dpkg/info/less.preinst" \
  "$checkout/src/fixtures/ubuntu-resolute-less.preinst"
require_protected_path "$checkout/.zig-cache"
mkdir -m0700 "$checkout/.zig-cache/arm64-less-probe-data"

check_source_inputs() {
  env -u DEBZ_REQUIRE_SIGNED_ARM64_LESS_PREINST_ROOT \
    DEBZ_REQUIRE_SIGNED_ARM64_LESS_SOURCE_ROOT="$source_root" \
    TMPDIR="$checkout/.zig-cache/arm64-less-probe-data" \
    ZIG_GLOBAL_CACHE_DIR="$checkout/.zig-cache/arm64-less-global" \
    "$zig" build test-native-unpack -Doptimize=ReleaseSafe -j2 --summary all
}

check_source_inputs
for path in "$script_root" "$dpkg_root" "$bad_script" "$bad_mode" \
  "$bad_tool" "$bad_alias" "$bad_prestate"; do
  cp -a --reflink=auto -- "$source_root" "$path"
  require_protected_path "$path"
done
python3 - "$bad_script" "$bad_mode" "$bad_tool" "$bad_alias" "$bad_prestate" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, "tools")
from real_snapshot_less_fixtures import mutate_negative_roots
mutate_negative_roots([Path(root) for root in sys.argv[1:]])
PY

check_activated_roots() {
  env DEBZ_REQUIRE_SIGNED_ARM64_LESS_PREINST_ROOT="$source_root" \
    DEBZ_REQUIRE_SIGNED_ARM64_LESS_SCRIPT_AFTER="$script_root" \
    DEBZ_REQUIRE_SIGNED_ARM64_LESS_DPKG_AFTER="$dpkg_root" \
    DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_SCRIPT_ROOT="$bad_script" \
    DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_MODE_ROOT="$bad_mode" \
    DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_TOOL_ROOT="$bad_tool" \
    DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_ALIAS_ROOT="$bad_alias" \
    DEBZ_REQUIRE_SIGNED_ARM64_LESS_BAD_PRESTATE_ROOT="$bad_prestate" \
    TMPDIR="$checkout/.zig-cache/arm64-less-probe-data" \
    ZIG_GLOBAL_CACHE_DIR="$checkout/.zig-cache/arm64-less-global" \
    "$zig" build test-native-unpack -Doptimize=ReleaseSafe -j2 --summary all
}

alternatives_fingerprint() {
  (
    cd "$1"
    find var/lib/dpkg/alternatives -mindepth 1 -maxdepth 1 -type f -print0 |
      sort -z | xargs -0 sha256sum
    find etc/alternatives -mindepth 1 -maxdepth 1 -type l -printf '%P %l\n' | sort
  ) | sha256sum | cut -d' ' -f1
}

# Validate every root before execution, then activate the same Zig gate again after real replay.
check_activated_roots
before=$(alternatives_fingerprint "$source_root")
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$script_root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      /bin/sh /var/lib/debz-lifecycle-scripts/less.preinst install
  '
python3 - "$dpkg_root" "$pinned" "$archive" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, "tools")
from real_snapshot_less_fixtures import stage_dpkg_reference
stage_dpkg_reference(*(Path(path) for path in sys.argv[1:]))
PY
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$dpkg_root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs /bin/sh -ec '\''
      /usr/local/sbin/dpkg --root=/ --force-not-root --force-bad-path \
        --force-depends --no-triggers --purge less
      /usr/local/sbin/dpkg --root=/ --force-not-root --force-bad-path \
        --no-triggers --unpack /var/lib/dpkg/less-probe.deb
    '\'' sh
  '
[[ $(alternatives_fingerprint "$source_root") == "$before" &&
   $(alternatives_fingerprint "$script_root") == "$before" &&
   $(alternatives_fingerprint "$dpkg_root") == "$before" ]]
[[ $(dpkg-query --admindir="$dpkg_root/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' less) == '668-1build1 arm64 install ok unpacked' ]]
check_activated_roots
printf 'signed_arm64_less_preinst=install\nscript_exit=0\npinned_dpkg_unpack_exit=0\nalternatives_fingerprint=%s\nactivated_zig_gate=passed\n' "$before"
