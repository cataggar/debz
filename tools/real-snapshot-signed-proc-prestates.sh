#!/usr/bin/env bash
# Generate fresh pre-script roots for the positive signed systemd, udev and
# sudo proc replays from the authenticated amd64 closure that
# tools/real-snapshot-signed-proc-bindings.sh downloaded into WORKSPACE.
# Pinned dpkg installs that exact closure in the reviewed reference order;
# tools/real-snapshot-reference-order.py copies the root just before each
# target is configured. Systemd and udev are copied after dpkg recorded
# half-configured and was denied execution of the unchanged signed postinst;
# sudo is copied while it is still unpacked. The copies are disposable
# fixtures, not native installation results.
# --python3 reuses this fixture producer to stop just before Python configure
# on an independent workspace. It does not enable any additional proc profile.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
purpose=proc
if [[ ${1:-} == --python3 ]]; then
  purpose=python3
  shift
fi

# The lock document digest also covers the local keyring path, so bind the
# authenticated snapshot Release, its signer and the exact archive closure.
readonly release_sha256=596ee4cea058f74d59e2180532c89904e306d90725d42162eda82c01d4370834
readonly updates_release_sha256=16d93e5e9358047ac2f5d671abcac2bb3f2945532452720cd9a17320c19c4f24
readonly security_release_sha256=bda7516aa5ed1aa2c8ebcbe36a07276f599559917a9de8fe5de041e99c9a2a10
readonly release_signer=f6ecb3762474eda9d21b7022871920d1991bc93c
# Digest of the sorted reference-archives TSV built below, which is a
# different scheme from the algorithm-tagged
# snapshot.closures.amd64.digest that tools/fixtures/real-snapshot/pin-v1.json
# records for the same closure. Do not copy one into the other.
readonly closure_sha256=5223cb19af6f686faa591eb6575b6d585a830473d98550df52ef958fd152f9f2
readonly pinned_dpkg_sha256=0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5
readonly signed_dpkg='usr/bin/dpkg:322728:755:972003a11f3ae0f5b2556dce1d2c2721fb5119818b9bbef1124293024fdb6517'
readonly setpriv_sha256=86965a019d37dc11d176ce8cbe9f5f5f8f37027c95e03cb4a8cad4c73d940993
readonly setpriv_runtime_sha256=60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f

[[ $# == 2 && $(id -u) == 0 ]] || {
  echo "usage (as root): $0 [--python3] PINNED_DPKG BINDING_WORKSPACE" >&2
  exit 2
}
[[ $(uname -m) == x86_64 ]] || {
  echo "the signed systemd/udev/sudo prestates are amd64-only" >&2
  exit 2
}

require_protected_path() {
  local path=$1 current=/ remainder=${1#/} component owner mode metadata
  [[ "$path" == /* ]] || return 2
  while :; do
    [[ -d "$current" && ! -L "$current" ]] || {
      echo "prestate path is not a real directory: $current" >&2
      return 2
    }
    metadata=$(stat -c '%u:%a' -- "$current")
    owner=${metadata%%:*}
    mode=${metadata#*:}
    [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] &&
      (( (8#$mode & 022) == 0 )) || {
      echo "prestate path is writable by an unprivileged user: $current" >&2
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
    echo "prestate file is writable by an unprivileged user: $path" >&2
    return 2
  }
}

repository_root=$(pwd -P)
script_path=$(realpath -- "${BASH_SOURCE[0]}")
[[ "$script_path" == "$repository_root/tools/real-snapshot-signed-proc-prestates.sh" ]] || {
  echo "run the protected prestate script from its checkout root" >&2
  exit 2
}
require_protected_file "$script_path"
require_protected_file "$repository_root/tools/real-snapshot-reference-order.py"
require_protected_file "$repository_root/tools/real-snapshot-reference-launcher.zig"
require_protected_file "$repository_root/tools/prepare-native-dpkg.py"
# The staged toolchain lives outside the fixed PATH above, so the caller names
# it and it is verified like every other root-trusted input: it compiles the
# launcher that runs as root below.
zig=$(command -v "${DEBZ_ZIG:-zig}") || {
  echo "the zig toolchain that compiles the launcher was not found: ${DEBZ_ZIG:-zig}" >&2
  exit 2
}
zig=$(realpath -- "$zig")
require_protected_file "$zig"
require_protected_path "$repository_root/.real-snapshot"
[[ $(stat -c '%u:%g:%a' "$repository_root/.real-snapshot") == 0:0:700 ]] || {
  echo "the fixture directory must be root-owned and mode 0700" >&2
  exit 2
}
pinned=$(realpath -- "$1")
workspace=$(realpath -- "$2")
for path in "$pinned" "$workspace"; do
  case "$path" in
    "$repository_root"/.real-snapshot/*) ;;
    *) echo "prestate inputs must be beneath this checkout's .real-snapshot" >&2; exit 2 ;;
  esac
done
[[ ! -L "$1" && ! -L "$2" ]]
require_protected_file "$pinned"
[[ -x "$pinned" && $(sha256sum "$pinned" | cut -d' ' -f1) == "$pinned_dpkg_sha256" ]]
require_protected_path "$workspace"
[[ $(stat -c '%u:%g:%a' "$workspace") == 0:0:700 ]]
snapshot=$workspace/snapshot
lock=$snapshot/evidence/ubuntu-minimal.lock.json
cache=$snapshot/cache
require_protected_file "$lock"
require_protected_path "$cache/packages-v2/objects"
prestates=$workspace/prestates
build=$workspace/prestate-build
tools=$workspace/reference-tools
for path in "$prestates" "$build" "$tools" "$workspace/prestates.env"; do
  [[ ! -e "$path" && ! -L "$path" ]] || {
    echo "prestate output must be new: $path" >&2
    exit 2
  }
done
python3 tools/prepare-native-dpkg.py --architecture amd64 --verify-only "$pinned"

# The signed proc profiles bind these exact package identities.
jq -e --arg release "$release_sha256" --arg updates "$updates_release_sha256" \
  --arg security "$security_release_sha256" --arg signer "$release_signer" '
  .schema == "https://debz.dev/schema/exact-closure-lock-v3" and
  .version == 3 and .target_architecture == "amd64" and
  (.repositories | length) == 3 and
  all(.repositories[]; .index_identity.primary == "sha256") and
  ([.repositories[].release_sha256] |
    index($release) != null and index($updates) != null and index($security) != null) and
  all(.repositories[].release_sha256; . == $release or . == $updates or . == $security) and
  ([.repositories[].signer_fingerprints[]] | unique) == [$signer] and
  all(.packages[]; .archive_identity.primary == "sha512" and
    ([.archive_identity.digests[] | select(.algorithm == "sha512")] | length) == 1) and
  ([.packages[] | select(.architecture == "amd64" and (
    (.name == "systemd" and .version == "259.5-0ubuntu3.4") or
    (.name == "udev" and .version == "259.5-0ubuntu3.4") or
    (.name == "sudo" and .version == "1.9.17p2-1ubuntu3.1") or
    (.name == "sudo-rs" and .version == "0.2.13-0ubuntu1.2") or
    (.name == "util-linux" and .version == "2.41.3-3ubuntu2.2") or
    (.name == "libcap-ng0" and .version == "0.8.5-4build5")))] | length) == 6
' "$lock" >/dev/null

install -d -o root -g root -m 0700 "$build" "$build/evidence" "$build/tmp" "$prestates" "$tools"
evidence=$build/evidence
jq -r '
  .packages[] |
  [.name, .version, .architecture,
   (.archive_identity.digests[] | select(.algorithm == "sha512") | .digest),
   .declared_size] | @tsv
' "$lock" >"$evidence/reference-archives.tsv"
[[ $(LC_ALL=C sort -- "$evidence/reference-archives.tsv" | sha256sum | cut -d' ' -f1) == "$closure_sha256" ]] || {
  echo "prestate closure differs from the reviewed snapshot closure" >&2
  exit 1
}

bootstrap=()
util_linux=
libcap_ng=
while IFS=$'\t' read -r name version package_arch digest size; do
  [[ "$name" =~ ^[a-z0-9][a-z0-9+.-]*$ &&
     "$version" != *$'\t'* && "$version" != *$'\n'* &&
     ( "$package_arch" == amd64 || "$package_arch" == all ) ]] || {
    echo "invalid prestate package identity" >&2
    exit 1
  }
  [[ "$digest" =~ ^[a-f0-9]{128}$ && "$size" =~ ^[0-9]+$ ]]
  archive=$cache/packages-v2/objects/sha512-$digest
  [[ -f "$archive" && ! -L "$archive" ]]
  [[ $(stat -c '%s' "$archive") == "$size" ]]
  printf '%s  %s\n' "$digest" "$archive" | sha512sum --check --status
  case "$name" in
    libc6|dash|bash|gnu-coreutils|coreutils|coreutils-from-gnu|dpkg|libmd0|libbz2-1.0|liblzma5|libselinux1|libzstd1|zlib1g|libacl1|libattr1|libgmp10|libssl3t64|libsystemd0|libpcre2-8-0|libgcc-s1|libcrypt1|perl-base|mawk|sed|grep|findutils|tar|gzip|debianutils|debconf)
      bootstrap+=("$archive") ;;
    util-linux) util_linux=$archive ;;
    libcap-ng0) libcap_ng=$archive ;;
  esac
done <"$evidence/reference-archives.tsv"
(( ${#bootstrap[@]} == 30 )) && [[ -n "$util_linux" && -n "$libcap_ng" ]] || {
  echo "prestate bootstrap tool closure is incomplete" >&2
  exit 1
}

# Same unregistered bootstrap as tools/real-snapshot-reference.sh.
root=$build/root
mkdir -p "$root/usr/bin" "$root/usr/sbin" "$root/usr/lib" "$root/usr/lib64" \
  "$root/var/lib/dpkg/"{info,triggers,updates} "$root/dev" "$root/proc" \
  "$root/tmp" "$root/var/tmp"
chmod 755 "$root/dev" "$root/proc"
chmod 1777 "$root/tmp" "$root/var/tmp"
mknod -m 666 "$root/dev/null" c 1 3
ln -s usr/bin "$root/bin"
ln -s usr/sbin "$root/sbin"
ln -s usr/lib "$root/lib"
ln -s usr/lib64 "$root/lib64"
: >"$root/var/lib/dpkg/status"
# The launcher binds each archive onto this mountpoint and requires it to
# already exist as an empty root-owned 0600 file, as in
# tools/real-snapshot-reference.sh.
: >"$root/.debz-reference-archive"
chmod 0600 "$root/.debz-reference-archive"
for archive in "${bootstrap[@]}"; do
  dpkg-deb --extract "$archive" "$root"
done
# Every archive carries ./ with mode 0755, so extraction widens the root that
# the launcher requires to be exactly 0700. Same remedy as
# tools/real-snapshot-reference.sh.
chmod 0700 "$root"
printf 'reference_dpkg_sha256=%s\nreference_lock_sha256=%s\nrelease_sha256=%s\nclosure_sha256=%s\nbootstrap_archives=%s\n' \
  "$(sha256sum "$pinned" | cut -d' ' -f1)" "$(sha256sum "$lock" | cut -d' ' -f1)" \
  "$release_sha256" "$closure_sha256" "${#bootstrap[@]}" >"$evidence/reference-identity.txt"
launcher=$tools/reference-launcher
"$zig" build-exe tools/real-snapshot-reference-launcher.zig -O ReleaseSafe -lc \
  --zig-lib-dir "$(dirname -- "$zig")/lib" \
  --cache-dir "$tools/zig-cache" \
  --global-cache-dir "$tools/zig-global-cache" \
  -femit-bin="$launcher"
chmod 0500 "$launcher"
require_protected_file "$launcher"

# This oracle has only the four reviewed packages registered. Its one possible
# libc6 callback is denied before exec; --pending is never used on the closure.
dpkg-deb --fsys-tarfile "$util_linux" | tar -xO ./usr/bin/setpriv >"$tools/setpriv"
chmod 0755 "$tools/setpriv"
[[ $(sha256sum "$tools/setpriv" | cut -d' ' -f1) == "$setpriv_sha256" ]]
sha256sum "$tools/setpriv" >"$tools/setpriv.sha256"
# setpriv needs libcap-ng.so.0, absent from the unchanged 30-archive bootstrap.
dpkg-deb --fsys-tarfile "$libcap_ng" |
  tar -xO ./usr/lib/x86_64-linux-gnu/libcap-ng.so.0.0.0 >"$tools/libcap-ng.so.0.0.0"
chmod 0644 "$tools/libcap-ng.so.0.0.0"
require_protected_file "$tools/libcap-ng.so.0.0.0"
[[ $(stat -c '%s' "$tools/libcap-ng.so.0.0.0") == 26928 &&
   $(sha256sum "$tools/libcap-ng.so.0.0.0" | cut -d' ' -f1) == "$setpriv_runtime_sha256" ]]
env -i PATH="$PATH" LC_ALL=C PYTHONDONTWRITEBYTECODE=1 TMPDIR="$build/tmp" \
  unshare --mount --propagation private -- \
  timeout --signal=TERM --kill-after=30s 5m \
  python3 tools/real-snapshot-reference-order.py \
    --launcher "$launcher" --architecture amd64 \
    --dpkg "$pinned" --root "$root" --cache "$cache" --evidence "$evidence" \
    --prove-base-cycle "$tools/setpriv"
[[ -s "$evidence/base-cycle-proof/comparison.json" ]]

if [[ $purpose == python3 ]]; then
  env -i PATH="$PATH" LC_ALL=C PYTHONDONTWRITEBYTECODE=1 TMPDIR="$build/tmp" \
    unshare --mount --propagation private -- \
    timeout --signal=TERM --kill-after=30s 20m \
    python3 -B tools/real-snapshot-reference-order.py \
      --launcher "$launcher" --architecture amd64 \
      --dpkg "$pinned" --root "$root" --cache "$cache" --evidence "$evidence" \
      --prestate "python3:amd64=unpacked:$prestates/python3"
  [[ $(cat "$prestates/prestates.tsv") == \
    "$(printf 'python3:amd64\t3.14.3-0ubuntu2 install ok unpacked\t%s' "$prestates/python3")" ]]
  printf 'PYTHON3_PRESTATE=%s\n' "$prestates/python3" >"$workspace/prestates.env"
  echo "protected Python pre-configure source captured; no full reference completion claimed"
  exit 0
fi

env -i PATH="$PATH" LC_ALL=C PYTHONDONTWRITEBYTECODE=1 TMPDIR="$build/tmp" \
  unshare --mount --propagation private -- \
  timeout --signal=TERM --kill-after=30s 20m \
  python3 tools/real-snapshot-reference-order.py \
    --launcher "$launcher" --architecture amd64 \
    --dpkg "$pinned" --root "$root" --cache "$cache" --evidence "$evidence" \
    --prestate "systemd:amd64=half-configured:$prestates/systemd" \
    --prestate "udev:amd64=half-configured:$prestates/udev" \
    --prestate "sudo:amd64=unpacked:$prestates/sudo"
dpkg-query --admindir="$root/var/lib/dpkg" \
  -W -f='${db:Status-Abbrev} ${binary:Package} ${Version}\n' >"$evidence/stopped-installed.txt"
[[ -z $(find "$root/proc" -mindepth 1 -print -quit) ]]
rm -rf --one-file-system -- "$root" "$build/tmp"

expected_record=$(printf '%s\t%s\t%s\n' \
  systemd:amd64 '259.5-0ubuntu3.4 install ok half-configured' "$prestates/systemd" \
  udev:amd64 '259.5-0ubuntu3.4 install ok half-configured' "$prestates/udev" \
  sudo:amd64 '1.9.17p2-1ubuntu3.1 install ok unpacked' "$prestates/sudo" | LC_ALL=C sort)
actual_record=$(LC_ALL=C sort -- "$prestates/prestates.tsv")
[[ $actual_record == "$expected_record" ]] || {
  echo "signed prestate record differs from exact requested selectors/statuses/destinations" >&2
  exit 1
}

require_control() { # root name:size:mode:sha256
  local name size mode digest file
  IFS=: read -r name size mode digest <<<"$2"
  file=$1/$name
  require_protected_file "$file"
  [[ $(stat -c '%u:%g:%s:%a:%h' "$file") == "0:0:$size:$mode:1" &&
     $(sha256sum "$file" | cut -d' ' -f1) == "$digest" ]] || {
    echo "prestate control changed: $file" >&2
    return 1
  }
}
require_prestate() { # package status control
  local target=$prestates/$1
  require_protected_path "$target"
  [[ $(stat -c '%u:%g:%a' "$target") == 0:0:700 ]]
  [[ ! -L "$target/proc" && $(stat -c '%u:%g:%a' "$target/proc") == 0:0:755 ]]
  [[ -z $(find "$target/proc" -mindepth 1 -print -quit) ]]
  [[ $(dpkg-query --admindir="$target/var/lib/dpkg" -W -f='${Version} ${Status}' "$1") == "$2" ]]
  require_control "$target" "$3"
  require_control "$target" "$signed_dpkg"
  [[ ! -e "$target/usr/bin/setpriv" && ! -L "$target/usr/bin/setpriv" ]]
}
require_prestate systemd '259.5-0ubuntu3.4 install ok half-configured' \
  'var/lib/dpkg/info/systemd.postinst:5037:755:d9df6a03ccb6b557c16ac1c674557a66c1db290f3c6d3cadbef335e0ce74e31d'
require_prestate udev '259.5-0ubuntu3.4 install ok half-configured' \
  'var/lib/dpkg/info/udev.postinst:2578:755:b7892e975bcce896c4938c2219a244fa03863d5eff37cd2eb66d2b8540f14606'
require_prestate sudo '1.9.17p2-1ubuntu3.1 install ok unpacked' \
  'var/lib/dpkg/info/sudo.postinst:1747:755:fd4c65932ab3ab7ce90c3633c42b8ee7a36af2c8292142d6e0cd134dda4c6383'

# The signed sudo binding pins the original archive-derived ownership bytes.
list=$prestates/sudo/var/lib/dpkg/info/sudo.list
require_protected_file "$list"
[[ $(stat -c '%u:%g:%a:%h' "$list") == 0:0:644:1 ]]
require_control "$prestates/sudo" \
  'var/lib/dpkg/info/sudo.list:2376:644:39fe94bdbeab0a80b3aaeae4cfa258be578949b791aeb06875ddf9d488387bc8'
# The pre-sudo record is sudo-rs's registration before sudo's postinst.
require_control "$prestates/sudo" \
  'var/lib/dpkg/alternatives/sudo:464:644:4f50d77a8e6f76e51745762486caec36324433ea7b09aac48274624c70e46da6'
[[ $(dpkg-query --admindir="$prestates/sudo/var/lib/dpkg" -W \
  -f='${Version} ${Status}' sudo-rs) == '0.2.13-0ubuntu1.2 install ok installed' ]]
for link in 'usr/bin/sudoedit:/etc/alternatives/sudoedit' \
  'usr/share/man/man8/sudoedit.8.gz:/etc/alternatives/sudoedit.8.gz'; do
  [[ -L "$prestates/sudo/${link%%:*}" &&
     $(readlink -- "$prestates/sudo/${link%%:*}") == "${link#*:}" ]]
done

# Udev's signed static-node permissions only adjust existing paths. These are
# regular files, never host device nodes, as in the recorded pinned proof.
for node in dev/kvm dev/fuse dev/snd/seq; do
  [[ ! -e "$prestates/udev/$node" && ! -L "$prestates/udev/$node" ]]
done
install -d -o root -g root -m 0755 "$prestates/udev/dev/snd"
for node in dev/kvm dev/fuse dev/snd/seq; do
  install -o root -g root -m 0600 /dev/null "$prestates/udev/$node"
done

printf 'SIGNED_SYSTEMD_PRESTATE=%s\nSIGNED_UDEV_PRESTATE=%s\nSIGNED_SUDO_PRESTATE=%s\nREFERENCE_SETPRIV=%s\n' \
  "$prestates/systemd" "$prestates/udev" "$prestates/sudo" "$tools/setpriv" \
  >"$workspace/prestates.env"
printf 'release_sha256=%s\nclosure_sha256=%s\nprestates=3\n' "$release_sha256" "$closure_sha256"
cat "$prestates/prestates.tsv"
