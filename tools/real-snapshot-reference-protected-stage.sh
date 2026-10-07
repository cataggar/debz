#!/usr/bin/env bash
# Stage root-owned inputs for `zig build test-real-snapshot-reference-protected`
# on the native architecture: a ReleaseSafe launcher, the hash-pinned Debian
# dpkg 1.22.22, a script-free template whose loader, libraries and tar come
# from an authenticated snapshot closure, a script-free proof archive, a
# static escape-probe archive, on amd64 the signed systemd/udev/sudo postinsts
# the launcher's proc profiles bind, and a new empty proof workspace. It does
# not run the proof and never proves runtime binding (#263).
set -euo pipefail
umask 077
trap 'echo "protected staging failed at line $LINENO" >&2' ERR
purpose=proof
if [[ ${1:-} == --arm64-less-source ]]; then
  purpose=arm64-less
  shift
fi

readonly snapshot_uri=https://snapshot.ubuntu.com/ubuntu/20261001T000000Z
# The launcher binds amd64 proc-profile postinsts by exact version, size and
# digest, so the staged profiles and runtime closure must come from the pinned
# resolute series. The frozen base pocket never satisfies an age window: bind
# its exact Release digest and use the fresh updates/security pockets only as
# witnesses and package overlays, matching the reviewed real-snapshot pin.
readonly snapshot_suite=resolute
readonly snapshot_witness_suites=(resolute-updates resolute-security)
readonly maximum_release_age_seconds=$((31 * 24 * 60 * 60))
readonly frozen_release_sha256=596ee4cea058f74d59e2180532c89904e306d90725d42162eda82c01d4370834
readonly keyring=${DEBZ_REAL_SNAPSHOT_KEYRING:-}
# The distribution dpkg's locked dependency closure supplies every runtime
# library and tar the pinned Debian dpkg and its helpers load in the root.
readonly closure_root=dpkg
readonly runtime_packages=(libc6 libacl1 libbz2-1.0 liblzma5 libmd0 libpcre2-8-0
  libselinux1 libzstd1 zlib1g tar)

[[ $# == 3 && $(id -u) == 0 && $(id -g) == 0 ]] || {
  echo "usage (as root): $0 PROTECTED_ZIG PROTECTED_DEBZ NEW_WORKSPACE" >&2
  exit 2
}

require_protected_path() {
  local path=$1 current=/ remainder=${1#/} component metadata
  [[ "$path" == /* ]] || return 2
  while :; do
    [[ -d "$current" && ! -L "$current" ]] || {
      echo "staging path is not a real directory: $current" >&2
      return 2
    }
    metadata=$(stat -c '%u:%g:%a' -- "$current")
    [[ "$metadata" =~ ^0:0:[0-7]{3,4}$ ]] && (( (8#${metadata##*:} & 022) == 0 )) || {
      echo "staging path is not root-owned and protected: $current (uid:gid:mode=$metadata; expected 0:0 with no group/world write bits)" >&2
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
  local metadata
  require_protected_path "$(dirname -- "$1")"
  [[ -f "$1" && ! -L "$1" ]] || return 2
  metadata=$(stat -c '%u:%g:%a' -- "$1")
  [[ "$metadata" =~ ^0:0:[0-7]{3,4}$ ]] && (( (8#${metadata##*:} & 022) == 0 )) || {
    echo "staging file is not root-owned and protected: $1 (uid:gid:mode=$metadata; expected 0:0 with no group/world write bits)" >&2
    return 2
  }
}

repository_root=$(pwd -P)
script_path=$(realpath -- "${BASH_SOURCE[0]}")
[[ "$script_path" == "$repository_root/tools/real-snapshot-reference-protected-stage.sh" ]] || {
  echo "run the protected staging script from its checkout root" >&2
  exit 2
}
for input in tools/real-snapshot-reference-protected-stage.sh \
  tools/real-snapshot-reference-launcher.zig tools/real-snapshot-reference-escape-probe.zig \
  tools/prepare-native-dpkg.py tools/real_snapshot_reference_paths.py; do
  require_protected_file "$repository_root/$input"
done
require_protected_path "$repository_root/.real-snapshot"
[[ $(stat -c '%u:%g:%a' "$repository_root/.real-snapshot") == 0:0:700 ]] || {
  echo "the staging directory must be root-owned and mode 0700" >&2
  exit 2
}
zig=$1
debz=$(realpath -- "$2")
workspace=$(realpath -m -- "$3")
require_protected_file "$zig"
require_protected_path "$(dirname -- "$zig")/lib"
python3 -I - "$repository_root/tools" "$zig" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import toolchain
print(toolchain(Path(sys.argv[2])))
PY
require_protected_file "$debz"
require_protected_file "$keyring"
[[ -x "$zig" && -x "$debz" ]]
case "$workspace" in
  "$repository_root"/.real-snapshot/*) ;;
  *) echo "the workspace must be beneath this checkout's .real-snapshot" >&2; exit 2 ;;
esac
require_protected_path "$(dirname -- "$workspace")"
[[ ! -e "$3" && ! -L "$3" && ! -e "$workspace" && ! -L "$workspace" ]] || {
  echo "the staging workspace must be new: $workspace" >&2
  exit 2
}
case "$(uname -m)" in
  x86_64) architecture=amd64 loader=usr/lib64/ld-linux-x86-64.so.2 ;;
  aarch64) architecture=arm64 loader=usr/lib/ld-linux-aarch64.so.1 ;;
  *) echo "unsupported native reference architecture" >&2; exit 2 ;;
esac
closure_args=("$closure_root")
if [[ $purpose == arm64-less ]]; then
  [[ $architecture == arm64 ]]
  closure_args+=(less dash util-linux)
fi
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH
unset ZIG_LIB_DIR
export PYTHONNOUSERSITE=1 LC_ALL=C SOURCE_DATE_EPOCH=0

install -d -o root -g root -m 0700 "$workspace"
evidence=$workspace/evidence
snapshot=$workspace/snapshot
install -d -o root -g root -m 0700 "$evidence" "$snapshot" "$snapshot/root" \
  "$snapshot/cache" "$snapshot/state" "$workspace/build" "$workspace/packages"

# Authenticated runtime closure for the chrooted pinned dpkg and its helpers.
source_dir=$snapshot/sources
config_dir=$snapshot/config
install -d -o root -g root -m 0700 "$source_dir" "$config_dir"
write_source() {
  local target=$1 suite_name=$2
  cat >"$target" <<EOF
Types: deb
URIs: $snapshot_uri
Suites: $suite_name
Components: main
Architectures: $architecture
Signed-By: $keyring
EOF
}
write_source "$source_dir/$snapshot_suite.sources" "$snapshot_suite"
printf '{"source_path":"%s","priority":500,"immutable":true,"freshness":{"mode":"frozen_release_with_witnesses","frozen_release_digest":"sha256:%s","witness_suites":["%s","%s"]}}\n' \
  "$source_dir/$snapshot_suite.sources" "$frozen_release_sha256" \
  "${snapshot_witness_suites[0]}" "${snapshot_witness_suites[1]}" \
  >"$config_dir/$snapshot_suite.json"
config_args=(--config "$config_dir/$snapshot_suite.json")
for witness in "${snapshot_witness_suites[@]}"; do
  write_source "$source_dir/$witness.sources" "$witness"
  printf '{"source_path":"%s","priority":500,"immutable":true,"freshness":{"mode":"allow_missing_valid_until_with_max_age_seconds","maximum_release_age_seconds":%s}}\n' \
    "$source_dir/$witness.sources" "$maximum_release_age_seconds" \
    >"$config_dir/$witness.json"
  config_args+=(--config "$config_dir/$witness.json")
done
lock=$evidence/runtime.lock.json
common=(
  --cache-path "$snapshot/cache"
  --state-path "$snapshot/state"
  --architecture "$architecture"
  "${config_args[@]}"
  --keyring "$keyring"
  --deadline-ms 300000
  --lock-wait-ms 30000
  --json
)
debz_step() { # evidence-name debz-command install-root arguments...
  local name=$1 command=$2 install_root=$3
  shift 3
  timeout --signal=TERM --kill-after=30s 20m "$debz" "$command" \
    --install-root "$install_root" "${common[@]}" "$@" \
    >"$evidence/$name.json" 2>"$evidence/$name.stderr"
}
authenticated_lock() {
  jq -e --arg arch "$architecture" '
    .schema == "https://debz.dev/schema/exact-closure-lock-v3" and
    .target_architecture == $arch and
    all(.packages[]; .archive_identity.primary == "sha512" and
      ([.archive_identity.digests[] | select(.algorithm == "sha512")] | length) == 1 and
      .origin.type == "authenticated_repository")
  ' "$1" >/dev/null
}
debz_step refresh refresh "$snapshot/root" --assume-yes
debz_step plan plan "$snapshot/root" --transaction-backend native --lock-output "$lock" "${closure_args[@]}"
debz_step download download "$snapshot/root" --transaction-backend native --lock-input "$lock" "${closure_args[@]}"
authenticated_lock "$lock"

template=$workspace/template
install -d -o root -g root -m 0700 "$template"
install -d -o root -g root -m 0755 "$template/usr" "$template/usr/bin" \
  "$template/usr/sbin" "$template/usr/lib" "$template/usr/lib64" "$template/var" \
  "$template/var/lib" "$template/var/lib/dpkg" "$template/var/lib/dpkg/info" \
  "$template/var/lib/dpkg/triggers" "$template/var/lib/dpkg/updates" \
  "$template/dev" "$template/proc"
# dpkg --unpack extracts control members beneath TMPDIR, which defaults to /tmp.
install -d -o root -g root -m 1777 "$template/tmp"
ln -s usr/bin "$template/bin"
ln -s usr/sbin "$template/sbin"
ln -s usr/lib "$template/lib"
ln -s usr/lib64 "$template/lib64"
mknod -m 0666 "$template/dev/null" c 1 3
install -o root -g root -m 0644 /dev/null "$template/var/lib/dpkg/status"
install -o root -g root -m 0600 /dev/null "$template/.debz-reference-archive"
: >"$evidence/runtime-archives.tsv"
locked_archive() { # name [lock evidence-table] -> verified cache object path
  local record version digest size object source=${2:-$lock} table=${3:-runtime-archives.tsv}
  record=$(jq -r --arg name "$1" --arg arch "$architecture" '
    [.packages[] | select(.name == $name and .architecture == $arch)] |
    if length == 1 then .[0] | [.version,
      (.archive_identity.digests[] | select(.algorithm == "sha512") | .digest),
      .declared_size] | @tsv else empty end' "$source")
  [[ -n "$record" ]] || {
    echo "package must be locked exactly once: $1" >&2
    return 1
  }
  IFS=$'\t' read -r version digest size <<<"$record"
  [[ "$digest" =~ ^[a-f0-9]{128}$ && "$size" =~ ^[0-9]+$ ]] || return 1
  object=$snapshot/cache/packages-v2/objects/sha512-$digest
  [[ -f "$object" && ! -L "$object" && $(stat -c %s "$object") == "$size" ]] || return 1
  [[ $(sha512sum "$object" | cut -d' ' -f1) == "$digest" ]] || return 1
  printf '%s\t%s\t%s\t%s\n' "$1" "$version" "$digest" "$size" >>"$evidence/$table"
  printf '%s\n' "$object"
}
for package in "${runtime_packages[@]}"; do
  object=$(locked_archive "$package")
  dpkg-deb --extract "$object" "$template"
done
# dpkg removes its control extraction directory with rm; stage only GNU rm,
# which needs nothing beyond libc, rather than the coreutils closure.
object=$(locked_archive gnu-coreutils)
install -d -o root -g root -m 0700 "$workspace/build/gnu-coreutils"
dpkg-deb --extract "$object" "$workspace/build/gnu-coreutils"
install -o root -g root -m 0755 "$workspace/build/gnu-coreutils/usr/bin/gnurm" "$template/usr/bin/rm"
for link in bin sbin lib lib64; do
  [[ -L "$template/$link" && $(readlink "$template/$link") == "usr/$link" ]] || {
    echo "runtime extraction replaced the /$link merged-usr link" >&2
    exit 1
  }
done
[[ -f "$template/$loader" && -x "$template/usr/bin/tar" ]]

# The hash-pinned Debian dpkg; the launcher executes dpkg itself from outside
# the root and dpkg runs its pinned dpkg-deb/dpkg-split helpers inside it.
dpkg_prefix=$workspace/dpkg
python3 -I - "$repository_root/tools/prepare-native-dpkg.py" "$architecture" \
  "$workspace/build/dpkg.deb" <<'PY'
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("prepare_native_dpkg", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
_, content = module.download_archive(sys.argv[2])
target = pathlib.Path(sys.argv[3])
target.write_bytes(content)
module.verify_file(target, module.PINS[sys.argv[2]]["archive"])
PY
install -d -o root -g root -m 0755 "$dpkg_prefix"
dpkg-deb --extract "$workspace/build/dpkg.deb" "$dpkg_prefix"
python3 -I - "$repository_root/tools/prepare-native-dpkg.py" "$architecture" \
  "$dpkg_prefix/usr/bin/dpkg" "$workspace/build/dpkg.deb" <<'PY'
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("prepare_native_dpkg", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.verify_file(pathlib.Path(sys.argv[3]), module.PINS[sys.argv[2]]["executable"])
module.receipt_from_extracted_archive(
    sys.argv[2], pathlib.Path(sys.argv[4]), pathlib.Path(sys.argv[3]).parents[2])
PY
python3 -B "$repository_root/tools/prepare-native-dpkg.py" \
  --architecture "$architecture" --verify-only "$dpkg_prefix/usr/bin/dpkg"
for helper in dpkg-deb dpkg-split; do
  install -o root -g root -m 0755 "$dpkg_prefix/usr/bin/$helper" "$template/usr/bin/$helper"
done
chmod 0700 "$template"
if [[ -n $(find "$template" \( ! -user 0 -o ! -group 0 \) -print -quit) ]]; then
  echo "the template must contain only root-owned entries" >&2
  exit 1
fi
if [[ $purpose == arm64-less ]]; then
  echo "fresh authenticated arm64 less runtime template staged; no replay claimed"
  exit 0
fi

# The launcher binds its proc profiles to the signed amd64 systemd, udev and
# sudo postinsts. Lock each package alone, recording the rest of its
# authenticated closure as installed, and stage only the postinst; the proof
# checks the launcher's digest binding. Other architectures stage none.
profiles=$workspace/profiles
install -d -o root -g root -m 0755 "$profiles"
if [[ $architecture == amd64 ]]; then
  : >"$evidence/profile-archives.tsv"
  for profile in systemd udev sudo; do
    closure=$evidence/$profile-closure.lock.json
    single=$evidence/$profile.lock.json
    install -d -o root -g root -m 0700 "$snapshot/$profile-root"
    debz_step "$profile-closure-plan" plan "$snapshot/root" \
      --transaction-backend native --lock-output "$closure" "$profile"
    authenticated_lock "$closure"
    jq -r --arg name "$profile" '.packages[] | select(.name != $name) |
      "Package: \(.name)\nStatus: install ok installed\nArchitecture: \(.architecture)\nVersion: \(.version)\n"' \
      "$closure" >"$snapshot/$profile.status"
    debz_step "$profile-plan" plan "$snapshot/$profile-root" --status-path "$snapshot/$profile.status" \
      --transaction-backend native --lock-output "$single" "$profile"
    debz_step "$profile-download" download "$snapshot/$profile-root" --status-path "$snapshot/$profile.status" \
      --transaction-backend native --lock-input "$single" "$profile"
    authenticated_lock "$single"
    object=$(locked_archive "$profile" "$single" profile-archives.tsv)
    dpkg-deb --control "$object" "$workspace/build/$profile-control"
    [[ -f "$workspace/build/$profile-control/postinst" && ! -L "$workspace/build/$profile-control/postinst" ]]
    install -o root -g root -m 0644 "$workspace/build/$profile-control/postinst" "$profiles/$profile.postinst"
  done
fi

launcher=$workspace/launcher
probe=$workspace/escape-probe
"$zig" build-exe tools/real-snapshot-reference-launcher.zig -O ReleaseSafe -lc \
  --zig-lib-dir "$(dirname -- "$zig")/lib" \
  --cache-dir "$workspace/build/zig-cache" \
  --global-cache-dir "$workspace/build/zig-global-cache" \
  -femit-bin="$launcher"
"$zig" build-exe tools/real-snapshot-reference-escape-probe.zig -O ReleaseSafe -fstrip \
  --zig-lib-dir "$(dirname -- "$zig")/lib" \
  --cache-dir "$workspace/build/zig-cache" \
  --global-cache-dir "$workspace/build/zig-global-cache" \
  -femit-bin="$probe"
chmod 0500 "$launcher" "$probe"
if readelf -l "$probe" | grep -q 'program interpreter'; then
  echo "the escape probe must be static" >&2
  exit 1
fi

build_package() { # name directory
  local name=$1 source=$2
  install -d -o root -g root -m 0755 "$source/DEBIAN" "$source/usr" \
    "$source/usr/share" "$source/usr/share/$name"
  printf '%s protected reference proof\n' "$name" >"$source/usr/share/$name/marker"
  chmod 0644 "$source/usr/share/$name/marker"
  cat >"$source/DEBIAN/control" <<EOF
Package: $name
Version: 1
Architecture: $architecture
Maintainer: debz reference proof <reference-proof@debz.invalid>
Description: debz protected reference confinement proof
EOF
  chmod 0644 "$source/DEBIAN/control"
  dpkg-deb --root-owner-group -Zxz --build "$source" \
    "$workspace/packages/${name}_1_$architecture.deb" >/dev/null
}
build_package debz-reference-proof "$workspace/build/proof-package"
install -d -o root -g root -m 0755 "$workspace/build/escape-package" \
  "$workspace/build/escape-package/DEBIAN"
install -o root -g root -m 0755 "$probe" "$workspace/build/escape-package/DEBIAN/preinst"
build_package debz-reference-escape-probe "$workspace/build/escape-package"
chmod 0644 "$workspace/packages/"*.deb

proof_archive=$workspace/packages/debz-reference-proof_1_$architecture.deb
escape_archive=$workspace/packages/debz-reference-escape-probe_1_$architecture.deb
install -d -o root -g root -m 0700 "$workspace/proof"
{
  printf -- '-Dreference-protected-launcher=%s\n' "$launcher"
  printf -- '-Dreference-protected-dpkg=%s\n' "$dpkg_prefix/usr/bin/dpkg"
  printf -- '-Dreference-protected-root-template=%s\n' "$template"
  printf -- '-Dreference-protected-workspace=%s\n' "$workspace/proof"
  printf -- '-Dreference-protected-archive=%s\n' "$proof_archive"
  printf -- '-Dreference-protected-archive-sha512=%s\n' "$(sha512sum "$proof_archive" | cut -d' ' -f1)"
  printf -- '-Dreference-protected-archive-size=%s\n' "$(stat -c %s "$proof_archive")"
  printf -- '-Dreference-protected-escape-probe=%s\n' "$probe"
  printf -- '-Dreference-protected-escape-archive=%s\n' "$escape_archive"
  printf -- '-Dreference-protected-escape-archive-sha512=%s\n' "$(sha512sum "$escape_archive" | cut -d' ' -f1)"
  printf -- '-Dreference-protected-escape-archive-size=%s\n' "$(stat -c %s "$escape_archive")"
  printf -- '-Dreference-protected-profile-scripts=%s\n' "$profiles"
  printf -- '-Dreference-protected-architecture=%s\n' "$architecture"
} >"$workspace/reference-protected.args"
{
  printf 'architecture=%s\nsnapshot_uri=%s\nsnapshot_suite=%s\n' \
    "$architecture" "$snapshot_uri" "$snapshot_suite"
  printf 'snapshot_witness_suites=%s\n' "$(IFS=,; echo "${snapshot_witness_suites[*]}")"
  printf 'repository_freshness=frozen_release_with_witnesses:%s:witnesses=%s:maximum_witness_age=%s\n' \
    "$frozen_release_sha256" "$(IFS=,; echo "${snapshot_witness_suites[*]}")" \
    "$maximum_release_age_seconds"
  printf 'keyring_sha256=%s\nruntime_lock_sha256=%s\n' \
    "$(sha256sum "$keyring" | cut -d' ' -f1)" "$(sha256sum "$lock" | cut -d' ' -f1)"
  printf 'zig_sha256=%s\ndebz_sha256=%s\n' \
    "$(sha256sum "$zig" | cut -d' ' -f1)" "$(sha256sum "$debz" | cut -d' ' -f1)"
  printf 'dpkg_archive_sha256=%s\n' "$(sha256sum "$workspace/build/dpkg.deb" | cut -d' ' -f1)"
  sha256sum "$source_dir"/*.sources | sed 's#^.*/##; s#^#source_profile_sha256 #'
  sha256sum "$config_dir"/*.json | sed 's#^.*/##; s#^#repository_profile_sha256 #'
  for path in "$dpkg_prefix/usr/bin/dpkg" "$template/usr/bin/dpkg-deb" \
    "$template/usr/bin/dpkg-split" "$template/usr/bin/tar" "$template/usr/bin/rm" "$template/$loader" \
    "$launcher" "$probe" "$profiles"/*.postinst; do
    [[ -e "$path" ]] || continue
    printf 'sha256 %s %s\n' "$(sha256sum "$path" | cut -d' ' -f1)" "${path#"$workspace"/}"
  done
  for path in "$proof_archive" "$escape_archive"; do
    printf 'sha512 %s %s %s\n' "$(sha512sum "$path" | cut -d' ' -f1)" \
      "$(stat -c %s "$path")" "${path#"$workspace"/}"
  done
} >"$evidence/staging-manifest.txt"
find "$workspace" -maxdepth 1 -mindepth 1 -printf '%f %u:%g %m\n' | LC_ALL=C sort
