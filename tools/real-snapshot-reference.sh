#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH
unset ZIG_LIB_DIR
export PYTHONNOUSERSITE=1

[[ $# == 5 ]] || {
  echo "usage: $0 REFERENCE_DPKG LOCK CACHE ARCHITECTURE WORKSPACE" >&2
  exit 2
}
reference_dpkg=$1
lock=$2
cache=$3
zig=${DEBZ_ZIG:-$(command -v zig || true)}
architecture=$4
workspace=$(realpath -m "$5")
repository_root=$(pwd -P)
script_path=$(realpath -- "${BASH_SOURCE[0]}")
[[ "$script_path" == "$repository_root/tools/real-snapshot-reference.sh" ]] || {
  echo "run the protected reference script from its checkout root" >&2
  exit 2
}
python3 -I - "$repository_root" "$workspace" "$reference_dpkg" "$lock" "$cache" "$zig" <<'PY'
import os
import stat
import sys
from pathlib import Path

def protected(path, directory=False):
    if not path.is_absolute() or any(
        item in ("", ".", "..") for item in str(path).split("/")[1:]
    ):
        raise ValueError(f"noncanonical reference path: {path}")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, component in enumerate(path.parts[1:]):
            last = index == len(path.parts) - 2
            opened = os.open(
                component, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                (os.O_DIRECTORY if not last or directory else 0),
                dir_fd=fd,
            )
            os.close(fd)
            fd = opened
            info = os.fstat(fd)
            if (info.st_uid != 0 or info.st_gid != 0 or
                stat.S_IMODE(info.st_mode) & 0o022 or
                ((not last or directory) and not stat.S_ISDIR(info.st_mode)) or
                (last and not directory and not stat.S_ISREG(info.st_mode))):
                raise ValueError(f"non-root or writable reference path: {path}")
        return os.fstat(fd)
    finally:
        os.close(fd)

repository, workspace, dpkg, lock, cache = map(Path, sys.argv[1:6])
for path in (repository, repository / ".real-snapshot", workspace, cache):
    result = protected(path, directory=True)
    if path in (repository / ".real-snapshot", workspace) and result.st_mode & 0o7777 != 0o700:
        raise ValueError(f"reference directory must be root-only 0700: {path}")
for path in (repository / "tools/real-snapshot-reference.sh",
             repository / "tools/real-snapshot-reference-launcher.zig",
             repository / "tools/real-snapshot-reference-runtime.zig",
             repository / "src/private_network.zig",
             repository / "tools/real-snapshot-reference-order.py",
             repository / "tools/real_snapshot_reference_paths.py",
             repository / "tools/prepare-native-dpkg.py",
             repository / "tools/native-differential.py",
             dpkg, lock, workspace / "evidence/create.json"):
    protected(path)
protected(workspace / "evidence", directory=True)
protected(cache / "packages-v2/objects", directory=True)
protected(repository / "tools/real_snapshot_reference_paths.py")
sys.path.insert(0, str(repository / "tools"))
from real_snapshot_reference_paths import toolchain
if not sys.argv[6]:
    raise ValueError("an explicit absolute protected DEBZ_ZIG compiler is required")
toolchain(Path(sys.argv[6]))
PY
case "$workspace" in
  "$repository_root"/.real-snapshot/*) ;;
  *) echo "unsafe reference workspace" >&2; exit 2 ;;
esac
case "$(uname -m):$architecture" in
  x86_64:amd64|aarch64:arm64) ;;
  *) echo "reference runner architecture does not match $architecture" >&2; exit 2 ;;
esac
[[ -f "$reference_dpkg" && -x "$reference_dpkg" && ! -L "$1" ]]
[[ -f "$lock" && ! -L "$2" && -d "$cache/packages-v2/objects" ]]
[[ "$lock" == "$workspace/evidence/ubuntu-minimal.lock.json" ]]
[[ "$cache" == "$workspace/cache" ]]
[[ -f "$workspace/evidence/create.json" ]]
jq -e '.exit_status == 0 and .changed == true' \
  "$workspace/evidence/create.json" >/dev/null

reference_root=$workspace/reference-root
evidence=$workspace/evidence
[[ ! -e "$reference_root" && ! -L "$reference_root" ]] || {
  echo "reference root must be new: $reference_root" >&2
  exit 2
}
for name in reference-archives.tsv reference-install.stdout reference-install.stderr \
  reference-identity.txt reference-installed.txt reference.snapshot.json; do
  [[ ! -e "$evidence/$name" && ! -L "$evidence/$name" ]] || {
    echo "reference evidence must be new: $evidence/$name" >&2
    exit 2
  }
done
[[ ! -e "$workspace/reference-launcher" && ! -L "$workspace/reference-launcher" ]] || {
  echo "reference launcher must be new" >&2
  exit 2
}
jq -e --arg arch "$architecture" '
  .schema == "https://debz.dev/schema/exact-closure-lock-v3" and
  .version == 3 and .target_architecture == $arch and
  (.packages | length) > 0 and
  all(.packages[]; .archive_identity.primary == "sha512" and
    ([.archive_identity.digests[] | select(.algorithm == "sha512")] | length) == 1)
' "$lock" >/dev/null
jq -r '
  .packages[] |
  [.name, .version, .architecture,
   (.archive_identity.digests[] | select(.algorithm == "sha512") | .digest),
   .declared_size] | @tsv
' "$lock" >"$evidence/reference-archives.tsv"

bootstrap=()
while IFS=$'\t' read -r name version package_arch digest size; do
  [[ "$name" =~ ^[a-z0-9][a-z0-9+.-]*$ &&
     "$version" != *$'\t'* && "$version" != *$'\n'* &&
     ( "$package_arch" == "$architecture" || "$package_arch" == all ) ]] || {
    echo "invalid reference package identity" >&2
    exit 1
  }
  [[ "$digest" =~ ^[a-f0-9]{128}$ && "$size" =~ ^[0-9]+$ ]]
  archive=$cache/packages-v2/objects/sha512-$digest
  [[ -f "$archive" && ! -L "$archive" ]]
  [[ $(stat -c '%u:%g' "$archive") == 0:0 ]]
  (( ($(stat -c '0%a' "$archive") & 022) == 0 ))
  [[ $(stat -c '%s' "$archive") == "$size" ]]
  printf '%s  %s\n' "$digest" "$archive" | sha512sum --check --status
  case "$name" in
    libc6|dash|bash|gnu-coreutils|coreutils|coreutils-from-gnu|dpkg|libmd0|libbz2-1.0|liblzma5|libselinux1|libzstd1|zlib1g|libacl1|libattr1|libgmp10|libssl3t64|libsystemd0|libpcre2-8-0|libgcc-s1|libcrypt1|perl-base|mawk|sed|grep|findutils|tar|gzip|debianutils|debconf)
      bootstrap+=("$archive") ;;
  esac
done <"$evidence/reference-archives.tsv"
if (( ${#bootstrap[@]} != 30 )); then
  echo "reference bootstrap tool closure is incomplete" >&2
  exit 1
fi
python3 tools/prepare-native-dpkg.py --architecture "$architecture" \
  --verify-only "$reference_dpkg"

mkdir -m 0700 "$reference_root"
mkdir -p "$reference_root/usr/bin" "$reference_root/usr/sbin" \
  "$reference_root/usr/lib" "$reference_root/usr/lib64" \
  "$reference_root/var/lib/dpkg/"{info,triggers,updates} "$reference_root/dev" \
  "$reference_root/proc" "$reference_root/tmp" "$reference_root/var/tmp"
chmod 755 "$reference_root/dev" "$reference_root/proc"
chmod 1777 "$reference_root/tmp" "$reference_root/var/tmp"
mknod -m 666 "$reference_root/dev/null" c 1 3
ln -s usr/bin "$reference_root/bin"
ln -s usr/sbin "$reference_root/sbin"
ln -s usr/lib "$reference_root/lib"
ln -s usr/lib64 "$reference_root/lib64"
: >"$reference_root/var/lib/dpkg/status"
: >"$reference_root/.debz-reference-archive"
chmod 0600 "$reference_root/.debz-reference-archive"

# The oracle alone receives exact-lock payloads for its chrooted script
# interpreter and tools; no package database entries are preinstalled.
for archive in "${bootstrap[@]}"; do
  dpkg-deb --extract "$archive" "$reference_root"
done
[[ -x "$reference_root/usr/bin/dash" ]]
[[ -x "$reference_root/usr/bin/bash" ]]
[[ -x "$reference_root/usr/bin/perl" ]]
[[ -L "$reference_root/usr/bin/sh" &&
   $(readlink "$reference_root/usr/bin/sh") == dash ]]
chmod 0700 "$reference_root"

printf 'reference_dpkg_sha256=%s\nreference_lock_sha256=%s\nbootstrap_archives=%s\n' \
  "$(sha256sum "$reference_dpkg" | cut -d' ' -f1)" \
  "$(sha256sum "$lock" | cut -d' ' -f1)" "${#bootstrap[@]}" \
  >"$evidence/reference-identity.txt"
launcher="$workspace/reference-launcher"
"$zig" build-exe -O ReleaseSafe -lc --dep private_network \
  -Mroot=tools/real-snapshot-reference-launcher.zig -Mprivate_network=src/private_network.zig \
  --zig-lib-dir "$(dirname -- "$zig")/lib" \
  --cache-dir "$workspace/reference-zig-cache" \
  --global-cache-dir "$workspace/reference-zig-global-cache" \
  -femit-bin="$launcher"
chmod 0500 "$launcher"
"$zig" build build-reference-runtime -Doptimize=ReleaseSafe \
  --cache-dir "$workspace/reference-zig-cache" \
  --global-cache-dir "$workspace/reference-zig-global-cache" \
  --prefix "$workspace/runtime-tool"
runtime="$workspace/reference-runtime"
"$workspace/runtime-tool/bin/debz-reference-runtime" record \
  "$architecture" "$lock" "$cache" "$reference_dpkg" "$runtime"
cp -- "$runtime/binding.json" "$evidence/reference-runtime-binding.json"
timeout --signal=TERM --kill-after=30s 40m \
  python3 tools/real-snapshot-reference-order.py \
    --launcher "$launcher" --runtime "$runtime" --architecture "$architecture" \
    --dpkg "$reference_dpkg" --root "$reference_root" \
    --cache "$cache" --evidence "$evidence"
python3 tools/real-snapshot-reference-order.py \
  --report-only --architecture "$architecture" \
  --root "$reference_root" --cache "$cache" --evidence "$evidence"
grep -Eq '^ii  ubuntu-minimal(:[^ ]+)? ' "$evidence/reference-installed.txt"
[[ -c "$reference_root/dev/null" && ! -L "$reference_root/dev/null" &&
   $(stat -c '%t:%T' "$reference_root/dev/null") == 1:3 ]]
device_claim=0
grep -Fqx '/dev/null' "$reference_root/var/lib/dpkg/info/"*.list || device_claim=$?
if (( device_claim != 1 )); then
  echo "reference package claims excluded chroot device" >&2
  exit 1
fi
[[ -f "$reference_root/.debz-reference-archive" &&
   ! -L "$reference_root/.debz-reference-archive" &&
   $(stat -c '%s' "$reference_root/.debz-reference-archive") == 0 ]]
rm -- "$reference_root/.debz-reference-archive"
zig-out/bin/native-differential capture \
  --root "$reference_root" \
  --exclude dev/null \
  --output "$evidence/reference.snapshot.json"
