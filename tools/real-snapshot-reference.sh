#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $# == 5 ]] || {
  echo "usage: $0 REFERENCE_DPKG LOCK CACHE ARCHITECTURE WORKSPACE" >&2
  exit 2
}
reference_dpkg=$(realpath "$1")
lock=$(realpath "$2")
cache=$(realpath "$3")
architecture=$4
workspace=$(realpath -m "$5")
repository_root=$(pwd -P)
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

archives=()
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
  [[ $(stat -c '%s' "$archive") == "$size" ]]
  printf '%s  %s\n' "$digest" "$archive" | sha512sum --check --status
  archives+=("$archive")
  case "$name" in
    libc6|dash|coreutils|dpkg) bootstrap+=("$archive") ;;
  esac
done <"$evidence/reference-archives.tsv"
(( ${#archives[@]} > 0 && ${#bootstrap[@]} == 4 ))

mkdir -p "$reference_root/usr/bin" "$reference_root/usr/sbin" \
  "$reference_root/usr/lib" "$reference_root/usr/lib64" \
  "$reference_root/var/lib/dpkg/"{info,triggers,updates}
ln -s usr/bin "$reference_root/bin"
ln -s usr/sbin "$reference_root/sbin"
ln -s usr/lib "$reference_root/lib"
ln -s usr/lib64 "$reference_root/lib64"
: >"$reference_root/var/lib/dpkg/status"
: >"$reference_root/var/lib/dpkg/available"

# The oracle alone receives exact-lock payloads for its chrooted script
# interpreter and tools; no package database entries are preinstalled.
for archive in "${bootstrap[@]}"; do
  dpkg-deb --extract "$archive" "$reference_root"
done
[[ -x "$reference_root/usr/bin/dash" ]]
[[ -L "$reference_root/usr/bin/sh" &&
   $(readlink "$reference_root/usr/bin/sh") == dash ]]

printf 'reference_dpkg_sha256=%s\nreference_lock_sha256=%s\nbootstrap_archives=%s\n' \
  "$(sha256sum "$reference_dpkg" | cut -d' ' -f1)" \
  "$(sha256sum "$lock" | cut -d' ' -f1)" "${#bootstrap[@]}" \
  >"$evidence/reference-identity.txt"
timeout --signal=TERM --kill-after=30s 40m \
  "$reference_dpkg" --root="$reference_root" \
  --force-not-root --force-bad-path --install "${archives[@]}" \
  >"$evidence/reference-install.stdout" 2>"$evidence/reference-install.stderr"
dpkg-query --admindir="$reference_root/var/lib/dpkg" \
  -W -f='${db:Status-Abbrev} ${binary:Package} ${Version}\n' \
  >"$evidence/reference-installed.txt"
grep -Eq '^ii  ubuntu-minimal(:[^ ]+)? ' "$evidence/reference-installed.txt"
if grep -Evq '^ii  ' "$evidence/reference-installed.txt"; then
  echo "reference dpkg database contains unconfigured packages" >&2
  exit 1
fi
python3 tools/native-differential.py capture \
  --root "$reference_root" \
  --output "$evidence/reference.snapshot.json"
