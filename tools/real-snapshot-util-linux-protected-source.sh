#!/usr/bin/env bash
# Decode real ARM helper sources independently. No package script is executed.
set -euo pipefail
umask 077
[[ $# == 4 && $(id -u) == 0 && $(id -g) == 0 && $(uname -m) == aarch64 ]] || {
  echo "usage (root on disposable hosted ARM): $0 PROTECTED_ZIG ORIGINAL_FULL_LOCK ORIGINAL_CAS NEW_WORKSPACE" >&2
  exit 2
}
checkout=$(pwd -P)
zig=$1 lock=$2 cache=$3 workspace=$4
[[ "$workspace" == "$checkout/.real-snapshot/bash-arm64/arm-util-linux-source" &&
  ! -e "$workspace" && ! -L "$workspace" ]]
evidence=${workspace%/arm-util-linux-source}/evidence
export PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH ZIG_LIB_DIR
mkdir -m 0700 "$workspace"
mkdir -m 0700 "$workspace/extracted"
env "TMPDIR=$checkout/.zig-cache/data" "$zig" build build-arm64-util-linux-authority \
  -Doptimize=ReleaseSafe -j2 --summary all
inspector=$checkout/zig-out/bin/debz-arm-util-linux-authority
"$inspector" --protected source "$lock" "$cache" "$evidence/util-linux-helper-native-source.json"
packages=(dash dpkg init-system-helpers libblkid1 libc6 libcrypt1 libmount1
  libpcre2-8-0 libselinux1 libssl3t64 libsystemd-shared libtinfo6 perl-base systemd util-linux)
for package in "${packages[@]}"; do
  record=$(jq -er --arg name "$package" '
    [.packages[] | select(.name == $name)] |
    if length != 1 then error("ambiguous original source") else .[0] |
      if .origin.type != "authenticated_repository" or .archive_identity.primary != "sha512"
      then error("unauthenticated original source") else
      [.declared_size, (.archive_identity.digests[] | select(.algorithm == "sha512") | .digest)] | @tsv end end' "$lock")
  IFS=$'\t' read -r size digest <<<"$record"
  [[ "$size" =~ ^[0-9]+$ && "$digest" =~ ^[a-f0-9]{128}$ ]]
  object=$cache/sha512-$digest
  [[ -f "$object" && ! -L "$object" && $(stat -c %s "$object") == "$size" &&
    $(sha512sum "$object" | cut -d' ' -f1) == "$digest" ]]
  mkdir -m 0700 "$workspace/extracted/$package"
  timeout --signal=TERM --kill-after=5s 60s \
    /usr/bin/dpkg-deb --extract "$object" "$workspace/extracted/$package"
done
"$inspector" --protected compare "$lock" "$cache" "$workspace/extracted" "$evidence/util-linux-helper-independent-source.json"
jq -e '
  .callback_admitted == false and .runtime_proved == false and
  .independent_extraction_compared == true and (.sources | length) == 15 and
  ([.sources[] | select(.package == "perl-base") | .members[] |
    select(.path == "usr/bin/perl" or .path == "usr/bin/perl5.40.1") |
    .hardlink_count] == [2, 2])
' "$evidence/util-linux-helper-independent-source.json" >/dev/null
echo "original ARM helper Perl hardlink and pager fstrim library sources compared; callback and runtime permission withheld"
