#!/usr/bin/env bash
# Smoke-test the immutable original debz v0.3.0 Linux release archives on a
# matching host and record independent observations of their members and
# metadata. `debz-release verify --smoke` refuses these archives because they
# predate share/debz/digest-cutover-policy.json, so this script applies the same
# smoke protocol with standard host tools only (no debz build is needed).
#
# Every input is pinned here or under security/release-originals/v0.3.0. The
# downloaded bytes are checked against these digests and their GitHub build
# provenance is verified from the committed Sigstore bundles, without
# credentials, before anything is decoded, extracted or executed.
set -euo pipefail
umask 077
trap 'echo "release-original-smoke: failed at line $LINENO" >&2' ERR
export LC_ALL=C TZ=UTC

if [[ $# -ne 2 || ( $1 != linux-x64 && $1 != linux-arm64 ) ]]; then
  echo "usage: tools/release-original-smoke.sh linux-x64|linux-arm64 <new-work-directory>" >&2
  exit 2
fi
platform=$1
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
evidence=$root/security/release-originals/v0.3.0

readonly repository=cataggar/debz
readonly download=https://github.com/cataggar/debz/releases/download/v0.3.0
readonly source_ref=refs/tags/v0.3.0
readonly source_commit=abdcd27e034a05ea25ed7e4bd5d9d44ca0242938
readonly signer=https://github.com/cataggar/debz/.github/workflows/release.yml@refs/tags/v0.3.0
readonly issuer=https://token.actions.githubusercontent.com
readonly invocation=https://github.com/cataggar/debz/actions/runs/33984408974/attempts/1
readonly predicate=https://slsa.dev/provenance/v1
readonly gzip_header=1f8b08000000000002ff
readonly stem=debz-0.3.0-$platform

case $platform in
  linux-x64)
    machine=x86_64
    gz_size=6923082
    gz_sha256=21477d40cebc41feae31ac29babe9b68c128e15eb5cf9c29a7f4cf9d063dd7e4
    xz_size=5096384
    xz_sha256=7394fcf69d0445be2207add0b0776b81e43de6b62cc467d0b71ec959e0ed3925
    tar_size=24852480
    tar_sha256=e1a0ca2589426e579923a66df47f88ddea8ef1849523f69f0ebce7e91ad6eaf8
    pins=(
      31dde61d927454219f782256be439113fbf3661e766371da17f20290a460f8e4 debz-0.3.0-linux-x64.members
      1ee9776b6ee5c6c787785383d567e9dec7faf6062122401c95f9eb92b19a7864 debz-0.3.0-linux-x64.tree
      a42159659a7de4c40ba41d36ec1d3bf469d7f200a6dae45bae15c5c205afac3c debz-0.3.0-linux-x64.contents
      2396a8148fec6a4498999808623af28e6f0523cea427560a01f4aa007c471ad4 debz-0.3.0-linux-x64.elf
    )
    ;;
  linux-arm64)
    machine=aarch64
    gz_size=6623356
    gz_sha256=01cee4e158b1542613a34311c89c2f3b175a63a10e549ecc4aa639a7fc3fa704
    xz_size=4740400
    xz_sha256=d0d156c9e019e5503fde8043becc6ab2d56a7f9512d63face1468f6f86c0d507
    tar_size=23787520
    tar_sha256=ff6220e60202981bf7f09291ece91f7a5173aaa850a6704a484c9029d7913b52
    pins=(
      598184daf5d4bf7d6c99cbe10418d771ce471d46d61980e335a60bdbd8167d59 debz-0.3.0-linux-arm64.members
      4c33b54c66bb5b7a2f491e353da165313cd6915ca94c2d84e0f20456f49c07a8 debz-0.3.0-linux-arm64.tree
      e4c0bbe939243f7fa6e0940e1b0bf0c87785a2633daf76d0b9a07f895b707df4 debz-0.3.0-linux-arm64.contents
      cbe476f5969086bce5119f04e0cbaba1c6c2d18c4cee86388bc1b234dca22ad9 debz-0.3.0-linux-arm64.elf
    )
    ;;
esac
pins+=(
  08c9f1d982c06e614b35fe69bf1794ba3e195888ca7d9a74d9174714bc112608 provenance-tar-gz.sigstore.jsonl
  cb82b67b0f1cc1b1ba1c82ac4b0f962ace888060ed8edf8f277b26a5e83553c8 provenance-tar-xz.sigstore.jsonl
  2fa7d0f1f35a7d918168b0919cd135b362a9df680e2f1e90b59de9acead54107 debz-0.3.0.help
  d915cc95d6ca8f47ae297713ed46d4e5c5d99ddd29fc3c61e263bdf305f2b5b0 debz-0.3.0.version
)

note() { printf 'release-original-smoke: %s\n' "$*"; }
check_size() {
  local actual
  actual=$(stat --format=%s -- "$1")
  if [[ $actual != "$2" ]]; then
    echo "release-original-smoke: $1 has $actual bytes; expected $2" >&2
    return 1
  fi
}

if [[ $(uname --machine) != "$machine" ]]; then
  echo "release-original-smoke: $platform originals require a matching $machine host" >&2
  exit 2
fi
mkdir --mode=0700 -- "$2"
work=$(cd -- "$2" && pwd -P)
observations=$work/observations
mkdir --mode=0700 -- "$work/assets" "$work/gh" "$work/cache" "$observations"
trap 'rm -rf -- "$work/.debz-release-smoke-gz" "$work/.debz-release-smoke-xz"' EXIT
note "platform $platform on $(uname --machine) originals ${download}/$stem.tar.{gz,xz}"

# 1. Reviewed evidence, then exact original bytes, then provenance.
(cd -- "$evidence" && printf '%s  %s\n' "${pins[@]}" | sha256sum --check --strict --quiet)
for format in gz xz; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 3 --max-time 300 --max-filesize 67108864 \
    --output "$work/assets/$stem.tar.$format" "$download/$stem.tar.$format"
done
check_size "$work/assets/$stem.tar.gz" "$gz_size"
check_size "$work/assets/$stem.tar.xz" "$xz_size"
(cd -- "$work/assets" && printf '%s  %s\n' "$gz_sha256" "$stem.tar.gz" "$xz_sha256" "$stem.tar.xz" \
  | sha256sum --check --strict)
for format in gz xz; do
  if [[ $format == gz ]]; then digest=$gz_sha256; else digest=$xz_sha256; fi
  env -u GH_TOKEN -u GITHUB_TOKEN -u GH_ENTERPRISE_TOKEN -u GITHUB_ENTERPRISE_TOKEN \
    GH_CONFIG_DIR="$work/gh" XDG_CACHE_HOME="$work/cache" GH_PROMPT_DISABLED=1 GH_NO_UPDATE_NOTIFIER=1 \
    gh attestation verify "$work/assets/$stem.tar.$format" \
      --bundle "$evidence/provenance-tar-$format.sigstore.jsonl" \
      --repo "$repository" --cert-identity "$signer" --cert-oidc-issuer "$issuer" \
      --signer-digest "$source_commit" --source-ref "$source_ref" --source-digest "$source_commit" \
      --predicate-type "$predicate" --deny-self-hosted-runners --format json \
      > "$observations/provenance-tar-$format.json"
  jq --exit-status --arg name "$stem.tar.$format" --arg digest "$digest" --arg signer "$signer" \
    --arg commit "$source_commit" --arg invocation "$invocation" --arg predicate "$predicate" '
      length == 1
      and .[0].verificationResult.statement.predicateType == $predicate
      and [.[0].verificationResult.statement.subject[] | select(.name == $name)]
        == [{name: $name, digest: {sha256: $digest}}]
      and .[0].verificationResult.signature.certificate.subjectAlternativeName == $signer
      and .[0].verificationResult.signature.certificate.sourceRepositoryDigest == $commit
      and .[0].verificationResult.signature.certificate.runInvocationURI == $invocation
      and .[0].verificationResult.signature.certificate.runnerEnvironment == "github-hosted"
      and (.[0].verificationResult.verifiedTimestamps | length) >= 1' \
    "$observations/provenance-tar-$format.json" > /dev/null
  note "verified $stem.tar.$format sha256 $digest provenance $invocation"
done

# 2. Decode both formats and observe canonical container and tar metadata.
gzip --decompress --stdout -- "$work/assets/$stem.tar.gz" > "$work/$stem.tar-gz"
xz --decompress --stdout -- "$work/assets/$stem.tar.xz" > "$work/$stem.tar-xz"
check_size "$work/$stem.tar-gz" "$tar_size"
check_size "$work/$stem.tar-xz" "$tar_size"
(cd -- "$work" && printf '%s  %s\n' "$tar_sha256" "$stem.tar-gz" "$tar_sha256" "$stem.tar-xz" \
  | sha256sum --check --strict)
cmp -- "$work/$stem.tar-gz" "$work/$stem.tar-xz"
od --address-radix=n --format=x1 --read-bytes=10 --output-duplicates -- "$work/assets/$stem.tar.gz" \
  > "$observations/gzip-header.txt"
test "$(tr -d ' \n' < "$observations/gzip-header.txt")" = "$gzip_header"
(cd -- "$work/assets" && xz --robot --list -- "$stem.tar.xz") > "$observations/xz-list.txt"
test "$(awk -F '\t' '$1 == "file" { print $2, $3, $4, $5, $7, $8 }' "$observations/xz-list.txt")" \
  = "1 1 $xz_size $tar_size CRC64 0"
note "decoded identical gzip and xz tar payloads: $tar_size bytes sha256 $tar_sha256"
tar --list --verbose --full-time --numeric-owner --file "$work/$stem.tar-gz" > "$observations/tar-numeric.txt"
tar --list --verbose --full-time --file "$work/$stem.tar-gz" > "$observations/tar-named.txt"
awk 'NF != 6 { exit 1 } { print $1, $2, $3, $4, $5, $6 }' "$observations/tar-numeric.txt" \
  > "$observations/members.txt"
cmp -- "$evidence/$stem.members" "$observations/members.txt"
awk 'NF != 6 || $2 != "root/root" { exit 1 }' "$observations/tar-named.txt"
note "$(wc -l < "$observations/members.txt") members match independent expectations; all root/root"

# 3. Mirror the native smoke for each archive: extract into a fresh 0700
# directory, verify every extracted entry before execution, then run the
# binary by absolute path with PATH=/no-host-interpreters and a 60 s timeout.
for format in gz xz; do
  smoke=$work/.debz-release-smoke-$format
  mkdir --mode=0700 -- "$smoke"
  tar --extract --preserve-permissions --no-same-owner --file "$work/$stem.tar-$format" --directory "$smoke"
  (cd -- "$smoke" && find . -mindepth 1 -printf '%P\0' | sort --zero-terminated \
    | xargs --null stat --printf '%f %Y %s %n\n' --) \
    | awk '$1 ~ /^4/ { $3 = "-" } { print }' > "$observations/tree-tar-$format.txt"
  cmp -- "$evidence/$stem.tree" "$observations/tree-tar-$format.txt"
  (cd -- "$smoke" && find . -mindepth 1 -type f -printf '%P\0' | sort --zero-terminated \
    | xargs --null sha256sum --) > "$observations/contents-tar-$format.txt"
  cmp -- "$evidence/$stem.contents" "$observations/contents-tar-$format.txt"
  binary=$smoke/$stem/bin/debz
  readelf --file-header --program-headers --wide "$binary" > "$observations/readelf-tar-$format.txt"
  awk '
    /^ELF Header:/ { header = 1; next }
    /^Program Headers:/ { header = 0; programs = 1; next }
    /^ Section to Segment mapping:/ { programs = 0 }
    header && index($0, ":") {
      key = substr($0, 1, index($0, ":") - 1); sub(/^ +/, "", key)
      value = substr($0, index($0, ":") + 1); sub(/^ +/, "", value); sub(/ +$/, "", value)
      if (key ~ /^(Class|Data|Version|OS\/ABI|Type|Machine|Entry point address|Number of program headers)$/ && !(key in seen)) {
        seen[key] = 1; print key ": " value
      }
    }
    programs && NF && $1 != "Type" { print "Program header: " $1 }
  ' "$observations/readelf-tar-$format.txt" > "$observations/elf-tar-$format.txt"
  cmp -- "$evidence/$stem.elf" "$observations/elf-tar-$format.txt"
  jq --exit-status '.schema_version == 1 and .package == "debz"
    and .linux_release_runtime.binary_kind == "fully_static"
    and .linux_release_runtime.fully_static == true
    and .linux_release_runtime.libc.implementation == "musl"
    and .linux_release_runtime.libc.linkage == "static"
    and .linux_release_runtime.system_libraries == []' \
    "$smoke/$stem/share/debz/runtime-dependencies.json" > /dev/null
  note "tar.$format extracted tree, contents and static ELF facts match; runtime metadata is fully static"
  for probe in version -h --help; do
    case $probe in version) name=version expected=debz-0.3.0.version ;; -h) name=short-help expected=debz-0.3.0.help ;;
      *) name=long-help expected=debz-0.3.0.help ;; esac
    status=0
    timeout --kill-after=5 60 env PATH=/no-host-interpreters "$binary" "$probe" \
      > "$observations/probe-tar-$format-$name.stdout" 2> "$observations/probe-tar-$format-$name.stderr" \
      || status=$?
    test "$status" = 0
    test ! -s "$observations/probe-tar-$format-$name.stderr"
    cmp -- "$evidence/$expected" "$observations/probe-tar-$format-$name.stdout"
  done
  rm -rf -- "$smoke"
  test ! -e "$smoke"
  note "tar.$format probes version, -h and --help passed; smoke directory removed"
done

{
  uname --kernel-name --kernel-release --machine
  gh --version | sed -n 1p
  curl --version | sed -n 1p
  tar --version | sed -n 1p
  gzip --version | sed -n 1p
  xz --version | sed -n 1p
  readelf --version | sed -n 1p
  jq --version
} > "$observations/host.txt"
(cd -- "$observations" && find . -type f -printf '%P\0' | sort --zero-terminated \
  | xargs --null sha256sum --) > "$work/observations.sums"
mv -- "$work/observations.sums" "$observations/SHA256SUMS"
note "PASS $stem gzip and xz originals; observations in $observations"
