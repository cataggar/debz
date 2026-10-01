#!/usr/bin/env bash
# Root-only hosted-CI staging and protected per-operation reference proof (#268).
#
# The workflow bootstrap clones the reviewed commit, verified by SHA, from a
# root-owned bare copy into TREE/checkout, where TREE is a new root-owned
# mode-0700 directory under /srv/debz-protected, and executes this script from
# that clone. It installs a minisign- and SHA256-pinned Zig, fetches Zig's
# package sources and tightens and records their modes without executing them,
# builds debz, stages the pinned dpkg, runtime closure, archives and (amd64)
# signed profile postinsts, refuses fail-closed preflight negatives on new
# workspaces, and runs the protected proof on a new empty workspace. Bounded
# evidence is copied into TREE/upload; nothing outside TREE is written.
set -euo pipefail
umask 022
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root
unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH

readonly zig_version=0.16.0
readonly zig_release=https://github.com/cataggar/zig/releases/download/v0.16.0
readonly zig_public_key=RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U

[[ $# == 3 && $(id -u) == 0 && $(id -g) == 0 ]] || {
  echo "usage (as root, from the protected clone): $0 TREE ARCHITECTURE COMMIT" >&2
  exit 2
}
tree=$1 architecture=$2 commit=$3
[[ $tree =~ ^/srv/debz-protected/ci-[0-9]+-[0-9]+-(amd64|arm64)$ && ${BASH_REMATCH[1]} == "$architecture" &&
  $commit =~ ^[0-9a-f]{40}$ ]] || {
  echo "the protected tree, architecture and commit must be the workflow's named values" >&2
  exit 2
}
readonly tree architecture commit
readonly checkout=$tree/checkout
[[ $(realpath -- "${BASH_SOURCE[0]}") == "$checkout/tools/real-snapshot-reference-protected-ci.sh" ]] || {
  echo "run the protected CI script from the root-owned clone in its tree" >&2
  exit 2
}
case "$architecture/$(uname -m)/$(dpkg --print-architecture)" in
  amd64/x86_64/amd64)
    zig_name=zig-x86_64-linux-$zig_version
    zig_sha256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
    zig_size=55478392
    other_architecture=arm64
    ;;
  arm64/aarch64/arm64)
    zig_name=zig-aarch64-linux-$zig_version
    zig_sha256=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17
    zig_size=51211944
    other_architecture=amd64
    ;;
  *)
    echo "runner architecture differs from the requested $architecture" >&2
    exit 2
    ;;
esac

evidence=$tree/evidence
upload=$tree/upload
install -d -o root -g root -m 0700 "$evidence" "$upload"
codes=$evidence/exit-codes.tsv
: >"$codes"
cd "$checkout"

# Copy bounded evidence into TREE/upload on every exit; the unprivileged
# workflow step only reads it back through `sudo tar`.
collect() {
  local status=$?
  set +e
  local workspace=$checkout/.real-snapshot/$architecture
  install -d -o root -g root -m 0755 "$upload/staging" "$upload/proof" "$upload/negatives"
  find "$evidence" -maxdepth 1 -type f -size -16777217c -exec install -m 0644 -t "$upload" {} +
  if [[ -d $workspace/evidence ]]; then
    find "$workspace/evidence" -maxdepth 1 -type f -size -16777217c -exec install -m 0644 -t "$upload/staging" {} +
  fi
  if [[ -f $workspace/reference-protected.args && ! -L $workspace/reference-protected.args ]]; then
    install -m 0644 "$workspace/reference-protected.args" "$upload/staging/"
  fi
  if [[ -d $workspace/proof ]]; then
    find "$workspace/proof" -maxdepth 1 -type f \( -name '*.json' -o -name '*.stdout' -o -name '*.stderr' \) \
      -size -16777217c -exec install -m 0644 -t "$upload/proof" {} +
  fi
  for directory in "$workspace"/negative-*; do
    [[ -d $directory && ! -L $directory ]] || continue
    find "$directory" -maxdepth 1 -printf '%M %u:%g %s %P\n' >"$upload/negatives/${directory##*/}.listing"
  done
  printf 'status=%s\ncommit=%s\narchitecture=%s\nfinished=%s\n' \
    "$status" "$commit" "$architecture" "$(date -u +%FT%TZ)" >"$upload/result.txt"
  local bytes
  bytes=$(du -sb "$upload" | cut -f1)
  if ((bytes > 256 * 1024 * 1024)); then
    echo "bounded evidence exceeds 256 MiB" >&2
    find "$upload" -mindepth 1 -delete
    printf 'status=%s\nevidence=oversized\n' "$status" >"$upload/result.txt"
    status=1
  fi
  (cd "$upload" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 -r sha256sum >SHA256SUMS)
  exit "$status"
}
trap collect EXIT

# step NAME EXPECTED(0|refused) PATTERN COMMAND... records the status and output;
# a refusal must fail and print PATTERN.
step() {
  local name=$1 expected=$2 pattern=$3 status=0
  shift 3
  echo "== $name: $*"
  "$@" >"$evidence/$name.log" 2>&1 || status=$?
  printf '%s\t%s\t%s\n' "$name" "$status" "$expected" >>"$codes"
  tail -n 12 "$evidence/$name.log"
  local accepted=true
  case "$expected" in
    0) [[ $status == 0 ]] || accepted=false ;;
    refused) [[ $status != 0 && -n $pattern ]] || accepted=false ;;
    *) accepted=false ;;
  esac
  if [[ -n $pattern ]] && ! grep -qF -- "$pattern" "$evidence/$name.log"; then
    accepted=false
  fi
  if [[ $accepted != true ]]; then
    echo "$name: exit $status, expected $expected${pattern:+ with '$pattern'}" >&2
    exit 1
  fi
}

echo "protected reference CI: commit=$commit architecture=$architecture kernel=$(uname -r) started=$(date -u +%FT%TZ)"
test "$(git -C "$checkout" rev-parse HEAD)" = "$commit"
test -z "$(git -C "$checkout" status --porcelain --ignored)"
step tree-initial 0 "" python3 -I tools/real-snapshot-reference-tree-check.py tree "$tree"

# Zig from the pinned release, accepted only after its pinned size, SHA256 and
# both minisign signatures verify against the pinned key.
downloads=$tree/downloads
install -d -o root -g root -m 0700 "$downloads"
step zig-download 0 "" python3 -I -c '
import sys, urllib.request
for name in (sys.argv[2], sys.argv[2] + ".minisig"):
    url = sys.argv[1] + "/" + name
    with urllib.request.urlopen(url, timeout=300) as response, open(sys.argv[3] + "/" + name, "xb") as out:
        while block := response.read(1 << 20):
            out.write(block)
    print(url)
' "$zig_release" "$zig_name.tar.xz" "$downloads"
step zig-verify 0 "" python3 -I tools/verify-minisign.py --public-key "$zig_public_key" \
  --artifact "$downloads/$zig_name.tar.xz" --signature "$downloads/$zig_name.tar.xz.minisig" \
  --name "$zig_name.tar.xz" --sha256 "$zig_sha256" --size "$zig_size"
step zig-extract 0 "" python3 -I -c '
import sys, tarfile
with tarfile.open(sys.argv[1]) as archive:
    archive.extractall(sys.argv[2], filter="data")
' "$downloads/$zig_name.tar.xz" "$tree/zig"
zig=$tree/zig/$zig_name/zig
zenv=(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C
  "ZIG_GLOBAL_CACHE_DIR=$tree/zig-global" "ZIG_LOCAL_CACHE_DIR=$checkout/.zig-cache")
step zig-version 0 "$zig_version" "${zenv[@]}" "$zig" version

# Zig 0.16 writes fetched package files with their archive modes, including
# group/world-writable 0777 scripts. Tighten them, then verify and record every
# entry; the scripts are compiled-around sources and are never executed.
[[ ! -e zig-pkg && ! -L zig-pkg ]]
step zig-fetch 0 "" "${zenv[@]}" "$zig" build --fetch
[[ -d zig-pkg && ! -L zig-pkg && -d $tree/zig-global && ! -L $tree/zig-global ]]
find zig-pkg "$tree/zig-global" -xdev -perm /0022 ! -type l -printf '%M %u:%g %p\n' \
  >"$evidence/zig-pkg-writable-before.txt"
chmod -R go-w zig-pkg "$tree/zig-global"
step zig-pkg-verify 0 "" python3 -I tools/real-snapshot-reference-tree-check.py packages \
  "$checkout/zig-pkg" "$evidence/zig-pkg-manifest.txt"
step debz-build 0 "" "${zenv[@]}" "$zig" build -Doptimize=ReleaseSafe -j4
chmod -R go-w "$tree/zig-global" "$checkout/.zig-cache" "$checkout/zig-out"
step tree-built 0 "" python3 -I tools/real-snapshot-reference-tree-check.py tree "$tree"

workspace=$checkout/.real-snapshot/$architecture
install -d -o root -g root -m 0700 .real-snapshot
step stage 0 "" "${zenv[@]}" tools/real-snapshot-reference-protected-stage.sh \
  "$zig" "$checkout/zig-out/bin/debz" ".real-snapshot/$architecture"
arguments=$workspace/reference-protected.args
mapfile -t proof_arguments <"$arguments"
[[ ${#proof_arguments[@]} == 13 ]]
step tree-staged 0 "" python3 -I tools/real-snapshot-reference-tree-check.py tree "$tree"

# Preflight negatives: each must refuse before any reference launch and leave
# its new workspace empty.
negative() { # NAME PATTERN sed-expression...
  local name=$1 pattern=$2 ws=$workspace/negative-$1
  shift 2
  install -d -o root -g root -m 0700 "$ws"
  local edits=(-e "s|^-Dreference-protected-workspace=.*|-Dreference-protected-workspace=$ws|")
  for edit in "$@"; do edits+=(-e "$edit"); done
  sed "${edits[@]}" "$arguments" >"$evidence/negative-$name.args"
  mapfile -t negative_arguments <"$evidence/negative-$name.args"
  step "negative-$name" refused "$pattern" "${zenv[@]}" "$zig" build test-real-snapshot-reference-protected \
    "${negative_arguments[@]}" -Doptimize=ReleaseSafe -j4
  [[ -z $(find "$ws" -mindepth 1 -print -quit) ]] || {
    echo "negative-$name launched before refusing" >&2
    exit 1
  }
}
mutable=$(mktemp -d /tmp/debz-protected-negative.XXXXXXXX)
install -o root -g root -m 0500 "$workspace/launcher" "$mutable/launcher"
negative mutable-ancestor "writable or non-root ancestor" \
  "s|^-Dreference-protected-launcher=.*|-Dreference-protected-launcher=$mutable/launcher|"
rm -rf --one-file-system -- "$mutable"
negatives=$tree/negative-inputs
install -d -o root -g root -m 0755 "$negatives" "$negatives/profiles"
install -o root -g root -m 0755 /usr/bin/dpkg "$negatives/dpkg"
negative swapped-dpkg "reference dpkg executable is not the pinned architecture artifact" \
  "s|^-Dreference-protected-dpkg=.*|-Dreference-protected-dpkg=$negatives/dpkg|"
escape_sha512=$(sed -n 's/^-Dreference-protected-escape-archive-sha512=//p' "$arguments")
negative swapped-archive "authenticated archive SHA512 differs" \
  "s|^-Dreference-protected-archive-sha512=.*|-Dreference-protected-archive-sha512=$escape_sha512|"
negative wrong-architecture "reference dpkg executable is not the pinned architecture artifact" \
  "s|^-Dreference-protected-architecture=.*|-Dreference-protected-architecture=$other_architecture|"
printf 'unsigned\n' >"$negatives/profiles/systemd.postinst"
negative unbound-profile-scripts "profile scripts" \
  "s|^-Dreference-protected-profile-scripts=.*|-Dreference-protected-profile-scripts=$negatives/profiles|"
install -d -o root -g root -m 0700 "$workspace/negative-reused-workspace"
install -o root -g root -m 0600 /dev/null "$workspace/negative-reused-workspace/previous-run"
sed "s|^-Dreference-protected-workspace=.*|-Dreference-protected-workspace=$workspace/negative-reused-workspace|" \
  "$arguments" >"$evidence/negative-reused-workspace.args"
mapfile -t negative_arguments <"$evidence/negative-reused-workspace.args"
step negative-reused-workspace refused "must be new and empty" "${zenv[@]}" "$zig" build \
  test-real-snapshot-reference-protected "${negative_arguments[@]}" -Doptimize=ReleaseSafe -j4
# A valid OpenPGP keyring for a different signer must fail the authenticated
# refresh before staging locks or downloads anything.
swapped_keyring_stage() {
  local status=0 refused=$checkout/.real-snapshot/negative-keyring/evidence
  env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \
    "DEBZ_REAL_SNAPSHOT_KEYRING=$checkout/src/fixtures/batch_workflow/keyring.gpg" \
    tools/real-snapshot-reference-protected-stage.sh "$zig" "$checkout/zig-out/bin/debz" \
    .real-snapshot/negative-keyring || status=$?
  cat "$refused/refresh.json" "$refused/refresh.stderr"
  return "$status"
}
step negative-swapped-keyring refused '"summary":"WrongSigningKey"' swapped_keyring_stage
[[ ! -e .real-snapshot/negative-keyring/evidence/runtime.lock.json &&
  ! -e .real-snapshot/negative-keyring/evidence/plan.json ]] || {
  echo "staging continued past the swapped keyring" >&2
  exit 1
}

# The protected proof on the staged new empty workspace, bounded by a timeout
# that kills the proof's process group.
step proof 0 "executed without skips" timeout --signal=TERM --kill-after=60s 45m \
  "${zenv[@]}" "$zig" build test-real-snapshot-reference-protected "${proof_arguments[@]}" \
  -Doptimize=ReleaseSafe -j4 --summary all
grep -F "executed without skips" "$evidence/proof.log" >"$evidence/proof-summary.txt"
if grep -F " $tree" /proc/self/mountinfo >"$evidence/mounts-after.txt"; then
  echo "mounts remain beneath the protected tree" >&2
  exit 1
fi
step tree-final 0 "" python3 -I tools/real-snapshot-reference-tree-check.py tree "$tree"
echo "protected reference CI: proof and preflight refusals passed for $architecture at $commit"
