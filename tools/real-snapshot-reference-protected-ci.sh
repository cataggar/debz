#!/usr/bin/env bash
# Shared root-only staging/trust bootstrap and small protected proof (#268).
#
# The workflow bootstrap clones the reviewed commit, verified by SHA, from a
# root-owned bare copy into TREE/checkout, where TREE is a new root-owned
# mode-0700 directory under /srv/debz-protected, and executes this script from
# that clone. It installs a minisign- and SHA256-pinned Zig, fetches Zig's
# package sources and tightens and records their modes without executing them,
# copies the Ubuntu archive keyring only after pinning it to a reviewed
# package-derived digest, builds debz, stages the pinned dpkg, runtime closure,
# archives and (amd64) signed profile postinsts, refuses fail-closed preflight
# negatives on new workspaces, and runs the protected proof on a new empty
# workspace. Bounded evidence is copied into TREE/upload; nothing outside TREE
# is written.
# --stage-native stages the same trusted inputs in a distinct native-ci tree,
# without running or reusing the small proof. --check-keyring verifies protected
# member bytes against the same reviewed constants for the acceptance consumer.
set -euo pipefail
umask 022
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root
unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH
unset ZIG_LIB_DIR

readonly zig_version=0.17.0
readonly zig_release=https://github.com/cataggar/zig/releases/download/v0.17.0
readonly zig_public_key=RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
# Pin source: ubuntu-keyring 2023.11.28.1build1 (Architecture: all) from
# https://snapshot.ubuntu.com/ubuntu/20261001T000000Z, suite resolute:
# pool/main/u/ubuntu-keyring/ubuntu-keyring_2023.11.28.1build1_all.deb
# (Size 11228, SHA512 80446b4521a3cc100d797a7ed03532f4358c028f1c0c110e00cfc6e1db3b2795e2f98f92a4077baea0cee3c82b292f9eeb20f7f1dc06ce28b6b46e661b1fad35).
# The pinned artifact is usr/share/keyrings/ubuntu-archive-keyring.gpg extracted
# from that deb, deliberately committed as a reviewed trust root.
readonly archive_keyring_deb_url=https://snapshot.ubuntu.com/ubuntu/20261001T000000Z/pool/main/u/ubuntu-keyring/ubuntu-keyring_2023.11.28.1build1_all.deb
readonly archive_keyring_deb_sha512=80446b4521a3cc100d797a7ed03532f4358c028f1c0c110e00cfc6e1db3b2795e2f98f92a4077baea0cee3c82b292f9eeb20f7f1dc06ce28b6b46e661b1fad35
readonly archive_keyring_deb_size=11228
readonly archive_keyring_member=./usr/share/keyrings/ubuntu-archive-keyring.gpg
readonly archive_keyring_sha256=80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31
readonly archive_keyring_size=3607

if [[ ${1:-} == --check-keyring && $# == 2 ]]; then
  exec "$(dirname -- "${BASH_SOURCE[0]}")/../zig-out/bin/debz-reference-paths" \
    verify-keyring "$2" "$archive_keyring_size" "$archive_keyring_sha256"
fi

mode=proof
if [[ ${1:-} == --stage-native ]]; then
  mode=native-staging
  shift
fi
readonly mode
native_optimize=ReleaseSafe
if [[ $mode == native-staging ]]; then
  native_optimize=${DEBZ_NATIVE_SNAPSHOT_OPTIMIZE:-ReleaseSafe}
  [[ $native_optimize == Debug || $native_optimize == ReleaseSafe ]] || {
    echo "native snapshot optimization must be Debug or ReleaseSafe" >&2
    exit 2
  }
fi
readonly native_optimize
[[ $# == 3 && $(id -u) == 0 && $(id -g) == 0 ]] || {
  echo "usage (as root, from the protected clone): $0 TREE ARCHITECTURE COMMIT" >&2
  exit 2
}
tree=$1 architecture=$2 commit=$3
prefix=ci
[[ $mode == proof ]] || prefix=native-ci
[[ $tree =~ ^/srv/debz-protected/$prefix-[0-9]+-[0-9]+-(amd64|arm64)$ && ${BASH_REMATCH[1]} == "$architecture" &&
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
    zig_sha256=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
    zig_size=57332648
    other_architecture=arm64
    ;;
  arm64/aarch64/arm64)
    zig_name=zig-aarch64-linux-$zig_version
    zig_sha256=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8
    zig_size=52877280
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
  install -d -o root -g root -m 0755 "$upload/staging" "$upload/proof" "$upload/negatives" "$upload/python3"
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
  if [[ -d $checkout/.real-snapshot/python3-amd64/evidence ]]; then
    find "$checkout/.real-snapshot/python3-amd64/evidence" -maxdepth 1 -type f \
      -size -16777217c -exec install -m 0644 -t "$upload/python3" {} +
  fi
  if [[ -d $checkout/.real-snapshot/less-arm64/evidence &&
        ! -L $checkout/.real-snapshot/less-arm64/evidence ]]; then
    install -d -o root -g root -m 0755 "$upload/arm64-less"
    find "$checkout/.real-snapshot/less-arm64/evidence" -maxdepth 1 -type f \
      -size -16777217c -exec install -m 0644 -t "$upload/arm64-less" {} +
  fi
  if [[ -d $checkout/.real-snapshot/bash-arm64/evidence &&
        ! -L $checkout/.real-snapshot/bash-arm64/evidence ]]; then
    install -d -o root -g root -m 0755 "$upload/arm64-bash"
    find "$checkout/.real-snapshot/bash-arm64/evidence" -maxdepth 1 -type f \
      -size -16777217c -exec install -m 0644 -t "$upload/arm64-bash" {} +
  fi
  for source in snapshot/evidence prestate-build/evidence; do
    local python3_evidence=$checkout/.real-snapshot/python3-amd64/$source
    [[ -d $python3_evidence && ! -L $python3_evidence ]] || continue
    install -d -o root -g root -m 0755 "$upload/python3/$source"
    find "$python3_evidence" -maxdepth 1 -type f -size -16777217c \
      -exec install -m 0644 -t "$upload/python3/$source" {} +
  done
  for directory in "$workspace"/negative-*; do
    [[ -d $directory && ! -L $directory ]] || continue
    find "$directory" -maxdepth 1 -printf '%M %u:%g %s %P\n' >"$upload/negatives/${directory##*/}.listing"
  done
  printf 'status=%s\nmode=%s\ncommit=%s\narchitecture=%s\nfinished=%s\n' \
    "$status" "$mode" "$commit" "$architecture" "$(date -u +%FT%TZ)" >"$upload/result.txt"
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

stage_verified_archive_keyring() {
  local trust_dir package target
  trust_dir=$tree/trust
  package=$trust_dir/ubuntu-keyring.deb
  target=$trust_dir/ubuntu-archive-keyring.gpg
  printf 'path\trole\tuid:gid:mode:size\talgorithm\tdigest\n' >"$evidence/archive-keyring-path.tsv"
  [[ ! -e "$trust_dir" && ! -L "$trust_dir" ]] || {
    echo "trusted keyring staging directory must be new: $trust_dir" >&2
    exit 2
  }
  install -d -o root -g root -m 0700 "$trust_dir"
  [[ -d "$trust_dir" && ! -L "$trust_dir" ]]
  [[ ! -e "$target" && ! -L "$target" ]] || {
    echo "trusted keyring copy must be new: $target" >&2
    exit 2
  }
  [[ ! -e "$package" && ! -L "$package" ]] || {
    echo "trusted keyring package must be new: $package" >&2
    exit 2
  }
  if ! (
    umask 077
    set -C
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      --max-time 300 --user-agent debz-protected-reference/1 \
      "$archive_keyring_deb_url" >"$package"
  ); then
    rm -f -- "$package"
    exit 1
  fi
  "$reference_paths" stage-keyring \
    "$package" "$archive_keyring_deb_sha512" "$archive_keyring_deb_size" \
    "$archive_keyring_member" "$target" "$archive_keyring_sha256" \
    "$archive_keyring_size" "$evidence/archive-keyring-path.tsv"
  staged_archive_keyring=$target
}

download_zig_release() {
  local name url target
  for name in "$zig_name.tar.xz" "$zig_name.tar.xz.minisig"; do
    url=$zig_release/$name
    target=$downloads/$name
    [[ ! -e "$target" && ! -L "$target" ]]
    (
      umask 077
      set -C
      curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --max-time 300 "$url" >"$target"
    )
    [[ -f "$target" && ! -L "$target" ]]
    printf '%s\n' "$url"
  done
  [[ $(stat -c '%u:%g:%a:%s:%h' "$downloads/$zig_name.tar.xz") == "0:0:600:$zig_size:1" ]]
  [[ $(sha256sum "$downloads/$zig_name.tar.xz") == "$zig_sha256  $downloads/$zig_name.tar.xz" ]]
}

extract_zig_release() {
  [[ ! -e "$tree/zig" && ! -L "$tree/zig" ]]
  install -d -o root -g root -m 0755 "$tree/zig"
  tar --no-same-owner --no-same-permissions -C "$tree/zig" -xf "$downloads/$zig_name.tar.xz"
  chmod -R go-w "$tree/zig"
}

echo "protected reference CI: commit=$commit architecture=$architecture kernel=$(uname -r) started=$(date -u +%FT%TZ)"
test "$(git -C "$checkout" rev-parse HEAD)" = "$commit"
test -z "$(git -C "$checkout" status --porcelain --ignored)"

# Zig from the pinned release, accepted only after its pinned size, SHA256 and
# both minisign signatures verify against the pinned key.
downloads=$tree/downloads
install -d -o root -g root -m 0700 "$downloads"
step zig-download 0 "" download_zig_release
step zig-extract 0 "" extract_zig_release
zig=$tree/zig/$zig_name/zig
zenv=(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C
  "ZIG_GLOBAL_CACHE_DIR=$tree/zig-global" "ZIG_LOCAL_CACHE_DIR=$checkout/.zig-cache")
step zig-version 0 "$zig_version" "${zenv[@]}" "$zig" version
reference_paths=$tree/debz-reference-paths
step reference-paths-build 0 "" "${zenv[@]}" "$zig" build-exe -O ReleaseSafe \
  -Mroot=tools/real-snapshot-reference-paths.zig \
  --zig-lib-dir "$(dirname -- "$zig")/lib" \
  -femit-bin="$reference_paths"
chmod -R go-w "$tree/zig-global" "$checkout/.zig-cache" "$reference_paths"
step zig-verify 0 "" "$reference_paths" verify-minisign --public-key "$zig_public_key" \
  --artifact "$downloads/$zig_name.tar.xz" --signature "$downloads/$zig_name.tar.xz.minisig" \
  --name "$zig_name.tar.xz" --sha256 "$zig_sha256" --size "$zig_size"
staged_archive_keyring=
stage_verified_archive_keyring
readonly staged_archive_keyring
step tree-initial 0 "" "$reference_paths" tree "$tree"
step zig-library-check 0 "" "$reference_paths" toolchain "$zig"

# Zig 0.16 writes fetched package files with their archive modes, including
# group/world-writable 0777 scripts. Tighten them, then verify and record every
# entry; the scripts are compiled-around sources and are never executed.
[[ ! -e zig-pkg && ! -L zig-pkg ]]
step zig-fetch 0 "" "${zenv[@]}" "$zig" build --fetch
[[ -d zig-pkg && ! -L zig-pkg && -d $tree/zig-global && ! -L $tree/zig-global ]]
find zig-pkg "$tree/zig-global" -xdev -perm /0022 ! -type l -printf '%M %u:%g %p\n' \
  >"$evidence/zig-pkg-writable-before.txt"
chmod -R go-w zig-pkg "$tree/zig-global"
step zig-pkg-verify 0 "" "$reference_paths" packages \
  "$checkout/zig-pkg" "$evidence/zig-pkg-manifest.txt"
step debz-build 0 "" "${zenv[@]}" "$zig" build -Doptimize="$native_optimize" -j2
chmod -R go-w "$tree/zig-global" "$checkout/.zig-cache" "$checkout/zig-out"
step tree-built 0 "" "$reference_paths" tree "$tree"

stage_native_inputs() {
  step comparator-build 0 "" "${zenv[@]}" "$zig" build test-real-snapshot-comparator -Doptimize="$native_optimize" -j2
  step native-outcome-build 0 "" "${zenv[@]}" "$zig" build build-native-outcome test-native-outcome \
    build-native-phase-summary test-native-phase-summary build-exec-audit test-exec-audit \
    -Doptimize="$native_optimize" -j2
  "$checkout/zig-out/bin/debz-native-dpkg-reference" --architecture "$architecture" \
    --download-archive "$tree/reference-dpkg.deb"
  dpkg-deb --extract "$tree/reference-dpkg.deb" "$tree/reference-dpkg"
  "$checkout/zig-out/bin/debz-native-dpkg-reference" --architecture "$architecture" \
    --receipt-from-archive "$tree/reference-dpkg.deb" --prefix "$tree/reference-dpkg"
  "$checkout/zig-out/bin/debz-native-dpkg-reference" --architecture "$architecture" \
    --verify-receipt "$tree/reference-dpkg/reference-receipt-v1.json"
  install -d -o root -g root -m 0700 "$checkout/.real-snapshot"
  printf '%s\n' "$zig" "$tree/reference-dpkg/usr/bin/dpkg" "$staged_archive_keyring" \
    >"$tree/native-inputs.args"
  printf '%s\n' "$native_optimize" >"$tree/native-optimize.txt"
  step native-tree-staged 0 "" "$reference_paths" tree "$tree"
}
if [[ $mode == native-staging ]]; then
  stage_native_inputs
  echo "protected native inputs staged; native wrapper and full reference have not executed"
  exit "$?"
fi

workspace=$checkout/.real-snapshot/$architecture
install -d -o root -g root -m 0700 .real-snapshot
step stage 0 "" "${zenv[@]}" "DEBZ_REAL_SNAPSHOT_KEYRING=$staged_archive_keyring" \
  tools/real-snapshot-reference-protected-stage.sh \
  "$zig" "$checkout/zig-out/bin/debz" ".real-snapshot/$architecture"
arguments=$workspace/reference-protected.args
mapfile -t proof_arguments <"$arguments"
[[ ${#proof_arguments[@]} == 15 ]]
step tree-staged 0 "" "$reference_paths" tree "$tree"

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
    "${negative_arguments[@]}" -Doptimize=ReleaseSafe -j2
  [[ -z $(find "$ws" -mindepth 1 -print -quit) ]] || {
    echo "negative-$name launched before refusing" >&2
    exit 1
  }
}
negatives=$tree/negative-inputs
install -d -o root -g root -m 0755 "$negatives"
mutable=$negatives/mutable-ancestor
[[ ! -e "$mutable" && ! -L "$mutable" ]]
install -d -o root -g root -m 0777 "$mutable"
install -o root -g root -m 0500 "$workspace/launcher" "$mutable/launcher"
negative mutable-ancestor "writable or non-root ancestor" \
  "s|^-Dreference-protected-launcher=.*|-Dreference-protected-launcher=$mutable/launcher|"
rm -rf --one-file-system -- "$mutable"
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
  test-real-snapshot-reference-protected "${negative_arguments[@]}" -Doptimize=ReleaseSafe -j2
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

if [[ $architecture == amd64 ]]; then
  python3_workspace=$checkout/.real-snapshot/python3-amd64
  step python3-stage 0 "all 18 root coordinates staged" timeout --signal=TERM --kill-after=60s 40m \
    "${zenv[@]}" "DEBZ_REAL_SNAPSHOT_KEYRING=$staged_archive_keyring" \
    bash tools/real-snapshot-python3-protected-stage.sh "$zig" "$checkout/zig-out/bin/debz" \
    "$workspace/dpkg/usr/bin/dpkg" "$python3_workspace"
  "$reference_paths" protected "$python3_workspace/evidence/python3-reference.args"
  mapfile -t python3_arguments <"$python3_workspace/evidence/python3-reference.args"
  [[ ${#python3_arguments[@]} == 20 ]]
  step python3-guards 0 "" timeout --signal=TERM --kill-after=60s 10m \
    "${zenv[@]}" "$zig" build test-real-snapshot-python3-protected "${python3_arguments[@]}" \
    -Doptimize=ReleaseSafe -j2 --summary all
  grep -Fx "signed Python empty0600/0644 and amd64 20/96 input/output guards executed without skips" \
    "$python3_workspace/evidence/inputs-proof.txt"
  grep -Fx "signed Python alternatives records and selectors executed without skips" \
    "$python3_workspace/evidence/alternatives-proof.txt"
  find "$python3_workspace/evidence" -maxdepth 1 -type f -size -16777217c \
    -exec install -m 0644 -t "$evidence" {} +
  # Remove only the fresh replay workspace, not package-owned bytes or bad
  # inputs "repaired" to satisfy the final protected tool-tree check.
  if grep -F " $python3_workspace" /proc/self/mountinfo; then
    echo "mounts remain beneath the Python replay workspace" >&2
    exit 1
  fi
  rm -rf --one-file-system -- "$python3_workspace"
elif [[ $architecture == arm64 ]]; then
  less_workspace=$checkout/.real-snapshot/less-arm64
  step arm64-less-stage 0 "fifteen replay roots staged" timeout --signal=TERM --kill-after=60s 30m \
    "${zenv[@]}" "DEBZ_REAL_SNAPSHOT_KEYRING=$staged_archive_keyring" \
    bash tools/real-snapshot-less-protected-stage.sh "$zig" "$checkout/zig-out/bin/debz" "$less_workspace"
  step arm64-less-guards 0 "" timeout --signal=TERM --kill-after=60s 10m \
    "${zenv[@]}" "$zig" build test-real-snapshot-arm64-less-protected \
    "-Darm64-less-reference-root=$less_workspace/source" \
    "-Darm64-less-reference-script-after=$less_workspace/script-after" \
    "-Darm64-less-reference-dpkg-after=$less_workspace/dpkg-after" \
    "-Darm64-less-reference-bad-script=$less_workspace/script-after-bad-script" \
    "-Darm64-less-reference-bad-mode=$less_workspace/script-after-bad-mode" \
    "-Darm64-less-reference-bad-tool=$less_workspace/script-after-bad-tool" \
    "-Darm64-less-reference-bad-alias=$less_workspace/script-after-bad-alias" \
    "-Darm64-less-reference-bad-prestate=$less_workspace/script-after-bad-prestate" \
    "-Darm64-less-reference-source-proof=$less_workspace/evidence/less-source-proof.txt" \
    "-Darm64-less-reference-replay-proof=$less_workspace/evidence/less-replay-proof.txt" \
    -Doptimize=ReleaseSafe -j2 --summary all
  grep -Fx "signed arm64 less source guard executed without skips" "$less_workspace/evidence/less-source-proof.txt"
  grep -Fx "signed arm64 less eight replay roots executed without skips" "$less_workspace/evidence/less-replay-proof.txt"
  step arm64-less-postinst 0 "" timeout --signal=TERM --kill-after=60s 10m \
    "${zenv[@]}" "$zig" build test-real-snapshot-arm64-less-postinst-protected \
    "-Darm64-less-postinst-root=$less_workspace/source" \
    "-Darm64-less-postinst-native-root=$less_workspace/script-after-postinst" \
    "-Darm64-less-postinst-dpkg-root=$less_workspace/dpkg-after-postinst" \
    "-Darm64-less-postinst-bad-script=$less_workspace/script-after-postinst-bad-script" \
    "-Darm64-less-postinst-bad-mode=$less_workspace/script-after-postinst-bad-mode" \
    "-Darm64-less-postinst-bad-tool=$less_workspace/script-after-postinst-bad-tool" \
    "-Darm64-less-postinst-bad-alias=$less_workspace/script-after-postinst-bad-alias" \
    "-Darm64-less-postinst-bad-prestate=$less_workspace/script-after-postinst-bad-prestate" \
    "-Darm64-less-postinst-proof=$less_workspace/evidence/less-postinst-proof.txt" \
    -Doptimize=ReleaseSafe -j2 --summary all
  grep -Fx "signed arm64 less native postinst and independent pinned dpkg agree without skips" "$less_workspace/evidence/less-postinst-proof.txt"
  find "$less_workspace/evidence" -maxdepth 1 -type f -size -16777217c \
    -exec install -m 0644 -t "$evidence" {} +
  if grep -F " $less_workspace" /proc/self/mountinfo; then
    echo "mounts remain beneath the ARM less replay workspace" >&2
    exit 1
  fi
  rm -rf --one-file-system -- "$less_workspace"
  bash_workspace=$checkout/.real-snapshot/bash-arm64
  step arm64-bash-stage 0 "nine replay roots staged" timeout --signal=TERM --kill-after=60s 30m \
    "${zenv[@]}" "DEBZ_REAL_SNAPSHOT_KEYRING=$staged_archive_keyring" \
    bash tools/real-snapshot-bash-protected-stage.sh "$zig" "$checkout/zig-out/bin/debz" "$bash_workspace"
  step arm64-bash-postinst 0 "" timeout --signal=TERM --kill-after=60s 10m \
    "${zenv[@]}" "$zig" build test-real-snapshot-arm64-bash-postinst-protected \
    "-Darm64-bash-postinst-root=$bash_workspace/source" \
    "-Darm64-bash-postinst-native-root=$bash_workspace/native" \
    "-Darm64-bash-postinst-dpkg-root=$bash_workspace/dpkg-after" \
    "-Darm64-bash-postinst-bad-script=$bash_workspace/bad-script" \
    "-Darm64-bash-postinst-bad-mode=$bash_workspace/bad-mode" \
    "-Darm64-bash-postinst-bad-tool=$bash_workspace/bad-tool" \
    "-Darm64-bash-postinst-bad-alias=$bash_workspace/bad-alias" \
    "-Darm64-bash-postinst-bad-prestate=$bash_workspace/bad-prestate" \
    "-Darm64-bash-postinst-bad-cache=$bash_workspace/bad-cache" \
    "-Darm64-bash-postinst-proof=$bash_workspace/evidence/bash-postinst-proof.txt" \
    -Doptimize=ReleaseSafe -j2 --summary all
  grep -Fx "signed arm64 bash native postinst and independent pinned dpkg agree without skips" "$bash_workspace/evidence/bash-postinst-proof.txt"
  step arm64-util-linux-postinst 0 "" timeout --signal=TERM --kill-after=60s 10m \
    "${zenv[@]}" "$zig" build test-real-snapshot-arm64-util-linux-postinst-protected \
    "-Darm64-util-linux-postinst-root=$bash_workspace/util-linux/source" \
    "-Darm64-util-linux-postinst-native-root=$bash_workspace/util-linux/native" \
    "-Darm64-util-linux-postinst-dpkg-root=$bash_workspace/util-linux/dpkg-after" \
    "-Darm64-util-linux-postinst-bad-script=$bash_workspace/util-linux/bad-script" \
    "-Darm64-util-linux-postinst-bad-mode=$bash_workspace/util-linux/bad-mode" \
    "-Darm64-util-linux-postinst-bad-tool=$bash_workspace/util-linux/bad-tool" \
    "-Darm64-util-linux-postinst-bad-alias=$bash_workspace/util-linux/bad-alias" \
    "-Darm64-util-linux-postinst-bad-prestate=$bash_workspace/util-linux/bad-prestate" \
    "-Darm64-util-linux-postinst-bad-cache=$bash_workspace/util-linux/bad-cache" \
    "-Darm64-util-linux-postinst-proof=$bash_workspace/evidence/util-linux-postinst-proof.txt" \
    -Doptimize=ReleaseSafe -j2 --summary all
  grep -Fx "signed arm64 util-linux native postinst and independent pinned dpkg agree without skips" "$bash_workspace/evidence/util-linux-postinst-proof.txt"
  find "$bash_workspace/evidence" -maxdepth 1 -type f -size -16777217c \
    -exec install -m 0644 -t "$evidence" {} +
  if grep -F " $bash_workspace" /proc/self/mountinfo; then
    echo "mounts remain beneath the ARM bash replay workspace" >&2
    exit 1
  fi
  rm -rf --one-file-system -- "$bash_workspace"
fi

# The protected proof on the staged new empty workspace, bounded by a timeout
# that kills the proof's process group.
step proof 0 "executed without skips" timeout --signal=TERM --kill-after=60s 45m \
  "${zenv[@]}" "$zig" build test-real-snapshot-reference-protected "${proof_arguments[@]}" \
  -Doptimize=ReleaseSafe -j2 --summary all
grep -F "executed without skips" "$evidence/proof.log" >"$evidence/proof-summary.txt"
if grep -F " $tree" /proc/self/mountinfo >"$evidence/mounts-after.txt"; then
  echo "mounts remain beneath the protected tree" >&2
  exit 1
fi
step tree-final 0 "" "$reference_paths" tree "$tree"
echo "protected reference CI: proof and preflight refusals passed for $architecture at $commit"
