#!/bin/sh
set -eu
umask 077

debz=$1
runtime=${2:-"$PWD/zig-out/bin/debz-disposable-runtime"}
if [ ! -x "$runtime" ]; then
  printf 'native disposable runtime helper is not executable: %s\n' "$runtime" >&2
  exit 2
fi
repository_generator=${3:-"$PWD/zig-out/bin/debz-integration-repository"}
test "$#" -le 3 || { echo "unexpected integration fixture argument" >&2; exit 2; }
case "$repository_generator" in
  /*) ;;
  *) repository_generator="$PWD/$repository_generator" ;;
esac
if [ ! -x "$repository_generator" ]; then
  printf 'native integration repository generator is not executable: %s\n' "$repository_generator" >&2
  exit 2
fi
suite=${DEBZ_INTEGRATION_SUITE:-debian-stable}
architecture=${DEBZ_INTEGRATION_ARCH:-amd64}
mode=${DEBZ_INTEGRATION_MODE:-smoke}
use_sudo=${DEBZ_INTEGRATION_SUDO:-0}
workspace="$PWD/.zig-cache/integration-$suite-$architecture"
repo="$workspace/repository"
root="$workspace/root"
cache="$workspace/cache"
state="$workspace/state"
source_file="$workspace/fixture.sources"
keyring="$repo/fixture-keyring.gpg"
stderr_file="$workspace/stderr"

case "$workspace" in
  "$PWD"/.zig-cache/integration-*) ;;
  *) echo "refusing unsafe integration workspace: $workspace" >&2; exit 2 ;;
esac
test ! -L "$workspace"

case "$suite:$architecture:$mode" in
  debian-stable:amd64:smoke|debian-stable:arm64:smoke|ubuntu-26.04:amd64:smoke|ubuntu-26.04:arm64:smoke) ;;
  debian-stable:amd64:full|debian-stable:arm64:full|ubuntu-26.04:amd64:full|ubuntu-26.04:arm64:full) ;;
  debian-stable:amd64:native|debian-stable:arm64:native|ubuntu-26.04:amd64:native|ubuntu-26.04:arm64:native) ;;
  *) echo "unsupported integration tuple: $suite/$architecture/$mode" >&2; exit 2 ;;
esac

rm -rf "$workspace"
mkdir -p "$root/var/lib/dpkg" "$root/var/lib/debz" "$cache" "$state"
mkdir -p "$root/var/lib/dpkg/info" "$root/var/lib/dpkg/updates" "$root/var/lib/dpkg/triggers"
printf '1\n' >"$root/var/lib/dpkg/info/format"
: >"$root/var/lib/dpkg/status"
"$repository_generator" \
  --output "$repo" --suite "$suite" --architecture "$architecture"
cat >"$source_file" <<EOF
Types: deb
URIs: file://$repo
Suites: $suite
Components: main
Architectures: $architecture
Signed-By: $keyring
EOF

# Debian publishes only signed SHA256 archive digests (#261). Legacy v1/v2
# package-cache locks address SHA256 CAS objects, so legacy package-cache
# coverage and the native signed-SHA256 binding use this Debian-like fixture;
# the main fixture also publishes signed SHA512 for native exact-lock v3.
sha256_repo="$workspace/sha256-repository"
"$repository_generator" \
  --output "$sha256_repo" --suite "$suite" --architecture "$architecture" --sha256-only
if grep -q '^SHA512:' "$sha256_repo/dists/$suite/main/binary-$architecture/Packages"; then
  echo "SHA256-only fixture unexpectedly publishes SHA512" >&2
  exit 1
fi
grep -q '^SHA512:' "$repo/dists/$suite/main/binary-$architecture/Packages"
sha256_keyring="$sha256_repo/fixture-keyring.gpg"
sha256_source="$workspace/sha256.sources"
cat >"$sha256_source" <<EOF
Types: deb
URIs: file://$sha256_repo
Suites: $suite
Components: main
Architectures: $architecture
Signed-By: $sha256_keyring
EOF
sha256_cache="$workspace/sha256-cache"
sha256_common="--install-root $root --cache-path $sha256_cache --state-path $state --architecture $architecture --keyring $sha256_keyring --json"

common="--install-root $root --cache-path $cache --state-path $state --architecture $architecture --source $source_file --keyring $keyring --json"
mutating="$common --assume-yes --noninteractive --conffile keep-existing"

run_json() {
  set +e
  output=$("$debz" "$@" 2>"$stderr_file")
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    cat "$stderr_file" >&2
    printf '%s\n' "$output" >&2
    return "$status"
  fi
  test ! -s "$stderr_file"
  printf '%s\n' "$output"
}

run_mutating_json() {
  if [ "$use_sudo" = 1 ]; then
    set +e
    output=$(sudo -- "$debz" "$@" 2>"$stderr_file")
    status=$?
    set -e
    if [ "$status" -ne 0 ]; then
      cat "$stderr_file" >&2
      printf '%s\n' "$output" >&2
      return "$status"
    fi
    test ! -s "$stderr_file"
    printf '%s\n' "$output"
  else
    run_json "$@"
  fi
}

refresh_a=$(run_json refresh $common --assume-yes)
printf '%s' "$refresh_a" | grep -q '"exit_status":0'
printf '%s' "$refresh_a" | grep -q '"detail":"authenticated"'
refresh_b=$(run_json refresh $common --assume-yes --offline)
test "$refresh_a" = "$refresh_b"

plan_a=$(run_json plan $common base-dep)
plan_b=$(run_json plan $common base-dep)
test "$plan_a" = "$plan_b"
printf '%s' "$plan_a" | grep -q '"package":"base-dep"'
resolved_lock="$workspace/base-dep.lock.json"
run_json plan $common --lock-output "$resolved_lock" base-dep | grep -q '"exit_status":0'
test -s "$resolved_lock"
run_json plan $common --lock-input "$resolved_lock" base-dep | grep -q '"exit_status":0'
run_json download $common --lock-input "$resolved_lock" base-dep | grep -q '"exit_status":0'
run_json plan $common --lock-input "$resolved_lock" --lock-output "$workspace/base-dep.copy.lock.json" base-dep |
  grep -q '"exit_status":0'
cmp "$resolved_lock" "$workspace/base-dep.copy.lock.json"

native_cache="$workspace/native-cache"
native_lock="$workspace/base-dep.native.lock.json"
native_common="--install-root $root --cache-path $native_cache --state-path $state --architecture $architecture --source $source_file --keyring $keyring --transaction-backend native --json"
run_json plan $native_common --lock-output "$native_lock" base-dep | grep -q '"exit_status":0'
run_json plan $native_common --lock-input "$native_lock" --lock-output "$workspace/base-dep.native.copy.lock.json" base-dep |
  grep -q '"exit_status":0'
cmp "$native_lock" "$workspace/base-dep.native.copy.lock.json"
run_json download $native_common --lock-input "$native_lock" base-dep | grep -q '"changed":false'
run_json download $native_common --lock-input "$native_lock" --cache-only base-dep | grep -q '"changed":false'
"$repository_generator" --check-roots native-lock "$resolved_lock" "$native_lock" "$native_cache"

native_package_cache="$workspace/native-package-cache"
native_package_archive="$workspace/native-package-cache.dbzcache"
native_package_common="--transaction-backend native --lock-input $native_lock --cache-path $native_package_cache --architecture $architecture --json"
native_fingerprint=$(run_json package-cache fingerprint $native_package_common)
native_prepared=$(run_json package-cache prepare $native_package_common \
  --source "$source_file" --keyring "$keyring" --archive-output "$native_package_archive")
native_warm=$(run_json package-cache prepare $native_package_common \
  --source "$source_file" --keyring "$keyring" --offline)
"$repository_generator" --check-roots native-cache-prepare "$native_fingerprint" "$native_prepared" "$native_warm" "$native_lock" "$native_package_archive"

native_scenario_lock="$workspace/scenario.native.lock.json"
run_json plan $native_common --lock-output "$native_scenario_lock" scenario-main | grep -q '"exit_status":0'
native_partial=$(run_json package-cache prepare \
  --transaction-backend native --lock-input "$native_scenario_lock" \
  --cache-path "$workspace/native-package-cache-partial" --architecture "$architecture" \
  --source "$source_file" --keyring "$keyring" \
  --archive-input "$native_package_archive" --restored-cache partial \
  --archive-output "$workspace/native-scenario.dbzcache" --json)
native_exact=$(run_json package-cache prepare \
  --transaction-backend native --lock-input "$native_scenario_lock" \
  --cache-path "$workspace/native-package-cache-exact" --architecture "$architecture" \
  --source "$source_file" --keyring "$keyring" \
  --archive-input "$workspace/native-scenario.dbzcache" --restored-cache exact --json)
"$repository_generator" --check-roots native-cache-partial-exact "$native_partial" "$native_exact"

native_empty_lock="$workspace/empty.native.lock.json"
native_mixed_lock="$workspace/mixed.native.lock.json"
native_local_lock="$workspace/local.native.lock.json"
legacy_v1_lock="$workspace/legacy.lock.json"
legacy_v1_archive="$workspace/legacy-package-cache.dbzcache"
"$repository_generator" --check-roots write-native-cache-fixtures \
  "$native_lock" "$native_empty_lock" "$native_mixed_lock" "$native_local_lock" \
  "$legacy_v1_lock" "$legacy_v1_archive"
native_empty_fingerprint=$(run_json package-cache fingerprint \
  --transaction-backend native --lock-input "$native_empty_lock" \
  --cache-path "$workspace/native-package-cache-empty" --architecture "$architecture" --json)
native_empty_prepared=$(run_json package-cache prepare \
  --transaction-backend native --lock-input "$native_empty_lock" \
  --cache-path "$workspace/native-package-cache-empty" --architecture "$architecture" \
  --archive-output "$workspace/native-empty.dbzcache" --offline --json)
native_empty_restored=$(run_json package-cache prepare \
  --transaction-backend native --lock-input "$native_empty_lock" \
  --cache-path "$workspace/native-package-cache-empty-restored" --architecture "$architecture" \
  --archive-input "$workspace/native-empty.dbzcache" --restored-cache exact --offline --json)
"$repository_generator" --check-roots native-cache-empty "$native_empty_fingerprint" "$native_empty_prepared" "$native_empty_restored" "$native_empty_lock" "$workspace/native-empty.dbzcache"

native_mixed_prepared=$(run_json package-cache prepare \
  --transaction-backend native --lock-input "$native_mixed_lock" \
  --cache-path "$workspace/native-package-cache-mixed" --architecture "$architecture" \
  --source "$source_file" --keyring "$keyring" \
  --archive-input "$native_package_archive" --restored-cache exact --json)
native_local_prepared=$(run_json package-cache prepare \
  --transaction-backend native --lock-input "$native_local_lock" \
  --cache-path "$workspace/native-package-cache-local" --architecture "$architecture" \
  --archive-input "$native_package_archive" --restored-cache partial --offline --json)
"$repository_generator" --check-roots native-cache-mixed-local "$native_mixed_prepared" "$native_local_prepared"
set +e
missing_local=$("$debz" package-cache prepare \
  --transaction-backend native --lock-input "$native_local_lock" \
  --cache-path "$workspace/native-package-cache-local-missing" --architecture "$architecture" \
  --json 2>"$stderr_file")
missing_local_status=$?
set -e
test "$missing_local_status" -eq 6
test ! -s "$stderr_file"
printf '%s' "$missing_local" | grep -q '"id":"local_artifact_acquisition_required"'

refused_cache="$workspace/native-cache-version-refusal-native"
set +e
refused=$("$debz" package-cache prepare --transaction-backend native \
  --lock-input "$native_lock" --cache-path "$refused_cache" \
  --architecture "$architecture" --source "$source_file" --keyring "$keyring" \
  --archive-input "$legacy_v1_archive" --restored-cache exact --json 2>"$stderr_file")
refused_status=$?
set -e
test "$refused_status" -eq 6
test ! -s "$stderr_file"
printf '%s' "$refused" | grep -q '"id":"corrupt_cache_archive"'
test ! -d "$refused_cache/packages-v2/objects" ||
  test -z "$(find "$refused_cache/packages-v2/objects" -mindepth 1 -print -quit)"

refused_legacy_cache="$workspace/native-cache-version-refusal-legacy_dpkg"
set +e
refused_legacy=$("$debz" package-cache prepare --transaction-backend legacy_dpkg \
  --lock-input "$legacy_v1_lock" --cache-path "$refused_legacy_cache" \
  --architecture "$architecture" --source "$sha256_source" --keyring "$sha256_keyring" \
  --archive-input "$native_package_archive" --restored-cache exact --json 2>"$stderr_file")
refused_legacy_status=$?
set -e
test "$refused_legacy_status" -eq 8
test ! -s "$stderr_file"
printf '%s' "$refused_legacy" | grep -q '"id":"legacy_recovery_release_required"'
printf '%s' "$refused_legacy" | grep -Fq '>=0.3.0,<0.4.0'
test ! -d "$refused_legacy_cache/packages-v2/objects" ||
  test -z "$(find "$refused_legacy_cache/packages-v2/objects" -mindepth 1 -print -quit)"

set +e
native_cache_wrong_lock=$("$debz" package-cache fingerprint \
  --transaction-backend native --lock-input "$legacy_v1_lock" \
  --cache-path "$native_package_cache" --architecture "$architecture" --json 2>"$stderr_file")
native_cache_wrong_lock_status=$?
set -e
test "$native_cache_wrong_lock_status" -eq 5
test ! -s "$stderr_file"
printf '%s' "$native_cache_wrong_lock" | grep -q '"id":"unsupported_lock_schema"'
test ! -s "$root/var/lib/dpkg/status"
test ! -e "$root/var/lib/debz/root-operation-v1.json"

set +e
native_wrong_version=$("$debz" plan $native_common --lock-input "$legacy_v1_lock" base-dep 2>"$stderr_file")
native_wrong_version_status=$?
set -e
test "$native_wrong_version_status" -eq 5
test ! -s "$stderr_file"
printf '%s' "$native_wrong_version" | grep -q '"id":"lock_verification_failed"'
set +e
native_wrong_policy=$("$debz" plan $native_common --lock-input "$native_lock" --recommends base-dep 2>"$stderr_file")
native_wrong_policy_status=$?
set -e
test "$native_wrong_policy_status" -eq 5
test ! -s "$stderr_file"
printf '%s' "$native_wrong_policy" | grep -q '"id":"lock_verification_failed"'
set +e
native_unavailable=$("$debz" install $native_common --lock-input "$native_lock" \
  --assume-yes --noninteractive --conffile keep-existing base-dep 2>"$stderr_file")
native_unavailable_status=$?
set -e
test "$native_unavailable_status" -eq 7
test ! -s "$stderr_file"
printf '%s' "$native_unavailable" | grep -q 'NativeHelperBootstrapOwnerMissing'
test ! -s "$root/var/lib/dpkg/status"
test ! -e "$root/var/lib/debz/root-operation-v1.json"
test ! -e "$root/var/lib/debz/native-execution-intent-v1.json"
test ! -e "$root/var/lib/debz/native-helper-cache-v1"

# Debian publishes only signed SHA256 archive digests. Native exact-lock v3
# consumers require a SHA-512 archive identity (#261): the unbound lock is
# refused, legacy locks are unchanged, and the per-repository config opt-in
# publishes a lock whose derived SHA-512 is bound to the verified SHA256.
sha256_config="$workspace/sha256-binding.json"
printf '{"source_path":"%s","archive_binding":"signed_sha256_derived_sha512"}\n' "$sha256_source" >"$sha256_config"
sha256_unbound_lock="$workspace/sha256-unbound.native.lock.json"
set +e
sha256_unbound=$("$debz" plan $sha256_common --source "$sha256_source" --transaction-backend native \
  --lock-output "$sha256_unbound_lock" scenario-main 2>"$stderr_file")
sha256_unbound_status=$?
set -e
test "$sha256_unbound_status" -eq 5
test ! -s "$stderr_file"
printf '%s' "$sha256_unbound" | grep -q 'SHA-512 archive identity'
test ! -e "$sha256_unbound_lock"
set +e
sha256_legacy=$("$debz" plan $sha256_common --source "$sha256_source" --transaction-backend legacy_dpkg \
  --lock-output "$workspace/sha256.legacy.lock.json" scenario-main 2>"$stderr_file")
sha256_legacy_status=$?
set -e
test "$sha256_legacy_status" -eq 8
test ! -s "$stderr_file"
printf '%s' "$sha256_legacy" | grep -q '"id":"legacy_recovery_release_required"'
test ! -e "$workspace/sha256.legacy.lock.json"
sha256_bound_lock="$workspace/sha256-bound.native.lock.json"
run_json plan $sha256_common --config "$sha256_config" --transaction-backend native \
  --lock-output "$sha256_bound_lock" scenario-main | grep -q '"exit_status":0'
run_json download $sha256_common --config "$sha256_config" --transaction-backend native \
  --lock-input "$sha256_bound_lock" --cache-only scenario-main | grep -q '"exit_status":0'
sha256_forged_lock="$workspace/sha256-forged.native.lock.json"
sha256_tampered=$("$repository_generator" --check-roots sha256-bound-lock "$sha256_bound_lock" "$sha256_cache" "$native_scenario_lock" "$sha256_forged_lock")
set +e
sha256_forged=$("$debz" plan $sha256_common --config "$sha256_config" --transaction-backend native \
  --lock-input "$sha256_forged_lock" scenario-main 2>"$stderr_file")
sha256_forged_status=$?
set -e
test "$sha256_forged_status" -eq 5
test ! -s "$stderr_file"
printf '%s' "$sha256_forged" | grep -q '"id":"lock_verification_failed"'
chmod u+w "$sha256_tampered"
printf 'tampered' | dd of="$sha256_tampered" bs=1 seek=0 conv=notrunc 2>/dev/null
set +e
sha256_refused=$("$debz" download $sha256_common --config "$sha256_config" --transaction-backend native \
  --lock-input "$sha256_bound_lock" --cache-only scenario-main 2>"$stderr_file")
sha256_refused_status=$?
set -e
test "$sha256_refused_status" -eq 6
test ! -s "$stderr_file"
printf '%s' "$sha256_refused" | grep -q '"id":"download_failed"'
test ! -s "$root/var/lib/dpkg/status"

if [ "$mode" != smoke ]; then
  privileged=
  if [ "$use_sudo" = 1 ]; then privileged="sudo -n"; fi
  native_root="$workspace/native-root"
  native_state="$workspace/native-unused-state"
  mkdir -p "$native_root/var/lib/dpkg"
  : >"$native_root/var/lib/dpkg/status"
  # This script-free helper fixture also seeds cross-architecture roots.
  $privileged dpkg --force-architecture --root="$native_root" --install \
    "$repo/pool/main/native-helper-target_1.0-1_$architecture.deb" \
    >"$workspace/native-seed.log" 2>&1
  native_execution="--install-root $native_root --cache-path $native_cache --state-path $native_state --architecture $architecture --source $source_file --keyring $keyring --transaction-backend native --json"
  native_execution_lock="$workspace/native-execution.lock.json"
  # Keep private cache files under one UID across planning and execution.
  run_mutating_json plan $native_execution --lock-output "$native_execution_lock" base-dep | grep -q '"exit_status":0'
  run_mutating_json install $native_execution --lock-input "$native_execution_lock" \
    --assume-yes --noninteractive --conffile keep-existing base-dep |
    grep -q '"changed":true'
  $privileged "$repository_generator" --check-roots native-execution "$native_root" "$native_execution_lock"
  run_mutating_json install $native_execution --lock-input "$native_execution_lock" \
    --assume-yes --noninteractive --conffile keep-existing --cache-only base-dep |
    grep -q '"changed":true'
  native_noop_lock="$workspace/native-noop.lock.json"
  run_mutating_json plan $native_execution --lock-output "$native_noop_lock" | grep -q '"exit_status":0'
  run_mutating_json upgrade-all $native_execution --lock-input "$native_noop_lock" \
    --assume-yes --noninteractive --conffile keep-existing --cache-only |
    grep -q '"changed":false'
  run_mutating_json recover --install-root "$native_root" --architecture "$architecture" \
    --cache-path "$workspace/native-recovery-unused-cache" --state-path "$native_state" \
    --transaction-backend native --assume-yes --json | grep -q '"changed":false'
  test ! -e "$workspace/native-recovery-unused-cache"
  test ! -e "$native_state"
  $privileged "$runtime" "$native_root" /bin/sh /bin/sh
  native_trigger_lock="$workspace/native-trigger.lock.json"
  run_mutating_json plan $native_execution --lock-output "$native_trigger_lock" native-trigger-pkg | grep -q '"exit_status":0'
  run_mutating_json install $native_execution --lock-input "$native_trigger_lock" \
    --assume-yes --noninteractive --conffile keep-existing native-trigger-pkg |
    grep -q '"changed":true'
  $privileged "$repository_generator" --check-roots native-trigger "$native_root"
  # The per-repository opt-in lets native execution consume a Debian-like
  # signed SHA256 identity with its bound derived SHA-512 (#261).
  bound_root="$workspace/native-bound-root"
  mkdir -p "$bound_root/var/lib/dpkg"
  : >"$bound_root/var/lib/dpkg/status"
  $privileged dpkg --force-architecture --root="$bound_root" --install \
    "$sha256_repo/pool/main/native-helper-target_1.0-1_$architecture.deb" \
    >"$workspace/native-bound-seed.log" 2>&1
  bound_execution="--install-root $bound_root --cache-path $workspace/native-bound-cache --state-path $workspace/native-bound-unused-state --architecture $architecture --config $sha256_config --keyring $sha256_keyring --transaction-backend native --json"
  bound_execution_lock="$workspace/native-bound-execution.lock.json"
  run_mutating_json plan $bound_execution --lock-output "$bound_execution_lock" base-dep | grep -q '"exit_status":0'
  run_mutating_json install $bound_execution --lock-input "$bound_execution_lock" \
    --assume-yes --noninteractive --conffile keep-existing base-dep |
    grep -q '"changed":true'
  $privileged "$repository_generator" --check-roots bound-execution "$bound_root" "$bound_execution_lock"
  if [ "$mode" = native ]; then
    printf 'integration-root: %s/%s native core passed\n' "$suite" "$architecture"
    exit 0
  fi
fi

package_cache_root="$workspace/package-cache"
package_cache_archives="$workspace/package-cache-archives"
mkdir -p "$package_cache_archives"
package_cache_common="--lock-input $resolved_lock --cache-path $package_cache_root --architecture $architecture"
fingerprint=$(run_json package-cache fingerprint $package_cache_common --json)
printf '%s' "$fingerprint" | grep -q '"schema":"io.github.cataggar.debz.package-cache-fingerprint.v5"'
printf '%s' "$fingerprint" | grep -q '"capability":"package-cache-v5"'
printf '%s' "$fingerprint" | grep -q '"cas_layout":"packages-v2"'

set +e
unsupported=$("$debz" package-cache fingerprint \
  --lock-input "$legacy_v1_lock" \
  --cache-path "$package_cache_root" --architecture "$architecture" --json \
  2>"$stderr_file")
unsupported_status=$?
set -e
test "$unsupported_status" -eq 5
test ! -s "$stderr_file"
printf '%s' "$unsupported" | grep -q '"id":"unsupported_lock_schema"'

set +e
wrong_architecture=$("$debz" package-cache fingerprint \
  --lock-input "$resolved_lock" --cache-path "$package_cache_root" \
  --architecture other-architecture --json 2>"$stderr_file")
wrong_architecture_status=$?
set -e
test "$wrong_architecture_status" -eq 2
test ! -s "$stderr_file"
printf '%s' "$wrong_architecture" | grep -q '"id":"invalid_request"'

cold=$(run_json package-cache prepare $package_cache_common \
  --source "$source_file" --keyring "$keyring" \
  --archive-output "$package_cache_archives/base.dbzcache" --json)
printf '%s' "$cold" | grep -q '"schema":"io.github.cataggar.debz.package-cache-result.v5"'
"$repository_generator" --check-roots cache-result cold "$cold"

retry_cache="$workspace/package-cache-retry"
"$repository_generator" --check-roots write-abandoned-staging "$resolved_lock" "$retry_cache"
retried=$(run_json package-cache prepare \
  --lock-input "$resolved_lock" --cache-path "$retry_cache" \
  --architecture "$architecture" --source "$source_file" --keyring "$keyring" \
  --archive-input "$package_cache_archives/base.dbzcache" \
  --restored-cache exact --json)
"$repository_generator" --check-roots cache-result retried "$retried"
test -z "$(find "$retry_cache/packages-v2/staging" -mindepth 1 -print -quit)"

limited_cache="$workspace/package-cache-cleanup-limit"
mkdir -p "$limited_cache/packages-v2/staging"
printf partial >"$limited_cache/packages-v2/staging/one"
printf partial >"$limited_cache/packages-v2/staging/two"
set +e
cleanup_limited=$("$debz" package-cache prepare \
  --lock-input "$resolved_lock" --cache-path "$limited_cache" \
  --architecture "$architecture" --source "$source_file" --keyring "$keyring" \
  --archive-input "$package_cache_archives/base.dbzcache" \
  --restored-cache exact --maximum-staging-entries 1 --json 2>"$stderr_file")
cleanup_limited_status=$?
set -e
test "$cleanup_limited_status" -eq 3
test ! -s "$stderr_file"
printf '%s' "$cleanup_limited" | grep -q '"id":"staging_cleanup_incomplete"'
test -z "$(find "$limited_cache/packages-v2/objects" -mindepth 1 -type f -print -quit)"

exact=$(run_json package-cache prepare $package_cache_common \
  --source "$source_file" --keyring "$keyring" --offline --json)
"$repository_generator" --check-roots cache-result exact "$exact"

scenario_lock="$workspace/scenario-main.lock.json"
run_json plan $common --lock-output "$scenario_lock" scenario-main | grep -q '"exit_status":0'
archive_partial=$(run_json package-cache prepare \
  --lock-input "$scenario_lock" --cache-path "$workspace/package-cache-relocated" \
  --architecture "$architecture" --source "$source_file" --keyring "$keyring" \
  --archive-input "$package_cache_archives/base.dbzcache" \
  --archive-output "$package_cache_archives/scenario.dbzcache" \
  --restored-cache partial --json)
"$repository_generator" --check-roots cache-result partial "$archive_partial"

archive_exact=$(run_json package-cache prepare \
  --lock-input "$scenario_lock" --cache-path "$workspace/package-cache-relocated-exact" \
  --architecture "$architecture" --source "$source_file" --keyring "$keyring" \
  --archive-input "$package_cache_archives/scenario.dbzcache" \
  --restored-cache exact --json)
"$repository_generator" --check-roots cache-result exact "$archive_exact"

cp "$package_cache_archives/base.dbzcache" "$package_cache_archives/corrupt.dbzcache"
printf 'corrupt' >>"$package_cache_archives/corrupt.dbzcache"
set +e
corrupt_archive=$("$debz" package-cache prepare \
  --lock-input "$scenario_lock" --cache-path "$workspace/package-cache-corrupt-archive" \
  --architecture "$architecture" --source "$source_file" --keyring "$keyring" \
  --archive-input "$package_cache_archives/corrupt.dbzcache" \
  --restored-cache partial --json 2>"$stderr_file")
corrupt_archive_status=$?
set -e
test "$corrupt_archive_status" -eq 6
test ! -s "$stderr_file"
printf '%s' "$corrupt_archive" | grep -q '"id":"corrupt_cache_archive"'

partial=$(run_json package-cache prepare \
  --lock-input "$scenario_lock" --cache-path "$package_cache_root" \
  --architecture "$architecture" --source "$source_file" --keyring "$keyring" --json)
"$repository_generator" --check-roots cache-result partial "$partial"

pruned=$(run_json package-cache prepare $package_cache_common \
  --source "$source_file" --keyring "$keyring" --offline --json)
"$repository_generator" --check-roots cache-result pruned "$pruned"

first_cache_object=$(find "$package_cache_root/packages-v2/objects" -type f | head -n 1 || true)
test -n "$first_cache_object"
cp "$first_cache_object" "$workspace/package-cache-object.backup"
printf 'corrupt' >"$first_cache_object"
set +e
corrupt=$("$debz" package-cache prepare $package_cache_common \
  --source "$source_file" --keyring "$keyring" --offline --json 2>"$stderr_file")
corrupt_status=$?
set -e
test "$corrupt_status" -eq 6
test ! -s "$stderr_file"
printf '%s' "$corrupt" | grep -q '"id":"corrupt_cache_object"'

repaired=$(run_json package-cache prepare $package_cache_common \
  --source "$source_file" --keyring "$keyring" --repair-corrupt-cache --json)
"$repository_generator" --check-roots cache-result repaired "$repaired"
rm -f "$workspace/package-cache-object.backup"

offline_objects_only="$workspace/offline-objects-only"
mkdir -p "$offline_objects_only/packages-v2"
cp -R "$package_cache_root/packages-v2/objects" "$offline_objects_only/packages-v2/objects"
set +e
offline_without_metadata=$("$debz" package-cache prepare \
  --lock-input "$resolved_lock" --cache-path "$offline_objects_only" \
  --architecture "$architecture" --source "$source_file" --keyring "$keyring" \
  --offline --json 2>"$stderr_file")
offline_without_metadata_status=$?
set -e
test "$offline_without_metadata_status" -eq 6
test ! -s "$stderr_file"
printf '%s' "$offline_without_metadata" | grep -q '"id":"offline_cache_miss"'

cp "$repo/dists/$suite/InRelease" "$workspace/InRelease.backup"
printf 'tamper' >>"$repo/dists/$suite/InRelease"
set +e
moving_repository=$("$debz" package-cache prepare $package_cache_common \
  --source "$source_file" --keyring "$keyring" --json 2>"$stderr_file")
moving_repository_status=$?
set -e
test "$moving_repository_status" -eq 4
test ! -s "$stderr_file"
printf '%s' "$moving_repository" | grep -q '"id":"repository_authentication_failed"'
mv "$workspace/InRelease.backup" "$repo/dists/$suite/InRelease"

find "$package_cache_root/packages-v2/objects" -mindepth 1 -maxdepth 1 -type f |
  while IFS= read -r object; do
    basename "$object" | grep -Eq '^sha(256|512)-[0-9a-f]+$'
  done
case "$suite" in
  debian-stable) run_json info $common trigger-pkg | grep -q '"version":"1.0-1debian1"' ;;
  ubuntu-26.04) run_json info $common trigger-pkg | grep -q '"version":"1.0-1ubuntu1"' ;;
esac

run_json plan $common alt-consumer | grep -q '"package":"alt-a"\|"package":"alt-b"'
run_json info $common pre-app | grep -q '"package":"pre-app"'
run_json info $common recommend-app | grep -q '"package":"recommend-app"'
run_json plan $common cycle-a | grep -q '"package":"cycle-b"'
run_json provides $common virtual-api | grep -q '"package":"virtual-provider"'
run_json plan $common multi-lib | grep -q "\"architecture\":\"$architecture\""
run_json download $common base-dep | grep -q '"exit_status":0'
run_json download $common --offline base-dep | grep -q '"exit_status":0'

cp "$repo/fixture-provenance.txt" "$workspace/provenance.first"
"$repository_generator" \
  --output "$repo" --suite "$suite" --architecture "$architecture"
cmp "$workspace/provenance.first" "$repo/fixture-provenance.txt"

printf 'not canonical lock json\n' >"$workspace/bad.lock"
set +e
bad_lock=$("$debz" plan $common --lock-input "$workspace/bad.lock" base-dep 2>"$stderr_file")
bad_lock_status=$?
set -e
test "$bad_lock_status" -ne 0
printf '%s' "$bad_lock" | grep -q '"exit_status":5'

if [ "$mode" = full ]; then
  run_json info $common conflict-new | grep -q '"package":"conflict-new"'
  run_json plan $common essential-core | grep -q '"package":"essential-core"'
  run_json plan $common protected-core | grep -q '"package":"protected-core"'
  run_json info $common conffile-pkg | grep -q '"package":"conffile-pkg"'
  run_json info $common trigger-pkg | grep -q '"package":"trigger-pkg"'
  run_json info $common fail-script | grep -q '"package":"fail-script"'
  cat >"$workspace/held.status" <<EOF
Package: held-fixture
Status: hold ok installed
Architecture: $architecture
Version: 1.0-1
Installed-Size: 1
EOF
  run_json why $common --status-path "$workspace/held.status" held-fixture |
    grep -q '"detail":"explicit dpkg hold"'

  first_object=$(find "$cache" -type f -path '*/packages-v2/objects/*' | head -n 1 || true)
  if [ -n "$first_object" ]; then
    cp "$first_object" "$workspace/cache-object.backup"
    printf 'corrupt' >"$first_object"
    set +e
    corrupt=$("$debz" download $common --offline base-dep 2>"$stderr_file")
    corrupt_status=$?
    set -e
    test "$corrupt_status" -ne 0
    printf '%s' "$corrupt" | grep -q '"exit_status":6'
    mv "$workspace/cache-object.backup" "$first_object"
  else
    echo "required package cache object was not published" >&2
    exit 1
  fi

  command -v dpkg >/dev/null 2>&1 || {
    echo "required dpkg-root-transactions capability is unavailable" >&2
    exit 1
  }
  printf 'CAPABILITY dpkg-root-transactions: %s\n' "$(dpkg --version | head -n 1)"
  mkdir -p "$root/var/lib/dpkg/updates" "$root/var/lib/dpkg/info"
  $privileged dpkg --force-architecture --root="$root" --install \
    "$repo/pool/main/native-helper-target_1.0-1_$architecture.deb" \
    >"$workspace/root-seed.log" 2>&1
  $privileged "$runtime" "$root" /bin/sh /bin/sh
  full_lock="$workspace/full-base-dep.lock.json"
  run_mutating_json plan $common --lock-output "$full_lock" base-dep | grep -q '"exit_status":0'
  run_mutating_json install $mutating --lock-input "$full_lock" base-dep | grep -q '"exit_status":0'
  echo "ASSERT dpkg-install: passed"
  run_mutating_json install $mutating --lock-input "$full_lock" --cache-only base-dep | grep -q '"exit_status":0'
  echo "ASSERT dpkg-reinstall: passed"
  $privileged dpkg --root="$root" --remove base-dep >/dev/null 2>&1
  echo "ASSERT dpkg-remove: passed"
  run_mutating_json clean $mutating | grep -q '"exit_status":0'
  echo "ASSERT cache-clean: passed"
  fail_lock="$workspace/full-fail-script.lock.json"
  run_mutating_json plan $common --lock-output "$fail_lock" fail-script | grep -q '"exit_status":0'
  set +e
  if [ "$use_sudo" = 1 ]; then
    failed_script=$(sudo -- "$debz" install $mutating --lock-input "$fail_lock" fail-script 2>"$stderr_file")
  else
    failed_script=$("$debz" install $mutating --lock-input "$fail_lock" fail-script 2>"$stderr_file")
  fi
  failed_script_status=$?
  set -e
  test "$failed_script_status" -eq 7
  printf '%s' "$failed_script" | grep -q '"id":"transaction_failed"'
  echo "ASSERT maintainer-script-failure: passed"
  set +e
  if [ "$use_sudo" = 1 ]; then
    recovery=$(sudo -- "$debz" recover --install-root "$root" --architecture "$architecture" --cache-path "$cache" --state-path "$state" --assume-yes --json 2>"$stderr_file")
  else
    recovery=$("$debz" recover --install-root "$root" --architecture "$architecture" --cache-path "$cache" --state-path "$state" --assume-yes --json 2>"$stderr_file")
  fi
  recovery_status=$?
  set -e
  printf 'RECOVERY status=%s output=%s\n' "$recovery_status" "$recovery"
  test "$recovery_status" -eq 0
  printf '%s' "$recovery" | grep -q '"exit_status":0'
fi

printf 'integration-root: %s/%s %s passed\n' "$suite" "$architecture" "$mode"
