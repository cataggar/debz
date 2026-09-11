#!/bin/sh
set -eu
umask 077

debz=$1
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
python3 tools/generate-integration-repository.py \
  --output "$repo" --suite "$suite" --architecture "$architecture"
cat >"$source_file" <<EOF
Types: deb
URIs: file://$repo
Suites: $suite
Components: main
Architectures: $architecture
Signed-By: $keyring
EOF

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
python3 - "$resolved_lock" "$native_lock" "$native_cache" <<'PY'
import hashlib
import json
import pathlib
import sys

legacy = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
native = json.loads(pathlib.Path(sys.argv[2]).read_bytes())
assert native["schema"] == "https://debz.dev/schema/exact-closure-lock-v2"
assert native["version"] == 2
assert native["request_sha256"] == legacy["request_sha256"]
assert native["policy_sha256"] == hashlib.sha256(
    b"debz.product-native-solver-policy-v1\0" + bytes.fromhex(legacy["policy_sha256"])
).hexdigest()
assert native["repositories"] == legacy["repositories"]
assert native["local_artifacts"] == []
assert len(native["packages"]) == len(legacy["packages"])
for package, previous in zip(native["packages"], legacy["packages"]):
    origin = package["origin"]
    assert origin["type"] == "authenticated_repository"
    for field in ("repository_id", "repository_snapshot_sha256"):
        assert origin[field] == previous[field]
    for field in ("name", "version", "architecture", "sha256", "declared_size", "retention", "dpkg_selection_hold"):
        assert package[field] == previous[field]
    data = (pathlib.Path(sys.argv[3]) / "packages-v1/objects" / package["sha256"]).read_bytes()
    assert len(data) == package["declared_size"]
    assert hashlib.sha256(data).hexdigest() == package["sha256"]
expected = native.pop("digest_sha256")
assert hashlib.sha256(json.dumps(native, separators=(",", ":")).encode()).hexdigest() == expected
PY
set +e
native_wrong_version=$("$debz" plan $native_common --lock-input "$resolved_lock" base-dep 2>"$stderr_file")
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
printf '%s' "$native_unavailable" | grep -q 'NativeHelperTargetMissing'
test ! -s "$root/var/lib/dpkg/status"
test ! -e "$root/var/lib/debz/root-operation-v1.json"
test ! -e "$root/var/lib/debz/native-execution-intent-v1.json"
test ! -e "$root/var/lib/debz/native-helper-cache-v1"

if [ "$mode" != smoke ]; then
  privileged=
  if [ "$use_sudo" = 1 ]; then privileged="sudo -n"; fi
  native_root="$workspace/native-root"
  native_state="$workspace/native-unused-state"
  mkdir -p "$native_root/var/lib/dpkg"
  : >"$native_root/var/lib/dpkg/status"
  $privileged dpkg --root="$native_root" --install \
    "$repo/pool/main/native-helper-target_1.0-1_$architecture.deb" \
    >"$workspace/native-seed.log" 2>&1
  native_execution="--install-root $native_root --cache-path $native_cache --state-path $native_state --architecture $architecture --source $source_file --keyring $keyring --transaction-backend native --json"
  native_execution_lock="$workspace/native-execution.lock.json"
  # Keep private cache files under one UID across planning and execution.
  run_mutating_json plan $native_execution --lock-output "$native_execution_lock" base-dep | grep -q '"exit_status":0'
  run_mutating_json install $native_execution --lock-input "$native_execution_lock" \
    --assume-yes --noninteractive --conffile keep-existing base-dep |
    grep -q '"changed":true'
  $privileged python3 - "$native_root" "$native_execution_lock" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
lock = json.loads(pathlib.Path(sys.argv[2]).read_bytes())
assert {entry["name"] for entry in lock["packages"]} == {"base-dep", "essential-core", "native-helper-target"}
namespace = root / "var/lib/debz"
receipt = json.loads((namespace / "native-transaction-provenance-v1.json").read_bytes())
completion = json.loads((namespace / "root-operation-completion-v1.json").read_bytes())
assert receipt["outcome"] == "succeeded"
assert receipt["backend"] == completion["backend"] == "native"
assert receipt["attempt_id"] == completion["attempt_id"]
assert receipt["install_root"] == str(root)
assert receipt["exact_lock_sha256"] == lock["digest_sha256"]
assert completion["transaction_provenance"]["schema"] == receipt["schema"]
assert completion["transaction_provenance"]["document_sha256"] == receipt["digest_sha256"]
assert completion["journal"]["status"] == "absent"
for evidence in receipt["evidence_files"]:
    data = (root / evidence["path"]).read_bytes()
    assert len(data) == evidence["size"]
    assert hashlib.sha256(data).hexdigest() == evidence["sha256"]
assert (root / "usr/share/debz-fixtures/base-dep").is_file()
assert (root / "usr/bin/dpkg-trigger").read_bytes().startswith(b"native-helper-target=")
for path in ("root-operation-v1.json", "native-execution-intent-v1.json", "native-recovery-v1"):
    assert not (namespace / path).exists()
PY
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
  $privileged python3 -B - "$native_root" <<'PY'
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("runtime", "tools/test-apt-system-acceptance.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
runtime.copy_program(Path(sys.argv[1]), Path("/bin/sh"), "/bin/sh")
PY
  native_trigger_lock="$workspace/native-trigger.lock.json"
  run_mutating_json plan $native_execution --lock-output "$native_trigger_lock" native-trigger-pkg | grep -q '"exit_status":0'
  run_mutating_json install $native_execution --lock-input "$native_trigger_lock" \
    --assume-yes --noninteractive --conffile keep-existing native-trigger-pkg |
    grep -q '"changed":true'
  $privileged python3 - "$native_root" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
trace = (root / "native-trigger-trace").read_text().splitlines()
assert trace == ["configure ", "triggered native-fixture"], trace
receipt = json.loads((root / "var/lib/debz/native-transaction-provenance-v1.json").read_bytes())
assert receipt["outcome"] == "succeeded"
authorization_file = next(entry for entry in receipt["evidence_files"] if entry["kind"] == "authorization")
authorization = json.loads((root / authorization_file["path"]).read_bytes())
assert authorization["trigger_authority"]["allowed_triggers"] == ["native-fixture"]
assert not (root / "var/lib/debz/native-execution-intent-v1.json").exists()
PY
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
printf '%s' "$fingerprint" | grep -q '"schema":"io.github.cataggar.debz.package-cache-fingerprint.v1"'
printf '%s' "$fingerprint" | grep -q '"capability":"package-cache-v1"'
printf '%s' "$fingerprint" | grep -q '"cas_layout":"packages-v1"'

set +e
unsupported=$("$debz" package-cache fingerprint \
  --lock-input "$native_lock" \
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
printf '%s' "$cold" | grep -q '"schema":"io.github.cataggar.debz.package-cache-result.v1"'
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["downloaded_count"] == value["verified_count"]; assert value["reused_count"] == 0' <<EOF
$cold
EOF

retry_cache="$workspace/package-cache-retry"
python3 - "$resolved_lock" "$retry_cache" <<'PY'
import json
import pathlib
import sys
lock = json.loads(pathlib.Path(sys.argv[1]).read_text())
digest = lock["packages"][0]["sha256"]
name = f"package-{digest[:8]}-0000000000000000.tmp"
name += "_" * (96 - len(name))
staging = pathlib.Path(sys.argv[2]) / "packages-v1" / "staging"
staging.mkdir(parents=True)
(staging / name).write_bytes(b"abandoned")
PY
retried=$(run_json package-cache prepare \
  --lock-input "$resolved_lock" --cache-path "$retry_cache" \
  --architecture "$architecture" --source "$source_file" --keyring "$keyring" \
  --archive-input "$package_cache_archives/base.dbzcache" \
  --restored-cache exact --json)
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["downloaded_count"] == 0; assert value["reused_count"] == value["verified_count"]; assert value["staging"]["deleted"] >= 1' <<EOF
$retried
EOF
test -z "$(find "$retry_cache/packages-v1/staging" -mindepth 1 -print -quit)"

limited_cache="$workspace/package-cache-cleanup-limit"
mkdir -p "$limited_cache/packages-v1/staging"
printf partial >"$limited_cache/packages-v1/staging/one"
printf partial >"$limited_cache/packages-v1/staging/two"
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
test -z "$(find "$limited_cache/packages-v1/objects" -mindepth 1 -type f -print -quit)"

exact=$(run_json package-cache prepare $package_cache_common \
  --source "$source_file" --keyring "$keyring" --offline --json)
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["downloaded_count"] == 0; assert value["reused_count"] == value["verified_count"]' <<EOF
$exact
EOF

scenario_lock="$workspace/scenario-main.lock.json"
run_json plan $common --lock-output "$scenario_lock" scenario-main | grep -q '"exit_status":0'
archive_partial=$(run_json package-cache prepare \
  --lock-input "$scenario_lock" --cache-path "$workspace/package-cache-relocated" \
  --architecture "$architecture" --source "$source_file" --keyring "$keyring" \
  --archive-input "$package_cache_archives/base.dbzcache" \
  --archive-output "$package_cache_archives/scenario.dbzcache" \
  --restored-cache partial --json)
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["downloaded_count"] > 0; assert value["reused_count"] > 0' <<EOF
$archive_partial
EOF

archive_exact=$(run_json package-cache prepare \
  --lock-input "$scenario_lock" --cache-path "$workspace/package-cache-relocated-exact" \
  --architecture "$architecture" --source "$source_file" --keyring "$keyring" \
  --archive-input "$package_cache_archives/scenario.dbzcache" \
  --restored-cache exact --json)
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["downloaded_count"] == 0; assert value["reused_count"] == value["verified_count"]' <<EOF
$archive_exact
EOF

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
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["downloaded_count"] > 0; assert value["reused_count"] > 0' <<EOF
$partial
EOF

pruned=$(run_json package-cache prepare $package_cache_common \
  --source "$source_file" --keyring "$keyring" --offline --json)
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["gc"]["deleted"] > 0; assert value["gc"]["complete"] is True' <<EOF
$pruned
EOF

first_cache_object=$(find "$package_cache_root/packages-v1/objects" -type f | head -n 1 || true)
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
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["downloaded_count"] == 1; assert value["reused_count"] + 1 == value["verified_count"]' <<EOF
$repaired
EOF
rm -f "$workspace/package-cache-object.backup"

offline_objects_only="$workspace/offline-objects-only"
mkdir -p "$offline_objects_only/packages-v1"
cp -R "$package_cache_root/packages-v1/objects" "$offline_objects_only/packages-v1/objects"
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

printf 'tamper' >>"$repo/dists/$suite/InRelease"
set +e
moving_repository=$("$debz" package-cache prepare $package_cache_common \
  --source "$source_file" --keyring "$keyring" --json 2>"$stderr_file")
moving_repository_status=$?
set -e
test "$moving_repository_status" -eq 4
test ! -s "$stderr_file"
printf '%s' "$moving_repository" | grep -q '"id":"repository_authentication_failed"'
python3 tools/generate-integration-repository.py \
  --output "$repo" --suite "$suite" --architecture "$architecture"

find "$package_cache_root/packages-v1/objects" -mindepth 1 -maxdepth 1 -type f |
  while IFS= read -r object; do
    basename "$object" | grep -Eq '^[0-9a-f]{64}$'
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
python3 tools/generate-integration-repository.py \
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

  first_object=$(find "$cache" -type f -path '*/packages-v1/objects/*' | head -n 1 || true)
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
  dpkg --admindir="$root/var/lib/dpkg" --add-architecture "$architecture"
  run_mutating_json install $mutating base-dep | grep -q '"exit_status":0'
  echo "ASSERT dpkg-install: passed"
  run_mutating_json reinstall $mutating base-dep | grep -q '"exit_status":0'
  echo "ASSERT dpkg-reinstall: passed"
  run_mutating_json remove $mutating base-dep | grep -q '"exit_status":0'
  echo "ASSERT dpkg-remove: passed"
  run_mutating_json clean $mutating | grep -q '"exit_status":0'
  echo "ASSERT cache-clean: passed"
  set +e
  if [ "$use_sudo" = 1 ]; then
    failed_script=$(sudo -- "$debz" install $mutating fail-script 2>"$stderr_file")
  else
    failed_script=$("$debz" install $mutating fail-script 2>"$stderr_file")
  fi
  failed_script_status=$?
  set -e
  test "$failed_script_status" -eq 7
  printf '%s' "$failed_script" | grep -q '"id":"transaction_failed"'
  echo "ASSERT maintainer-script-failure: passed"
  set +e
  if [ "$use_sudo" = 1 ]; then
    recovery=$(sudo -- "$debz" recover $mutating 2>"$stderr_file")
  else
    recovery=$("$debz" recover $mutating 2>"$stderr_file")
  fi
  recovery_status=$?
  set -e
  printf 'RECOVERY status=%s output=%s\n' "$recovery_status" "$recovery"
  test "$recovery_status" -ne 0
  printf '%s' "$recovery" | grep -q '"exit_status":7\|"exit_status":8'
fi

printf 'integration-root: %s/%s %s passed\n' "$suite" "$architecture" "$mode"
