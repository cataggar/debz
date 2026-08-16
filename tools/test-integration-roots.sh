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
  *) echo "unsupported integration tuple: $suite/$architecture/$mode" >&2; exit 2 ;;
esac

rm -rf "$workspace"
mkdir -p "$root/var/lib/dpkg" "$root/var/lib/debz" "$cache" "$state"
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
