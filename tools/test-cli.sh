#!/bin/sh
set -eu
trap 'rm -rf .zig-cache/cli-production-test; rm -f cli-test-stderr' EXIT

debz=$1
root="$PWD/.zig-cache/cli-production-test/root"
cache="$PWD/.zig-cache/cli-production-test/cache"
state="$PWD/.zig-cache/cli-production-test/state"
status="$PWD/src/fixtures/dpkg-status/installed.status"
common="--install-root $root --cache-path $cache --state-path $state --status-path $status --architecture amd64 --json"

mkdir -p "$root/var/lib/dpkg" "$state"

"$debz" --help >/dev/null
"$debz" --version | grep -q 'API v1'

output=$("$debz" list-installed $common 2>cli-test-stderr)
test ! -s cli-test-stderr
printf '%s' "$output" | grep -q '"operation":"list-installed"'
printf '%s' "$output" | grep -q '"exit_status":0'
printf '%s' "$output" | grep -q '"package":"debz"'

output=$("$debz" why $common debz 2>cli-test-stderr)
test ! -s cli-test-stderr
printf '%s' "$output" | grep -q '"operation":"why"'
printf '%s' "$output" | grep -q '"exit_status":0'

for command in refresh list-available; do
    extra=
    test "$command" != refresh || extra=--assume-yes
    set +e
    output=$("$debz" "$command" $common $extra 2>cli-test-stderr)
    status_code=$?
    set -e
    test "$status_code" -eq 2
    test ! -s cli-test-stderr
    printf '%s' "$output" | grep -q '"id":"configuration_required"'
    printf '%s' "$output" | grep -vq '"exit_status":3'
done

set +e
output=$("$debz" install $common demo 2>cli-test-stderr)
status_code=$?
set -e
test "$status_code" -eq 2
test ! -s cli-test-stderr
printf '%s' "$output" | grep -q '"id":"confirmation_required"'

output=$("$debz" clean $common --assume-yes 2>cli-test-stderr)
test ! -s cli-test-stderr
printf '%s' "$output" | grep -q '"operation":"clean"'
printf '%s' "$output" | grep -q '"exit_status":0'
