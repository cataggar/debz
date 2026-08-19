#!/bin/sh
set -eu
trap 'rm -rf .zig-cache/cli-production-test; rm -f cli-test-stderr' EXIT

debz=$1
expected_version=$2
root="$PWD/.zig-cache/cli-production-test/root"
cache="$PWD/.zig-cache/cli-production-test/cache"
state="$PWD/.zig-cache/cli-production-test/state"
status="$PWD/src/fixtures/dpkg-status/installed.status"
common="--install-root $root --cache-path $cache --state-path $state --architecture amd64 --json"
read_common="$common --status-path $status"

mkdir -p "$root/var/lib/dpkg" "$state"

"$debz" --help >/dev/null
test "$("$debz" --version)" = "$expected_version"

output=$("$debz" list-installed $read_common 2>cli-test-stderr)
test ! -s cli-test-stderr
printf '%s' "$output" | grep -q '"operation":"list-installed"'
printf '%s' "$output" | grep -q '"exit_status":0'
printf '%s' "$output" | grep -q '"package":"debz"'

output=$("$debz" why $read_common debz 2>cli-test-stderr)
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

for arguments in \
    "list-installed --json --install-root $root --install-root $root --cache-path $cache --state-path $state --architecture amd64" \
    "install --json --install-root $root --cache-path $cache --state-path $state --architecture amd64 --assume-yes one two" \
    "clean --json --install-root $root --cache-path $cache --state-path $state --status-path $status --architecture amd64 --assume-yes" \
    "clean --json --install-root / --cache-path / --state-path / --architecture amd64 --assume-yes"
do
    set +e
    output=$("$debz" $arguments 2>cli-test-stderr)
    status_code=$?
    set -e
    test "$status_code" -eq 2
    test ! -s cli-test-stderr
    printf '%s' "$output" | grep -q '"id":"invalid_request"'
    printf '%s' "$output" | grep -q '"exit_status":2'
done
