#!/bin/sh
set -eu
trap 'rm -rf .zig-cache/cli-production-test; rm -f cli-test-stderr cli-test-stdout' EXIT

debz=$1
expected_version=$2
root="$PWD/.zig-cache/cli-production-test/root"
cache="$PWD/.zig-cache/cli-production-test/cache"
state="$PWD/.zig-cache/cli-production-test/state"
status="$PWD/src/fixtures/dpkg-status/installed.status"
common="--install-root $root --cache-path $cache --state-path $state --architecture amd64 --json"
read_common="$common --status-path $status"

mkdir -p "$root/var/lib/dpkg" "$state"

for help in -h --help; do
    output=$("$debz" "$help" 2>cli-test-stderr)
    test ! -s cli-test-stderr
    printf '%s' "$output" | grep -q 'debz <command> \[options\] \[packages\.\.\.\]'
done
test "$("$debz" version)" = "$expected_version"
set +e
"$debz" --version >/dev/null 2>cli-test-stderr
status_code=$?
set -e
test "$status_code" -eq 2
grep -q "unknown command '--version'" cli-test-stderr

set +e
"$debz" repo >/dev/null 2>cli-test-stderr
status_code=$?
set -e
test "$status_code" -eq 2
grep -q "missing command for 'debz repo'" cli-test-stderr

set +e
"$debz" repo unknown >/dev/null 2>cli-test-stderr
status_code=$?
set -e
test "$status_code" -eq 2
grep -q "unknown repository command 'unknown'" cli-test-stderr

set +e
"$debz" package-cache unknown >/dev/null 2>cli-test-stderr
status_code=$?
set -e
test "$status_code" -eq 2
grep -q "unknown package-cache command 'unknown'" cli-test-stderr

for arguments in \
    "package-cache fingerprint --json --lock-input relative --cache-path $cache --architecture amd64" \
    "package-cache fingerprint --json --lock-input /missing --cache-path $cache --architecture amd64 --offline" \
    "package-cache fingerprint --json --lock-input /missing --cache-path $cache --architecture amd64 --archive-input /archive" \
    "package-cache prepare --json --lock-input /missing --cache-path $cache --architecture amd64 --repair-corrupt-cache --offline" \
    "package-cache prepare --json --lock-input /missing --cache-path $cache --architecture amd64 --restored-cache exact" \
    "package-cache prepare --json --lock-input /missing --cache-path $cache --architecture amd64"
do
    set +e
    output=$("$debz" $arguments 2>cli-test-stderr)
    status_code=$?
    set -e
    test "$status_code" -eq 2
    test ! -s cli-test-stderr
    printf '%s' "$output" | grep -q '"schema":"io.github.cataggar.debz.package-cache-error.v1"'
    printf '%s' "$output" | grep -q '"id":"invalid_request"'
done

for arguments in \
    "repo add --json" \
    "repo add --json --url https://one.invalid/config.deb --url https://two.invalid/config.deb" \
    "repo add --json --url https://packages.invalid/config.deb --sha256 malformed" \
    "repo add --json --url https://packages.invalid/config.deb --redirect-limit 65536" \
    "repo add --json --url https://packages.invalid/config.deb --deadline-ms 0" \
    "repo add --json --url https://packages.invalid/config.deb --root relative" \
    "repo add --json --url https://packages.invalid/config.deb -- --operand" \
    "repo add --json --url https://packages.invalid/config.deb --refresh" \
    "repo add --json --url https://packages.invalid/config.deb --install-root /" \
    "repo add --json --url https://packages.invalid/config.deb --import-target-apt-config" \
    "repo add --json --url https://packages.invalid/config.deb --allow-host-root" \
    "repo add --json --url https://packages.invalid/config.deb --assume-yes"
do
    set +e
    output=$("$debz" $arguments 2>cli-test-stderr)
    status_code=$?
    set -e
    test "$status_code" -eq 2
    test ! -s cli-test-stderr
    printf '%s' "$output" | grep -q '"operation":"add"'
    printf '%s' "$output" | grep -q '"id":"invalid_request"\|"id":"invalid_digest"\|"id":"invalid_root"'
    printf '%s' "$output" | grep -q '"exit_status":2'
done

secret='fixture-query-secret'
scheme=https
credential_authority='user:credential@packages.invalid'
set +e
output=$("$debz" repo add --json \
    --url "$scheme://$credential_authority/config.deb?token=$secret" \
    2>cli-test-stderr)
status_code=$?
set -e
test "$status_code" -eq 2
test ! -s cli-test-stderr
printf '%s' "$output" | grep -q '"id":"credential_bearing_url"'
printf '%s' "$output" | grep -vq "$secret"
printf '%s' "$output" | grep -vq 'user:credential'

set +e
"$debz" repo add \
    --url https://packages.invalid/config.deb \
    --root relative \
    >cli-test-stdout 2>cli-test-stderr
status_code=$?
set -e
test "$status_code" -eq 2
test ! -s cli-test-stdout
grep -q 'repo add: root must be a canonical absolute path' cli-test-stderr
grep -Fq 'debz[invalid_root] (request): root must be a canonical absolute path' cli-test-stderr

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
