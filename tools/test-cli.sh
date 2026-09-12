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

for arguments in \
    "apt" \
    "apt --help" \
    "apt update --help ignored-secret" \
    "apt install --bad --help ignored-secret" \
    "apt remove --help ignored-secret" \
    "apt upgrade --help ignored-secret" \
    "apt list --help ignored-secret"
do
    output=$("$debz" $arguments 2>cli-test-stderr)
    test ! -s cli-test-stderr
    printf '%s' "$output" | grep -q 'debz apt'
    printf '%s' "$output" | grep -vq 'ignored-secret'
done

set +e
"$debz" apt --json update extra >cli-test-stdout 2>cli-test-stderr
status_code=$?
set -e
test "$status_code" -eq 2
test ! -s cli-test-stderr
test "$(wc -l <cli-test-stdout)" -eq 1
grep -q 'apt-system-cli-diagnostic.v1' cli-test-stdout

secret='misplaced-json-control-secret'
for arguments in \
    "apt update --json" \
    "apt --profile --json update" \
    "apt --$secret --json update"
do
    set +e
    "$debz" $arguments >cli-test-stdout 2>cli-test-stderr
    status_code=$?
    set -e
    test "$status_code" -eq 2
    test ! -s cli-test-stdout
    grep -q 'usage error' cli-test-stderr
    grep -vq "$secret" cli-test-stderr
done

set +e
"$debz" recover --system-profile --json >cli-test-stdout 2>cli-test-stderr
status_code=$?
set -e
test "$status_code" -eq 2
test ! -s cli-test-stdout
grep -q 'usage error' cli-test-stderr

python3 - "$debz" <<'PY'
import subprocess
import sys

debz = sys.argv[1]
dangerous = "--credential=decisive-help-secret"
result = subprocess.run(
    [debz, "apt", "update", "--help", dangerous]
    + list("ignored" for _ in range(8000)),
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    timeout=5,
    check=False,
)
assert result.returncode == 0, result
assert b"debz apt update" in result.stdout
assert dangerous.encode() not in result.stdout
assert not result.stderr

result = subprocess.run(
    [debz, "recover", "--system-profile", "/profile.json", "--help", dangerous]
    + list("ignored" for _ in range(8000)),
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    timeout=5,
    check=False,
)
assert result.returncode == 0, result
assert b"debz recover --system-profile PATH" in result.stdout
assert dangerous.encode() not in result.stdout
assert not result.stderr
PY

secret='rejected-cli-secret'
for arguments in \
    "apt --profile /missing-profile.json --json install --$secret" \
    "apt --profile /missing-profile.json --json list --available" \
    "apt --profile /missing-profile.json --json upgrade extra" \
    "apt --profile /missing-profile.json --json update --json"
do
    set +e
    output=$("$debz" $arguments 2>cli-test-stderr)
    status_code=$?
    set -e
    test "$status_code" -eq 2
    test ! -s cli-test-stderr
    test "$(printf '%s\n' "$output" | wc -l)" -eq 1
    printf '%s' "$output" | grep -q 'apt-system-cli-diagnostic.v1'
    printf '%s' "$output" | grep -vq "$secret"
done

for arguments in \
    "apt --profile /missing-profile.json --json update" \
    "apt --json --profile /missing-profile.json install -y alpha beta" \
    "apt --profile /missing-profile.json --json remove -y alpha beta" \
    "apt --profile /missing-profile.json --json upgrade -y" \
    "apt --profile /missing-profile.json --json list --installed"
do
    set +e
    output=$("$debz" $arguments 2>cli-test-stderr)
    status_code=$?
    set -e
    test "$status_code" -eq 3
    test ! -s cli-test-stderr
    test "$(printf '%s\n' "$output" | wc -l)" -eq 1
    printf '%s' "$output" | grep -q 'apt-system-result.v'
    printf '%s' "$output" | grep -q '"id":"profile_invalid"'
done

output=$("$debz" recover --system-profile /missing-profile.json --help ignored-secret 2>cli-test-stderr)
test ! -s cli-test-stderr
printf '%s' "$output" | grep -q 'apt-system operation'
printf '%s' "$output" | grep -vq 'ignored-secret'

set +e
output=$("$debz" recover --json --system-profile relative 2>cli-test-stderr)
status_code=$?
set -e
test "$status_code" -eq 2
test ! -s cli-test-stderr
test "$(printf '%s\n' "$output" | wc -l)" -eq 1
printf '%s' "$output" | grep -q 'invalid_profile_path'

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

set +e
"$debz" transaction-result verify --state-path relative \
    --lock-input /missing --architecture amd64 --json \
    >/dev/null 2>cli-test-stderr
status_code=$?
set -e
test "$status_code" -eq 2
grep -q "invalid explicit path or architecture" cli-test-stderr

set +e
"$debz" transaction-result verify --state-path "$state" \
    --lock-input /missing --architecture amd64 --json \
    >/dev/null 2>cli-test-stderr
status_code=$?
set -e
test "$status_code" -eq 7
grep -q "transaction result verification failed" cli-test-stderr

"$debz" transaction-result capabilities --transaction-backend native --json >cli-test-stdout
python3 - cli-test-stdout <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_bytes()
value = json.loads(source)
assert source.count(b"\n") == 1 and source.endswith(b"\n")
assert value["schema"] == "io.github.cataggar.debz.transaction-result-capability.v1"
assert value["backend"] == "native"
assert value["capability"] == "native-transaction-result-v1"
assert value["summary_schema"] == "io.github.cataggar.debz.transaction-result-summary.v2"
assert value["summary_api_version"] == 2
assert value["lock_schema_version"] == 2
assert value["read_only"] is True
PY

for arguments in \
    "transaction-result capabilities --json" \
    "transaction-result capabilities --transaction-backend native --install-root /unused --json" \
    "transaction-result verify --transaction-backend other --json" \
    "transaction-result verify --transaction-backend native --transaction-backend native --json" \
    "transaction-result verify --transaction-backend native --state-path $state --lock-input /missing --architecture amd64 --json" \
    "transaction-result verify --transaction-backend native --lock-input /missing --architecture amd64 --json" \
    "transaction-result verify --transaction-backend native --install-root relative --lock-input /missing --architecture amd64 --json" \
    "transaction-result verify --install-root /unused --lock-input /missing --architecture amd64 --json"
do
    set +e
    "$debz" $arguments >cli-test-stdout 2>cli-test-stderr
    status_code=$?
    set -e
    test "$status_code" -eq 2
    test ! -s cli-test-stdout
done

for arguments in \
    "package-cache fingerprint --json --lock-input relative --cache-path $cache --architecture amd64" \
    "package-cache fingerprint --json --lock-input /missing --cache-path $cache --architecture amd64 --offline" \
    "package-cache fingerprint --json --lock-input /missing --cache-path $cache --architecture amd64 --archive-input /archive" \
    "package-cache fingerprint --json --transaction-backend other --lock-input /missing --cache-path $cache --architecture amd64" \
    "package-cache fingerprint --json --transaction-backend native --transaction-backend native --lock-input /missing --cache-path $cache --architecture amd64" \
    "package-cache prepare --json --transaction-backend native --transaction-backend legacy_dpkg --lock-input /missing --cache-path $cache --architecture amd64" \
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

for command in plan download; do
    set +e
    output=$("$debz" "$command" $common --transaction-backend native demo 2>cli-test-stderr)
    status_code=$?
    set -e
    test "$status_code" -eq 2
    test ! -s cli-test-stderr
    printf '%s' "$output" | grep -q '"id":"configuration_required"'
done

for arguments in \
    "install demo" \
    "remove demo" \
    "reinstall demo" \
    "upgrade demo" \
    "upgrade-all"
do
    set +e
    output=$("$debz" $arguments $common --transaction-backend native \
        --assume-yes --conffile keep-existing 2>cli-test-stderr)
    status_code=$?
    set -e
    test "$status_code" -eq 2
    test ! -s cli-test-stderr
    printf '%s' "$output" | grep -q '"id":"configuration_required"'
done

output=$("$debz" recover $common --transaction-backend native \
    --assume-yes --conffile keep-existing 2>cli-test-stderr)
test ! -s cli-test-stderr
printf '%s' "$output" | grep -q '"exit_status":0'
printf '%s' "$output" | grep -q '"changed":false'
test ! -e "$root/var/lib/debz/root-operation-v1.json"

for arguments in \
    "plan --json demo --transaction-backend unknown" \
    "plan --json demo --transaction-backend native --transaction-backend legacy_dpkg" \
    "plan --json demo --transaction-backend" \
    "list-installed --json --transaction-backend native"
do
    set +e
    output=$("$debz" $arguments $common 2>cli-test-stderr)
    status_code=$?
    set -e
    test "$status_code" -eq 2
    test ! -s cli-test-stderr
    printf '%s' "$output" | grep -q '"id":"invalid_request"'
done

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
