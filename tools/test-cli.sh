#!/bin/sh
set -eu
trap 'rm -f cli-test-stderr' EXIT

debz=$1
common="--install-root /fixture/root --cache-path /fixture/cache --state-path /fixture/state --architecture amd64 --json"

"$debz" --help >/dev/null
"$debz" --version | grep -q 'API v1'

for command in refresh upgrade-all list-installed list-available clean recover; do
    extra=
    case "$command" in
        refresh|upgrade-all|clean|recover) extra="--assume-yes" ;;
    esac
    set +e
    output=$("$debz" "$command" $common $extra 2>cli-test-stderr)
    status=$?
    set -e
    test "$status" -eq 3
    test ! -s cli-test-stderr
    printf '%s' "$output" | grep -q '"schema":"io.github.cataggar.debz.command.v1"'
    printf '%s' "$output" | grep -q "\"operation\":\"$command\""
    printf '%s' "$output" | grep -q '"id":"configuration_required"'
done

for command in install remove upgrade reinstall download plan info provides why; do
    extra=demo
    case "$command" in
        install|remove|upgrade|reinstall) extra="--assume-yes demo" ;;
    esac
    set +e
    output=$("$debz" "$command" $common $extra 2>cli-test-stderr)
    status=$?
    set -e
    test "$status" -eq 3
    test ! -s cli-test-stderr
    printf '%s' "$output" | grep -q "\"operation\":\"$command\""
done

set +e
output=$("$debz" install $common demo 2>cli-test-stderr)
status=$?
set -e
test "$status" -eq 2
test ! -s cli-test-stderr
printf '%s' "$output" | grep -q '"id":"confirmation_required"'
