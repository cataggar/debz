#!/bin/sh
set -eu

debz=$1
scratch="native-only-rehearsal-$$"
test ! -e "$scratch"
test ! -L "$scratch"
mkdir "$scratch"
mkdir "$scratch/root"
trap 'rm -rf -- "$scratch"' EXIT
root="$PWD/$scratch/root"
printf 'unchanged\n' >"$scratch/root/sentinel"

unchanged() {
    test "$(cat "$scratch/root/sentinel")" = "unchanged"
    test ! -e "$scratch/root/var"
    test ! -e "$scratch/lock.json"
    test ! -e "$scratch/lock.json.legacy-capability-v1.json"
    test ! -e "$scratch/state"
    test ! -e "$scratch/cache"
}

refuses_legacy() {
    expected=$1
    shift
    status=0
    output=$("$debz" "$@" 2>"$scratch/stderr") || status=$?
    test "$status" -eq "$expected"
    test ! -s "$scratch/stderr"
    printf '%s' "$output" | grep -Fq '"legacy_recovery_release_required"'
    printf '%s' "$output" | grep -Fq 'Recover this operation with debz >=0.3.0,<0.4.0 before installing a native-only release.'
    unchanged
}

for command in install recover; do
    refuses_legacy 8 "$command" --json --transaction-backend legacy_dpkg \
        --install-root "$root" --cache-path "$PWD/$scratch/cache" \
        --state-path "$PWD/$scratch/state" --architecture amd64 \
        --lock-input "$PWD/$scratch/no-lock" --lock-output "$PWD/$scratch/lock.json"
done
refuses_legacy 9 repo add --json --transaction-backend legacy_dpkg \
    --url https://packages.test/config.deb --root "$root"
refuses_legacy 9 repo add --json --transaction-backend legacy_dpkg \
    --url https://packages.test/config.deb --root "$root"

for backend in omitted native; do
    status=0
    if [ "$backend" = native ]; then
        output=$("$debz" repo add --json --transaction-backend native \
            --url https://packages.test/config.deb --root "$root" 2>"$scratch/stderr") || status=$?
    else
        output=$("$debz" repo add --json \
            --url https://packages.test/config.deb --root "$root" 2>"$scratch/stderr") || status=$?
    fi
    test "$status" -eq 3
    test ! -s "$scratch/stderr"
    printf '%s' "$output" | grep -Fq '"transaction_backend_unavailable"'
    unchanged
done

status=0
output=$("$debz" install --json demo --install-root "$root" \
    --cache-path "$PWD/$scratch/cache" --state-path "$PWD/$scratch/state" \
    --architecture amd64 --assume-yes --conffile keep-existing 2>"$scratch/stderr") || status=$?
test "$status" -ne 0
test ! -s "$scratch/stderr"
! printf '%s' "$output" | grep -Fq '"legacy_recovery_release_required"'
unchanged

status=0
"$debz" transaction-result verify --json --transaction-backend legacy_dpkg \
    --state-path "$root" --lock-input "$PWD/$scratch/no-lock" \
    --architecture amd64 >"$scratch/output" 2>"$scratch/stderr" || status=$?
test "$status" -eq 7
grep -Fq 'transaction result verification failed' "$scratch/stderr"
unchanged

status=0
"$debz" transaction-result verify --json --state-path "$root" \
    --lock-input "$PWD/$scratch/no-lock" --architecture amd64 \
    >"$scratch/output" 2>"$scratch/stderr" || status=$?
test "$status" -eq 2
grep -Fq 'native verification does not use --state-path' "$scratch/stderr"
unchanged

status=0
"$debz" apt install --json demo >"$scratch/output" 2>"$scratch/stderr" || status=$?
test "$status" -eq 2
grep -Fq 'native-only rehearsal does not cover this selector (#280/#284)' "$scratch/stderr"
unchanged
