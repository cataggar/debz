#!/bin/sh
set -eu
umask 077
export PYTHONDONTWRITEBYTECODE=1

debz=$1
harness=$2
architecture=${DEBZ_REPOSITORY_ADD_ARCH:-amd64}
system_install_integration=${DEBZ_SYSTEM_INSTALL_INTEGRATION:-0}
workspace="$PWD/.zig-cache/repository-add-integration"
http_root="$workspace/http"
repository="$http_root/repository"
descriptor="$http_root/config/packages-microsoft-prod.deb"
port_file="$workspace/http.port"
request_log="$workspace/http.requests"
server_stderr="$workspace/http.stderr"
harness_stderr="$workspace/harness.stderr"

case "$workspace" in
  "$PWD"/.zig-cache/repository-add-integration) ;;
  *) echo "refusing unsafe repository integration workspace" >&2; exit 2 ;;
esac
test ! -L "$workspace"
rm -rf "$workspace"
mkdir -p "$http_root"
: >"$request_log"

python3 tools/http-fixture-server.py \
  --root "$http_root" \
  --port-file "$port_file" \
  --request-log "$request_log" \
  2>"$server_stderr" &
server_pid=$!
cleanup() {
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  if [ -e "$workspace" ] && [ "$(id -u)" -ne 0 ]; then
    sudo -n chown -R "$(id -u):$(id -g)" "$workspace" 2>/dev/null || true
  fi
  rm -rf "$workspace"
}
trap cleanup EXIT HUP INT TERM

attempt=0
while [ ! -s "$port_file" ]; do
  attempt=$((attempt + 1))
  test "$attempt" -lt 100 || {
    cat "$server_stderr" >&2
    echo "local fixture server did not start" >&2
    exit 1
  }
  sleep 0.05
done
port=$(cat "$port_file")
repository_url="http://127.0.0.1:$port/repository"
descriptor_url="http://127.0.0.1:$port/config/packages-microsoft-prod.deb?token=fixture-query-secret"
release_date_unix=$(date -u +%s)

python3 tools/generate-integration-repository.py \
  --output "$repository" \
  --suite debian-stable \
  --architecture "$architecture" \
  --missing-valid-until \
  --release-date-unix "$release_date_unix" \
  --descriptor-output "$descriptor" \
  --descriptor-repository-url "$repository_url"
bootstrap_repository="$http_root/bootstrap-repository"
python3 tools/generate-integration-repository.py \
  --output "$bootstrap_repository" \
  --suite debian-stable \
  --architecture "$architecture"
bootstrap_repository_url="http://127.0.0.1:$port/bootstrap-repository"

source_file="$workspace/microsoft-prod.list"
cat >"$source_file" <<EOF
deb [arch=$architecture signed-by=/usr/share/keyrings/microsoft-prod.gpg] $repository_url debian-stable main
EOF
keyring="$repository/fixture-keyring.gpg"
set -- $(sha256sum "$descriptor")
descriptor_sha256=$1

run_harness() {
  target_root=$1
  shift
  mkdir -p \
    "$target_root/var/lib/dpkg" \
    "$target_root/etc/apt/sources.list.d" \
    "$target_root/usr/share/keyrings"
  : >"$target_root/var/lib/dpkg/status"
  cp "$keyring" "$target_root/usr/share/keyrings/bootstrap.gpg"
  cat >"$target_root/etc/apt/sources.list.d/bootstrap.sources" <<EOF
Types: deb
URIs: $bootstrap_repository_url
Suites: debian-stable
Components: main
Architectures: $architecture
Signed-By: /usr/share/keyrings/bootstrap.gpg
EOF
  set +e
  output=$("$harness" "$source_file" "$keyring" \
    --url "$descriptor_url" \
    --root "$target_root" \
    --sha256 "$descriptor_sha256" \
    --architecture "$architecture" \
    --deadline-ms 60000 \
    --lock-wait-ms 5000 \
    --maximum-repositories 8 \
    --maximum-actions 64 \
    --missing-valid-until-max-age-seconds 604800 \
    --json "$@" 2>"$harness_stderr")
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    cat "$harness_stderr" >&2
    return "$status"
  fi
  if [ -s "$harness_stderr" ]; then
    cat "$harness_stderr" >&2
    exit 1
  fi
  printf '%s\n' "$output"
}

run_product() {
  if [ "$(id -u)" -eq 0 ]; then
    "$debz" "$@"
  else
    sudo -n true >/dev/null 2>&1 || {
      echo "two-command transaction integration requires noninteractive sudo" >&2
      return 1
    }
    sudo -- "$debz" "$@"
  fi
}

prepare_dpkg_root() {
  target_root=$1
  mkdir -p "$target_root/var/lib/dpkg/info" "$target_root/var/lib/dpkg/updates"
  dpkg --admindir="$target_root/var/lib/dpkg" --add-architecture "$architecture"
}

full_root="$workspace/full-root"
full_output=$(run_harness "$full_root")
printf '%s' "$full_output" | grep -q 'FIRST=.*"exit_status":0'
printf '%s' "$full_output" | grep -q 'FIRST=.*"changed":true'
printf '%s' "$full_output" | grep -q 'FIRST=.*"refreshed_phase":"complete"'
printf '%s' "$full_output" | grep -q 'SECOND=.*"changed":false'
printf '%s' "$full_output" | grep -q 'HUMAN=repository added: packages-microsoft-prod=1.2-fixture:all; installed=yes; refreshed=yes'
test -s "$full_root/etc/apt/sources.list.d/microsoft-prod.list"
test -s "$full_root/usr/share/keyrings/microsoft-prod.gpg"
cmp "$source_file" "$full_root/etc/apt/sources.list.d/microsoft-prod.list"
cmp "$keyring" "$full_root/usr/share/keyrings/microsoft-prod.gpg"
active_config="$full_root/var/lib/debz/repository/active-apt-config-snapshot-v2.json"
test -s "$active_config"
grep -q '"allow_missing_valid_until_with_max_age_seconds"' "$active_config"
test "$(grep -c '/config/packages-microsoft-prod.deb' "$request_log")" -eq 1
test "$(grep -c '/repository/dists/debian-stable/InRelease' "$request_log")" -eq 3
grep -q "/repository/dists/debian-stable/main/binary-$architecture/Packages" "$request_log"
grep -q '/bootstrap-repository/pool/main/ca-certificates_20240203_all.deb' "$request_log"
if grep -R -a -q 'fixture-query-secret' "$full_root"; then
  echo "descriptor query secret persisted under the target root" >&2
  exit 1
fi

if [ "$system_install_integration" = 1 ]; then
prepare_dpkg_root "$full_root"
set +e
system_install=$(run_product install \
  --install-root "$full_root" \
  --json \
  symcrypt-openssl 2>"$harness_stderr")
system_install_status=$?
set -e
if [ "$(id -u)" -ne 0 ]; then
  sudo chown -R "$(id -u):$(id -g)" "$full_root"
fi
if [ "$system_install_status" -ne 0 ]; then
  cat "$harness_stderr" >&2
  printf '%s\n' "$system_install" >&2
  exit "$system_install_status"
fi
if [ -s "$harness_stderr" ]; then
  cat "$harness_stderr" >&2
  exit 1
fi
printf '%s' "$system_install" | grep -q '"package":"symcrypt-openssl"'
printf '%s' "$system_install" | grep -q '"package":"symcrypt"'
printf '%s' "$system_install" | grep -q '"exact_lock":"'
printf '%s' "$system_install" | grep -q '"provenance":"'
grep -q '^Package: symcrypt-openssl$' "$full_root/var/lib/dpkg/status"
grep -q '^Package: symcrypt$' "$full_root/var/lib/dpkg/status"
lock_path=$(printf '%s' "$system_install" | python3 -c 'import json,sys; print(json.load(sys.stdin)["paths"]["exact_lock"])')
provenance_path=$(printf '%s' "$system_install" | python3 -c 'import json,sys; print(json.load(sys.stdin)["paths"]["provenance"])')
test -s "$lock_path"
test -s "$provenance_path"
evidence_dir=$(dirname "$provenance_path")
test -s "$evidence_dir/transaction.complete"
lock_digest=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["digest_sha256"])' "$lock_path")
grep -q "^lock	$lock_digest$" "$evidence_dir/transaction.complete"
grep -q '"schema":"https://debz.dev/schema/exact-closure-lock-v2"' "$lock_path"
grep -q '"name":"symcrypt"' "$lock_path"
grep -q '"name":"symcrypt-openssl"' "$lock_path"
grep -q '"schema":"https://debz.dev/schema/transaction-result-v3"' "$provenance_path"
grep -q 'missing_valid_until_exception_exercised' "$provenance_path"
grep -q 'maximum_release_age_seconds' "$provenance_path"
grep -q "\"selected_packages_path\":\"main/binary-$architecture/Packages.gz\"" "$provenance_path"
grep -q '"compression":"gzip"' "$provenance_path"
grep -q '/usr/bin/dpkg' "$provenance_path"
grep -q '"status":"exact_match"' "$provenance_path"

set +e
failed_install=$(run_product install \
  --install-root "$full_root" \
  --json \
  fail-script 2>"$harness_stderr")
failed_install_status=$?
set -e
if [ "$(id -u)" -ne 0 ]; then
  sudo chown -R "$(id -u):$(id -g)" "$full_root"
fi
test "$failed_install_status" -eq 7
test ! -s "$harness_stderr"
printf '%s' "$failed_install" | grep -q '"id":"transaction_failed"'
failed_lock=$(printf '%s' "$failed_install" | python3 -c 'import json,sys; print(json.load(sys.stdin)["paths"]["exact_lock"])')
failed_provenance=$(printf '%s' "$failed_install" | python3 -c 'import json,sys; print(json.load(sys.stdin)["paths"]["provenance"])')
test -s "$failed_lock"
test -s "$failed_provenance"
grep -q 'outcome.*failed' "$failed_provenance"
requests_before_retry=$(wc -l <"$request_log")

set +e
retry_install=$(run_product install \
  --install-root "$full_root" \
  --json \
  fail-script 2>"$harness_stderr")
retry_status=$?
set -e
test "$retry_status" -eq 8
test ! -s "$harness_stderr"
printf '%s' "$retry_install" | grep -q '"id":"recovery_required"'
retry_lock=$(printf '%s' "$retry_install" | python3 -c 'import json,sys; print(json.load(sys.stdin)["paths"]["exact_lock"])')
test "$retry_lock" = "$failed_lock"
test "$(wc -l <"$request_log")" -eq "$requests_before_retry"

set +e
mismatched_retry=$(run_product install \
  --install-root "$full_root" \
  --json \
  base-dep 2>"$harness_stderr")
mismatched_retry_status=$?
set -e
test "$mismatched_retry_status" -eq 8
test ! -s "$harness_stderr"
printf '%s' "$mismatched_retry" | grep -q '"id":"recovery_required"'
test "$(wc -l <"$request_log")" -eq "$requests_before_retry"

set +e
recovery_output=$(run_product recover \
  --install-root "$full_root" \
  --json 2>"$harness_stderr")
recovery_status=$?
set -e
if [ "$(id -u)" -ne 0 ]; then
  sudo chown -R "$(id -u):$(id -g)" "$full_root"
fi
test "$recovery_status" -eq 8
test ! -s "$harness_stderr"
printf '%s' "$recovery_output" | grep -q '"id":"recovery_failed"'
recovery_lock=$(printf '%s' "$recovery_output" | python3 -c 'import json,sys; print(json.load(sys.stdin)["paths"]["exact_lock"])')
test "$recovery_lock" = "$failed_lock"

core_root="$workspace/core-root"
core_output=$(run_harness "$core_root")
printf '%s' "$core_output" | grep -q 'FIRST=.*"exit_status":0'
prepare_dpkg_root "$core_root"
set +e
core_install=$(run_product install \
  --install-root "$core_root" \
  --json \
  symcrypt 2>"$harness_stderr")
core_install_status=$?
set -e
if [ "$(id -u)" -ne 0 ]; then
  sudo chown -R "$(id -u):$(id -g)" "$core_root"
fi
if [ "$core_install_status" -ne 0 ]; then
  cat "$harness_stderr" >&2
  printf '%s\n' "$core_install" >&2
  exit "$core_install_status"
fi
test ! -s "$harness_stderr"
printf '%s' "$core_install" | grep -q '"package":"symcrypt"'
printf '%s' "$core_install" | grep -vq '"package":"symcrypt-openssl"'
grep -q '^Package: symcrypt$' "$core_root/var/lib/dpkg/status"
if grep -q '^Package: symcrypt-openssl$' "$core_root/var/lib/dpkg/status"; then
  echo "core-only workflow installed symcrypt-openssl" >&2
  exit 1
fi

conflict_root="$workspace/conflict-root"
conflict_output=$(run_harness "$conflict_root")
printf '%s' "$conflict_output" | grep -q 'FIRST=.*"exit_status":0'
sed -i 's/Version: 3\.0\.13-0ubuntu3/Version: 3.1.0-1/' \
  "$conflict_root/var/lib/dpkg/status"
grep -q '^Package: openssl$' "$conflict_root/var/lib/dpkg/status" || {
  cat "$conflict_root/var/lib/dpkg/status" >&2
  exit 1
}
grep -q '^Version: 3.1.0-1$' "$conflict_root/var/lib/dpkg/status" || {
  cat "$conflict_root/var/lib/dpkg/status" >&2
  exit 1
}
requests_before_conflict=$(wc -l <"$request_log")
set +e
conflict_install=$(run_product install \
  --install-root "$conflict_root" \
  --json \
  symcrypt-openssl 2>"$harness_stderr")
conflict_status=$?
set -e
test "$conflict_status" -eq 5
test ! -s "$harness_stderr"
printf '%s' "$conflict_install" | grep -q '"id":"planning_failed"'
printf '%s' "$conflict_install" | grep -q 'openssl'
test "$(wc -l <"$request_log")" -gt "$requests_before_conflict"
test ! -e "$conflict_root/var/lib/debz/transactions"
if grep -q '^Package: symcrypt$' "$conflict_root/var/lib/dpkg/status"; then
  echo "solver conflict mutated the target" >&2
  exit 1
fi
fi

in_release_before=$(grep -c '/repository/dists/debian-stable/InRelease' "$request_log")
no_refresh_root="$workspace/no-refresh-root"
no_refresh_output=$(run_harness "$no_refresh_root" --no-refresh)
printf '%s' "$no_refresh_output" | grep -q 'FIRST=.*"refreshed_phase":"skipped"'
printf '%s' "$no_refresh_output" | grep -q 'FIRST=.*"refreshed":false'
in_release_after=$(grep -c '/repository/dists/debian-stable/InRelease' "$request_log")
test $((in_release_after - in_release_before)) -eq 2
test ! -e "$no_refresh_root/etc/apt/sources.list.d/host.list"

mismatch_root="$workspace/mismatch-root"
mkdir -p "$mismatch_root/var/lib/dpkg"
: >"$mismatch_root/var/lib/dpkg/status"
set +e
mismatch=$("$debz" repo add \
  --url "$descriptor_url" \
  --root "$mismatch_root" \
  --sha256 0000000000000000000000000000000000000000000000000000000000000000 \
  --architecture "$architecture" \
  --json 2>"$harness_stderr")
mismatch_status=$?
set -e
test "$mismatch_status" -eq 6
test ! -s "$harness_stderr"
printf '%s' "$mismatch" | grep -q '"id":"acquisition_failed"'
printf '%s' "$mismatch" | grep -q '"installed":false'
printf '%s' "$mismatch" | grep -vq 'fixture-query-secret'
test ! -e "$mismatch_root/etc/apt/sources.list.d/microsoft-prod.list"

printf 'repository-add integration passed\n'
