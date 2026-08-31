#!/bin/sh
set -eu
umask 077
export PYTHONDONTWRITEBYTECODE=1

debz=$1
harness=$2
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
trap 'kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; rm -rf "$workspace"' EXIT HUP INT TERM

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

python3 tools/generate-integration-repository.py \
  --output "$repository" \
  --suite debian-stable \
  --architecture amd64 \
  --descriptor-output "$descriptor" \
  --descriptor-repository-url "$repository_url"
bootstrap_repository="$http_root/bootstrap-repository"
cp -R "$repository" "$bootstrap_repository"
bootstrap_repository_url="http://127.0.0.1:$port/bootstrap-repository"

source_file="$workspace/microsoft-prod.list"
cat >"$source_file" <<EOF
deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] $repository_url debian-stable main
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
Architectures: amd64
Signed-By: /usr/share/keyrings/bootstrap.gpg
EOF
  set +e
  output=$("$harness" "$source_file" "$keyring" \
    --url "$descriptor_url" \
    --root "$target_root" \
    --sha256 "$descriptor_sha256" \
    --architecture amd64 \
    --deadline-ms 60000 \
    --lock-wait-ms 5000 \
    --maximum-repositories 8 \
    --maximum-actions 64 \
    --json "$@" 2>"$harness_stderr")
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    cat "$harness_stderr" >&2
    return "$status"
  fi
  test ! -s "$harness_stderr"
  printf '%s\n' "$output"
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
test "$(grep -c '/config/packages-microsoft-prod.deb' "$request_log")" -eq 1
test "$(grep -c '/repository/dists/debian-stable/InRelease' "$request_log")" -eq 3
grep -q '/repository/dists/debian-stable/main/binary-amd64/Packages' "$request_log"
grep -q '/bootstrap-repository/pool/main/ca-certificates_20240203_all.deb' "$request_log"
if grep -R -a -q 'fixture-query-secret' "$full_root"; then
  echo "descriptor query secret persisted under the target root" >&2
  exit 1
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
  --architecture amd64 \
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
