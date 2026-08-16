#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly pinned_uri=https://snapshot.ubuntu.com/ubuntu/20260816T000000Z
readonly pinned_suite=resolute
readonly keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
readonly max_download_bytes=$((1536 * 1024 * 1024))
readonly max_package_bytes=$((512 * 1024 * 1024))
readonly max_cache_bytes=$((2 * 1024 * 1024 * 1024))

validate_values() {
  local uri=$1 suite=$2 architecture=$3
  [[ "$uri" == "$pinned_uri" ]]
  [[ "$suite" == "$pinned_suite" ]]
  [[ "$architecture" == amd64 || "$architecture" == arm64 ]]
}

validate() {
  local uri=$1 suite=$2 architecture=$3
  validate_values "$uri" "$suite" "$architecture"
  [[ -f "$keyring" && ! -L "$keyring" ]]
  case "$(uname -m):$architecture" in
    x86_64:amd64|aarch64:arm64) ;;
    *) echo "native runner architecture does not match $architecture" >&2; return 2 ;;
  esac
}

if [[ ${1:-} == --validate-values ]]; then
  validate_values "$2" "$3" "$4"
  exit
fi
if [[ ${1:-} == --validate ]]; then
  validate "$2" "$3" "$4"
  exit
fi

[[ $# == 5 ]] || {
  echo "usage: $0 DEBZ URI SUITE ARCHITECTURE WORKSPACE" >&2
  exit 2
}
debz=$(realpath "$1")
uri=$2
suite=$3
architecture=$4
workspace=$(realpath -m "$5")
validate "$uri" "$suite" "$architecture"
[[ -x "$debz" ]]
case "$workspace" in "$PWD"/.real-snapshot/*) ;; *) echo "unsafe workspace" >&2; exit 2 ;; esac
[[ ! -L "$workspace" ]]

root=$workspace/root
cache=$workspace/cache
state=$workspace/state
evidence=$workspace/evidence
source_file=$workspace/ubuntu.sources
lock=$evidence/ubuntu-minimal.lock.json
mkdir -p "$root/var/lib/dpkg/"{info,updates,triggers} "$cache" "$state" "$evidence"
: >"$root/var/lib/dpkg/status"
: >"$root/var/lib/dpkg/available"
cat >"$source_file" <<EOF
Types: deb
URIs: $uri
Suites: $suite
Components: main
Architectures: $architecture
Signed-By: $keyring
EOF

common=(
  --install-root "$root"
  --cache-path "$cache"
  --state-path "$state"
  --architecture "$architecture"
  --source "$source_file"
  --keyring "$keyring"
  --deadline-ms 300000
  --lock-wait-ms 30000
  --json
)
mutating=(--assume-yes --noninteractive --conffile keep-existing)

run() {
  local name=$1
  shift
  timeout --signal=TERM --kill-after=30s 10m "$debz" "$@" \
    >"$evidence/$name.json" 2>"$evidence/$name.stderr"
  [[ ! -s "$evidence/$name.stderr" ]]
  grep -q '"exit_status":0' "$evidence/$name.json"
}

run refresh refresh "${common[@]}"
metadata_bytes=$(du -sb "$cache" | cut -f1)
(( metadata_bytes <= max_cache_bytes ))

run resolve-lock plan "${common[@]}" --lock-output "$lock" ubuntu-minimal
jq -e --arg arch "$architecture" '
  .target_architecture == $arch and
  ([.packages[] | select(.name == "ubuntu-minimal")] | length) == 1 and
  (.repositories | length) == 1 and
  ([.repositories[].signer_fingerprints[]] | length) > 0
' "$lock" >/dev/null
download_bytes=$(jq '[.packages[].declared_size] | add' "$lock")
largest_package=$(jq '[.packages[].declared_size] | max' "$lock")
package_count=$(jq '.packages | length' "$lock")
(( download_bytes <= max_download_bytes ))
(( largest_package <= max_package_bytes ))
(( package_count <= 2000 ))
printf 'download_bytes=%s\nlargest_package_bytes=%s\npackage_count=%s\nmetadata_bytes=%s\n' \
  "$download_bytes" "$largest_package" "$package_count" "$metadata_bytes" \
  >"$evidence/bounds.txt"

run download download "${common[@]}" --lock-input "$lock" ubuntu-minimal
run create install "${common[@]}" "${mutating[@]}" --lock-input "$lock" ubuntu-minimal
cp "$state/transaction-result.json" "$evidence/create-transaction-result.json"
cp "$root/var/lib/dpkg/status" "$evidence/status-after-create"

dpkg-query --admindir="$root/var/lib/dpkg" -W -f='${db:Status-Abbrev} ${binary:Package} ${Version}\n' \
  >"$evidence/installed.txt"
grep -Eq '^ii  ubuntu-minimal(:[^ ]+)? ' "$evidence/installed.txt"
if grep -Eq '^[^i][^i]|^.R|^..[A-Z]' "$evidence/installed.txt"; then
  echo "unhealthy dpkg package state" >&2
  exit 1
fi

run reproduce-lock plan "${common[@]}" --lock-input "$lock" \
  --lock-output "$evidence/reproduced.lock.json" ubuntu-minimal
cmp "$lock" "$evidence/reproduced.lock.json"
run update upgrade-all "${common[@]}" "${mutating[@]}" --lock-input "$lock"
cp "$state/transaction-result.json" "$evidence/update-transaction-result.json"

status_digest=$(sha256sum "$root/var/lib/dpkg/status" | cut -d' ' -f1)
cp "$lock" "$evidence/injected-invalid.lock.json"
python3 - "$evidence/injected-invalid.lock.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
value["digest_sha256"] = ("0" if value["digest_sha256"][0] != "0" else "1") + value["digest_sha256"][1:]
path.write_text(json.dumps(value, separators=(",", ":")) + "\n")
PY
set +e
timeout --signal=TERM --kill-after=30s 10m "$debz" plan "${common[@]}" \
  --lock-input "$evidence/injected-invalid.lock.json" ubuntu-minimal \
  >"$evidence/injected-failure.json" 2>"$evidence/injected-failure.stderr"
failure_status=$?
set -e
(( failure_status != 0 ))
grep -q '"exit_status":5' "$evidence/injected-failure.json"
[[ "$status_digest" == "$(sha256sum "$root/var/lib/dpkg/status" | cut -d' ' -f1)" ]]
printf 'exit_status=%s\nroot_unchanged=true\n' "$failure_status" >"$evidence/injected-failure.txt"

for pid_root in /proc/[0-9]*/root; do
  [[ -e "$pid_root" ]] || continue
  [[ $(readlink "$pid_root" 2>/dev/null || true) == "$root" ]] || continue
  pid=${pid_root#/proc/}; pid=${pid%/root}
  comm=$(cat "/proc/$pid/comm" 2>/dev/null || true)
  [[ "$comm" != apt* && "$comm" != dpkg* ]]
done
printf 'native_architecture=%s\nsuite=%s\nsnapshot_uri=%s\napt_processes_in_root=0\n' \
  "$architecture" "$suite" "$uri" >"$evidence/root-identity.txt"
du -sh "$workspace" >"$evidence/disk-usage.txt"
