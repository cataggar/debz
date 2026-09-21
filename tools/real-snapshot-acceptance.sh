#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly pinned_uri=https://snapshot.ubuntu.com/ubuntu/20260816T000000Z
readonly pinned_suite=resolute
readonly keyring=${DEBZ_REAL_SNAPSHOT_KEYRING:-/usr/share/keyrings/ubuntu-archive-keyring.gpg}
readonly max_download_bytes=$((1536 * 1024 * 1024))
readonly max_package_bytes=$((512 * 1024 * 1024))
readonly max_cache_bytes=$((2 * 1024 * 1024 * 1024))
readonly maximum_release_age_seconds=$((31 * 24 * 60 * 60))

validate_values() {
  local uri=$1 suite=$2 architecture=$3
  [[ "$uri" == "$pinned_uri" ]]
  [[ "$suite" == "$pinned_suite" ]]
  [[ "$architecture" == amd64 || "$architecture" == arm64 ]]
}

validate() {
  local uri=$1 suite=$2 architecture=$3
  validate_values "$uri" "$suite" "$architecture"
  [[ "$keyring" == /* && -f "$keyring" && ! -L "$keyring" ]] || {
    echo "an explicit regular Ubuntu archive keyring is required: $keyring" >&2
    return 2
  }
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
repository_root=$(pwd -P)
validate "$uri" "$suite" "$architecture"
[[ -x "$debz" ]]
case "$workspace" in "$repository_root"/.real-snapshot/*) ;; *) echo "unsafe workspace" >&2; exit 2 ;; esac
[[ ! -e "$5" && ! -L "$5" && ! -e "$workspace" && ! -L "$workspace" ]] || {
  echo "snapshot workspace must be new: $workspace" >&2
  exit 2
}

root=$workspace/root
cache=$workspace/cache
state=$workspace/state
evidence=$workspace/evidence
source_file=$workspace/ubuntu.sources
config_file=$workspace/ubuntu.json
lock=$evidence/ubuntu-minimal.lock.json
update_lock=$evidence/ubuntu-minimal.update.lock.json
mkdir -p "$root" "$cache" "$state" "$evidence"
[[ -z $(find "$root" -mindepth 1 -print -quit) ]]
printf 'install_root_exists=true\ndpkg_database_present=false\nhelper_placeholder_present=false\npackage_state_present=false\n' \
  >"$evidence/fresh-root-before.txt"
capture_root_layout() {
  {
    for path in bin sbin lib lib64 bin/sh usr/bin/sh usr/bin/dpkg usr/bin/dpkg-deb \
      usr/bin/dpkg-trigger; do
      target=$(readlink "$root/$path" 2>/dev/null || true)
      printf '%s target=%s exists=%s executable=%s\n' "$path" "${target:-none}" \
        "$([[ -e "$root/$path" ]] && echo true || echo false)" \
        "$([[ -x "$root/$path" ]] && echo true || echo false)"
    done
  } >"$evidence/root-layout.txt"
}
trap capture_root_layout EXIT
cat >"$source_file" <<EOF
Types: deb
URIs: $uri
Suites: $suite
Components: main
Architectures: $architecture
Signed-By: $keyring
EOF
printf '{"source_path":"%s","priority":500,"default_release":"%s","immutable":true,"freshness":{"mode":"allow_missing_valid_until_with_max_age_seconds","maximum_release_age_seconds":%s}}\n' \
  "$source_file" "$suite" "$maximum_release_age_seconds" >"$config_file"
source_commit=${GITHUB_SHA:-}
if [[ -z "$source_commit" ]]; then
  source_commit=$(git -C "$(dirname "$0")/.." rev-parse HEAD)
fi
{
  printf 'source_commit=%s\n' "$source_commit"
  printf 'architecture=%s\nsnapshot_uri=%s\nsnapshot_suite=%s\n' \
    "$architecture" "$uri" "$suite"
  printf 'invocation_unix=%s\nworkflow=%s\nrun_id=%s\nrun_attempt=%s\njob=%s\n' \
    "$(date -u +%s)" "${GITHUB_WORKFLOW:-local}" "${GITHUB_RUN_ID:-local}" \
    "${GITHUB_RUN_ATTEMPT:-local}" "${GITHUB_JOB:-local}"
  printf 'candidate_backend=native\nreference_backend=pinned-dpkg-oracle\n'
  printf 'repository_freshness=allow_missing_valid_until_with_max_age_seconds:%s\n' \
    "$maximum_release_age_seconds"
  printf 'program_sha256=%s\nkeyring_sha256=%s\n' \
    "$(sha256sum "$debz" | cut -d' ' -f1)" \
    "$(sha256sum "$keyring" | cut -d' ' -f1)"
  printf 'source_profile_sha256=%s\nrepository_profile_sha256=%s\n' \
    "$(sha256sum "$source_file" | cut -d' ' -f1)" \
    "$(sha256sum "$config_file" | cut -d' ' -f1)"
} >"$evidence/invocation-identity.txt"

common=(
  --install-root "$root"
  --cache-path "$cache"
  --state-path "$state"
  --architecture "$architecture"
  --config "$config_file"
  --keyring "$keyring"
  --deadline-ms 300000
  --lock-wait-ms 30000
  --json
)
native_common=("${common[@]}" --transaction-backend native)
mutating=(--assume-yes --noninteractive --conffile keep-existing)

run() {
  local name=$1
  local status
  shift
  if [[ ${DEBZ_REAL_SNAPSHOT_TRACE:-0} == 1 ]]; then
    set +e
    timeout --signal=TERM --kill-after=30s 30m \
      strace -f -qq -e trace=execve -o "$evidence/$name.execve" \
      "$debz" "$@" >"$evidence/$name.json" 2>"$evidence/$name.stderr"
    status=$?
    set -e
    if grep -Eq 'execve\\("(/usr)?/(s?bin/)?dpkg(-deb)?"' "$evidence/$name.execve"; then
      echo "native candidate invoked dpkg or dpkg-deb during $name" >&2
      printf 'operation=%s\nexit_status=%s\nforbidden_dpkg_exec=true\n' \
        "$name" "$status" >>"$evidence/native-exec-audit.txt"
      return 90
    fi
    printf 'operation=%s\nexit_status=%s\nforbidden_dpkg_exec=false\n' \
      "$name" "$status" >>"$evidence/native-exec-audit.txt"
    (( status == 0 )) || return "$status"
  else
    timeout --signal=TERM --kill-after=30s 30m "$debz" "$@" \
      >"$evidence/$name.json" 2>"$evidence/$name.stderr"
  fi
  [[ ! -s "$evidence/$name.stderr" ]]
  grep -q '"exit_status":0' "$evidence/$name.json"
}

verify_result() {
  local name=$1 lock_input=$2
  timeout --signal=TERM --kill-after=30s 10m "$debz" transaction-result verify \
    --transaction-backend native --install-root "$root" --state-path "$state" \
    --lock-input "$lock_input" --architecture "$architecture" --json \
    >"$evidence/$name-summary.json" 2>"$evidence/$name-summary.stderr"
  [[ ! -s "$evidence/$name-summary.stderr" ]]
  jq -e '.outcome == "succeeded"' "$evidence/$name-summary.json" >/dev/null
}

review_lock() {
  jq -e --arg arch "$architecture" '
    .target_architecture == $arch and
    ([.packages[] | select(.name == "ubuntu-minimal")] | length) == 1 and
    (.repositories | length) == 1 and
    ([.repositories[].signer_fingerprints[]] | unique) ==
      ["f6ecb3762474eda9d21b7022871920d1991bc93c"]
  ' "$1" >/dev/null
}

run refresh refresh "${common[@]}" --assume-yes
metadata_bytes=$(du -sb "$cache" | cut -f1)
(( metadata_bytes <= max_cache_bytes ))

run resolve-lock plan "${native_common[@]}" --lock-output "$lock" ubuntu-minimal
review_lock "$lock"
printf 'lock_file_sha256=%s\nlock_document_digest=%s\n' \
  "$(sha256sum "$lock" | cut -d' ' -f1)" \
  "$(jq -r '.digest_sha256' "$lock")" >"$evidence/install-lock-identity.txt"
download_bytes=$(jq '[.packages[].declared_size] | add' "$lock")
largest_package=$(jq '[.packages[].declared_size] | max' "$lock")
package_count=$(jq '.packages | length' "$lock")
(( download_bytes <= max_download_bytes ))
(( largest_package <= max_package_bytes ))
(( package_count <= 2000 ))
printf 'download_bytes=%s\nlargest_package_bytes=%s\npackage_count=%s\nmetadata_bytes=%s\n' \
  "$download_bytes" "$largest_package" "$package_count" "$metadata_bytes" \
  >"$evidence/bounds.txt"

run download download "${native_common[@]}" --lock-input "$lock" ubuntu-minimal
run create install "${native_common[@]}" "${mutating[@]}" --lock-input "$lock" ubuntu-minimal
verify_result create "$lock"
cp "$root/var/lib/debz/native-transaction-provenance-v1.json" \
  "$evidence/create-native-transaction-provenance-v1.json"
cp "$root/var/lib/debz/root-operation-completion-v1.json" \
  "$evidence/create-root-operation-completion-v1.json"
cp "$root/var/lib/dpkg/status" "$evidence/status-after-create"

awk '
  /^Package: / { package=$2 }
  /^Status: / && package == "ubuntu-minimal" && $0 == "Status: install ok installed" { found=1 }
  END { exit !found }
' "$root/var/lib/dpkg/status"

run reproduce-lock plan "${native_common[@]}" --lock-input "$lock" \
  --lock-output "$evidence/reproduced.lock.json" ubuntu-minimal
cmp "$lock" "$evidence/reproduced.lock.json"
before_update_status=$(sha256sum "$root/var/lib/dpkg/status" | cut -d' ' -f1)
run resolve-update-lock plan "${native_common[@]}" --lock-output "$update_lock"
review_lock "$update_lock"
printf 'lock_file_sha256=%s\nlock_document_digest=%s\n' \
  "$(sha256sum "$update_lock" | cut -d' ' -f1)" \
  "$(jq -r '.digest_sha256' "$update_lock")" >"$evidence/update-lock-identity.txt"
before_update_provenance=$(sha256sum \
  "$root/var/lib/debz/native-transaction-provenance-v1.json" | cut -d' ' -f1)
run update upgrade-all "${native_common[@]}" "${mutating[@]}" --lock-input "$update_lock"
jq -e '.changed == false' "$evidence/update.json" >/dev/null
[[ "$before_update_status" == "$(sha256sum "$root/var/lib/dpkg/status" | cut -d' ' -f1)" ]]
[[ "$before_update_provenance" == "$(sha256sum \
  "$root/var/lib/debz/native-transaction-provenance-v1.json" | cut -d' ' -f1)" ]]
printf 'changed=false\nstatus_unchanged=true\nprovenance_unchanged=true\n' \
  >"$evidence/update-zero-actions.txt"

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
timeout --signal=TERM --kill-after=30s 10m "$debz" plan "${native_common[@]}" \
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
