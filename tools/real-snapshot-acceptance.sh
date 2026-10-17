#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly pinned_uri=https://snapshot.ubuntu.com/ubuntu/20261001T000000Z
readonly pinned_suite=resolute
readonly keyring=${DEBZ_REAL_SNAPSHOT_KEYRING:-}
readonly max_download_bytes=$((1536 * 1024 * 1024))
readonly max_package_bytes=$((512 * 1024 * 1024))
readonly max_cache_bytes=$((2 * 1024 * 1024 * 1024))
readonly maximum_release_age_seconds=$((31 * 24 * 60 * 60))
readonly frozen_release_sha256=596ee4cea058f74d59e2180532c89904e306d90725d42162eda82c01d4370834
readonly updates_release_sha256=16d93e5e9358047ac2f5d671abcac2bb3f2945532452720cd9a17320c19c4f24
readonly security_release_sha256=bda7516aa5ed1aa2c8ebcbe36a07276f599559917a9de8fe5de041e99c9a2a10
# Command bounds; see "Acceptance time bounds" in doc/integration-roots.md.
# Native install alone is bounded by time without durable progress, up to a
# fixed ceiling, because a complete traced install can exceed any short limit.
readonly operation_limit=30m
readonly verification_limit=10m
readonly maximum_install_progress_limit_seconds=$((20 * 60))
readonly maximum_install_ceiling_seconds=$((180 * 60))
readonly progress_sample_seconds=60
readonly native_progress_log=var/lib/debz/native-execution-progress-v1.log
readonly mutation_progress_log=var/lib/debz/root-mutation-v2.log
readonly phase_telemetry=${DEBZ_NATIVE_PHASE_TELEMETRY:-0}
readonly expected_packages=${DEBZ_NATIVE_PERFORMANCE_EXPECT_PACKAGES:-}
readonly snapshot_optimize=${DEBZ_NATIVE_SNAPSHOT_OPTIMIZE:-ReleaseSafe}
# Reviewed identities of the target root's /usr/bin/dpkg, dpkg-divert and
# dpkg-statoverride, which maintainer scripts may run in reviewed argument
# shapes; see "Native exec audit" in doc/integration-roots.md. Bytes, size and
# version come from each architecture's authenticated dpkg archive in the
# pinned snapshot, never from another architecture or snapshot.
readonly script_dpkg_snapshot=20261001T000000Z
readonly script_dpkg_version=1.23.7ubuntu1
readonly script_dpkg_amd64='972003a11f3ae0f5b2556dce1d2c2721fb5119818b9bbef1124293024fdb6517 322728'
readonly script_dpkg_arm64='6c03c9fa2053b5a4e899438c1318ed460f62f01812da7f91f6c35a7e0957692f 330816'
readonly script_dpkg_divert_amd64='e975eecfbceda235ecedc2e35addf5cc5abe05de355202780cf8e47b2f6745eb 125768'
readonly script_dpkg_divert_arm64='50fd191a3a97a17ff0de4bb921ded2d877e5648e197712e8025631c09d456798 133872'
readonly script_dpkg_statoverride_amd64='f8496aa47ff782a4881ebdf9e0a4e4615e81f8c56bc004af51f49954e315ff8c 55936'
readonly script_dpkg_statoverride_arm64='b9c47a676498db293c4f674d63af54656d274e68b7598e235ec50f2380dba0f6 68184'

validate_values() {
  local uri=$1 suite=$2 architecture=$3
  [[ "$uri" == "$pinned_uri" ]]
  [[ "$suite" == "$pinned_suite" ]]
  [[ "$architecture" == amd64 || "$architecture" == arm64 ]]
}

validate_performance_values() {
  [[ $1 == Debug || $1 == ReleaseSafe ]] &&
    [[ $2 == 0 || $2 == 1 ]] &&
    [[ -z $3 || $3 == 177 ]]
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
  bash "$(dirname -- "${BASH_SOURCE[0]}")/real-snapshot-reference-protected-ci.sh" \
    --check-keyring "$keyring" >/dev/null
}

seconds_value() {
  [[ $1 =~ ^(0|[1-9][0-9]{0,5})$ ]]
}

# Prints running, stalled (no durable progress within the limit) or ceiling.
progress_verdict() {
  local elapsed=$1 progressed=$2 limit=$3 ceiling=$4
  seconds_value "$elapsed" && seconds_value "$progressed" &&
    seconds_value "$limit" && seconds_value "$ceiling" &&
    (( progressed <= elapsed && 0 < limit && limit <= ceiling )) || {
    echo "invalid progress verdict input" >&2
    return 2
  }
  if (( elapsed >= ceiling )); then
    echo ceiling
  elif (( elapsed - progressed >= limit )); then
    echo stalled
  else
    echo running
  fi
}

# Local overrides may only tighten the reviewed install bounds.
install_bound() {
  local value=$1 maximum=$2
  seconds_value "$value" && (( 0 < value && value <= maximum )) || {
    echo "install progress bounds may only tighten the reviewed limits" >&2
    return 2
  }
  echo "$value"
}

# Prints the reviewed "DIGEST SIZE" of the root's /usr/bin/TOOL for an
# architecture.
reviewed_script_tool() {
  [[ "$pinned_uri" == */"$script_dpkg_snapshot" ]] || {
    echo "reviewed script dpkg identity is not bound to the pinned snapshot" >&2
    return 91
  }
  case "$1:$2" in
    amd64:dpkg) echo "$script_dpkg_amd64" ;;
    arm64:dpkg) echo "$script_dpkg_arm64" ;;
    amd64:dpkg-divert) echo "$script_dpkg_divert_amd64" ;;
    arm64:dpkg-divert) echo "$script_dpkg_divert_arm64" ;;
    amd64:dpkg-statoverride) echo "$script_dpkg_statoverride_amd64" ;;
    arm64:dpkg-statoverride) echo "$script_dpkg_statoverride_arm64" ;;
    *) echo "no reviewed script $2 identity for $1" >&2; return 91 ;;
  esac
}

# Prints the reviewed identities of every script-callable tool for an
# architecture as the TOOL=DIGEST:SIZE words that audit_exec_trace takes.
reviewed_script_tools() {
  local tool identity words=()
  for tool in dpkg dpkg-divert dpkg-statoverride; do
    identity=$(reviewed_script_tool "$1" "$tool") || return 91
    words+=("$tool=${identity% *}:${identity#* }")
  done
  echo "${words[*]}"
}

# Audits one strace exec trace of a candidate command. Every execve or
# execveat of dpkg, dpkg-deb, dpkg-divert or dpkg-statoverride fails (exit 90)
# unless it is a successful plain execve of exactly the filename /usr/bin/TOOL
# for dpkg, dpkg-divert or dpkg-statoverride, with argv[0] "TOOL" or
# "/usr/bin/TOOL" and reviewed arguments (a read-only dpkg action, or one of
# the exact dpkg-divert and dpkg-statoverride shapes that the closure's
# scripts use), made by a descendant of a lifecycle script that the candidate
# itself executed, and the root's /usr/bin/TOOL then has the reviewed identity
# with no PATH shadow. argv[0] is only a label; the filename and identity
# decide which binary ran, so /bin/TOOL is refused even when /bin links to
# usr/bin. Exit 91 means the trace or root could not be audited. Prints one
# record per allowed or refused exec.
audit_exec_trace() {
  local status=0
  PATH=/no-host-interpreters zig-out/bin/debz-exec-audit "$@" || status=$?
  case "$status" in
    0|90) return "$status" ;;
    *) return 91 ;;
  esac
}

if [[ ${1:-} == --audit-exec-trace ]]; then
  [[ $# == 5 ]] || { echo "usage: $0 --audit-exec-trace TRACE ROOT ARCHITECTURE DEBZ" >&2; exit 2; }
  identities=$(reviewed_script_tools "$4") || exit 91
  audit_exec_trace "$2" "$3" "$4" "$5" "$script_dpkg_version" "$identities"
  exit
fi
if [[ ${1:-} == --audit-exec-trace-lifecycle ]]; then
  [[ $# == 5 ]] || { echo "usage: $0 --audit-exec-trace-lifecycle TRACE ROOT ARCHITECTURE DEBZ" >&2; exit 2; }
  identities=$(reviewed_script_tools "$4") || exit 91
  audit_exec_trace --lifecycle "$2" "$3" "$4" "$5" "$script_dpkg_version" "$identities"
  exit
fi
# Tests only: the same audit against explicit fixture identities, given as
# "TOOL=DIGEST:SIZE ..." for dpkg, dpkg-divert and dpkg-statoverride. Production
# and CI audits use --audit-exec-trace, which accepts only the reviewed pins.
if [[ ${1:-} == --audit-exec-trace-fixture ]]; then
  [[ $# == 7 ]] || {
    echo "usage: $0 --audit-exec-trace-fixture TRACE ROOT ARCHITECTURE DEBZ VERSION IDENTITIES" >&2
    exit 2
  }
  audit_exec_trace "$2" "$3" "$4" "$5" "$6" "$7"
  exit
fi
if [[ ${1:-} == --audit-exec-trace-lifecycle-fixture ]]; then
  [[ $# == 7 ]] || {
    echo "usage: $0 --audit-exec-trace-lifecycle-fixture TRACE ROOT ARCHITECTURE DEBZ VERSION IDENTITIES" >&2
    exit 2
  }
  audit_exec_trace --lifecycle "$2" "$3" "$4" "$5" "$6" "$7"
  exit
fi
if [[ ${1:-} == --validate-values ]]; then
  validate_values "$2" "$3" "$4"
  exit
fi
if [[ ${1:-} == --validate-performance-values ]]; then
  [[ $# == 4 ]] || exit 2
  validate_performance_values "$2" "$3" "$4"
  exit "$?"
fi
if [[ ${1:-} == --progress-verdict ]]; then
  [[ $# == 5 ]] || { echo "usage: $0 --progress-verdict ELAPSED PROGRESSED LIMIT CEILING" >&2; exit 2; }
  progress_verdict "$2" "$3" "$4" "$5"
  exit
fi
validate_performance_values "$snapshot_optimize" "$phase_telemetry" "$expected_packages" || {
  echo "invalid native database performance selectors" >&2
  exit 2
}
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
install_progress_limit_seconds=$(install_bound \
  "${DEBZ_REAL_SNAPSHOT_INSTALL_PROGRESS_LIMIT_SECONDS:-$maximum_install_progress_limit_seconds}" \
  "$maximum_install_progress_limit_seconds")
install_ceiling_seconds=$(install_bound \
  "${DEBZ_REAL_SNAPSHOT_INSTALL_CEILING_SECONDS:-$maximum_install_ceiling_seconds}" \
  "$maximum_install_ceiling_seconds")
(( install_progress_limit_seconds <= install_ceiling_seconds )) || {
  echo "install progress limit exceeds its ceiling" >&2
  exit 2
}
readonly install_progress_limit_seconds install_ceiling_seconds
[[ -x "$debz" ]]
case "$workspace" in "$repository_root"/.real-snapshot/*) ;; *) echo "unsafe workspace" >&2; exit 2 ;; esac
"$repository_root/zig-out/bin/debz-reference-paths" protected --directory \
  "$repository_root" "$repository_root/.real-snapshot"
"$repository_root/zig-out/bin/debz-reference-paths" protected \
  "$debz" "$repository_root/zig-out/bin/debz-exec-audit" \
  "$repository_root/zig-out/bin/debz-reference-paths" \
  "$repository_root/tools/real-snapshot-acceptance.sh" \
  "$repository_root/tools/real-snapshot-reference-protected-ci.sh"
[[ ! -e "$5" && ! -L "$5" && ! -e "$workspace" && ! -L "$workspace" ]] || {
  echo "snapshot workspace must be new: $workspace" >&2
  exit 2
}

root=$workspace/root
cache=$workspace/cache
state=$workspace/state
evidence=$workspace/evidence
source_dir=$workspace/sources
config_dir=$workspace/config
lock=$evidence/ubuntu-minimal.lock.json
update_lock=$evidence/ubuntu-minimal.update.lock.json
mkdir -p "$root" "$cache" "$state" "$evidence" "$source_dir" "$config_dir"
[[ -z $(find "$root" -mindepth 1 -print -quit) ]]
printf 'install_root_exists=true\ndpkg_database_present=false\nhelper_placeholder_present=false\npackage_state_present=false\n' \
  >"$evidence/fresh-root-before.txt"
capture_root_layout() {
  local wrapper_status=$?
  printf '%s\n' "$wrapper_status" >"$evidence/native-wrapper-exit-status.txt"
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
write_source() {
  local target=$1 suite_name=$2
  cat >"$target" <<EOF
Types: deb
URIs: $uri
Suites: $suite_name
Components: main
Architectures: $architecture
Signed-By: $keyring
EOF
}
write_source "$source_dir/resolute.sources" resolute
write_source "$source_dir/resolute-updates.sources" resolute-updates
write_source "$source_dir/resolute-security.sources" resolute-security
printf '{"source_path":"%s","priority":500,"immutable":true,"freshness":{"mode":"frozen_release_with_witnesses","frozen_release_digest":"sha256:%s","witness_suites":["resolute-updates","resolute-security"]}}\n' \
  "$source_dir/resolute.sources" "$frozen_release_sha256" >"$config_dir/resolute.json"
for witness in resolute-updates resolute-security; do
  printf '{"source_path":"%s","priority":500,"immutable":true,"freshness":{"mode":"allow_missing_valid_until_with_max_age_seconds","maximum_release_age_seconds":%s}}\n' \
    "$source_dir/$witness.sources" "$maximum_release_age_seconds" >"$config_dir/$witness.json"
done
config_args=(
  --config "$config_dir/resolute.json"
  --config "$config_dir/resolute-updates.json"
  --config "$config_dir/resolute-security.json"
)
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
  printf 'optimization_mode=%s\nphase_telemetry=%s\nexpected_packages=%s\n' \
    "$snapshot_optimize" "$phase_telemetry" "${expected_packages:-unconstrained}"
  printf 'source_tree=%s\n' "$(git -C "$(dirname "$0")/.." rev-parse HEAD^{tree})"
  printf 'repository_freshness=frozen_release_with_witnesses:%s:witnesses=resolute-updates,resolute-security:maximum_witness_age=%s\n' \
    "$frozen_release_sha256" "$maximum_release_age_seconds"
  printf 'program_sha256=%s\nkeyring_sha256=%s\n' \
    "$(sha256sum "$debz" | cut -d' ' -f1)" \
    "$(sha256sum "$keyring" | cut -d' ' -f1)"
  sha256sum "$source_dir"/*.sources | sed 's#^.*/##; s#^#source_profile_sha256 #'
  sha256sum "$config_dir"/*.json | sed 's#^.*/##; s#^#repository_profile_sha256 #'
  printf 'operation_limit=%s\nverification_limit=%s\n' \
    "$operation_limit" "$verification_limit"
  printf 'install_progress_limit_seconds=%s\ninstall_ceiling_seconds=%s\n' \
    "$install_progress_limit_seconds" "$install_ceiling_seconds"
} >"$evidence/invocation-identity.txt"

common=(
  --install-root "$root"
  --cache-path "$cache"
  --state-path "$state"
  --architecture "$architecture"
  "${config_args[@]}"
  --keyring "$keyring"
  --deadline-ms 300000
  --lock-wait-ms 30000
  --json
)
native_common=("${common[@]}" --transaction-backend native)
mutating=(--assume-yes --noninteractive --conffile keep-existing)

progress_fingerprint() {
  stat -c '%n %i %s %.9Y' -- "$root" "$root/var/lib/debz" "$root/var/lib/dpkg" \
    "$root/$native_progress_log" "$root/$mutation_progress_log" \
    "$root/var/lib/dpkg/status" 2>/dev/null || true
}

package_progress() {
  local ledger_bytes=0
  if [[ -f "$root/$native_progress_log" ]]; then
    ledger_bytes=$(stat -c '%s' "$root/$native_progress_log" 2>/dev/null || echo 0)
  fi
  if [[ -f "$root/var/lib/dpkg/status" ]]; then
    awk '$1 == "Status:" { total++; state[$4]++ }
      END { printf "status_entries=%d installed=%d unpacked=%d other=%d", total,
        state["installed"], state["unpacked"], total - state["installed"] - state["unpacked"] }' \
      "$root/var/lib/dpkg/status" 2>/dev/null || printf 'status_entries=unreadable'
  else
    printf 'status_entries=0 installed=0 unpacked=0 other=0'
  fi
  printf ' ledger_bytes=%s\n' "$ledger_bytes"
}

runner_identity() {
  awk -F': *' '
    /^(model name|CPU part)/ && model == "" { model = $2 }
    /^(flags|Features)/ && sha == "" {
      count = split($2, flag, " ")
      for (i = 1; i <= count; i++) if (flag[i] == "sha_ni" || flag[i] == "sha2") sha = flag[i]
    }
    END { printf "cpu_model=%s\nsha_instructions=%s\n", model == "" ? "unknown" : model, sha == "" ? "none" : sha }
  ' /proc/cpuinfo 2>/dev/null || true
  printf 'usable_cpus=%s\n' "$(nproc 2>/dev/null || echo unknown)"
}

watchdog_snapshot() {
  local name=$1 group=$2 verdict=$3 elapsed=$4 since=$5
  {
    printf 'verdict=%s\nelapsed_seconds=%s\nsince_progress_seconds=%s\n' \
      "$verdict" "$elapsed" "$since"
    printf 'loadavg=%s\n' "$(cat /proc/loadavg 2>/dev/null || echo unknown)"
    printf '%s\n' "$(package_progress)"
    ps -e -o pid=,ppid=,pgid=,stat=,etimes=,time=,wchan:32=,args= 2>/dev/null |
      awk -v group="$group" '$3 == group { print substr($0, 1, 512) }' || true
  } >>"$evidence/$name-watchdog.txt"
}

# Waits for the timeout(1) process PID that runs a native install. A stall or
# the ceiling sends it SIGALRM, its own expiry signal: timeout then sends TERM
# to its process group, escalates to KILL after 30 seconds and exits 124.
watch_progress() {
  local name=$1 pid=$2
  local log=$evidence/$name-progress.txt
  local started=$SECONDS elapsed=0 progressed=0 longest_gap=0 sampled=-1
  local stopped='' verdict status=0 fingerprint current
  fingerprint=$(progress_fingerprint)
  {
    printf 'progress_limit_seconds=%s\nceiling_seconds=%s\nsample_seconds=%s\n' \
      "$install_progress_limit_seconds" "$install_ceiling_seconds" "$progress_sample_seconds"
    runner_identity
  } >"$log"
  while kill -0 "$pid" 2>/dev/null; do
    sleep 1
    elapsed=$((SECONDS - started))
    current=$(progress_fingerprint)
    if [[ "$current" != "$fingerprint" ]]; then
      fingerprint=$current
      if (( elapsed - progressed > longest_gap )); then
        longest_gap=$((elapsed - progressed))
      fi
      progressed=$elapsed
    fi
    if (( elapsed / progress_sample_seconds > sampled )); then
      sampled=$((elapsed / progress_sample_seconds))
      printf 'elapsed_seconds=%s since_progress_seconds=%s %s\n' \
        "$elapsed" "$((elapsed - progressed))" "$(package_progress)" >>"$log"
    fi
    [[ -z "$stopped" ]] || continue
    verdict=$(progress_verdict "$elapsed" "$progressed" \
      "$install_progress_limit_seconds" "$install_ceiling_seconds")
    if [[ "$verdict" != running ]]; then
      stopped=$verdict
      watchdog_snapshot "$name" "$pid" "$verdict" "$elapsed" "$((elapsed - progressed))"
      echo "native $name $verdict after ${elapsed}s, $((elapsed - progressed))s without durable progress" >&2
      kill -ALRM "$pid" 2>/dev/null || true
    fi
  done
  wait "$pid" || status=$?
  elapsed=$((SECONDS - started))
  if (( elapsed - progressed > longest_gap )); then
    longest_gap=$((elapsed - progressed))
  fi
  if [[ -z "$stopped" ]]; then
    stopped=completed
    (( status != 124 )) || stopped=timeout
  fi
  printf 'verdict=%s\nexit_status=%s\nelapsed_seconds=%s\nlongest_progress_gap_seconds=%s\n%s\n' \
    "$stopped" "$status" "$elapsed" "$longest_gap" "$(package_progress)" >>"$log"
  if [[ "$stopped" == stalled || "$stopped" == ceiling ]]; then
    return 124
  fi
  return "$status"
}

run_candidate() {
  local name=$1 duration=$2
  local status=0
  local audit_status=0
  local command
  shift 2
  printf '{"stage":"%s","command_exit_status":null}\n' "$name" >"$evidence/native-stage-v1.json"
  if [[ "$duration" == progress ]]; then
    # The watchdog stops the install at its ceiling; timeout's own limit is a backstop.
    command=(timeout --signal=TERM --kill-after=30s "$((install_ceiling_seconds + 30))s")
  else
    command=(timeout --signal=TERM --kill-after=30s "$duration")
  fi
  if [[ ${DEBZ_REAL_SNAPSHOT_TRACE:-0} == 1 ]]; then
    # A seccomp filter stops the tracee only at exec and process creation;
    # per-syscall ptrace stops otherwise dominate native install time. Process
    # creation and namespace-translated PIDs give the audit each exec's lineage.
    command+=(strace -f --seccomp-bpf -qq -yy -s 4096 --pidns-translation -e signal=none
      -e trace=execve,execveat,fork,vfork,clone,clone3 -o "$evidence/$name.execve")
  fi
  command+=("$@")
  if [[ "$duration" == progress ]]; then
    "${command[@]}" </dev/null >"$evidence/$name.json" 2>"$evidence/$name.stderr" &
    watch_progress "$name" "$!" || status=$?
  else
    "${command[@]}" >"$evidence/$name.json" 2>"$evidence/$name.stderr" || status=$?
  fi
  printf '{"stage":"%s","command_exit_status":%s}\n' "$name" "$status" >"$evidence/native-stage-v1.json"
  if [[ ${DEBZ_REAL_SNAPSHOT_TRACE:-0} == 1 ]]; then
    [[ -s "$evidence/$name.execve" ]] || {
      echo "candidate execution trace missing for $name" >&2
      exit 91
    }
    local identities records tool count
    identities=$(reviewed_script_tools "$architecture") || exit 91
    records=$(audit_exec_trace "$evidence/$name.execve" "$root" "$architecture" "$debz" \
      "$script_dpkg_version" "$identities") || audit_status=$?
    if (( audit_status != 0 && audit_status != 90 )); then
      echo "candidate execution trace unreadable for $name" >&2
      exit 91
    fi
    printf 'operation=%s\nexit_status=%s\n%s\n' "$name" "$status" "$records" \
      >>"$evidence/native-exec-audit.txt"
    audited_operations=$((audited_operations + 1))
    for tool in dpkg dpkg_divert dpkg_statoverride; do
      count=$(sed -n "s/^allowed_script_${tool}_exec=\([0-9][0-9]*\)\$/\1/p" <<<"$records")
      allowed_script_execs[$tool]=$((allowed_script_execs[$tool] + ${count:-0}))
    done
    printf 'audited_operations=%s\nallowed_script_dpkg_exec=%s\nallowed_script_dpkg_divert_exec=%s\nallowed_script_dpkg_statoverride_exec=%s\nforbidden_dpkg_exec=%s\n' \
      "$audited_operations" "${allowed_script_execs[dpkg]}" \
      "${allowed_script_execs[dpkg_divert]}" "${allowed_script_execs[dpkg_statoverride]}" \
      "$( (( audit_status == 0 )) && echo false || echo true)" \
      >"$evidence/exec-audit-summary.txt"
    if (( audit_status == 90 )); then
      echo "native candidate invoked a dpkg tool outside the reviewed script exception during $name" >&2
      exit 90
    fi
  fi
  return "$status"
}
audited_operations=0
declare -A allowed_script_execs=([dpkg]=0 [dpkg_divert]=0 [dpkg_statoverride]=0)

run() {
  local name=$1 bound=$operation_limit
  shift
  if [[ "$name" == create ]]; then
    bound=progress
  fi
  run_candidate "$name" "$bound" "$debz" "$@"
  if [[ -s "$evidence/$name.stderr" ]]; then
    local retry_check=0
    local stderr_bytes
    stderr_bytes=$(stat -c '%s' "$evidence/$name.stderr")
    if [[ "$name" == create && "$phase_telemetry" == 1 ]]; then
      # Full syntax, ordering and canonical-record bindings are checked below;
      # other stderr remains an error, even during profiling.
      grep -Evq '^info: native_phase [^[:cntrl:]]+ schema=https://debz.dev/schema/native-phase-telemetry-v1 version=1 clock=awake published=(true|false) progress_version=[0-4] intent_sha256=([0-9a-f]{64}|-) progress_sequence=[0-9]+ progress_record_sha256=([0-9a-f]{64}|-) progress_document_sha256=([0-9a-f]{64}|-)$|^debz acquisition retry failed_attempt=[1-6]/6 delay_ms=[1-9][0-9]{0,5} http_status=(429|500|502|503|504)$' \
        "$evidence/$name.stderr" || retry_check=$?
    elif [[ "$name" == refresh || "$name" == download || "$name" == create ]] &&
      (( stderr_bytes <= 4096 )); then
      grep -Evq '^debz acquisition retry failed_attempt=[1-6]/6 delay_ms=[1-9][0-9]{0,5} http_status=(429|500|502|503|504)$' \
        "$evidence/$name.stderr" || retry_check=$?
    fi
    if (( retry_check != 1 )); then
      echo "unexpected candidate stderr during $name" >&2
      return 1
    fi
  fi
  grep -q '"exit_status":0' "$evidence/$name.json"
}

verify_result() {
  local name=$1 lock_input=$2
  run_candidate "$name-summary" "$verification_limit" "$debz" transaction-result verify \
    --transaction-backend native --install-root "$root" \
    --lock-input "$lock_input" --architecture "$architecture" --json || {
      local status=$?
      echo "native $name transaction-result verification failed (exit $status)" >&2
      return "$status"
    }
  [[ ! -s "$evidence/$name-summary.stderr" ]] &&
    jq -e '.backend == "native" and .outcome == "succeeded" and
      .final_verification_status == "exact_match" and
      .lock_evidence == "exact_match" and .receipt_evidence == "exact_match" and
      .root_operation_status == "cleared"' "$evidence/$name-summary.json" >/dev/null || {
    echo "native $name transaction-result verification did not report exact success" >&2
    return 1
  }
}

review_lock() {
  jq -e --arg arch "$architecture" \
    --arg frozen "$frozen_release_sha256" \
    --arg updates "$updates_release_sha256" \
    --arg security "$security_release_sha256" '
    .schema == "https://debz.dev/schema/exact-closure-lock-v3" and
    .version == 3 and
    .target_architecture == $arch and
    ([.packages[] | select(.name == "ubuntu-minimal")] | length) == 1 and
    all(.packages[]; .archive_identity.primary == "sha512") and
    (.repositories | length) >= 2 and (.repositories | length) <= 3 and
    all(.repositories[]; .index_identity.primary == "sha256") and
    ([.repositories[].release_sha256] | index($frozen) != null and index($updates) != null) and
    all(.repositories[].release_sha256; . == $frozen or . == $updates or . == $security) and
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
if [[ -n "$expected_packages" && "$package_count" != "$expected_packages" ]]; then
  echo "database performance requires all $expected_packages packages, got $package_count" >&2
  exit 1
fi
printf 'download_bytes=%s\nlargest_package_bytes=%s\npackage_count=%s\nmetadata_bytes=%s\n' \
  "$download_bytes" "$largest_package" "$package_count" "$metadata_bytes" \
  >"$evidence/bounds.txt"

run download download "${native_common[@]}" --lock-input "$lock" ubuntu-minimal
run create install "${native_common[@]}" "${mutating[@]}" --lock-input "$lock" ubuntu-minimal
verify_result create "$lock"
cp "$root/var/lib/debz/native-transaction-provenance-v2.json" \
  "$evidence/create-native-transaction-provenance-v2.json"
cp "$root/var/lib/debz/root-operation-completion-v2.json" \
  "$evidence/create-root-operation-completion-v2.json"
if [[ "$phase_telemetry" == 1 ]]; then
  progress_member=$(jq -er '
    [.evidence_files[] | select(.kind == "progress") | .path] |
    if length == 1 then .[0] else error("one retained progress member required") end
  ' "$evidence/create-native-transaction-provenance-v2.json")
  [[ "$progress_member" =~ ^var/lib/debz/native-receipts-v1/[0-9a-f]{64}/[A-Za-z0-9._-]+$ ]] || {
    echo "invalid retained native progress path" >&2
    exit 1
  }
  cp "$root/$progress_member" "$evidence/create-native-execution-progress.json"
  PATH=/no-host-interpreters "$(dirname "$debz")/debz-native-phase-summary" \
    "$evidence/create.stderr" "$evidence/create-native-execution-progress.json" \
    >"$evidence/create-native-phase-summary-v1.json"
  jq -e '.all_invocations_finished == true and .durable_records > 0' \
    "$evidence/create-native-phase-summary-v1.json" >/dev/null
  sync -f "$evidence/create.stderr"
  sync -f "$evidence/create-native-execution-progress.json"
  sync -f "$evidence/create-native-phase-summary-v1.json"
  sync -f "$evidence"
fi
cp "$root/var/lib/dpkg/status" "$evidence/status-after-create"
device_claim=0
grep -Fqx '/dev/null' "$root/var/lib/dpkg/info/"*.list || device_claim=$?
if (( device_claim != 1 )); then
  echo "candidate package claims excluded chroot device" >&2
  exit 1
fi

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
  "$root/var/lib/debz/native-transaction-provenance-v2.json" | cut -d' ' -f1)
run update upgrade-all "${native_common[@]}" "${mutating[@]}" --lock-input "$update_lock"
jq -e '.changed == false' "$evidence/update.json" >/dev/null
[[ "$before_update_status" == "$(sha256sum "$root/var/lib/dpkg/status" | cut -d' ' -f1)" ]]
[[ "$before_update_provenance" == "$(sha256sum \
  "$root/var/lib/debz/native-transaction-provenance-v2.json" | cut -d' ' -f1)" ]]
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
run_candidate injected-failure "$verification_limit" "$debz" plan "${native_common[@]}" \
  --lock-input "$evidence/injected-invalid.lock.json" ubuntu-minimal
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
