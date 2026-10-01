#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly pinned_uri=https://snapshot.ubuntu.com/ubuntu/20261001T000000Z
readonly pinned_suite=stonking
readonly keyring=${DEBZ_REAL_SNAPSHOT_KEYRING:-/usr/share/keyrings/ubuntu-archive-keyring.gpg}
readonly max_download_bytes=$((1536 * 1024 * 1024))
readonly max_package_bytes=$((512 * 1024 * 1024))
readonly max_cache_bytes=$((2 * 1024 * 1024 * 1024))
readonly maximum_release_age_seconds=$((31 * 24 * 60 * 60))
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
# Reviewed identity of the target root's /usr/bin/dpkg, which maintainer
# scripts may run for read-only queries; see "Native exec audit" in
# doc/integration-roots.md. Bytes, size and version come from each
# architecture's authenticated dpkg archive in the pinned snapshot, never from
# another architecture or snapshot.
readonly script_dpkg_snapshot=20261001T000000Z
readonly script_dpkg_version=1.23.7ubuntu2
readonly script_dpkg_amd64='6587ef9e2ef69b1a0426d69d667bfd7cbcec6c3be5f0560cc4c219f95d65739f 322728'
readonly script_dpkg_arm64='d622099d3b73899228a9333421d11700982562775300c590adbfb15f3615d4b4 330816'

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

# Prints the reviewed "DIGEST SIZE" of the root's dpkg for an architecture.
reviewed_script_dpkg() {
  [[ "$pinned_uri" == */"$script_dpkg_snapshot" ]] || {
    echo "reviewed script dpkg identity is not bound to the pinned snapshot" >&2
    return 91
  }
  case "$1" in
    amd64) echo "$script_dpkg_amd64" ;;
    arm64) echo "$script_dpkg_arm64" ;;
    *) echo "no reviewed script dpkg identity for $1" >&2; return 91 ;;
  esac
}

# Audits one strace exec trace of a candidate command. Every execve or
# execveat of dpkg or dpkg-deb fails (exit 90) unless it is a successful plain
# execve of exactly the filename /usr/bin/dpkg, with argv[0] "dpkg" or
# "/usr/bin/dpkg" and a reviewed read-only action, made by a descendant of a
# lifecycle script that the candidate itself executed, and the root's
# /usr/bin/dpkg then has the reviewed identity with no PATH shadow. argv[0] is
# only a label; the filename and identity decide which binary ran, so /bin/dpkg
# is refused even when /bin links to usr/bin. Exit 91 means the trace or root
# could not be audited. Prints one record per allowed or refused exec.
audit_exec_trace() {
  local trace=$1 audit_root=$2 audit_architecture=$3 candidate=$4 digest=$5 size=$6 version=$7
  local status=0
  python3 - "$trace" "$audit_root" "$audit_architecture" "$candidate" \
    "$digest" "$size" "$version" <<'PY' || status=$?
import errno, hashlib, json, os, re, stat, sys

trace, root, architecture, candidate, digest, size, version = sys.argv[1:8]
size = int(size)
ARGV0 = ("dpkg", "/usr/bin/dpkg")
ACTIONS = ("--compare-versions", "--validate-version", "--print-architecture", "-s", "-L", "-l")
REFUSED_OPTIONS = ("--root", "--admindir", "--instdir", "--force")
SHADOWS = ("usr/local/sbin", "usr/local/bin", "usr/sbin", "sbin")
SCRIPT = re.compile(
    r"/var/lib/(?:debz-lifecycle-scripts|dpkg/info)/[a-z0-9][a-z0-9+.-]*"
    r"(?::[a-z0-9-]+)?\.(?:preinst|postinst|prerm|postrm)"
)
DPKG_EXEC = re.compile(
    r'execve\("([^"]*/)?dpkg(-deb)?"|execveat\([^,]+, "([^"]*/)?dpkg(-deb)?"|'
    r'execveat\([^,]*</[^>]+/dpkg(-deb)?>, ""'
)
LINE = re.compile(r"(\d+) +(.*)")
RESUMED = re.compile(r"<\.\.\. ([a-z0-9_]+) resumed>(.*)")
SUPERSEDED = re.compile(r"\+\+\+ superseded by execve in pid (\d+) \+\+\+")
CALL = re.compile(r"([a-z0-9_]+)\(")
CHILD = re.compile(r"\)\s*=\s*(\d+)(?:\s*/\* (\d+) in strace's PID NS \*/)?\s*$")
EXECVE_TAIL = re.compile(
    r", (?:0x[0-9a-f]+|NULL)(?: /\* \d+ vars? \*/)?"
    r"(?:\)\s*=\s*(0|-1 [A-Z0-9]+|\?)(?: .*)?| <unfinished>)"
)
ESCAPES = {"n": 10, "t": 9, "r": 13, "v": 11, "f": 12, "a": 7, "b": 8, "\\": 92, '"': 34, "'": 39}
UNFINISHED = " <unfinished ...>"


def c_string(text, index):
    value = bytearray()
    index += 1
    while index < len(text):
        char = text[index]
        if char == '"':
            index += 1
            truncated = text.startswith("...", index)
            return value.decode("utf-8", "surrogateescape"), index + (3 if truncated else 0), truncated
        if char != "\\":
            value += char.encode("utf-8", "surrogateescape")
            index += 1
            continue
        escape = text[index + 1:index + 2]
        if escape in ESCAPES:
            value.append(ESCAPES[escape])
            index += 2
        elif escape == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", text[index + 2:index + 4]):
            value.append(int(text[index + 2:index + 4], 16))
            index += 4
        elif escape and escape in "01234567":
            end = index + 1
            while end < len(text) and end < index + 4 and text[end] in "01234567":
                end += 1
            value.append(int(text[index + 1:end], 8) & 0xFF)
            index = end
        else:
            raise ValueError("unknown escape")
    raise ValueError("unterminated string")


def parse_execve(text):
    """Returns (path, argv, result, truncated), or None if not understood."""
    try:
        if not text.startswith('execve("'):
            return None
        path, index, truncated = c_string(text, len("execve("))
        if not text.startswith(", [", index):
            return None
        index += 3
        argv = []
        if text.startswith("]", index):
            index += 1
        else:
            while True:
                if text.startswith("...", index):
                    truncated = True
                    index += 3
                elif text.startswith('"', index):
                    value, index, cut = c_string(text, index)
                    argv.append(value)
                    truncated = truncated or cut
                else:
                    return None
                if text.startswith(", ", index):
                    index += 2
                elif text.startswith("]", index):
                    index += 1
                    break
                else:
                    return None
        tail = EXECVE_TAIL.fullmatch(text[index:])
        if tail is None:
            return None
        return path, argv, tail.group(1) or "?", truncated
    except ValueError:
        return None


try:
    with open(trace, "rb") as source:
        lines = source.read().decode("utf-8", "surrogateescape").split("\n")
except OSError as error:
    print(f"exec trace unreadable: {error}", file=sys.stderr)
    sys.exit(91)

events = {}
candidates = []
pending = {}
poisoned = set()
root_pid = None
for seq, raw in enumerate(lines):
    if not raw:
        continue
    if DPKG_EXEC.search(raw):
        candidates.append(seq)
    match = LINE.fullmatch(raw)
    if match is None:
        continue
    pid, rest = int(match.group(1)), match.group(2)
    if root_pid is None:
        root_pid = pid
    superseded = SUPERSEDED.fullmatch(rest)
    if superseded:
        poisoned.update((pid, int(superseded.group(1))))
        continue
    resumed = RESUMED.match(rest)
    if resumed:
        entry = pending.pop(pid, None)
        if entry is not None and entry[2] == resumed.group(1):
            events[entry[0]] = (pid, entry[1] + resumed.group(2))
        continue
    call = CALL.match(rest)
    if rest.endswith(UNFINISHED):
        pending[pid] = (seq, rest[:-len(UNFINISHED)], call.group(1) if call else "")
    else:
        events[seq] = (pid, rest)
for pid, (seq, text, _) in pending.items():
    events[seq] = (pid, text + " <unfinished>")

parents = {}
execs = {}
for seq in sorted(events):
    pid, text = events[seq]
    call = CALL.match(text)
    name = call.group(1) if call else ""
    if name in ("clone", "clone3", "fork", "vfork"):
        child = CHILD.search(text)
        if child:
            child_pid = int(child.group(2) or child.group(1))
            if child_pid in parents or child_pid == root_pid:
                poisoned.add(child_pid)
            parents[child_pid] = (pid, seq)
    elif name == "execve":
        execs.setdefault(pid, []).append((seq, parse_execve(text)))


def lineage_state(pid, seq):
    chain = []
    seen = set()
    while True:
        if pid in seen or len(chain) > 4096:
            return None, [str(item[0]) for item in reversed(chain)], True
        seen.add(pid)
        chain.append((pid, seq))
        if pid not in parents:
            break
        pid, seq = parents[pid]
    lineage = [str(item[0]) for item in reversed(chain)]
    if chain[-1][0] != root_pid:
        return None, lineage, False
    script = None
    ambiguous = False
    debz = False
    for pid, seq in reversed(chain):
        ambiguous = ambiguous or pid in poisoned
        for exec_seq, parsed in execs.get(pid, []):
            if exec_seq >= seq:
                break
            if parsed is None:
                debz = False
                continue
            path, _, result, truncated = parsed
            if result != "0":
                continue
            if script is None and debz and not truncated and SCRIPT.fullmatch(path):
                script = (path, pid)
            debz = path == candidate
    return script, lineage, ambiguous


def operands_before_separator(values):
    return values[:values.index("--")] if "--" in values else values


def refusal(seq):
    pid, text = events.get(seq, (None, ""))
    if not text.startswith("execve("):
        return ("execveat" if text.startswith("execveat(") else "unparsed"), pid, None, None, [], None
    parsed = dict(execs.get(pid, [])).get(seq)
    if parsed is None:
        return "unparsed", pid, None, None, [], None
    path, argv, result, truncated = parsed
    script, lineage, ambiguous = lineage_state(pid, seq)
    reason = None
    if truncated:
        reason = "truncated"
    elif path != "/usr/bin/dpkg":
        reason = "path"
    elif result != "0":
        reason = "exec-result"
    elif not argv or argv[0] not in ARGV0:
        reason = "argv0"
    elif len(argv) < 2 or argv[1] not in ACTIONS:
        reason = "action"
    elif any(value.startswith(REFUSED_OPTIONS) for value in argv[2:]):
        reason = "option"
    elif any(value.startswith("-") for value in operands_before_separator(argv[2:])):
        reason = "option"
    elif ambiguous:
        reason = "ambiguous-lineage"
    elif script is None:
        reason = "not-script-descended"
    return reason, pid, script, lineage, argv, path


def open_beneath(relative):
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    finally:
        os.close(descriptor)


def exists_beneath(relative):
    todo = [part for part in relative.split("/") if part not in ("", ".")]
    done = []
    links = 0
    while todo:
        part = todo.pop(0)
        if part == "..":
            if done:
                done.pop()
            continue
        path = os.path.join(root, *done, part)
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return False
        except NotADirectoryError:
            return False
        if not todo:
            return True
        if stat.S_ISLNK(info.st_mode):
            links += 1
            if links > 40:
                raise OSError("too many symbolic links")
            target = os.readlink(path)
            if target.startswith("/"):
                done = []
            todo = [item for item in target.split("/") if item not in ("", ".")] + todo
        elif stat.S_ISDIR(info.st_mode):
            done.append(part)
        else:
            return False
    return True


def identity_refusal():
    try:
        try:
            descriptor = open_beneath("usr/bin/dpkg")
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOTDIR):
                return "dpkg-identity:not-regular"
            raise
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                return "dpkg-identity:not-regular"
            hasher = hashlib.sha256()
            while chunk := os.read(descriptor, 1 << 20):
                hasher.update(chunk)
        finally:
            os.close(descriptor)
        if info.st_size != size or hasher.hexdigest() != digest:
            return "dpkg-identity:digest"
        for directory in SHADOWS:
            if exists_beneath(directory + "/dpkg"):
                return "dpkg-identity:shadow:/" + directory + "/dpkg"
        descriptor = open_beneath("var/lib/dpkg/status")
        try:
            status = b""
            while chunk := os.read(descriptor, 1 << 20):
                status += chunk
                if len(status) > 64 << 20:
                    return "dpkg-identity:status"
        finally:
            os.close(descriptor)
    except OSError:
        return "dpkg-identity:unreadable"
    for stanza in status.decode("utf-8", "replace").split("\n\n"):
        fields = dict(line.split(": ", 1) for line in stanza.split("\n") if ": " in line and not line.startswith(" "))
        if fields.get("Package") == "dpkg":
            if fields.get("Version") == version and fields.get("Architecture") == architecture:
                return None
            return "dpkg-identity:version"
    return "dpkg-identity:version"


allowed = []
refused = []
for seq in candidates:
    reason, pid, script, lineage, argv, path = refusal(seq)
    record = {"line": seq + 1, "pid": pid, "argv": argv, "path": path,
              "script": script, "lineage": lineage}
    (refused if reason else allowed).append((reason, record))
if allowed:
    reason = identity_refusal()
    if reason:
        refused = sorted(refused + [(reason, record) for _, record in allowed], key=lambda item: item[1]["line"])
        allowed = []


def show(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


for _, record in allowed:
    print(f"script_dpkg_exec line={record['line']} pid={record['pid']} "
          f"script={record['script'][0]} script_pid={record['script'][1]} "
          f"lineage={'>'.join(record['lineage'])} argv={show(record['argv'])}")
for reason, record in refused[:200]:
    script, script_pid = record["script"] or ("-", "-")
    print(f"forbidden_exec reason={reason} line={record['line']} pid={record['pid']} "
          f"path={show(record['path'])} script={script} script_pid={script_pid} "
          f"lineage={'>'.join(record['lineage'] or [])} argv={show(record['argv'])}")
if len(refused) > 200:
    print(f"forbidden_exec_records_omitted={len(refused) - 200}")
if allowed:
    print(f"script_dpkg_identity version={version} architecture={architecture} size={size} digest={digest}")
print(f"allowed_script_dpkg_exec={len(allowed)}")
print(f"forbidden_dpkg_exec={'true' if refused else 'false'}")
sys.exit(90 if refused else 0)
PY
  case "$status" in
    0|90) return "$status" ;;
    *) return 91 ;;
  esac
}

if [[ ${1:-} == --audit-exec-trace ]]; then
  [[ $# == 5 ]] || { echo "usage: $0 --audit-exec-trace TRACE ROOT ARCHITECTURE DEBZ" >&2; exit 2; }
  identity=$(reviewed_script_dpkg "$4") || exit 91
  audit_exec_trace "$2" "$3" "$4" "$5" "${identity% *}" "${identity#* }" "$script_dpkg_version"
  exit
fi
# Tests only: the same audit against an explicit fixture identity. Production
# and CI audits use --audit-exec-trace, which accepts only the reviewed pins.
if [[ ${1:-} == --audit-exec-trace-fixture ]]; then
  [[ $# == 8 ]] || {
    echo "usage: $0 --audit-exec-trace-fixture TRACE ROOT ARCHITECTURE DEBZ DIGEST SIZE VERSION" >&2
    exit 2
  }
  audit_exec_trace "$2" "$3" "$4" "$5" "$6" "$7" "$8"
  exit
fi
if [[ ${1:-} == --validate-values ]]; then
  validate_values "$2" "$3" "$4"
  exit
fi
if [[ ${1:-} == --progress-verdict ]]; then
  [[ $# == 5 ]] || { echo "usage: $0 --progress-verdict ELAPSED PROGRESSED LIMIT CEILING" >&2; exit 2; }
  progress_verdict "$2" "$3" "$4" "$5"
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
  --config "$config_file"
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
  if [[ ${DEBZ_REAL_SNAPSHOT_TRACE:-0} == 1 ]]; then
    [[ -s "$evidence/$name.execve" ]] || {
      echo "candidate execution trace missing for $name" >&2
      exit 91
    }
    local identity records allowed
    identity=$(reviewed_script_dpkg "$architecture") || exit 91
    records=$(audit_exec_trace "$evidence/$name.execve" "$root" "$architecture" "$debz" \
      "${identity% *}" "${identity#* }" "$script_dpkg_version") || audit_status=$?
    if (( audit_status != 0 && audit_status != 90 )); then
      echo "candidate execution trace unreadable for $name" >&2
      exit 91
    fi
    printf 'operation=%s\nexit_status=%s\n%s\n' "$name" "$status" "$records" \
      >>"$evidence/native-exec-audit.txt"
    allowed=$(sed -n 's/^allowed_script_dpkg_exec=\([0-9][0-9]*\)$/\1/p' <<<"$records")
    audited_operations=$((audited_operations + 1))
    allowed_script_dpkg_execs=$((allowed_script_dpkg_execs + ${allowed:-0}))
    printf 'audited_operations=%s\nallowed_script_dpkg_exec=%s\nforbidden_dpkg_exec=%s\n' \
      "$audited_operations" "$allowed_script_dpkg_execs" \
      "$( (( audit_status == 0 )) && echo false || echo true)" \
      >"$evidence/exec-audit-summary.txt"
    if (( audit_status == 90 )); then
      echo "native candidate invoked dpkg or dpkg-deb outside the reviewed script exception during $name" >&2
      exit 90
    fi
  fi
  return "$status"
}
audited_operations=0
allowed_script_dpkg_execs=0

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
    if [[ "$name" == refresh || "$name" == download || "$name" == create ]] &&
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
  jq -e --arg arch "$architecture" '
    .schema == "https://debz.dev/schema/exact-closure-lock-v3" and
    .version == 3 and
    .target_architecture == $arch and
    ([.packages[] | select(.name == "ubuntu-minimal")] | length) == 1 and
    all(.packages[]; .archive_identity.primary == "sha512") and
    (.repositories | length) == 1 and
    all(.repositories[]; .index_identity.primary == "sha512") and
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
cp "$root/var/lib/debz/native-transaction-provenance-v2.json" \
  "$evidence/create-native-transaction-provenance-v2.json"
cp "$root/var/lib/debz/root-operation-completion-v2.json" \
  "$evidence/create-root-operation-completion-v2.json"
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
