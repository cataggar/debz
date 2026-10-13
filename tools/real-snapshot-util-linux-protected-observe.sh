#!/usr/bin/env bash
# Observe the original authenticated arm64 util-linux 2.41.3-3ubuntu2.2
# postinst (`configure ""`) executed by the hash-pinned Debian dpkg inside the
# protected sanitized chroot, traced from the host. less and util-linux are
# dpkg-unpacked from the template, the rest of the original 177-package closure
# is extracted script-free inside the chroot, and less is configured first so
# the pager prestate follows the original order. The decoded trace is an
# observation witness only: it admits no callback, proves no native runtime and
# borrows no amd64 authority.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C PYTHONDONTWRITEBYTECODE=1
unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH ZIG_LIB_DIR
[[ $# == 3 && $(id -u) == 0 && $(id -g) == 0 && $(uname -m) == aarch64 ]] || {
  echo "usage (as root on disposable hosted arm64): $0 PROTECTED_ZIG PROTECTED_DEBZ NEW_WORKSPACE" >&2
  exit 2
}
readonly original_postinst_sha256=31f01940fe6aa22a9b35b54029eb5e4dd4ea5146dd2bacdb495d0d37eb210fc9
checkout=$(pwd -P)
zig=$1 debz=$2 workspace=$3
[[ "$workspace" == "$checkout/.real-snapshot/util-linux-observe-arm64" &&
  ! -e "$workspace" && ! -L "$workspace" && -n ${DEBZ_REAL_SNAPSHOT_KEYRING:-} ]]
python3 -B -I - "$checkout/tools" "$checkout" "$zig" "$debz" "$DEBZ_REAL_SNAPSHOT_KEYRING" \
  /usr/bin/strace <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import protected, toolchain
for name in ("real-snapshot-util-linux-protected-observe.sh", "real_snapshot_less_stage.py",
             "real_snapshot_less_fixtures.py", "real-snapshot-reference-protected-stage.sh",
             "real-snapshot-util-linux-authority.zig"):
    protected(Path(sys.argv[2]) / "tools" / name)
toolchain(Path(sys.argv[3]))
for argument in sys.argv[4:]:
    protected(Path(argument))
PY
bash "$checkout/tools/real-snapshot-reference-protected-ci.sh" \
  --check-keyring "$DEBZ_REAL_SNAPSHOT_KEYRING" >/dev/null
bash tools/real-snapshot-reference-protected-stage.sh --arm64-bash-source "$zig" "$debz" "$workspace"
evidence=$workspace/evidence
lock=$evidence/ubuntu-minimal.lock.json
cache=$workspace/snapshot/cache/packages-v2/objects
pinned=$workspace/dpkg/usr/bin/dpkg
env "TMPDIR=$checkout/.zig-cache/data" "$zig" build build-arm64-util-linux-authority \
  -Doptimize=ReleaseSafe -j2 --summary all
inspector=$checkout/zig-out/bin/debz-arm-util-linux-authority
"$inspector" --protected source "$lock" "$cache" "$evidence/util-linux-observation-source.json"
jq -e '.callback_admitted == false and .runtime_proved == false and (.sources | length) == 15' \
  "$evidence/util-linux-observation-source.json" >/dev/null

# Verify every other original closure archive before any chroot.
jq -r '
  [.packages[] | select(.name != "less" and .name != "util-linux")] |
  if length != 175 then error("unexpected original closure") else .[] |
    if (.architecture != "arm64" and .architecture != "all") or
      .origin.type != "authenticated_repository" or .archive_identity.primary != "sha512" or
      ([.archive_identity.digests[] | select(.algorithm == "sha512")] | length) != 1
    then error("unauthenticated original closure archive") else
      [.name, .version, .architecture, .declared_size,
        (.archive_identity.digests[] | select(.algorithm == "sha512") | .digest)] | @tsv end end
' "$lock" >"$evidence/observation-closure.tsv"
mapfile -t closure <"$evidence/observation-closure.tsv"
(( ${#closure[@]} == 175 ))
for record in "${closure[@]}"; do
  IFS=$'\t' read -r name version _ size digest <<<"$record"
  [[ -n "$name" && -n "$version" && "$size" =~ ^[0-9]+$ && "$digest" =~ ^[a-f0-9]{128}$ ]]
  object=$cache/sha512-$digest
  [[ -f "$object" && ! -L "$object" && $(stat -c %s "$object") == "$size" &&
    $(sha512sum "$object" | cut -d' ' -f1) == "$digest" ]]
done

root=$workspace/root
[[ ! -e "$root" && ! -L "$root" ]]
cp -a --reflink=auto --one-file-system -- "$workspace/template" "$root"
python3 -B -I tools/real_snapshot_less_stage.py prepare "$root" "$lock" "$cache" "$pinned"
rm -f -- "$root/.debz-reference-archive"
rmdir -- "$root/usr/lib64"
original=$(python3 -B -I - "$checkout/tools" "$root" "$lock" "$cache" <<'PY'
from pathlib import Path
import json
import sys
sys.path.insert(0, sys.argv[1])
from real_snapshot_less_fixtures import copy_exclusive
from real_snapshot_less_stage import archive
root, lock, cache = (Path(argument) for argument in sys.argv[2:])
original = archive(json.loads(lock.read_bytes()), cache, "util-linux")
copy_exclusive(root, "var/lib/dpkg/producer-util-linux.deb", original, 0o644)
print(original)
PY
)
[[ "$original" == "$cache"/sha512-* && -f "$original" && ! -L "$original" ]]
chmod 0755 "$root"

# (a) The pinned dpkg unpacks less and util-linux while the template still
# holds only its own pinned helpers.
{
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      /var/lib/dpkg/producer-dpkg --root=/ --force-not-root --force-bad-path \
      --force-depends --no-triggers --unpack /var/lib/dpkg/producer-less.deb /var/lib/dpkg/producer-util-linux.deb
  '
} >"$evidence/observation-unpack.stdout" 2>"$evidence/observation-unpack.stderr"
[[ $(dpkg-query --admindir="$root/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' less) == '668-1build1 arm64 install ok unpacked' ]]
[[ $(dpkg-query --admindir="$root/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' util-linux) == '2.41.3-3ubuntu2.2 arm64 install ok unpacked' ]]

# (b) Every other verified original archive is extracted without maintainer
# scripts by tar inside the chroot, so absolute links resolve beneath it.
for record in "${closure[@]}"; do
  IFS=$'\t' read -r _ _ _ _ digest <<<"$record"
  object=$cache/sha512-$digest
  /usr/bin/dpkg-deb --fsys-tarfile "$object" |
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      tar -xpf - --warning=no-timestamp --keep-directory-symlink --numeric-owner -C /
  '
done >"$evidence/observation-closure.stdout" 2>"$evidence/observation-closure.stderr"
for link in bin sbin lib; do
  [[ -L "$root/$link" && $(readlink "$root/$link") == "usr/$link" ]]
done

# (c) The original libc-bin ldconfig, byte-equal to the member of its verified
# archive, builds only the loader cache; links come from the archives.
python3 -B -I - "$checkout/tools" "$root" "$lock" "$cache" <<'PY'
from pathlib import Path
import json
import sys
sys.path.insert(0, sys.argv[1])
from real_snapshot_less_fixtures import read_regular
from real_snapshot_less_stage import archive, member
root, lock, cache = (Path(argument) for argument in sys.argv[2:])
expected = member(archive(json.loads(lock.read_bytes()), cache, "libc-bin"), "usr/sbin/ldconfig")
if read_regular(root, "usr/sbin/ldconfig", len(expected)) != expected:
    raise SystemExit("original libc-bin ldconfig changed")
PY
{
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs /usr/sbin/ldconfig -X
  '
} >"$evidence/observation-ldconfig.stdout" 2>"$evidence/observation-ldconfig.stderr"
[[ -f "$root/etc/ld.so.cache" && ! -L "$root/etc/ld.so.cache" ]]
install -m 0644 "$root/etc/ld.so.cache" "$evidence/util-linux-observation-ld.so.cache"

# (d) less is configured first, matching the original pager prestate.
{
timeout --signal=TERM --kill-after=5s 120s \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      /var/lib/dpkg/producer-dpkg --root=/ --force-not-root --force-bad-path \
      --force-depends --no-triggers --configure less
  '
} >"$evidence/observation-less-configure.stdout" 2>"$evidence/observation-less-configure.stderr"
[[ $(dpkg-query --admindir="$root/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' less) == '668-1build1 arm64 install ok installed' ]]
pager=$root/var/lib/dpkg/alternatives/pager
[[ -f "$pager" && ! -L "$pager" ]]
install -m 0644 "$pager" "$evidence/util-linux-observation-pager-before.txt"

observation_files() { # manifest ROOT OUTPUT | delta BEFORE AFTER OUTPUT
  python3 -B -I - "$@" <<'PY'
import hashlib
import json
import os
import stat
import sys


def fail(error: OSError) -> None:
    raise error


def row(root: str, relative: str) -> str:
    path = os.path.join(root, relative)
    metadata = os.lstat(path)
    size, detail = "-", "-"
    if stat.S_ISLNK(metadata.st_mode):
        detail = "-> " + json.dumps(os.readlink(path))
    elif stat.S_ISREG(metadata.st_mode):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or
                    (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)):
                raise ValueError(f"observation root entry changed: {relative}")
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 1 << 20):
                digest.update(chunk)
        finally:
            os.close(descriptor)
        size, detail = str(metadata.st_size), "sha256:" + digest.hexdigest()
    elif stat.S_ISCHR(metadata.st_mode) or stat.S_ISBLK(metadata.st_mode):
        detail = f"{os.major(metadata.st_rdev)},{os.minor(metadata.st_rdev)}"
    return "\t".join((json.dumps(relative), stat.filemode(metadata.st_mode),
                      f"{metadata.st_uid}:{metadata.st_gid}", str(metadata.st_nlink), size, detail))


def entries(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8") as stream:
        return dict(line.rstrip("\n").split("\t", 1) for line in stream)


if sys.argv[1] == "manifest" and len(sys.argv) == 4:
    root = sys.argv[2]
    rows = [row(root, ".")]
    for directory, directories, files in os.walk(root, onerror=fail):
        directories.sort()
        for name in sorted(directories + files):
            rows.append(row(root, os.path.relpath(os.path.join(directory, name), root)))
    with open(sys.argv[3], "x", encoding="utf-8") as output:
        output.write("\n".join(rows) + "\n")
elif sys.argv[1] == "delta" and len(sys.argv) == 5:
    before, after = entries(sys.argv[2]), entries(sys.argv[3])
    with open(sys.argv[4], "x", encoding="utf-8") as output:
        for path in sorted(set(before) | set(after)):
            if path not in after:
                output.write(f"-\t{path}\t{before[path]}\n")
            elif path not in before:
                output.write(f"+\t{path}\t{after[path]}\n")
            elif before[path] != after[path]:
                output.write(f"~\t{path}\t{before[path]}\t=>\t{after[path]}\n")
else:
    raise SystemExit("unknown observation file request")
PY
}

# (e) The original postinst is checked against the authenticated control
# archive, then executed once by the pinned dpkg under the host tracer.
postinst=$root/var/lib/dpkg/info/util-linux.postinst
timeout --signal=TERM --kill-after=5s 60s \
  /usr/bin/dpkg-deb --ctrl-tarfile "$original" |
  /usr/bin/tar -xOf - ./postinst >"$evidence/util-linux-observation-original.postinst"
[[ -f "$postinst" && ! -L "$postinst" &&
  $(sha256sum "$evidence/util-linux-observation-original.postinst" | cut -d' ' -f1) == "$original_postinst_sha256" ]]
cmp "$evidence/util-linux-observation-original.postinst" "$postinst"
observation_files manifest "$root" "$evidence/util-linux-observation-before.manifest"
[[ ! -e "$workspace/trace" && ! -L "$workspace/trace" ]]
install -d -o root -g root -m 0700 "$workspace/trace"
trace=$workspace/trace/util-linux-configure.strace
if {
timeout --signal=TERM --kill-after=5s 120s \
  /usr/bin/strace -f -q -y -s 4096 --pidns-translation -e signal=none -e 'abbrev=!execve,execveat' \
    -e trace=%file,%process,unshare,setns,fchdir,fchmod,fchown,ftruncate,socket,connect,bind -o "$trace" -- \
  unshare --mount --net --pid --fork --kill-child=SIGKILL --propagation private -- \
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LC_ALL=C \
      DEBIAN_FRONTEND=noninteractive DPKG_COLORS=never \
      chroot "$root" /bin/sh -c '
    set -eu
    test "$$" -eq 1
    exec setpriv --bounding-set=-sys_admin --no-new-privs \
      /var/lib/dpkg/producer-dpkg --root=/ --force-not-root --force-bad-path \
      --force-depends --no-triggers --configure util-linux
  '
} >"$evidence/util-linux-configure.stdout" 2>"$evidence/util-linux-configure.stderr"; then
  configure_status=0
else
  configure_status=$?
fi
printf 'configure_status=%s\n' "$configure_status" >"$evidence/util-linux-configure-status.txt"
# The raw trace is retained compressed before any check can stop the run.
gzip -9 -n -c "$trace" >"$evidence/util-linux-configure.strace.gz"
{
  /usr/bin/strace -V
  sha256sum /usr/bin/strace
  dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' strace
} >"$evidence/strace-provenance.txt"
dpkg-query --admindir="$root/var/lib/dpkg" -W \
  -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' >"$evidence/util-linux-observation-packages.tsv"
install -m 0644 "$root/var/lib/dpkg/status" "$evidence/util-linux-observation-dpkg-status.txt"
[[ -f "$pager" && ! -L "$pager" ]]
install -m 0644 "$pager" "$evidence/util-linux-observation-pager-after.txt"
for log in dpkg alternatives; do
  if [[ -f "$root/var/log/$log.log" && ! -L "$root/var/log/$log.log" ]]; then
    install -m 0644 "$root/var/log/$log.log" "$evidence/util-linux-observation-$log-log.txt"
  fi
done
observation_files manifest "$root" "$evidence/util-linux-observation-after.manifest"
observation_files delta "$evidence/util-linux-observation-before.manifest" \
  "$evidence/util-linux-observation-after.manifest" "$evidence/util-linux-observation-delta.tsv"
"$inspector" --protected observe "$lock" "$cache" "$root" "$trace" "$evidence/util-linux-observation.json"
report=$evidence/util-linux-observation.json
jq -e --arg postinst "$original_postinst_sha256" --slurpfile source "$evidence/util-linux-observation-source.json" '
  .observation_only == true and .callback_admitted == false and .runtime_proved == false and
  .original_postinst.sha256 == $postinst and .closure_digest == $source[0].closure_digest and
  .postinst.exit_status == 0
' "$report" >/dev/null
(( configure_status == 0 ))
[[ $(dpkg-query --admindir="$root/var/lib/dpkg" -W \
  -f='${Version} ${Architecture} ${Status}' util-linux) == '2.41.3-3ubuntu2.2 arm64 install ok installed' ]]
jq -r '[.executions[] | select(.scope == "postinst") | "\(.result)\t\(.attribution)\t\(.path)"] | unique | .[]' \
  "$report" >"$evidence/util-linux-observation-executed.tsv"
jq -r '[.paths[] | select(.scope == "postinst" and (.call == "openat" or .call == "openat2") and
    (.path | test("\\.(pm|pl|so(\\.[0-9]+)*)$"))) | "\(.result)\t\(.attribution)\t\(.path)"] | unique | .[]' \
  "$report" >"$evidence/util-linux-observation-loads.tsv"
jq -r '[.paths[] | select(.mutating and .result == "ok") | "\(.scope)\t\(.call)\t\(.attribution)\t\(.path)"] | unique | .[]' \
  "$report" >"$evidence/util-linux-observation-mutations.tsv"
read -r bytes _ < <(du -sb "$workspace")
(( bytes <= 8 * 1024 * 1024 * 1024 ))
{
  jq -r '"observation_only=\(.observation_only)", "callback_admitted=\(.callback_admitted)",
    "runtime_proved=\(.runtime_proved)", "postinst_exit_status=\(.postinst.exit_status)",
    "trace_sha256=\(.trace.sha256)", "trace_lines=\(.trace.lines)", "processes=\(.processes | length)",
    "executions=\(.executions | length)", "paths=\(.paths | length)",
    "host_descriptors=\(.host_descriptors | length)", "network=\(.network | length)",
    "confinement=\(.confinement | length)", "calls_not_decoded=\(.calls_not_decoded | length)"' "$report"
  printf 'configure_status=%s\n' "$configure_status"
  printf 'ldconfig_sha256=%s\n' "$(sha256sum "$root/usr/sbin/ldconfig" | cut -d' ' -f1)"
  printf 'ld_so_cache_sha256=%s\n' "$(sha256sum "$root/etc/ld.so.cache" | cut -d' ' -f1)"
  printf 'delta_rows=%s\n' "$(wc -l <"$evidence/util-linux-observation-delta.tsv")"
} >"$evidence/util-linux-observation-summary.txt"
cat "$evidence/util-linux-observation-summary.txt"
echo "original arm64 util-linux postinst observed without callback admission"
