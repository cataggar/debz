#!/usr/bin/env bash
# Fresh signed source and replay roots, separate from the small protected proof.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C
unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH ZIG_LIB_DIR

[[ $# == 4 && $(id -u) == 0 && $(id -g) == 0 && $(uname -m) == x86_64 ]] || {
  echo "usage (as root on amd64): $0 PROTECTED_ZIG PROTECTED_DEBZ PINNED_DPKG NEW_WORKSPACE" >&2
  exit 2
}
checkout=$(pwd -P)
zig=$1 debz=$2 pinned=$3 workspace=$4
[[ "$workspace" == "$checkout/.real-snapshot/python3-amd64" &&
  ! -e "$workspace" && ! -L "$workspace" ]]
[[ -n ${DEBZ_REAL_SNAPSHOT_KEYRING:-} ]]
python3 -B -I - "$checkout/tools" "$checkout" "$zig" "$debz" "$pinned" \
  "$DEBZ_REAL_SNAPSHOT_KEYRING" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import protected, toolchain
checkout = Path(sys.argv[2])
for relative in ("tools/real-snapshot-python3-protected-stage.sh",
                 "tools/real-snapshot-python3-reference.sh",
                 "tools/real-snapshot-signed-proc-bindings.sh",
                 "tools/real-snapshot-signed-proc-prestates.sh",
                 "tools/real-snapshot-reference-order.py",
                 "tools/real_snapshot_reference_paths.py"):
    protected(checkout / relative)
protected(checkout / ".real-snapshot", directory=True)
toolchain(Path(sys.argv[3]))
for argument in sys.argv[4:]:
    protected(Path(argument))
PY
bash "$checkout/tools/real-snapshot-reference-protected-ci.sh" \
  --check-keyring "$DEBZ_REAL_SNAPSHOT_KEYRING" >/dev/null
export DEBZ_ZIG=$zig PYTHONDONTWRITEBYTECODE=1

# Reuse the authenticated full closure and its existing pinned-dpkg scheduler;
# capture before Python configure, without changing configure semantics.
bash tools/real-snapshot-signed-proc-bindings.sh "$debz" "$workspace"
bash tools/real-snapshot-signed-proc-prestates.sh --python3 "$pinned" "$workspace"
source=$workspace/prestates/python3
evidence=$workspace/evidence
install -d -o root -g root -m 0700 "$evidence"
read -r bytes _ < <(du -sb "$source")
(( bytes <= 512 * 1024 * 1024 ))

copy_root() {
  [[ ! -e "$2" && ! -L "$2" ]]
  cp -a --reflink=auto --one-file-system -- "$1" "$2"
}
before=$workspace/empty-0600
before_0644=$workspace/empty-0644
copy_root "$source" "$before"
# This is a new disposable fixture, not a native-root repair. Never follow
# the captured root's null/proc aliases while preparing its empty sink.
python3 -B -I - "$checkout/tools" "$before" <<'PY'
import os
from pathlib import Path
import stat
import sys
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import open_protected, protected
root = Path(sys.argv[2])
protected(root, directory=True)
protected(root / "dev", directory=True)
protected(root / "proc", directory=True)
null = root / "dev/null"
meta = null.lstat()
if not stat.S_ISCHR(meta.st_mode) or meta.st_rdev != os.makedev(1, 3):
    raise ValueError("fresh captured source must have the reference null device")
if any((root / "proc").iterdir()):
    raise ValueError("captured source proc must be empty")
null.unlink()
fd = os.open(null, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
os.close(fd)
# Pinned dpkg lists use extraction order; the native binding uses C-sorted
# paths. Verify the exact path-set digest after normalization, not new paths.
for name, size, digest in (
    ("python3", 918, "383196acd094063e8e49dc4511deb7094e264a41d872bb889d21b197a550f628"),
    ("python3-minimal", 781, "82003099685ad735bdf486d434276cdb0b82b88f269330f87504a5739008f519"),
):
    import hashlib
    path = root / f"var/lib/dpkg/info/{name}.list"
    fd = open_protected(path)
    with os.fdopen(fd, "rb") as member:
        meta = os.fstat(member.fileno())
        if meta.st_size != size or meta.st_nlink != 1:
            raise ValueError(f"Python list metadata changed: {name}")
        content = b"".join(sorted(member.readlines()))
    if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
        raise ValueError(f"signed Python list path set changed: {name}")
    temporary = path.with_suffix(".list.sorted")
    with temporary.open("xb") as member:
        member.write(content)
    temporary.chmod(0o644)
    temporary.replace(path)
PY
copy_root "$before" "$before_0644"
chmod 0644 "$before_0644/dev/null"
lock=$workspace/snapshot/evidence/ubuntu-minimal.lock.json
archive_digest=$(jq -er '.packages[] | select(.name == "python3" and .architecture == "amd64") |
  .archive_identity.digests[] | select(.algorithm == "sha512") | .digest' "$lock")
archive=$workspace/snapshot/cache/packages-v2/objects/sha512-$archive_digest
after=$workspace/after-0600
after_0644=$workspace/after-0644
for mode in 0600 0644; do
  input=$before output=$after
  [[ $mode == 0600 ]] || { input=$before_0644; output=$after_0644; }
  timeout --signal=TERM --kill-after=30s 10m \
    bash tools/real-snapshot-python3-reference.sh "$pinned" "$input" "$lock" "$archive" \
    "$output" "$workspace/dpkg-$mode" >"$evidence/replay-$mode.txt" 2>"$evidence/replay-$mode.stderr"
done
for name in html link shadow null null-0640 root script proc; do
  copy_root "$before" "$workspace/bad-$name"
done
mkdir "$workspace/bad-html/usr/share/doc/python3/html"
rm -- "$workspace/bad-link/usr/bin/python3"
ln -s python3.invalid "$workspace/bad-link/usr/bin/python3"
printf 'shadow\n' >"$workspace/bad-shadow/usr/sbin/update-alternatives"
chmod 0666 "$workspace/bad-null/dev/null"
chmod 0640 "$workspace/bad-null-0640/dev/null"
chmod 0755 "$workspace/bad-root"
printf 'stale script\n' >"$workspace/bad-script/var/lib/dpkg/info/python3.preinst"
printf 'unexpected\n' >"$workspace/bad-proc/proc/unexpected"

printf '%s\n' \
  "-Dpython3-reference-root=$before" \
  "-Dpython3-reference-after=$after" \
  "-Dpython3-reference-root-0644=$before_0644" \
  "-Dpython3-reference-after-0644=$after_0644" \
  "-Dpython3-reference-root-py3compile=$after-py3compile-before" \
  "-Dpython3-reference-after-py3compile=$after-py3compile-after" \
  "-Dpython3-reference-bad-html=$workspace/bad-html" \
  "-Dpython3-reference-bad-link=$workspace/bad-link" \
  "-Dpython3-reference-bad-shadow=$workspace/bad-shadow" \
  "-Dpython3-reference-bad-null=$workspace/bad-null" \
  "-Dpython3-reference-bad-null-0640=$workspace/bad-null-0640" \
  "-Dpython3-reference-bad-root=$workspace/bad-root" \
  "-Dpython3-reference-bad-script=$workspace/bad-script" \
  "-Dpython3-reference-bad-proc=$workspace/bad-proc" \
  "-Dpython3-reference-bad-py3compile-hash=$after-py3compile-bad-hash" \
  "-Dpython3-reference-bad-py3compile-mode=$after-py3compile-bad-mode" \
  "-Dpython3-reference-bad-minimal-postinst=$after-py3compile-bad-postinst" \
  "-Dpython3-reference-bad-minimal-compiler=$after-py3compile-bad-compiler" \
  "-Dpython3-reference-inputs-proof=$evidence/inputs-proof.txt" \
  "-Dpython3-reference-alternatives-proof=$evidence/alternatives-proof.txt" \
  >"$evidence/python3-reference.args"
read -r bytes _ < <(du -sb "$workspace")
(( bytes <= 16 * 1024 * 1024 * 1024 ))
echo "Python source and all 18 root coordinates staged; Zig verification has not executed"
