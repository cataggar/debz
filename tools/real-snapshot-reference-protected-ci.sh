#!/usr/bin/env bash
# Shared root-only staging/trust bootstrap and small protected proof (#268).
#
# The workflow bootstrap clones the reviewed commit, verified by SHA, from a
# root-owned bare copy into TREE/checkout, where TREE is a new root-owned
# mode-0700 directory under /srv/debz-protected, and executes this script from
# that clone. It installs a minisign- and SHA256-pinned Zig, fetches Zig's
# package sources and tightens and records their modes without executing them,
# copies the Ubuntu archive keyring only after pinning it to a reviewed
# package-derived digest, builds debz, stages the pinned dpkg, runtime closure,
# archives and (amd64) signed profile postinsts, refuses fail-closed preflight
# negatives on new workspaces, and runs the protected proof on a new empty
# workspace. Bounded evidence is copied into TREE/upload; nothing outside TREE
# is written.
# --stage-native stages the same trusted inputs in a distinct native-ci tree,
# without running or reusing the small proof. --check-keyring verifies protected
# member bytes against the same reviewed constants for the acceptance consumer.
set -euo pipefail
umask 022
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root
unset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH
unset ZIG_LIB_DIR

readonly zig_version=0.16.0
readonly zig_release=https://github.com/cataggar/zig/releases/download/v0.16.0
readonly zig_public_key=RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
# Pin source: ubuntu-keyring 2023.11.28.1build1 (Architecture: all) from
# https://snapshot.ubuntu.com/ubuntu/20261001T000000Z, suite resolute:
# pool/main/u/ubuntu-keyring/ubuntu-keyring_2023.11.28.1build1_all.deb
# (Size 11228, SHA512 80446b4521a3cc100d797a7ed03532f4358c028f1c0c110e00cfc6e1db3b2795e2f98f92a4077baea0cee3c82b292f9eeb20f7f1dc06ce28b6b46e661b1fad35).
# The pinned artifact is usr/share/keyrings/ubuntu-archive-keyring.gpg extracted
# from that deb, deliberately committed as a reviewed trust root.
readonly archive_keyring_deb_url=https://snapshot.ubuntu.com/ubuntu/20261001T000000Z/pool/main/u/ubuntu-keyring/ubuntu-keyring_2023.11.28.1build1_all.deb
readonly archive_keyring_deb_sha512=80446b4521a3cc100d797a7ed03532f4358c028f1c0c110e00cfc6e1db3b2795e2f98f92a4077baea0cee3c82b292f9eeb20f7f1dc06ce28b6b46e661b1fad35
readonly archive_keyring_deb_size=11228
readonly archive_keyring_member=./usr/share/keyrings/ubuntu-archive-keyring.gpg
readonly archive_keyring_sha256=80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31
readonly archive_keyring_size=3607

if [[ ${1:-} == --check-keyring && $# == 2 ]]; then
  python3 -I - "$(dirname -- "${BASH_SOURCE[0]}")" "$2" \
    "$archive_keyring_size" "$archive_keyring_sha256" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import verify_keyring
print(verify_keyring(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4]))
PY
  exit "$?"
fi

mode=proof
if [[ ${1:-} == --stage-native ]]; then
  mode=native-staging
  shift
fi
readonly mode
[[ $# == 3 && $(id -u) == 0 && $(id -g) == 0 ]] || {
  echo "usage (as root, from the protected clone): $0 TREE ARCHITECTURE COMMIT" >&2
  exit 2
}
tree=$1 architecture=$2 commit=$3
prefix=ci
[[ $mode == proof ]] || prefix=native-ci
[[ $tree =~ ^/srv/debz-protected/$prefix-[0-9]+-[0-9]+-(amd64|arm64)$ && ${BASH_REMATCH[1]} == "$architecture" &&
  $commit =~ ^[0-9a-f]{40}$ ]] || {
  echo "the protected tree, architecture and commit must be the workflow's named values" >&2
  exit 2
}
readonly tree architecture commit
readonly checkout=$tree/checkout
[[ $(realpath -- "${BASH_SOURCE[0]}") == "$checkout/tools/real-snapshot-reference-protected-ci.sh" ]] || {
  echo "run the protected CI script from the root-owned clone in its tree" >&2
  exit 2
}
case "$architecture/$(uname -m)/$(dpkg --print-architecture)" in
  amd64/x86_64/amd64)
    zig_name=zig-x86_64-linux-$zig_version
    zig_sha256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
    zig_size=55478392
    other_architecture=arm64
    ;;
  arm64/aarch64/arm64)
    zig_name=zig-aarch64-linux-$zig_version
    zig_sha256=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17
    zig_size=51211944
    other_architecture=amd64
    ;;
  *)
    echo "runner architecture differs from the requested $architecture" >&2
    exit 2
    ;;
esac

evidence=$tree/evidence
upload=$tree/upload
install -d -o root -g root -m 0700 "$evidence" "$upload"
codes=$evidence/exit-codes.tsv
: >"$codes"
cd "$checkout"

# Copy bounded evidence into TREE/upload on every exit; the unprivileged
# workflow step only reads it back through `sudo tar`.
collect() {
  local status=$?
  set +e
  local workspace=$checkout/.real-snapshot/$architecture
  install -d -o root -g root -m 0755 "$upload/staging" "$upload/proof" "$upload/negatives" "$upload/python3"
  find "$evidence" -maxdepth 1 -type f -size -16777217c -exec install -m 0644 -t "$upload" {} +
  if [[ -d $workspace/evidence ]]; then
    find "$workspace/evidence" -maxdepth 1 -type f -size -16777217c -exec install -m 0644 -t "$upload/staging" {} +
  fi
  if [[ -f $workspace/reference-protected.args && ! -L $workspace/reference-protected.args ]]; then
    install -m 0644 "$workspace/reference-protected.args" "$upload/staging/"
  fi
  if [[ -d $workspace/proof ]]; then
    find "$workspace/proof" -maxdepth 1 -type f \( -name '*.json' -o -name '*.stdout' -o -name '*.stderr' \) \
      -size -16777217c -exec install -m 0644 -t "$upload/proof" {} +
  fi
  if [[ -d $checkout/.real-snapshot/python3-amd64/evidence ]]; then
    find "$checkout/.real-snapshot/python3-amd64/evidence" -maxdepth 1 -type f \
      -size -16777217c -exec install -m 0644 -t "$upload/python3" {} +
  fi
  if [[ -d $checkout/.real-snapshot/less-arm64/evidence &&
        ! -L $checkout/.real-snapshot/less-arm64/evidence ]]; then
    install -d -o root -g root -m 0755 "$upload/arm64-less"
    find "$checkout/.real-snapshot/less-arm64/evidence" -maxdepth 1 -type f \
      -size -16777217c -exec install -m 0644 -t "$upload/arm64-less" {} +
  fi
  for source in snapshot/evidence prestate-build/evidence; do
    local python3_evidence=$checkout/.real-snapshot/python3-amd64/$source
    [[ -d $python3_evidence && ! -L $python3_evidence ]] || continue
    install -d -o root -g root -m 0755 "$upload/python3/$source"
    find "$python3_evidence" -maxdepth 1 -type f -size -16777217c \
      -exec install -m 0644 -t "$upload/python3/$source" {} +
  done
  for directory in "$workspace"/negative-*; do
    [[ -d $directory && ! -L $directory ]] || continue
    find "$directory" -maxdepth 1 -printf '%M %u:%g %s %P\n' >"$upload/negatives/${directory##*/}.listing"
  done
  printf 'status=%s\nmode=%s\ncommit=%s\narchitecture=%s\nfinished=%s\n' \
    "$status" "$mode" "$commit" "$architecture" "$(date -u +%FT%TZ)" >"$upload/result.txt"
  local bytes
  bytes=$(du -sb "$upload" | cut -f1)
  if ((bytes > 256 * 1024 * 1024)); then
    echo "bounded evidence exceeds 256 MiB" >&2
    find "$upload" -mindepth 1 -delete
    printf 'status=%s\nevidence=oversized\n' "$status" >"$upload/result.txt"
    status=1
  fi
  (cd "$upload" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 -r sha256sum >SHA256SUMS)
  exit "$status"
}
trap collect EXIT

# step NAME EXPECTED(0|refused) PATTERN COMMAND... records the status and output;
# a refusal must fail and print PATTERN.
step() {
  local name=$1 expected=$2 pattern=$3 status=0
  shift 3
  echo "== $name: $*"
  "$@" >"$evidence/$name.log" 2>&1 || status=$?
  printf '%s\t%s\t%s\n' "$name" "$status" "$expected" >>"$codes"
  tail -n 12 "$evidence/$name.log"
  local accepted=true
  case "$expected" in
    0) [[ $status == 0 ]] || accepted=false ;;
    refused) [[ $status != 0 && -n $pattern ]] || accepted=false ;;
    *) accepted=false ;;
  esac
  if [[ -n $pattern ]] && ! grep -qF -- "$pattern" "$evidence/$name.log"; then
    accepted=false
  fi
  if [[ $accepted != true ]]; then
    echo "$name: exit $status, expected $expected${pattern:+ with '$pattern'}" >&2
    exit 1
  fi
}

stage_verified_archive_keyring() {
  local trust_dir package target
  trust_dir=$tree/trust
  package=$trust_dir/ubuntu-keyring.deb
  target=$trust_dir/ubuntu-archive-keyring.gpg
  printf 'path\trole\tuid:gid:mode:size\talgorithm\tdigest\n' >"$evidence/archive-keyring-path.tsv"
  [[ ! -e "$trust_dir" && ! -L "$trust_dir" ]] || {
    echo "trusted keyring staging directory must be new: $trust_dir" >&2
    exit 2
  }
  install -d -o root -g root -m 0700 "$trust_dir"
  [[ -d "$trust_dir" && ! -L "$trust_dir" ]]
  [[ ! -e "$target" && ! -L "$target" ]] || {
    echo "trusted keyring copy must be new: $target" >&2
    exit 2
  }
  [[ ! -e "$package" && ! -L "$package" ]] || {
    echo "trusted keyring package must be new: $package" >&2
    exit 2
  }
  python3 -I - "$archive_keyring_deb_url" "$package" "$archive_keyring_deb_sha512" \
    "$archive_keyring_deb_size" "$archive_keyring_member" "$target" \
    "$archive_keyring_sha256" "$archive_keyring_size" \
    "$evidence/archive-keyring-path.tsv" <<'PY'
import ctypes
import ctypes.util
import hashlib
import io
import os
import stat
import sys
import tarfile
import urllib.request

(
    deb_url,
    deb_path,
    expected_deb_sha512,
    expected_deb_size_text,
    member,
    target,
    expected_keyring_sha256,
    expected_keyring_size_text,
    evidence_path,
) = sys.argv[1:]
expected_deb_size = int(expected_deb_size_text)
expected_keyring_size = int(expected_keyring_size_text)
decompressed_limit = 1024 * 1024


def metadata(entry: os.stat_result) -> str:
    return f"{entry.st_uid}:{entry.st_gid}:{stat.S_IMODE(entry.st_mode):03o}:{entry.st_size}"


def append_evidence(role: str, path: str, entry: os.stat_result, algorithm: str, digest: str) -> None:
    with open(evidence_path, "a", encoding="utf-8") as evidence:
        evidence.write(f"{path}\t{role}\t{metadata(entry)}\t{algorithm}\t{digest}\n")


def require_root_owned_file(role: str, path: str, entry: os.stat_result, mode: int) -> None:
    if (
        (entry.st_uid, entry.st_gid) != (0, 0)
        or not stat.S_ISREG(entry.st_mode)
        or stat.S_IMODE(entry.st_mode) != mode
    ):
        append_evidence(role, path, entry, "-", "-")
        raise SystemExit(
            f"Ubuntu archive keyring artifact is not a protected regular file: {path} "
            f"(uid:gid:mode:size={metadata(entry)}; expected 0:0:{mode:03o})"
        )


def unlink_then_fail(path: str, message: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    raise SystemExit(message)


def write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while staging Ubuntu archive keyring")
        view = view[written:]


def read_verified_deb() -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(deb_path, flags)
    digest = hashlib.sha512()
    parts: list[bytes] = []
    size = 0
    try:
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            size += len(block)
            digest.update(block)
            parts.append(block)
    finally:
        os.close(fd)
    actual = digest.hexdigest()
    if size != expected_deb_size or actual != expected_deb_sha512:
        unlink_then_fail(
            deb_path,
            "Ubuntu archive keyring package pin mismatch after reopen: "
            f"expected size={expected_deb_size} sha512={expected_deb_sha512}; "
            f"read size={size} sha512={actual}",
        )
    return b"".join(parts)


def parse_ar_member(archive: bytes, expected_name: str) -> bytes:
    if not archive.startswith(b"!<arch>\n"):
        raise SystemExit("Ubuntu archive keyring package is not an ar archive")
    offset = 8
    found: bytes | None = None
    while offset < len(archive):
        if offset + 60 > len(archive):
            raise SystemExit("truncated ar member header in Ubuntu archive keyring package")
        header = archive[offset : offset + 60]
        offset += 60
        if header[58:60] != b"`\n":
            raise SystemExit("invalid ar member header in Ubuntu archive keyring package")
        raw_name = header[:16].decode("ascii", "strict").strip()
        if raw_name.startswith("//") or raw_name.startswith("/"):
            raise SystemExit(f"unsupported ar member name in Ubuntu archive keyring package: {raw_name}")
        name = raw_name.rstrip("/")
        try:
            size = int(header[48:58].decode("ascii", "strict").strip())
        except ValueError as error:
            raise SystemExit("invalid ar member size in Ubuntu archive keyring package") from error
        if size < 0 or offset + size > len(archive):
            raise SystemExit("truncated ar member payload in Ubuntu archive keyring package")
        payload = archive[offset : offset + size]
        offset += size + (size % 2)
        if name == expected_name:
            if found is not None:
                raise SystemExit(f"duplicate ar member in Ubuntu archive keyring package: {expected_name}")
            found = payload
    if found is None:
        raise SystemExit(f"missing ar member in Ubuntu archive keyring package: {expected_name}")
    return found


def zstd_decompress(payload: bytes) -> bytes:
    library_name = ctypes.util.find_library("zstd") or "libzstd.so.1"
    library = ctypes.CDLL(library_name)
    library.ZSTD_getFrameContentSize.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    library.ZSTD_getFrameContentSize.restype = ctypes.c_ulonglong
    library.ZSTD_decompress.argtypes = (
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    )
    library.ZSTD_decompress.restype = ctypes.c_size_t
    library.ZSTD_isError.argtypes = (ctypes.c_size_t,)
    library.ZSTD_isError.restype = ctypes.c_uint
    library.ZSTD_getErrorName.argtypes = (ctypes.c_size_t,)
    library.ZSTD_getErrorName.restype = ctypes.c_char_p
    source = ctypes.create_string_buffer(payload)
    frame_size = library.ZSTD_getFrameContentSize(source, len(payload))
    content_size_unknown = (1 << 64) - 1
    content_size_error = (1 << 64) - 2
    if frame_size == content_size_error:
        raise SystemExit("invalid zstd frame in Ubuntu archive keyring package")
    output_limit = decompressed_limit if frame_size == content_size_unknown else frame_size
    if output_limit > decompressed_limit:
        raise SystemExit(
            f"Ubuntu archive keyring data archive exceeds limit: {output_limit} > {decompressed_limit}"
        )
    output = ctypes.create_string_buffer(output_limit)
    result = library.ZSTD_decompress(output, output_limit, source, len(payload))
    if library.ZSTD_isError(result):
        error = library.ZSTD_getErrorName(result).decode("utf-8", "replace")
        raise SystemExit(f"failed to decompress Ubuntu archive keyring data archive: {error}")
    return output.raw[:result]


def extract_tar_member(archive: bytes, expected_name: str) -> bytes:
    if expected_name.startswith("/") or "/../" in f"/{expected_name}/":
        raise SystemExit(f"unsafe expected tar member name: {expected_name}")
    result: bytes | None = None
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member_info in tar:
            if member_info.name != expected_name:
                continue
            if result is not None:
                raise SystemExit(f"duplicate tar member in Ubuntu archive keyring package: {expected_name}")
            if not member_info.isfile() or member_info.issym() or member_info.islnk():
                raise SystemExit(f"Ubuntu archive keyring tar member is not a regular file: {expected_name}")
            if member_info.size != expected_keyring_size:
                raise SystemExit(
                    f"Ubuntu archive keyring tar member size mismatch: "
                    f"expected {expected_keyring_size}; archive has {member_info.size}"
                )
            extracted = tar.extractfile(member_info)
            if extracted is None:
                raise SystemExit(f"failed to read Ubuntu archive keyring tar member: {expected_name}")
            result = extracted.read()
            if len(result) != member_info.size:
                raise SystemExit(f"short read for Ubuntu archive keyring tar member: {expected_name}")
    if result is None:
        raise SystemExit(f"missing Ubuntu archive keyring tar member: {expected_name}")
    return result


request = urllib.request.Request(deb_url, headers={"User-Agent": "debz-protected-reference/1"})
download_sha512 = hashlib.sha512()
download_size = 0
try:
    package_fd = os.open(deb_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.fchown(package_fd, 0, 0)
        with urllib.request.urlopen(request, timeout=300) as response:
            while True:
                block = response.read(1 << 20)
                if not block:
                    break
                download_size += len(block)
                download_sha512.update(block)
                write_all(package_fd, block)
        os.fchmod(package_fd, 0o600)
    finally:
        os.close(package_fd)
except BaseException:
    try:
        os.unlink(deb_path)
    except FileNotFoundError:
        pass
    raise
package_stat = os.stat(deb_path, follow_symlinks=False)
actual_deb_sha512 = download_sha512.hexdigest()
append_evidence("downloaded-package", deb_path, package_stat, "sha512", actual_deb_sha512)
if download_size != expected_deb_size or package_stat.st_size != expected_deb_size or actual_deb_sha512 != expected_deb_sha512:
    unlink_then_fail(
        deb_path,
        "Ubuntu archive keyring package pin mismatch: "
        f"expected size={expected_deb_size} sha512={expected_deb_sha512}; "
        f"downloaded size={download_size} file_size={package_stat.st_size} sha512={actual_deb_sha512}",
    )
require_root_owned_file("downloaded-package", deb_path, package_stat, 0o600)

deb_bytes = read_verified_deb()
debian_binary = parse_ar_member(deb_bytes, "debian-binary")
if debian_binary != b"2.0\n":
    unlink_then_fail(deb_path, "Ubuntu archive keyring package has unexpected debian-binary member")
data_archive = parse_ar_member(deb_bytes, "data.tar.zst")
data_tar = zstd_decompress(data_archive)
keyring = extract_tar_member(data_tar, member)
actual_keyring_sha256 = hashlib.sha256(keyring).hexdigest()
if len(keyring) != expected_keyring_size or actual_keyring_sha256 != expected_keyring_sha256:
    unlink_then_fail(
        deb_path,
        "Ubuntu archive keyring member pin mismatch: "
        f"expected size={expected_keyring_size} sha256={expected_keyring_sha256}; "
        f"extracted size={len(keyring)} sha256={actual_keyring_sha256}",
    )

try:
    target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
    try:
        os.fchown(target_fd, 0, 0)
        write_all(target_fd, keyring)
        os.fchmod(target_fd, 0o644)
    finally:
        os.close(target_fd)
    target_stat = os.stat(target, follow_symlinks=False)
    append_evidence("staged-keyring", target, target_stat, "sha256", actual_keyring_sha256)
    require_root_owned_file("staged-keyring", target, target_stat, 0o644)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    verify_fd = os.open(target, flags)
    try:
        target_bytes = b""
        while True:
            block = os.read(verify_fd, 1 << 20)
            if not block:
                break
            target_bytes += block
    finally:
        os.close(verify_fd)
    target_sha256 = hashlib.sha256(target_bytes).hexdigest()
    if (
        len(target_bytes) != expected_keyring_size
        or target_stat.st_size != expected_keyring_size
        or target_sha256 != expected_keyring_sha256
    ):
        unlink_then_fail(
            target,
            "Ubuntu archive keyring staged-copy pin mismatch: "
            f"expected size={expected_keyring_size} sha256={expected_keyring_sha256}; "
            f"read size={len(target_bytes)} target_size={target_stat.st_size} sha256={target_sha256}",
        )
except BaseException:
    try:
        os.unlink(target)
    except FileNotFoundError:
        pass
    finally:
        raise
print(
    f"verified Ubuntu archive keyring from pinned package: {target} "
    f"package_size={download_size} package_sha512={actual_deb_sha512} "
    f"keyring_size={len(keyring)} keyring_sha256={actual_keyring_sha256}"
)
PY
  staged_archive_keyring=$target
}

echo "protected reference CI: commit=$commit architecture=$architecture kernel=$(uname -r) started=$(date -u +%FT%TZ)"
test "$(git -C "$checkout" rev-parse HEAD)" = "$commit"
test -z "$(git -C "$checkout" status --porcelain --ignored)"
staged_archive_keyring=
stage_verified_archive_keyring
readonly staged_archive_keyring
step tree-initial 0 "" python3 -I tools/real-snapshot-reference-tree-check.py tree "$tree"

# Zig from the pinned release, accepted only after its pinned size, SHA256 and
# both minisign signatures verify against the pinned key.
downloads=$tree/downloads
install -d -o root -g root -m 0700 "$downloads"
step zig-download 0 "" python3 -I -c '
import sys, urllib.request
for name in (sys.argv[2], sys.argv[2] + ".minisig"):
    url = sys.argv[1] + "/" + name
    with urllib.request.urlopen(url, timeout=300) as response, open(sys.argv[3] + "/" + name, "xb") as out:
        while block := response.read(1 << 20):
            out.write(block)
    print(url)
' "$zig_release" "$zig_name.tar.xz" "$downloads"
step zig-verify 0 "" python3 -I tools/verify-minisign.py --public-key "$zig_public_key" \
  --artifact "$downloads/$zig_name.tar.xz" --signature "$downloads/$zig_name.tar.xz.minisig" \
  --name "$zig_name.tar.xz" --sha256 "$zig_sha256" --size "$zig_size"
step zig-extract 0 "" python3 -I -c '
import sys, tarfile
with tarfile.open(sys.argv[1]) as archive:
    archive.extractall(sys.argv[2], filter="data")
' "$downloads/$zig_name.tar.xz" "$tree/zig"
zig=$tree/zig/$zig_name/zig
step zig-library-check 0 "" python3 -I - "$checkout/tools" "$zig" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import toolchain
print(toolchain(Path(sys.argv[2])))
PY
zenv=(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C
  "ZIG_GLOBAL_CACHE_DIR=$tree/zig-global" "ZIG_LOCAL_CACHE_DIR=$checkout/.zig-cache")
step zig-version 0 "$zig_version" "${zenv[@]}" "$zig" version

# Zig 0.16 writes fetched package files with their archive modes, including
# group/world-writable 0777 scripts. Tighten them, then verify and record every
# entry; the scripts are compiled-around sources and are never executed.
[[ ! -e zig-pkg && ! -L zig-pkg ]]
step zig-fetch 0 "" "${zenv[@]}" "$zig" build --fetch
[[ -d zig-pkg && ! -L zig-pkg && -d $tree/zig-global && ! -L $tree/zig-global ]]
find zig-pkg "$tree/zig-global" -xdev -perm /0022 ! -type l -printf '%M %u:%g %p\n' \
  >"$evidence/zig-pkg-writable-before.txt"
chmod -R go-w zig-pkg "$tree/zig-global"
step zig-pkg-verify 0 "" python3 -I tools/real-snapshot-reference-tree-check.py packages \
  "$checkout/zig-pkg" "$evidence/zig-pkg-manifest.txt"
step debz-build 0 "" "${zenv[@]}" "$zig" build -Doptimize=ReleaseSafe -j2
chmod -R go-w "$tree/zig-global" "$checkout/.zig-cache" "$checkout/zig-out"
step tree-built 0 "" python3 -I tools/real-snapshot-reference-tree-check.py tree "$tree"

stage_native_inputs() {
  step comparator-build 0 "" "${zenv[@]}" "$zig" build test-real-snapshot-comparator -Doptimize=ReleaseSafe -j2
  python3 -I - "$checkout/tools" "$architecture" "$tree/reference-dpkg" <<'PY'
import importlib.util
from pathlib import Path
import subprocess
import sys

spec = importlib.util.spec_from_file_location("prepare_native_dpkg", Path(sys.argv[1]) / "prepare-native-dpkg.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
architecture, prefix = sys.argv[2], Path(sys.argv[3])
url, content = module.download_archive(architecture)
archive = prefix.parent / "reference-dpkg.deb"
archive.write_bytes(content)
module.verify_file(archive, module.PINS[architecture]["archive"])
module.verify_archive_metadata(archive, architecture)
subprocess.run(["dpkg-deb", "--extract", str(archive), str(prefix)], check=True, timeout=60)
module.verify_extracted_bindings(prefix, architecture)
module.write_receipt(architecture, url, content, prefix)
module.verify_receipt(prefix / module.RECEIPT, architecture)
PY
  install -d -o root -g root -m 0700 "$checkout/.real-snapshot"
  printf '%s\n' "$zig" "$tree/reference-dpkg/usr/bin/dpkg" "$staged_archive_keyring" \
    >"$tree/native-inputs.args"
  step native-tree-staged 0 "" python3 -I tools/real-snapshot-reference-tree-check.py tree "$tree"
}
if [[ $mode == native-staging ]]; then
  stage_native_inputs
  echo "protected native inputs staged; native wrapper and full reference have not executed"
  exit "$?"
fi

workspace=$checkout/.real-snapshot/$architecture
install -d -o root -g root -m 0700 .real-snapshot
step stage 0 "" "${zenv[@]}" "DEBZ_REAL_SNAPSHOT_KEYRING=$staged_archive_keyring" \
  tools/real-snapshot-reference-protected-stage.sh \
  "$zig" "$checkout/zig-out/bin/debz" ".real-snapshot/$architecture"
arguments=$workspace/reference-protected.args
mapfile -t proof_arguments <"$arguments"
[[ ${#proof_arguments[@]} == 15 ]]
step tree-staged 0 "" python3 -I tools/real-snapshot-reference-tree-check.py tree "$tree"

# Preflight negatives: each must refuse before any reference launch and leave
# its new workspace empty.
negative() { # NAME PATTERN sed-expression...
  local name=$1 pattern=$2 ws=$workspace/negative-$1
  shift 2
  install -d -o root -g root -m 0700 "$ws"
  local edits=(-e "s|^-Dreference-protected-workspace=.*|-Dreference-protected-workspace=$ws|")
  for edit in "$@"; do edits+=(-e "$edit"); done
  sed "${edits[@]}" "$arguments" >"$evidence/negative-$name.args"
  mapfile -t negative_arguments <"$evidence/negative-$name.args"
  step "negative-$name" refused "$pattern" "${zenv[@]}" "$zig" build test-real-snapshot-reference-protected \
    "${negative_arguments[@]}" -Doptimize=ReleaseSafe -j2
  [[ -z $(find "$ws" -mindepth 1 -print -quit) ]] || {
    echo "negative-$name launched before refusing" >&2
    exit 1
  }
}
negatives=$tree/negative-inputs
install -d -o root -g root -m 0755 "$negatives"
mutable=$negatives/mutable-ancestor
[[ ! -e "$mutable" && ! -L "$mutable" ]]
install -d -o root -g root -m 0777 "$mutable"
install -o root -g root -m 0500 "$workspace/launcher" "$mutable/launcher"
negative mutable-ancestor "writable or non-root ancestor" \
  "s|^-Dreference-protected-launcher=.*|-Dreference-protected-launcher=$mutable/launcher|"
rm -rf --one-file-system -- "$mutable"
install -d -o root -g root -m 0755 "$negatives" "$negatives/profiles"
install -o root -g root -m 0755 /usr/bin/dpkg "$negatives/dpkg"
negative swapped-dpkg "reference dpkg executable is not the pinned architecture artifact" \
  "s|^-Dreference-protected-dpkg=.*|-Dreference-protected-dpkg=$negatives/dpkg|"
escape_sha512=$(sed -n 's/^-Dreference-protected-escape-archive-sha512=//p' "$arguments")
negative swapped-archive "authenticated archive SHA512 differs" \
  "s|^-Dreference-protected-archive-sha512=.*|-Dreference-protected-archive-sha512=$escape_sha512|"
negative wrong-architecture "reference dpkg executable is not the pinned architecture artifact" \
  "s|^-Dreference-protected-architecture=.*|-Dreference-protected-architecture=$other_architecture|"
printf 'unsigned\n' >"$negatives/profiles/systemd.postinst"
negative unbound-profile-scripts "profile scripts" \
  "s|^-Dreference-protected-profile-scripts=.*|-Dreference-protected-profile-scripts=$negatives/profiles|"
install -d -o root -g root -m 0700 "$workspace/negative-reused-workspace"
install -o root -g root -m 0600 /dev/null "$workspace/negative-reused-workspace/previous-run"
sed "s|^-Dreference-protected-workspace=.*|-Dreference-protected-workspace=$workspace/negative-reused-workspace|" \
  "$arguments" >"$evidence/negative-reused-workspace.args"
mapfile -t negative_arguments <"$evidence/negative-reused-workspace.args"
step negative-reused-workspace refused "must be new and empty" "${zenv[@]}" "$zig" build \
  test-real-snapshot-reference-protected "${negative_arguments[@]}" -Doptimize=ReleaseSafe -j2
# A valid OpenPGP keyring for a different signer must fail the authenticated
# refresh before staging locks or downloads anything.
swapped_keyring_stage() {
  local status=0 refused=$checkout/.real-snapshot/negative-keyring/evidence
  env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \
    "DEBZ_REAL_SNAPSHOT_KEYRING=$checkout/src/fixtures/batch_workflow/keyring.gpg" \
    tools/real-snapshot-reference-protected-stage.sh "$zig" "$checkout/zig-out/bin/debz" \
    .real-snapshot/negative-keyring || status=$?
  cat "$refused/refresh.json" "$refused/refresh.stderr"
  return "$status"
}
step negative-swapped-keyring refused '"summary":"WrongSigningKey"' swapped_keyring_stage
[[ ! -e .real-snapshot/negative-keyring/evidence/runtime.lock.json &&
  ! -e .real-snapshot/negative-keyring/evidence/plan.json ]] || {
  echo "staging continued past the swapped keyring" >&2
  exit 1
}

if [[ $architecture == amd64 ]]; then
  python3_workspace=$checkout/.real-snapshot/python3-amd64
  step python3-stage 0 "all 18 root coordinates staged" timeout --signal=TERM --kill-after=60s 40m \
    "${zenv[@]}" "DEBZ_REAL_SNAPSHOT_KEYRING=$staged_archive_keyring" \
    bash tools/real-snapshot-python3-protected-stage.sh "$zig" "$checkout/zig-out/bin/debz" \
    "$workspace/dpkg/usr/bin/dpkg" "$python3_workspace"
  python3 -B -I - "$checkout/tools" "$python3_workspace/evidence/python3-reference.args" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from real_snapshot_reference_paths import protected
protected(Path(sys.argv[2]))
PY
  mapfile -t python3_arguments <"$python3_workspace/evidence/python3-reference.args"
  [[ ${#python3_arguments[@]} == 20 ]]
  step python3-guards 0 "" timeout --signal=TERM --kill-after=60s 10m \
    "${zenv[@]}" "$zig" build test-real-snapshot-python3-protected "${python3_arguments[@]}" \
    -Doptimize=ReleaseSafe -j2 --summary all
  grep -Fx "signed Python empty0600/0644 and amd64 20/96 input/output guards executed without skips" \
    "$python3_workspace/evidence/inputs-proof.txt"
  grep -Fx "signed Python alternatives records and selectors executed without skips" \
    "$python3_workspace/evidence/alternatives-proof.txt"
  find "$python3_workspace/evidence" -maxdepth 1 -type f -size -16777217c \
    -exec install -m 0644 -t "$evidence" {} +
  # Remove only the fresh replay workspace, not package-owned bytes or bad
  # inputs "repaired" to satisfy the final protected tool-tree check.
  if grep -F " $python3_workspace" /proc/self/mountinfo; then
    echo "mounts remain beneath the Python replay workspace" >&2
    exit 1
  fi
  rm -rf --one-file-system -- "$python3_workspace"
elif [[ $architecture == arm64 ]]; then
  less_workspace=$checkout/.real-snapshot/less-arm64
  step arm64-less-stage 0 "eight replay roots staged" timeout --signal=TERM --kill-after=60s 30m \
    "${zenv[@]}" "DEBZ_REAL_SNAPSHOT_KEYRING=$staged_archive_keyring" \
    bash tools/real-snapshot-less-protected-stage.sh "$zig" "$checkout/zig-out/bin/debz" "$less_workspace"
  step arm64-less-guards 0 "" timeout --signal=TERM --kill-after=60s 10m \
    "${zenv[@]}" "$zig" build test-real-snapshot-arm64-less-protected \
    "-Darm64-less-reference-root=$less_workspace/source" \
    "-Darm64-less-reference-script-after=$less_workspace/script-after" \
    "-Darm64-less-reference-dpkg-after=$less_workspace/dpkg-after" \
    "-Darm64-less-reference-bad-script=$less_workspace/script-after-bad-script" \
    "-Darm64-less-reference-bad-mode=$less_workspace/script-after-bad-mode" \
    "-Darm64-less-reference-bad-tool=$less_workspace/script-after-bad-tool" \
    "-Darm64-less-reference-bad-alias=$less_workspace/script-after-bad-alias" \
    "-Darm64-less-reference-bad-prestate=$less_workspace/script-after-bad-prestate" \
    "-Darm64-less-reference-source-proof=$less_workspace/evidence/less-source-proof.txt" \
    "-Darm64-less-reference-replay-proof=$less_workspace/evidence/less-replay-proof.txt" \
    -Doptimize=ReleaseSafe -j2 --summary all
  grep -Fx "signed arm64 less source guard executed without skips" "$less_workspace/evidence/less-source-proof.txt"
  grep -Fx "signed arm64 less eight replay roots executed without skips" "$less_workspace/evidence/less-replay-proof.txt"
  find "$less_workspace/evidence" -maxdepth 1 -type f -size -16777217c \
    -exec install -m 0644 -t "$evidence" {} +
  if grep -F " $less_workspace" /proc/self/mountinfo; then
    echo "mounts remain beneath the ARM less replay workspace" >&2
    exit 1
  fi
  rm -rf --one-file-system -- "$less_workspace"
fi

# The protected proof on the staged new empty workspace, bounded by a timeout
# that kills the proof's process group.
step proof 0 "executed without skips" timeout --signal=TERM --kill-after=60s 45m \
  "${zenv[@]}" "$zig" build test-real-snapshot-reference-protected "${proof_arguments[@]}" \
  -Doptimize=ReleaseSafe -j2 --summary all
grep -F "executed without skips" "$evidence/proof.log" >"$evidence/proof-summary.txt"
if grep -F " $tree" /proc/self/mountinfo >"$evidence/mounts-after.txt"; then
  echo "mounts remain beneath the protected tree" >&2
  exit 1
fi
step tree-final 0 "" python3 -I tools/real-snapshot-reference-tree-check.py tree "$tree"
echo "protected reference CI: proof and preflight refusals passed for $architecture at $commit"
