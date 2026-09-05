#!/bin/sh
set -eu

zig=$1
version=$2
root=$PWD/.zig-cache/test-release-install
gnu_prefix=$root/gnu
release_prefix=$root/release

rm -rf "$root"
mkdir -p "$root"

"$zig" build \
  --cache-dir "$root/gnu-cache" \
  -Dtarget=x86_64-linux-gnu \
  -Doptimize=ReleaseSafe \
  -Dversion="$version" \
  install --prefix "$gnu_prefix"

test -x "$gnu_prefix/bin/debz"
test ! -e "$gnu_prefix/share/debz/runtime-dependencies.json"
if "$zig" build \
  --cache-dir "$root/gnu-cache" \
  -Dtarget=x86_64-linux-gnu \
  -Doptimize=ReleaseSafe \
  -Dversion="$version" \
  release-install --prefix "$root/invalid-gnu-release" >/dev/null 2>&1
then
  echo "GNU release-install unexpectedly succeeded" >&2
  exit 1
fi

"$zig" build \
  --cache-dir "$root/release-cache" \
  -Dtarget=x86_64-linux-musl \
  -Doptimize=ReleaseSafe \
  -Dversion="$version" \
  release-install --prefix "$release_prefix"

test -x "$release_prefix/bin/debz"
test -f "$release_prefix/share/debz/runtime-dependencies.json"
for schema in \
  apt-config-snapshot-v1.json \
  command-result-v1.json \
  exact-closure-lock-v1.json \
  exact-closure-lock-v2.json \
  package-cache-error-v1.json \
  package-cache-fingerprint-v1.json \
  package-cache-result-v1.json \
  repository-add-state-v1.json \
  repository-operation-result-v1.json \
  transaction-plan-v1.json \
  transaction-plan-v2.json \
  transaction-plan-v3.json \
  transaction-result-v1.json \
  transaction-result-v2.json
do
  test -f "$release_prefix/share/debz/schema/$schema"
  test -f "$release_prefix/share/doc/debz/schema/$schema"
done
test -f "$release_prefix/share/doc/debz/doc/target-apt-config.md"
test -f "$release_prefix/share/doc/debz/doc/repository-management.md"
python3 - "$release_prefix/share/debz/runtime-dependencies.json" <<'PY'
import json
import pathlib
import sys

runtime = json.loads(pathlib.Path(sys.argv[1]).read_text())
linux = runtime["linux_release_runtime"]
assert linux["fully_static"] is True
assert linux["libc"]["implementation"] == "musl"
assert linux["libc"]["linkage"] == "static"
assert {item["name"] for item in linux["included_libraries"]} == {
    "liblzma",
    "libsolv",
    "libzstd",
    "musl",
}
PY
