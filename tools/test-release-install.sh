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
test -f "$gnu_prefix/share/debz/digest-cutover-policy.json"
test -f "$gnu_prefix/share/debz/legacy-cutover-policy.json"
cmp "$gnu_prefix/share/debz/digest-cutover-policy.json" \
  "$gnu_prefix/share/doc/debz/digest-cutover-policy.json"
cmp "$gnu_prefix/share/debz/legacy-cutover-policy.json" \
  "$gnu_prefix/share/doc/debz/legacy-cutover-policy.json"
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
test -f "$release_prefix/share/debz/digest-cutover-policy.json"
test -f "$release_prefix/share/debz/legacy-cutover-policy.json"
cmp "$release_prefix/share/debz/digest-cutover-policy.json" \
  "$release_prefix/share/doc/debz/digest-cutover-policy.json"
cmp "$release_prefix/share/debz/legacy-cutover-policy.json" \
  "$release_prefix/share/doc/debz/legacy-cutover-policy.json"
source_schemas=$(cd schema && ls -- *.json | sort)
for destination in "$release_prefix/share/debz" "$release_prefix/share/doc/debz"
do
  installed_schemas=$(cd "$destination/schema" && ls -- *.json | sort)
  if [ "$source_schemas" != "$installed_schemas" ]
  then
    echo "installed schemas differ from schema/*.json: $destination" >&2
    exit 1
  fi
  for schema in schema/*.json
  do
    test -f "$schema"
    test ! -L "$schema"
    test -f "$destination/$schema"
    test ! -L "$destination/$schema"
    cmp "$schema" "$destination/$schema"
  done
done
for prefix in "$gnu_prefix" "$release_prefix"
do
  for schema in \
    apt-system-cli-diagnostic-v1.json \
    apt-system-execution-completion-v1.json \
    apt-system-operation-state-v1.json \
    apt-system-request-v1.json \
    apt-system-result-v1.json \
    apt-system-result-v2.json \
    apt-system-result-v3.json \
    system-profile-v1.json \
    system-profile-v2.json
  do
    cmp "schema/$schema" "$prefix/share/debz/schema/$schema"
    cmp "schema/$schema" "$prefix/share/doc/debz/schema/$schema"
  done
done
test -f "$release_prefix/share/doc/debz/doc/target-apt-config.md"
test -f "$release_prefix/share/doc/debz/doc/repository-management.md"
test -f "$release_prefix/share/doc/debz/doc/root-filesystem.md"
test -f "$release_prefix/share/doc/debz/doc/maintainer-script-runner.md"
test -f "$release_prefix/share/doc/debz/doc/apt-system-facade.md"
# Every tracked document must ship: a linked document that is never installed
# would leave the released documentation set silently incomplete.
for document in doc/*.md
do
  test -f "$release_prefix/share/doc/debz/$document"
done
installed_documents=$(cd "$release_prefix/share/doc/debz/doc" && ls -- *.md | sort)
tracked_documents=$(cd doc && ls -- *.md | sort)
if [ "$installed_documents" != "$tracked_documents" ]
then
  echo "installed documents differ from doc/*.md" >&2
  exit 1
fi
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
