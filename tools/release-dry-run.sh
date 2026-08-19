#!/bin/sh
set -eu

version=${1:-0.1.0}
platform=${2:?platform is required}
output=${3:-.zig-cache/release-dry-run}
output_repeat="$output-repeat"

rm -rf "$output" "$output_repeat"
mkdir -p "$output" "$output_repeat"
rm -rf .zig-cache/release-install
zig build -Doptimize=ReleaseSafe -Dversion="$version" release-install --prefix "$PWD/.zig-cache/release-install"
tools/release.py audit-runtime .zig-cache/release-install/bin/debz
test "$(.zig-cache/release-install/bin/debz --version)" = "$version"
tools/release.py package-binary "$version" "$platform" .zig-cache/release-install "$output"
tools/release.py package-binary "$version" "$platform" .zig-cache/release-install "$output_repeat"
cmp "$output/debz-$version-$platform.tar.gz" "$output-repeat/debz-$version-$platform.tar.gz"
if [ "$platform" = linux-x64 ]; then
    tools/release.py package-source "$version" "$output"
    tools/release.py package-source "$version" "$output-repeat"
    cmp "$output/debz-$version-source.tar.gz" "$output-repeat/debz-$version-source.tar.gz"
fi
tools/release.py verify-assets "$version" "$output"
