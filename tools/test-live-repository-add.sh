#!/bin/sh
# Manual evidence only: `zig build test-live-repository-add
# -Dlive-repository-tests=true`. It downloads the reviewed upstream
# packages-microsoft-prod descriptor and refreshes the live Microsoft Noble
# repository, so it needs network access, passwordless sudo and a
# dpkg-based host. CI never runs it.
set -eu
umask 022

debz=$1
url=https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb
sha256=c13f01ac7c3001b51a9281d40dde666db5e037e05512840c319832f7852bfec4
workspace="$PWD/.zig-cache/live-repository-add"
root="$workspace/root"
evidence="$PWD/.zig-cache/live-repository-add-evidence"

case "$workspace" in
  "$PWD"/.zig-cache/live-repository-add) ;;
  *) echo "refusing unsafe live repository workspace" >&2; exit 2 ;;
esac
sudo -n true || { echo "test-live-repository-add needs passwordless sudo" >&2; exit 2; }
test ! -L "$workspace"
sudo -n rm -rf "$workspace"
rm -rf "$evidence"
trap 'sudo -n rm -rf "$workspace"' EXIT HUP INT TERM
mkdir -p "$root/var/lib/dpkg/info" "$root/var/lib/dpkg/updates" \
  "$root/var/lib/dpkg/triggers" "$workspace/stub/DEBIAN" "$evidence"
: >"$root/var/lib/dpkg/status"
architecture=$(dpkg --print-architecture)

# The descriptor's maintainer scripts run chrooted in the target root.
for program in /bin/sh /usr/bin/rm /usr/bin/install; do
  for file in "$program" $(ldd "$program" | grep -o '/[^ ]*'); do
    mkdir -p "$root$(dirname "$file")"
    cp -L "$file" "$root$file"
  done
done

# Satisfy `Depends: ca-certificates` without a second live repository.
cat >"$workspace/stub/DEBIAN/control" <<CONTROL
Package: ca-certificates
Version: 0-debz-live-stub
Architecture: all
Maintainer: debz <debz@invalid>
Description: dependency stub for the live repository add evidence
CONTROL
dpkg-deb --root-owner-group --build "$workspace/stub" "$workspace/ca-certificates.deb" >/dev/null
sudo -n dpkg --root="$root" --force-script-chrootless --install "$workspace/ca-certificates.deb" >/dev/null

sudo -n "$debz" repo add \
  --url "$url" \
  --sha256 "$sha256" \
  --root "$root" \
  --architecture "$architecture" \
  --transaction-backend legacy_dpkg \
  --json >"$evidence/repo-add-result.json"

# The operation state is root-only; keep a reviewer-readable copy.
sudo -n python3 - "$evidence/repo-add-result.json" "$root" "$sha256" \
  >"$evidence/apt-config-snapshot.json" <<'CHECK'
import json
import sys

result = json.load(open(sys.argv[1]))
for key, expected in (
    ("exit_status", 0), ("installed", True), ("refreshed", True), ("refreshed_phase", "complete"),
):
    if result[key] != expected:
        sys.exit(f"repo add {key}: {result[key]!r}, expected {expected!r}")
if result["descriptor"]["sha256"] != sys.argv[3]:
    sys.exit("repo add installed an unreviewed descriptor")
raw = open(sys.argv[2] + result["paths"]["target_manifest"]).read()
snapshot = json.loads(raw)
freshness = [source["freshness"] for source in snapshot["sources"]]
freshness += [policy["freshness"] for policy in snapshot["repository_policies"]]
reviewed = {
    "mode": "allow_missing_valid_until_with_max_age_seconds",
    "maximum_release_age_seconds": 14 * 24 * 60 * 60,
}
if len(freshness) < 2 or any(item != reviewed for item in freshness):
    sys.exit(f"unexpected freshness policies: {freshness}")
sys.stdout.write(raw)
CHECK
printf 'live repository add passed; evidence in %s\n' "$evidence"
