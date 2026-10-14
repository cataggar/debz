#!/usr/bin/env bash
# Live proof of the short system profile (`sudo debz install <package>`) on a
# disposable GitHub-hosted Ubuntu 24.04 runner. CI runs it only from the
# dispatch-only `system-install-live` job (input run_system_install_live).
#
# DESTRUCTIVE: it purges packages-microsoft-prod, moves the runner's APT
# sources and Microsoft keyring into a root-only quarantine, and adds the
# reviewed Microsoft repository to the real root with `debz repo add`. It
# refuses to run anywhere but a GitHub-hosted Ubuntu 24.04 runner.
#
# Pass criteria for a build without system-install-execution-v1:
# - repo add installs the pinned descriptor and records the reviewed
#   signed_sha256_derived_sha512 binding of the Microsoft repository with
#   its explicit 1209600 s (14-day) missing-Valid-Until bound;
# - every root install of symcrypt or symcrypt-openssl exits 3
#   refused_before_mutation with request, progress, exact lock, program,
#   authorization and receipt; native plans carry SHA-512 values
#   derived_from_signed_sha256 that match the cached archive bytes whose
#   signed SHA-256 matched, and legacy plans stay signed_sha256_only;
# - the unprivileged install exits 3 rejected and publishes nothing;
# - an absent package exits 5 rejected without an exact lock;
# - no output names an upstream SHA-512;
# - /var/lib/dpkg is unchanged, content and metadata, after every install
#   run: any dpkg status change is a failure.
# A feed older than the reviewed bound is refused by debz (ReleaseExpired);
# the proof then fails without retrying or widening the bound.
set -euo pipefail
umask 022
export LC_ALL=C

die() {
  printf 'system-install-live-proof: %s\n' "$*" >&2
  exit 1
}

if [ "$#" -ne 1 ]; then die "usage: $0 amd64|arm64"; fi
arch=$1
case "$arch" in
  amd64|arm64) ;;
  *) die "unsupported architecture: $arch" ;;
esac
if [ "${GITHUB_ACTIONS:-}" != true ]; then die "refusing to run outside GitHub Actions"; fi
if [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then die "refusing to run outside a disposable GitHub-hosted runner"; fi
if [ ! -d "${RUNNER_TEMP:-}" ]; then die "RUNNER_TEMP is not a directory"; fi
if ! grep -qx 'ID=ubuntu' /etc/os-release; then die "refusing to run outside Ubuntu"; fi
if ! grep -qx 'VERSION_ID="24.04"' /etc/os-release; then die "refusing to run outside Ubuntu 24.04"; fi
if [ "$(dpkg --print-architecture)" != "$arch" ]; then die "the runner is not $arch"; fi
if ! sudo -n true; then die "passwordless root access through sudo -n is required"; fi

debz=$PWD/zig-out/bin/debz
if [ -L "$debz" ] || [ ! -f "$debz" ] || [ ! -x "$debz" ]; then die "build zig-out/bin/debz first"; fi
url=https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb
descriptor=c13f01ac7c3001b51a9281d40dde666db5e037e05512840c319832f7852bfec4
keyring=/usr/share/keyrings/microsoft-prod.gpg
out=$PWD/.system-install-live/$arch
work=$RUNNER_TEMP/system-install-live
quarantine=/root/debz-system-install-live
checker=$PWD/tools/system-install-live-proof.py
path=/usr/sbin:/usr/bin:/sbin:/bin

as_root() { sudo -n env -i PATH="$path" LC_ALL=C "$@"; }
as_user() { env -i PATH="$path" LC_ALL=C HOME="$HOME" "$@"; }
check() { as_root python3 -I "$checker" "$@"; }

# Records stdout, stderr and the exit status of one command without
# stopping the proof; the checker decides whether that status passes.
capture() {
  local prefix=$1 status=0
  shift
  "$@" </dev/null >"$prefix.stdout" 2>"$prefix.stderr" || status=$?
  printf '%s\n' "$status" >"$prefix.exit"
}

dpkg_state() {
  local state
  state=$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null) || state=
  printf '%s' "$state"
}

# The evidence and locks are root-only; keep a reviewer-readable copy.
finish() {
  local status=$?
  set +e
  if [ -d "$out" ]; then
    sudo -n tar -C / --ignore-failed-read -cf "$work/state.tar" \
      var/lib/debz/system-install var/lib/debz/locks 2>"$out/state.stderr"
    mkdir -p "$out/state"
    tar -C "$out/state" --no-same-owner --no-same-permissions -xf "$work/state.tar" 2>>"$out/state.stderr"
    chmod -R u+rwX "$out/state"
    sudo -n find /var/cache/debz -type f -printf '%s %P\n' >"$out/cache.txt" 2>>"$out/state.stderr"
    if [ "$status" -eq 0 ]; then
      printf 'passed\n' >"$out/result.txt"
    else
      printf 'failed (exit %s)\n' "$status" >"$out/result.txt"
    fi
  fi
  exit "$status"
}

rm -rf "$out"
mkdir -p "$out/runs" "$work"
trap finish EXIT

# No background package manager may touch /var/lib/dpkg during the proof.
for unit in apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service \
  unattended-upgrades.service; do
  if systemctl cat "$unit" >/dev/null 2>&1; then sudo -n systemctl stop "$unit"; fi
done
for attempt in $(seq 60); do
  if ! pgrep -x 'apt|apt-get|dpkg|unattended-upgr' >/dev/null; then break; fi
  if [ "$attempt" -eq 60 ]; then die "a package manager is still running"; fi
  sleep 10
done

# The image's Microsoft repository must come back only through debz repo add.
state=$(dpkg_state packages-microsoft-prod)
if [ -n "$state" ] && [ "$state" != not-installed ]; then
  sudo -n dpkg --purge packages-microsoft-prod >"$out/purge.log" 2>&1 || die "could not purge packages-microsoft-prod"
fi
for package in symcrypt symcrypt-openssl; do
  state=$(dpkg_state "$package")
  if [ -n "$state" ] && [ "$state" != not-installed ]; then die "$package is already known to dpkg ($state)"; fi
done
sudo -n install -d -o root -g root -m 0700 "$quarantine"
for source in /etc/apt/sources.list /etc/apt/sources.list.d; do
  if sudo -n test -e "$source"; then sudo -n mv "$source" "$quarantine/"; fi
done
sudo -n install -d -o root -g root -m 0755 /etc/apt/sources.list.d
if sudo -n test -e "$keyring"; then
  if dpkg-query -S "$keyring" >/dev/null 2>&1; then die "$keyring is still owned by a package"; fi
  sudo -n mv "$keyring" "$quarantine/"
fi
sudo -n find "$quarantine" -mindepth 1 -printf '%P\n' | sort >"$out/quarantined.txt"

{
  printf 'image_os=%s\n' "${ImageOS:-unknown}"
  printf 'image_version=%s\n' "${ImageVersion:-unknown}"
  printf 'commit=%s\n' "${GITHUB_SHA:-unknown}"
  printf 'architecture=%s\n' "$arch"
  printf 'kernel=%s\n' "$(uname -r)"
  printf 'foreign_architectures=%s\n' "$(dpkg --print-foreign-architectures | tr '\n' ' ')"
  printf 'debz_sha512=%s\n' "$(sha512sum "$debz" | cut -d' ' -f1)"
} >"$out/runner.txt"
check prestate "$arch" >"$out/prestate-initial.json" ||
  die "the runner's dpkg database is outside the healthy installed-prestate contract; see prestate-initial.json"

capture "$out/repo-add" as_root "$debz" repo add --url "$url" --sha256 "$descriptor" \
  --transaction-backend legacy_dpkg --json
status=$(cat "$out/repo-add.exit")
if [ "$status" -ne 0 ]; then
  if grep -q ReleaseExpired "$out/repo-add.stdout" "$out/repo-add.stderr"; then
    die "the Microsoft feed is older than the reviewed 1209600 s (14-day) bound; debz refused it (ReleaseExpired); no proof is possible from this feed state"
  fi
  die "repo add exited $status; see repo-add.stdout and repo-add.stderr"
fi
check repo-add "$out" "$descriptor" "$arch" >"$out/apt-config-snapshot.json" ||
  die "repo add did not record the reviewed Microsoft configuration"
check prestate "$arch" >"$out/prestate.json" ||
  die "the dpkg database left by repo add is outside the healthy installed-prestate contract"
check snapshot >"$work/baseline.txt" || die "could not snapshot /var/lib/dpkg"
cp "$work/baseline.txt" "$out/dpkg-baseline.txt"

# name user output backend package; `default` passes no backend option.
cat >"$out/runs/index" <<'RUNS'
native-symcrypt root json native symcrypt
native-symcrypt-openssl root json native symcrypt-openssl
legacy-symcrypt root json legacy_dpkg symcrypt
legacy-symcrypt-openssl root json legacy_dpkg symcrypt-openssl
native-symcrypt-again root json native symcrypt
native-symcrypt-human root human native symcrypt
default-symcrypt-human root human default symcrypt
unprivileged-native-symcrypt user json native symcrypt
native-absent root json native debz-live-proof-absent
RUNS
while read -r name user output backend package <&3; do
  set -- install
  if [ "$backend" != default ]; then set -- "$@" --transaction-backend "$backend"; fi
  if [ "$output" = json ]; then set -- "$@" --json; fi
  if [ "$name" = native-symcrypt-again ]; then set -- "$@" -y --noninteractive; fi
  set -- "$@" "$package"
  if [ "$user" = root ]; then
    capture "$out/runs/$name" as_root "$debz" "$@"
  else
    capture "$out/runs/$name" as_user "$debz" "$@"
  fi
  printf '%s: exit %s\n' "$name" "$(cat "$out/runs/$name.exit")"
  check snapshot >"$work/after.txt" || die "could not snapshot /var/lib/dpkg after $name"
  if ! cmp -s "$work/baseline.txt" "$work/after.txt"; then
    if diff "$work/baseline.txt" "$work/after.txt" >"$out/runs/$name.dpkg.diff"; then :; fi
    die "$name changed /var/lib/dpkg; see runs/$name.dpkg.diff"
  fi
done 3<"$out/runs/index"

check verify "$out" "$arch" >"$out/verified.json" || die "the install evidence does not meet the pass criteria"
printf 'system install live proof passed on %s\n' "$arch"
