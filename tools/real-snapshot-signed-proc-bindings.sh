#!/usr/bin/env bash
# Build root-owned binding fixtures for the signed udev/sudo proc refusal and
# changed-after-binding tests from the authenticated amd64 snapshot closure.
# The fixtures hold only the exact signed inputs; they are not executable
# pre-script roots and never prove signed script replay.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

readonly snapshot_uri=https://snapshot.ubuntu.com/ubuntu/20260923T000000Z
readonly snapshot_suite=stonking
readonly keyring=${DEBZ_REAL_SNAPSHOT_KEYRING:-/usr/share/keyrings/ubuntu-archive-keyring.gpg}

[[ $# == 2 && $(id -u) == 0 ]] || {
  echo "usage (as root): $0 PROTECTED_DEBZ NEW_WORKSPACE" >&2
  exit 2
}

require_protected_path() {
  local path=$1 current=/ remainder=${1#/} component owner mode metadata
  [[ "$path" == /* ]] || return 2
  while :; do
    [[ -d "$current" && ! -L "$current" ]] || {
      echo "fixture path is not a real directory: $current" >&2
      return 2
    }
    metadata=$(stat -c '%u:%a' -- "$current")
    owner=${metadata%%:*}
    mode=${metadata#*:}
    [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] &&
      (( (8#$mode & 022) == 0 )) || {
      echo "fixture path is writable by an unprivileged user: $current" >&2
      return 2
    }
    [[ -n "$remainder" ]] || break
    component=${remainder%%/*}
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 2
    current="${current%/}/$component"
    if [[ "$remainder" == "$component" ]]; then
      remainder=
    else
      remainder=${remainder#*/}
    fi
  done
}

require_protected_file() {
  local path=$1 metadata owner mode
  require_protected_path "$(dirname -- "$path")"
  [[ -f "$path" && ! -L "$path" ]] || return 2
  metadata=$(stat -c '%u:%a' -- "$path")
  owner=${metadata%%:*}
  mode=${metadata#*:}
  [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] &&
    (( (8#$mode & 022) == 0 )) || {
    echo "fixture file is writable by an unprivileged user: $path" >&2
    return 2
  }
}

repository_root=$(pwd -P)
script_path=$(realpath -- "${BASH_SOURCE[0]}")
[[ "$script_path" == "$repository_root/tools/real-snapshot-signed-proc-bindings.sh" ]] || {
  echo "run the protected fixture script from its checkout root" >&2
  exit 2
}
require_protected_file "$script_path"
require_protected_path "$repository_root/.real-snapshot"
[[ $(stat -c '%u:%g:%a' "$repository_root/.real-snapshot") == 0:0:700 ]] || {
  echo "the fixture directory must be root-owned and mode 0700" >&2
  exit 2
}
debz=$(realpath -- "$1")
workspace=$(realpath -m -- "$2")
require_protected_file "$debz"
[[ -x "$debz" ]]
require_protected_file "$keyring"
case "$workspace" in
  "$repository_root"/.real-snapshot/*) ;;
  *) echo "the workspace must be beneath this checkout's .real-snapshot" >&2; exit 2 ;;
esac
require_protected_path "$(dirname -- "$workspace")"
[[ ! -e "$2" && ! -L "$2" && ! -e "$workspace" && ! -L "$workspace" ]] || {
  echo "the fixture workspace must be new: $workspace" >&2
  exit 2
}

install -d -o root -g root -m 0700 "$workspace"
snapshot=$workspace/snapshot
bindings=$workspace/bindings
install -d -o root -g root -m 0700 "$snapshot" "$snapshot/root" "$snapshot/cache" \
  "$snapshot/state" "$snapshot/evidence" "$bindings"
cat >"$snapshot/ubuntu.sources" <<EOF
Types: deb
URIs: $snapshot_uri
Suites: $snapshot_suite
Components: main
Architectures: amd64
Signed-By: $keyring
EOF
printf '{"source_path":"%s","priority":500,"default_release":"%s","immutable":true,"freshness":{"mode":"allow_missing_valid_until_with_max_age_seconds","maximum_release_age_seconds":%s}}\n' \
  "$snapshot/ubuntu.sources" "$snapshot_suite" $((31 * 24 * 60 * 60)) >"$snapshot/ubuntu.json"
lock=$snapshot/evidence/ubuntu-minimal.lock.json
common=(
  --install-root "$snapshot/root"
  --cache-path "$snapshot/cache"
  --state-path "$snapshot/state"
  --architecture amd64
  --config "$snapshot/ubuntu.json"
  --keyring "$keyring"
  --deadline-ms 300000
  --lock-wait-ms 30000
  --json
)
for step in refresh plan download; do
  arguments=("${common[@]}")
  case "$step" in
    refresh) arguments+=(--assume-yes) ;;
    plan) arguments+=(--transaction-backend native --lock-output "$lock" ubuntu-minimal) ;;
    download) arguments+=(--transaction-backend native --lock-input "$lock" ubuntu-minimal) ;;
  esac
  timeout --signal=TERM --kill-after=30s 30m "$debz" "$step" "${arguments[@]}" \
    >"$snapshot/evidence/$step.json" 2>"$snapshot/evidence/$step.stderr"
done
jq -e '
  .schema == "https://debz.dev/schema/exact-closure-lock-v3" and
  .target_architecture == "amd64" and
  all(.packages[]; .archive_identity.primary == "sha512") and
  ([.packages[] | select(.name == "udev" and .version == "261.2-1ubuntu2" and
    .architecture == "amd64")] | length) == 1 and
  ([.packages[] | select(.name == "sudo" and .version == "1.9.17p2-7ubuntu3" and
    .architecture == "amd64")] | length) == 1
' "$lock" >/dev/null

# Rehash every locked archive and index the members of each package.
declare -A archive
listing=$snapshot/evidence/members.tsv
: >"$listing"
while IFS=$'\t' read -r name digest size; do
  object=$snapshot/cache/packages-v2/objects/sha512-$digest
  [[ -f "$object" && ! -L "$object" && $(stat -c %s "$object") == "$size" ]]
  [[ $(sha512sum "$object" | cut -d' ' -f1) == "$digest" ]]
  archive[$name]=$object
  dpkg-deb --fsys-tarfile "$object" | tar -t |
    sed -e 's#^\./##' -e 's#/$##' -e "s#^#$name\t#" >>"$listing"
done < <(jq -r '.packages[] | [.name, .archive_identity.digests[0].digest,
  .declared_size] | @tsv' "$lock")

extract() { # member mode destination
  local provider
  provider=$(awk -F'\t' -v path="$1" '$2 == path { print $1 }' "$listing")
  [[ -n "$provider" && "$provider" != *$'\n'* ]] || {
    echo "signed input must have exactly one provider: $1" >&2
    return 1
  }
  install -d -o root -g root -m 0755 "$(dirname -- "$3")"
  dpkg-deb --fsys-tarfile "${archive[$provider]}" | tar -xO "./$1" >"$3"
  chown root:root "$3"
  chmod "$2" "$3"
}

source_root=$workspace/signed-inputs
install -d -o root -g root -m 0700 "$source_root"
for input in \
  usr/bin/dash:0755 usr/bin/dpkg:0755 usr/bin/dpkg-query:0755 \
  usr/bin/systemd-hwdb:0755 usr/bin/systemd-sysusers:0755 usr/bin/systemd-tmpfiles:0755 \
  usr/bin/dpkg-maintscript-helper:0755 usr/bin/deb-systemd-helper:0755 \
  usr/sbin/update-rc.d:0755 usr/bin/systemctl:0755 usr/bin/deb-systemd-invoke:0755 \
  usr/bin/update-alternatives:0755 usr/bin/gnurm:0755 usr/bin/gnuchown:0755 \
  usr/bin/gnuchmod:0755 usr/bin/sudo.ws:4755 \
  usr/lib/tmpfiles.d/static-nodes-permissions.conf:0644 \
  usr/lib/sysusers.d/debian-udev.conf:0644 usr/share/dpkg/sh/dpkg-error.sh:0644 \
  usr/lib/tmpfiles.d/sudo.conf:0644 usr/share/man/man8/sudo.ws.8.gz:0644; do
  extract "${input%%:*}" "${input##*:}" "$source_root/${input%%:*}"
done
install -d -o root -g root -m 0755 "$source_root/var/lib/dpkg/info"
for package in udev sudo; do
  dpkg-deb --ctrl-tarfile "${archive[$package]}" | tar -xO ./postinst \
    >"$source_root/var/lib/dpkg/info/$package.postinst"
  chmod 0755 "$source_root/var/lib/dpkg/info/$package.postinst"
done
awk -F'\t' '$1 == "sudo" { print "/" $2 }' "$listing" | sed 's#^/$#/.#' |
  LC_ALL=C sort >"$source_root/var/lib/dpkg/info/sudo.list"
chmod 0644 "$source_root/var/lib/dpkg/info/sudo.list"

copy_input() { # root path
  install -d -o root -g root -m 0755 "$(dirname -- "$1/$2")"
  cp --preserve=mode,ownership -- "$source_root/$2" "$1/$2"
}
skeleton() { # root
  install -d -o root -g root -m 0700 "$1"
  install -d -o root -g root -m 0755 "$1/proc" "$1/usr" "$1/usr/bin" "$1/usr/sbin" \
    "$1/var" "$1/var/lib" "$1/var/lib/dpkg" "$1/var/lib/dpkg/info"
  ln -s usr/bin "$1/bin"
  ln -s dash "$1/usr/bin/sh"
}
udev_root() {
  skeleton "$1"
  for path in var/lib/dpkg/info/udev.postinst usr/bin/dash usr/bin/dpkg \
    usr/bin/systemd-hwdb usr/bin/systemd-sysusers usr/bin/systemd-tmpfiles \
    usr/bin/dpkg-maintscript-helper usr/bin/deb-systemd-helper usr/sbin/update-rc.d \
    usr/bin/systemctl usr/bin/deb-systemd-invoke \
    usr/lib/tmpfiles.d/static-nodes-permissions.conf usr/lib/sysusers.d/debian-udev.conf; do
    copy_input "$1" "$path"
  done
}
sudo_root() {
  skeleton "$1"
  ln -s usr/sbin "$1/sbin"
  ln -s gnurm "$1/usr/bin/rm"
  ln -s gnuchown "$1/usr/bin/chown"
  ln -s gnuchmod "$1/usr/bin/chmod"
  for path in var/lib/dpkg/info/sudo.postinst var/lib/dpkg/info/sudo.list usr/bin/dash \
    usr/bin/dpkg usr/bin/dpkg-query usr/bin/systemd-tmpfiles usr/bin/dpkg-maintscript-helper \
    usr/share/dpkg/sh/dpkg-error.sh usr/bin/update-alternatives usr/bin/gnurm \
    usr/bin/gnuchown usr/bin/gnuchmod usr/lib/tmpfiles.d/sudo.conf usr/bin/sudo.ws \
    usr/share/man/man8/sudo.ws.8.gz; do
    copy_input "$1" "$path"
  done
}
complement_last_byte() {
  local size last
  size=$(stat -c %s "$1")
  last=$(tail -c 1 -- "$1" | od -An -tu1 | tr -d ' ')
  printf "\\$(printf '%03o' $(( last ^ 255 )))" |
    dd of="$1" bs=1 seek=$(( size - 1 )) conv=notrunc status=none
}
empty_file() { # path mode
  install -d -o root -g root -m 0755 "$(dirname -- "$1")"
  install -o root -g root -m "$2" /dev/null "$1"
}

for variant in changed bad-tool bad-control override path-shadow bad-bin; do
  udev_root "$bindings/udev-$variant"
done
complement_last_byte "$bindings/udev-bad-tool/usr/bin/systemd-hwdb"
complement_last_byte "$bindings/udev-bad-control/usr/lib/tmpfiles.d/static-nodes-permissions.conf"
empty_file "$bindings/udev-override/etc/tmpfiles.d/static-nodes-permissions.conf" 0644
empty_file "$bindings/udev-path-shadow/usr/sbin/systemd-tmpfiles" 0755
ln -sfn usr/sbin "$bindings/udev-bad-bin/bin"

for variant in changed changed-fragment bad-tool bad-fragment missing-fragment \
  redirected-fragment bad-alias override shadow; do
  sudo_root "$bindings/sudo-$variant"
done
complement_last_byte "$bindings/sudo-bad-tool/usr/bin/update-alternatives"
complement_last_byte "$bindings/sudo-bad-fragment/usr/share/dpkg/sh/dpkg-error.sh"
rm -- "$bindings/sudo-missing-fragment/usr/share/dpkg/sh/dpkg-error.sh"
mv -- "$bindings/sudo-redirected-fragment/usr/share/dpkg/sh/dpkg-error.sh" \
  "$bindings/sudo-redirected-fragment/usr/share/dpkg/sh/dpkg-error.real"
ln -s dpkg-error.real "$bindings/sudo-redirected-fragment/usr/share/dpkg/sh/dpkg-error.sh"
ln -sfn gnuchmod "$bindings/sudo-bad-alias/usr/bin/rm"
empty_file "$bindings/sudo-override/etc/tmpfiles.d/sudo.conf" 0644
empty_file "$bindings/sudo-shadow/usr/sbin/update-alternatives" 0755

{
  for variant in bad-tool bad-fragment missing-fragment redirected-fragment bad-alias \
    override shadow changed changed-fragment; do
    name=${variant^^}
    printf 'DEBZ_REQUIRE_SIGNED_SUDO_PROC_%s_ROOT=%s\n' "${name//-/_}" "$bindings/sudo-$variant"
  done
  for variant in bad-tool bad-control override path-shadow bad-bin changed; do
    name=${variant^^}
    printf 'DEBZ_REQUIRE_SIGNED_UDEV_PROC_%s_ROOT=%s\n' "${name//-/_}" "$bindings/udev-$variant"
  done
} >"$workspace/bindings.env"
printf 'lock_document_digest=%s\nbinding_roots=%s\n' "$(jq -r .digest_sha256 "$lock")" \
  "$(find "$bindings" -mindepth 1 -maxdepth 1 | wc -l)"
