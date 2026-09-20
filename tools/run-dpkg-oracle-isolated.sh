#!/bin/sh
set -eu

if [ "$#" -lt 5 ] || [ "$#" -gt 6 ]; then
    echo "usage: run-dpkg-oracle-isolated.sh REPOSITORY KIND ARCHITECTURE DPKG OUTPUT [UPDATE_ALTERNATIVES]" >&2
    exit 2
fi
if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    echo "isolated dpkg oracle execution requires root" >&2
    exit 2
fi

repository=$(/usr/bin/readlink -f -- "$1")
kind=$2
architecture=$3
dpkg=$(/usr/bin/readlink -f -- "$4")
output=$5
update_alternatives=${6-}

case "$architecture" in
    amd64|arm64) ;;
    *) echo "unsupported oracle architecture: $architecture" >&2; exit 2 ;;
esac
case "$kind" in
    config)
        [ "$#" -eq 5 ] || exit 2
        ;;
    alternatives)
        [ "$#" -eq 6 ] || exit 2
        update_alternatives=$(/usr/bin/readlink -f -- "$update_alternatives")
        ;;
    *)
        echo "unsupported dpkg oracle: $kind" >&2
        exit 2
        ;;
esac

host_config="$repository/.tmp/arm64-dpkg-oracles/host-config/dpkg.cfg"
host_fragments="$repository/.tmp/arm64-dpkg-oracles/host-config/dpkg.cfg.d"
case "$output" in
    "$repository"/.tmp/arm64-dpkg-oracles/*.json) ;;
    *) echo "oracle output is outside its bounded directory" >&2; exit 2 ;;
esac
[ -f "$host_config" ] && [ ! -L "$host_config" ]
[ -d "$host_fragments" ] && [ ! -L "$host_fragments" ]
[ -f /etc/dpkg/dpkg.cfg ] && [ ! -L /etc/dpkg/dpkg.cfg ]
[ -d /etc/dpkg/dpkg.cfg.d ] && [ ! -L /etc/dpkg/dpkg.cfg.d ]
test "$(/usr/bin/sha256sum "$host_config")" = \
    "fead43b89af3ea5691c48f32d7fe1ba0f7ab229fb5d230f612d76fe8e6f5a015  $host_config"

/usr/bin/mount --bind "$host_config" /etc/dpkg/dpkg.cfg
/usr/bin/mount --bind "$host_fragments" /etc/dpkg/dpkg.cfg.d
cd "$repository"

if [ "$kind" = config ]; then
    exec /usr/bin/python3 tools/dpkg-config-reference.py \
        --architecture "$architecture" \
        --reference-dpkg "$dpkg" \
        --capture-observed "$output"
fi
exec /usr/bin/python3 tools/dpkg-alternatives-reference.py \
    --architecture "$architecture" \
    --reference-dpkg "$dpkg" \
    --reference-update-alternatives "$update_alternatives" \
    --capture-observed "$output"
