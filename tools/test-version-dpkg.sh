#!/bin/sh
set -eu

if ! command -v dpkg >/dev/null 2>&1; then
    echo "dpkg not found; skipping Debian version oracle comparison"
    exit 0
fi

oracle=$1
cases='
1.0~rc1|1.0
1.0|1.0-0
1.0|1.0-0~1
1.09|1.9
1.9|1.10
0001:1|1:1
2:0|1:9999
1.0a|1.0+
1.0+|1.0.
1.0-1~bpo1|1.0-1
1.0-1|1.0-1+b1
'

printf '%s\n' "$cases" | while IFS='|' read -r left right; do
    [ -n "$left" ] || continue
    actual=$("$oracle" "$left" "$right" 2>&1)
    if dpkg --compare-versions "$left" lt "$right"; then
        expected=lt
    elif dpkg --compare-versions "$left" gt "$right"; then
        expected=gt
    else
        expected=eq
    fi
    if [ "$actual" != "$expected" ]; then
        echo "version mismatch: '$left' vs '$right': debz=$actual dpkg=$expected" >&2
        exit 1
    fi
done

echo "Debian version ordering matches dpkg oracle cases"
