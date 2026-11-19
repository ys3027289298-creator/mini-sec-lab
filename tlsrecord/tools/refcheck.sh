#!/usr/bin/env bash
# Field-by-field parity: compare the C parser's normalized trace against
# the independent Python reference for every generated vector.
set -u
cd "$(dirname "$0")/.."
vd=vectors
fails=0
total=0
for bin in "$vd"/*.bin; do
    base="${bin%.bin}"
    name="$(basename "$base")"
    ctl=""
    [ -f "$base.ctl" ] && ctl="$base.ctl"
    total=$((total + 1))
    if [ -n "$ctl" ]; then
        ./tlsrecord dump "$bin" "$ctl" > "$base.actual" 2>&1
    else
        ./tlsrecord dump "$bin" > "$base.actual" 2>&1
    fi
    if diff -u "$base.expected" "$base.actual" > "$base.diff"; then
        echo "ok   $name"
    else
        echo "FAIL $name"
        cat "$base.diff"
        fails=$((fails + 1))
    fi
done
echo "refcheck total=$total failed=$fails"
[ "$fails" -eq 0 ]
