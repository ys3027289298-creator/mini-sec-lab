#!/usr/bin/env python3
"""Cross-check reqguard's chunked decoder against tests/ref_chunked.py.

Twenty vectors are decoded by both implementations and every observable
(status, completion, chunk count, trailer count, decoded bytes) must match.
Each vector is also fed to the C decoder in 1-, 2-, 3-, 5- and 7-byte slices
to prove incremental feeding reaches the same state as whole-buffer parsing.

Run from reqguard/:  python3 tests/crosscheck.py
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BINARY = os.path.join(ROOT, "reqguard")
REF = os.path.join(HERE, "ref_chunked.py")

CASES = [
    ("chunk_simple", b"5\r\nhello\r\n0\r\n\r\n"),
    ("chunk_multi", b"1\r\na\r\n1\r\nb\r\n0\r\n\r\n"),
    ("chunk_empty", b"0\r\n\r\n"),
    ("chunk_upper_hex", b"A\r\n0123456789\r\n0\r\n\r\n"),
    ("chunk_lower_hex", b"a\r\n0123456789\r\n0\r\n\r\n"),
    ("chunk_leading_zero", b"03\r\nabc\r\n0\r\n\r\n"),
    ("chunk_ext_value", b"5;foo=bar\r\nhello\r\n0\r\n\r\n"),
    ("chunk_ext_bare", b"5;ext\r\nhello\r\n0\r\n\r\n"),
    ("chunk_ext_quoted", b'5;q="a b"\r\nhello\r\n0\r\n\r\n'),
    ("chunk_one_trailer", b"5\r\nhello\r\n0\r\nX-T: v\r\n\r\n"),
    ("chunk_two_trailers", b"5\r\nhello\r\n0\r\nX-T: v\r\nX-U: w\r\n\r\n"),
    ("chunk_trailer_cl", b"5\r\nhello\r\n0\r\nContent-Length: 3\r\n\r\n"),
    ("chunk_trailer_obsfold", b"5\r\nhello\r\n0\r\nX-T: a\r\n b\r\n\r\n"),
    ("chunk_trailer_nocolon", b"5\r\nhello\r\n0\r\nNoColon\r\n\r\n"),
    ("chunk_bad_hex", b"g\r\nhello\r\n0\r\n\r\n"),
    ("chunk_missing_crlf", b"5\r\nhelloX\r\n0\r\n\r\n"),
    ("chunk_bare_lf", b"5\r\nhello\n0\r\n\r\n"),
    ("chunk_incomplete", b"5\r\nhello\r\n"),
    ("chunk_oversized", b"1001\r\n"),
    ("chunk_hex_overflow", b"FFFFFFFFFFFFFFFFF\r\n"),
]

SPLITS = (1, 2, 3, 5, 7)
FIELDS = ("status", "done", "chunks", "trailers", "body_len", "body_hex")


def parse_kv(text):
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def run_reference(data):
    p = subprocess.run(
        [sys.executable, REF], input=data.hex(), capture_output=True, text=True, check=True
    )
    return parse_kv(p.stdout)


def run_c(data, split=None):
    argv = [BINARY, "--decode"]
    if split:
        argv.append(f"--split={split}")
    p = subprocess.run(argv, input=data.hex(), capture_output=True, text=True, check=True)
    return parse_kv(p.stdout)


def main():
    if not os.path.exists(BINARY):
        print(f"missing {BINARY}; run make first", file=sys.stderr)
        return 2

    failures = 0
    for name, data in CASES:
        ref = run_reference(data)
        got = run_c(data)
        ok = all(ref.get(f) == got.get(f) for f in FIELDS)
        print(f"{name}={1 if ok else 0}")
        if not ok:
            failures += 1
            for f in FIELDS:
                if ref.get(f) != got.get(f):
                    print(f"  {name}.{f}: ref={ref.get(f)!r} got={got.get(f)!r}")

        for split in SPLITS:
            inc = run_c(data, split)
            same = all(ref.get(f) == inc.get(f) for f in FIELDS)
            if not same:
                failures += 1
                print(f"  {name}.split={split}: ref={ref!r} got={inc!r}")

    print("crosscheck_ok=%d" % (1 if failures == 0 else 0))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
