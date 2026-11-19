#!/usr/bin/env python3
"""Randomized differential + sanitizer test for reqguard's chunked decoder.

Generates structured mutations of valid chunked bodies (size lines, data,
CRLF runs, trailers, extensions) and asserts:
  * the C decoder under ASan/UBSan never crashes;
  * reference and C agree on every field;
  * incremental feeding (random slice sizes) matches whole-buffer parsing.

Usage: python3 tests/fuzz_crosscheck.py [iterations]
Run from reqguard/ after building the sanitizer binary at /tmp/reqguard_san
(or set REQGUARD_BIN).
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ref_chunked  # noqa: E402

BINARY = os.environ.get("REQGUARD_BIN", "/tmp/reqguard_san")
FIELDS = ("status", "done", "chunks", "trailers", "body_len", "body_hex")
SEEDS = [
    b"5\r\nhello\r\n0\r\n\r\n",
    b"1\r\na\r\n1\r\nb\r\n0\r\n\r\n",
    b"0\r\n\r\n",
    b"5;foo=bar\r\nhello\r\n0\r\nX-T: v\r\n\r\n",
    b"A\r\n0123456789\r\n0\r\n\r\n",
    b"1000\r\n" + b"x" * 4096 + b"\r\n0\r\n\r\n",
]


def parse_kv(text):
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def run_c(data, split=None):
    argv = [BINARY, "--decode"]
    if split:
        argv.append(f"--split={split}")
    p = subprocess.run(argv, input=data.hex(), capture_output=True, text=True)
    if p.returncode != 0 and "AddressSanitizer" in p.stderr or "runtime error" in p.stderr:
        raise SystemExit(f"sanitizer error on {data!r}:\n{p.stderr}")
    return parse_kv(p.stdout), p.stderr


def mutate(rng, data):
    b = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        op = rng.choice(["flip", "insert", "delete", "dup", "truncate", "crlf"])
        if not b:
            b = bytearray(b"0\r\n\r\n")
        i = rng.randrange(len(b))
        if op == "flip":
            b[i] = rng.randrange(256)
        elif op == "insert":
            b[i:i] = bytes([rng.randrange(256)])
        elif op == "delete":
            del b[i]
        elif op == "dup":
            j = min(len(b), i + rng.randint(1, 8))
            b[i:i] = b[i:j]
        elif op == "truncate":
            del b[i:]
        elif op == "crlf":
            b[i:i] = rng.choice([b"\r\n", b"\r", b"\n", b"\r\r", b"\n\r"])
    return bytes(b)


def main():
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    rng = random.Random(0xC0FFEE)
    failures = 0

    for it in range(iterations):
        data = rng.choice(SEEDS)
        if rng.random() < 0.9:
            data = mutate(rng, data)
        ref = ref_chunked.decode(data).as_dict()
        ref = {k: str(v) for k, v in ref.items()}
        got, stderr = run_c(data, None)
        if any(ref.get(f) != got.get(f) for f in FIELDS):
            failures += 1
            print(f"mismatch #{it} input={data.hex()!r}")
            for f in FIELDS:
                if ref.get(f) != got.get(f):
                    print(f"  {f}: ref={ref.get(f)!r} got={got.get(f)!r}")
            if failures > 5:
                break
        split = rng.randint(1, 9)
        inc, _ = run_c(data, split)
        if any(got.get(f) != inc.get(f) for f in FIELDS):
            failures += 1
            print(f"split mismatch #{it} split={split} input={data.hex()!r}")
            if failures > 5:
                break

    print("fuzz_ok=%d" % (1 if failures == 0 else 0))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
