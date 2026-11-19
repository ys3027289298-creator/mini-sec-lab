#!/usr/bin/env python3
"""Differential + sanitizer fuzz for reqguard's HPACK/HTTP2 path.

Random field blocks are generated from an HPACK-aware mutation grammar:
seeded valid blocks from the RFC 7541 examples get bytes flipped,
inserted, deleted and truncated, and random representation octets are
mixed in. Every candidate is decoded by the C binary built with
ASan/UBSan and by the independent Python reference; both must agree on
the full trace, and the C side must never crash or trip a sanitizer.

Run from reqguard/:  python3 -I tools/hpack_fuzz.py [iterations]
Set REQGUARD_SAN or pass the binary as argv[2] to use another build.
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import ref_hpack  # noqa: E402

BINARY = os.environ.get("REQGUARD_SAN", os.path.join(ROOT, "reqguard-san"))
REF = os.path.join(HERE, "ref_hpack.py")

SEEDS = [
    "828684410f7777772e6578616d706c652e636f6d",
    "828684418cf1e3c2e5f23a6ba0ab90f4ff",
    "828684be58086e6f2d6361636865",
    "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
    "828684400e636f6e74656e742d6c656e6774680135",
    "8286844002746508747261696c657273",
    "828684400a636f6e6e656374696f6e05636c6f7365",
    "82",
]

REP = [0x00, 0x10, 0x20, 0x40, 0x80, 0x3f, 0x7f, 0xff, 0x0f, 0x1f]


def run(binary, script):
    if binary.endswith(".py"):
        argv = [sys.executable, "-I", binary]
    else:
        argv = [binary, "h2trace"]
    p = subprocess.run(argv, input=script, capture_output=True, text=True)
    if p.returncode not in (0, 1):
        raise SystemExit("crash (rc=%d) on script %r\n%s" % (p.returncode, script, p.stderr))
    if "AddressSanitizer" in p.stderr or "runtime error" in p.stderr:
        raise SystemExit("sanitizer on script %r\n%s\n%s" % (script, p.stdout, p.stderr))
    return p.stdout


def mutate(rng, data):
    b = bytearray(data)
    for _ in range(rng.randint(1, 5)):
        if not b:
            b = bytearray([rng.choice(REP)])
        op = rng.choice(["flip", "insert", "delete", "dup", "truncate",
                         "byte", "rep"])
        i = rng.randrange(len(b))
        if op == "flip":
            b[i] ^= 1 << rng.randrange(8)
        elif op == "insert":
            b[i:i] = bytes([rng.randrange(256)])
        elif op == "delete":
            del b[i]
        elif op == "dup":
            j = min(len(b), i + rng.randint(1, 6))
            b[i:i] = b[i:j]
        elif op == "truncate":
            del b[i:]
        elif op == "byte":
            b[i] = rng.randrange(256)
        elif op == "rep":
            b[i] = rng.choice(REP)
    return bytes(b)


def random_block(rng):
    """Mix whole representations so we reach deeper decoder states."""
    out = bytearray()
    for _ in range(rng.randint(1, 4)):
        kind = rng.randrange(5)
        if kind == 0:
            out.append(0x80 | rng.randint(0, 0x7f))
        elif kind == 1:
            out += bytes.fromhex(rng.choice(SEEDS))
        elif kind == 2:
            out.append(0x20 | rng.randint(0, 0x1f))
            out += bytes([rng.randrange(256) for _ in range(rng.randint(0, 2))])
        elif kind == 3:
            out.append(rng.choice([0x40, 0x00, 0x10]))
            name = bytes(rng.randrange(0x61, 0x7b) for _ in range(rng.randint(0, 8)))
            value = bytes(rng.randrange(0x20, 0x7f) for _ in range(rng.randint(0, 12)))
            out.append(len(name))
            out += name
            out.append(len(value))
            out += value
        else:
            out += bytes(rng.randrange(256) for _ in range(rng.randint(1, 5)))
    return bytes(out)


def main():
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 400
    binary = sys.argv[2] if len(sys.argv) > 2 else BINARY
    if not os.path.exists(binary):
        print("missing %s; run make fuzz" % binary, file=sys.stderr)
        return 2

    rng = random.Random(0x48504B41)
    failures = 0
    for i in range(iterations):
        if i % 3:
            pool = [bytes.fromhex(s) for s in SEEDS]
            block = mutate(rng, rng.choice(pool))
        else:
            block = random_block(rng)
        # Sometimes run a two-block script so cross-block state is exercised.
        if rng.random() < 0.25:
            second = mutate(rng, rng.choice([bytes.fromhex(s) for s in SEEDS]))
            script = "block %s\nblock %s\n" % (block.hex(), second.hex())
        else:
            script = "block %s\n" % block.hex()
        ref = run(REF, script)
        got = run(binary, script)
        if ref != got:
            failures += 1
            print("mismatch on %r" % script)
            rl, gl = ref.splitlines(), got.splitlines()
            for j in range(max(len(rl), len(gl))):
                r = rl[j] if j < len(rl) else "<missing>"
                g = gl[j] if j < len(gl) else "<missing>"
                if r != g:
                    print("  line %d ref=%r got=%r" % (j, r, g))
            if failures > 10:
                break

    print("fuzz iterations=%d mismatches=%d" % (iterations, failures))
    print("fuzz_ok=%d" % (1 if failures == 0 else 0))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
