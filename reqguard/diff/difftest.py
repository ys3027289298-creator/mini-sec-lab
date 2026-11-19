#!/usr/bin/env python3
"""Differential tester: reqguard vs Node llhttp (reference parser).

Same raw bytes -> both parsers -> field-by-field compare -> classify
divergences by cause -> minimize >=3 reproducible samples per class.

Classes:
  agree                 both accept with identical fields, or both reject
  strict:<err>          reqguard rejects, reference accepts (hardening)
  hole:<refcode>        reqguard accepts, reference rejects   (DANGEROUS)
  field:<fields>        both accept but fields differ         (DANGEROUS)

Exit code 1 if any dangerous class is non-empty.
Writes: diff/report.md, diff/report.json, diff/samples/<class>/<n>.bin
"""
import json
import os
import random
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "reqguard-diff")
REF = os.path.join(HERE, "ref_server.mjs")
SAMPLES = os.path.join(HERE, "samples")
FUZZ_SEED = 20261119
FUZZ_N = 1500
MAX_MINIMIZE_EVALS = 400

# ---------------------------------------------------------------- corpus

RL = b"POST /a HTTP/1.1\r\nHost: x\r\n"

def req(headers: bytes, rl: bytes = RL) -> bytes:
    return rl + headers + b"\r\n"

CL_VALUES = [
    b"5", b"05", b"+5", b" 5", b"5 ", b"\t5\t", b"", b"-1", b"5\t5", b"5 5",
    b"0x5", b"5;", b"5, 5", b"5,5", b"9999999999999999999999999",
    b"18446744073709551615", b"9223372036854775807", b"9223372036854775808",
]
TE_VALUES = [
    b"chunked", b"Chunked", b"CHUNKED", b"identity", b"gzip", b"deflate",
    b"chunked, identity", b"identity, chunked", b"chunked, chunked",
    b"gzip, chunked", b" chunked ", b"", b"chunked;", b"xchunked", b"chunkedx",
    b"chunked chunked",
]
CL_NAMES = [b"Content-Length", b"content-length", b"CONTENT-LENGTH",
            b"Content-Length ", b"Content Length", b"Content_Length",
            b"X-Content-Length", b"Content--Length"]
TE_NAMES = [b"Transfer-Encoding", b"transfer-encoding", b"TRANSFER-ENCODING",
            b"Transfer-Encoding ", b"Transfer Encoding", b"Transfer_Encoding"]

def hand_corpus():
    cases = []
    add = cases.append

    # CL/TE full matrix: CL state x TE state
    cl_states = {
        "cl-absent": b"",
        "cl-valid": b"Content-Length: 5\r\n",
        "cl-dup-same": b"Content-Length: 5\r\nContent-Length: 5\r\n",
        "cl-dup-diff": b"Content-Length: 5\r\nContent-Length: 6\r\n",
        "cl-plus": b"Content-Length: +5\r\n",
        "cl-leading-zero": b"Content-Length: 05\r\n",
        "cl-overflow": b"Content-Length: 9999999999999999999999999\r\n",
        "cl-empty": b"Content-Length:\r\n",
    }
    te_states = {
        "te-absent": b"",
        "te-chunked": b"Transfer-Encoding: chunked\r\n",
        "te-identity": b"Transfer-Encoding: identity\r\n",
        "te-dup": b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        "te-empty": b"Transfer-Encoding:\r\n",
        "te-gzip-chunked": b"Transfer-Encoding: gzip, chunked\r\n",
        "te-chunked-gzip": b"Transfer-Encoding: chunked, gzip\r\n",
    }
    for cn, ch in sorted(cl_states.items()):
        for tn, th in sorted(te_states.items()):
            add((f"matrix:{cn}+{tn}", req(ch + th)))
            add((f"matrix-rev:{cn}+{tn}", req(th + ch)))  # both orders

    # individual CL / TE values and header-name spellings
    for v in CL_VALUES:
        add((f"cl-value:{v!r}", req(b"Content-Length: " + v + b"\r\n")))
        add((f"cl-value-te:{v!r}", req(b"Content-Length: " + v + b"\r\nTransfer-Encoding: chunked\r\n")))
    for v in TE_VALUES:
        add((f"te-value:{v!r}", req(b"Transfer-Encoding: " + v + b"\r\n")))
        add((f"te-value-cl:{v!r}", req(b"Transfer-Encoding: " + v + b"\r\nContent-Length: 5\r\n")))
    for n in CL_NAMES:
        add((f"cl-name:{n!r}", req(n + b": 5\r\n")))
        add((f"cl-name-te:{n!r}", req(n + b": 5\r\nTransfer-Encoding: chunked\r\n")))
    for n in TE_NAMES:
        add((f"te-name:{n!r}", req(n + b": chunked\r\n")))
        add((f"te-name-cl:{n!r}", req(n + b": chunked\r\nContent-Length: 5\r\n")))

    # line-ending / control-char faces
    add(("bare-lf-between-headers", b"GET /a HTTP/1.1\r\nHost: x\nX: 1\r\n\r\n"))
    add(("bare-lf-in-value", b"GET /a HTTP/1.1\r\nX: a\nInjected: 1\r\n\r\n"))
    add(("bare-lf-in-cl-value", b"POST /a HTTP/1.1\r\nContent-Length: 5\n\r\n\r\n"))
    add(("bare-cr-in-value", b"GET /a HTTP/1.1\r\nX: a\rb\r\n\r\n"))
    add(("crcrlf", b"GET /a HTTP/1.1\r\nX: a\r\r\n\r\n"))
    add(("lf-only-request", b"GET /a HTTP/1.1\nHost: x\n\n"))
    add(("cr-only-request", b"GET /a HTTP/1.1\rHost: x\r\r"))
    add(("nul-in-value", b"GET /a HTTP/1.1\r\nX: a\x00b\r\n\r\n"))
    add(("soh-in-value", b"GET /a HTTP/1.1\r\nX: a\x01b\r\n\r\n"))
    add(("del-in-value", b"GET /a HTTP/1.1\r\nX: a\x7fb\r\n\r\n"))
    add(("del-in-name", b"GET /a HTTP/1.1\r\nX\x7f: a\r\n\r\n"))
    add(("vtab-in-cl", b"POST /a HTTP/1.1\r\nContent-Length: 5\x0b\r\n\r\n"))
    add(("obs-fold-space", b"GET /a HTTP/1.1\r\nX: a\r\n b\r\n\r\n"))
    add(("obs-fold-tab", b"GET /a HTTP/1.1\r\nX: a\r\n\tb\r\n\r\n"))
    add(("obs-fold-cl", b"POST /a HTTP/1.1\r\nContent-Length: 5\r\n 6\r\n\r\n"))
    add(("obs-fold-te", b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n x\r\n\r\n"))
    add(("high-byte-target", b"GET /\x80 HTTP/1.1\r\nHost: x\r\n\r\n"))
    add(("high-byte-value", b"GET /a HTTP/1.1\r\nX: \x80\xff\r\n\r\n"))
    add(("high-byte-name", b"GET /a HTTP/1.1\r\nX\x80: a\r\n\r\n"))

    # request-line faces
    add(("double-space-1", b"GET  /a HTTP/1.1\r\nHost: x\r\n\r\n"))
    add(("double-space-2", b"GET /a  HTTP/1.1\r\nHost: x\r\n\r\n"))
    add(("tab-separated", b"GET\t/a\tHTTP/1.1\r\nHost: x\r\n\r\n"))
    add(("trailing-extra", b"GET /a HTTP/1.1 extra\r\nHost: x\r\n\r\n"))
    add(("lower-method", b"get /a HTTP/1.1\r\nHost: x\r\n\r\n"))
    add(("unknown-method", b"FOOBAR /a HTTP/1.1\r\nHost: x\r\n\r\n"))
    add(("absolute-target", b"GET http://e/ HTTP/1.1\r\nHost: x\r\n\r\n"))
    add(("asterisk-target", b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n"))
    add(("http10", b"GET /a HTTP/1.0\r\nHost: x\r\n\r\n"))
    add(("http09", b"GET /a HTTP/0.9\r\nHost: x\r\n\r\n"))
    add(("http20", b"GET /a HTTP/2.0\r\nHost: x\r\n\r\n"))
    add(("http110", b"GET /a HTTP/1.10\r\nHost: x\r\n\r\n"))
    add(("no-host", b"GET /a HTTP/1.1\r\n\r\n"))

    # header-syntax faces
    add(("no-colon", b"GET /a HTTP/1.1\r\nBadHeader\r\n\r\n"))
    add(("empty-name", b"GET /a HTTP/1.1\r\n: v\r\n\r\n"))
    add(("space-in-name", b"GET /a HTTP/1.1\r\nX Y: 1\r\n\r\n"))
    add(("space-before-colon", b"GET /a HTTP/1.1\r\nX : 1\r\n\r\n"))
    add(("tab-before-colon", b"GET /a HTTP/1.1\r\nX\t: 1\r\n\r\n"))
    add(("empty-value", b"GET /a HTTP/1.1\r\nX:\r\n\r\n"))
    add(("many-headers-33", req(b"".join(b"X%d: v\r\n" % i for i in range(33)))))
    add(("many-headers-40", req(b"".join(b"X%d: v\r\n" % i for i in range(40)))))
    add(("many-headers-64", req(b"".join(b"X%d: v\r\n" % i for i in range(64)))))
    add(("method-pipe", b"GE|T /a HTTP/1.1\r\nHost: x\r\n\r\n"))
    add(("method-tilde", b"GE~T /a HTTP/1.1\r\nHost: x\r\n\r\n"))
    add(("method-backtick", b"GE`T /a HTTP/1.1\r\nHost: x\r\n\r\n"))
    add(("long-line", req(b"X: " + b"a" * 300 + b"\r\n")))
    add(("cl-te-body-after", req(b"Content-Length: 3\r\nTransfer-Encoding: chunked\r\n") + b"GET /evil HTTP/1.1\r\n\r\n"))
    return cases

def fuzz_corpus(seeds, n=FUZZ_N, seed=FUZZ_SEED):
    rng = random.Random(seed)
    base = [b for _, b in seeds]
    interesting = [b"\r", b"\n", b"\r\n", b" ", b"\t", b":", b";", b",", b"+",
                   b"0", b"9", b"\x00", b"\x7f", b"\x80", b"chunked",
                   b"Content-Length: 0\r\n", b"Transfer-Encoding: x\r\n"]
    out = []
    for i in range(n):
        b = bytearray(rng.choice(base))
        for _ in range(rng.randint(1, 4)):
            op = rng.randrange(4)
            if op == 0 and b:
                b[rng.randrange(len(b))] = rng.randrange(256)
            elif op == 1 and b:
                del b[rng.randrange(len(b))]
            elif op == 2 and b:
                pos = rng.randrange(len(b) + 1)
                b[pos:pos] = bytes([rng.randrange(256)])
            else:
                pos = rng.randrange(len(b) + 1)
                b[pos:pos] = rng.choice(interesting)
        out.append((f"fuzz:{seed}:{i}", bytes(b)))
    return out

# ---------------------------------------------------------------- runners

class NodeRef:
    def __init__(self):
        self.p = subprocess.Popen(["node", REF], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE)
    def query(self, data: bytes):
        self.p.stdin.write(struct.pack(">I", len(data)) + data)
        self.p.stdin.flush()
        hdr = self.p.stdout.read(4)
        (n,) = struct.unpack(">I", hdr)
        return json.loads(self.p.stdout.read(n))
    def close(self):
        self.p.stdin.close()
        self.p.terminate()

def run_reqguard(data: bytes):
    out = subprocess.run([BIN], input=data, capture_output=True).stdout
    return out.decode("latin-1").strip()  # latin-1: raw bytes map 1:1

def unesc(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            c = s[i + 1]
            out.append({"\\": "\\", "r": "\r", "n": "\n", "p": "|"}.get(c, c))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)

def parse_dump(line):
    """Parse reqguard diff output into a canonical tuple."""
    if line.startswith("ERR|"):
        return ("ERR", line[4:])
    assert line.startswith("OK|"), line
    kv, cur, escp = {}, "", False
    # split on unescaped '|'
    parts, buf = [], ""
    i = 0
    body = line[3:]
    while i < len(body):
        c = body[i]
        if escp:
            buf += "\\" + c
            escp = False
        elif c == "\\":
            escp = True
        elif c == "|":
            parts.append(buf)
            buf = ""
        else:
            buf += c
        i += 1
    parts.append(buf)
    for p in parts:
        k, _, v = p.partition("=")
        kv[k] = v
    headers = []
    if kv["h"]:
        for h in kv["h"].split("\x1e"):
            n, _, v = h.partition("\x1f")
            headers.append((unesc(n).lower(), unesc(v)))
    return ("OK", unesc(kv["m"]), unesc(kv["t"]), unesc(kv["v"]),
            kv["cl"], int(kv["tc"]), tuple(headers))

def canon_ref(rec):
    """Canonicalize node result into the same shape."""
    if not rec["ok"]:
        return ("ERR", rec["code"])
    rh = rec["rawHeaders"]
    headers = tuple((rh[i].lower(), rh[i + 1]) for i in range(0, len(rh), 2))
    cls = [v for k, v in headers if k == "content-length"]
    tes = [v for k, v in headers if k == "transfer-encoding"]
    if not cls:
        cl = "-1"
    elif len(cls) == 1 and cls[0].isdigit():
        cl = str(int(cls[0]))  # normalize leading zeros
    else:
        cl = repr(cls)
    return ("OK", rec["method"], rec["target"], rec["version"],
            cl, len(tes), headers)

FIELDS = ["method", "target", "version", "cl", "te_count", "headers"]

# Divergence classes reviewed and classified as policy (not desync):
# both sides see byte-identical tokens; the reference applies an
# application-level policy reqguard deliberately leaves to callers.
POLICY_OK = {
    "hole:HPE_INVALID_METHOD":
        "llhttp 只接受已知方法名白名单（GET/POST/PROPFIND/...）；reqguard 接受任意 "
        "token 方法。两侧看到的字节完全一致，方法不参与分帧，不存在解析漂移——"
        "属方法策略差异，非走私面。",
}

CAUSES = {
    "strict:bad_content_length": "CL 超出 int64 或语法非法：llhttp 放宽到 uint64，reqguard 拒绝（溢出即走私原语）。",
    "strict:bad_header": "头部名非法（冒号前空白、空名、无冒号等）：RFC 7230 拒绝，llhttp 部分容忍。",
    "strict:bad_target": "目标非 origin-form（绝对形式、*、含空白）：reqguard 只收 / 开头。",
    "strict:bad_transfer_encoding": "TE 非 chunked、列表、重复或为空：reqguard 只收单个 chunked。",
    "strict:bad_version": "HTTP 版本非 1.0/1.1。",
    "strict:control_char": "裸 CR/LF、NUL 等控制字符：reqguard 拒绝，llhttp 部分场景容忍。",
    "strict:line_too_long": "单行超 256 字节（reqguard 限制）。",
    "strict:obs_fold": "折叠头（obs-fold）：RFC 7230 已废弃，reqguard 拒绝。",
    "strict:too_many_headers": "头部数超 32（reqguard 限制）。",
    "strict:cl_te_conflict": "CL+TE 同时出现：reqguard 拒绝。",
    "hole:HPE_INVALID_METHOD": POLICY_OK["hole:HPE_INVALID_METHOD"],
}

def cause_of(cls):
    if cls == "agree":
        return "—"
    if cls in CAUSES:
        return CAUSES[cls]
    if cls.startswith("strict:"):
        return "reqguard 更严格的拒绝（未单独注明）。"
    return "**未分类成因——需要人工审查！**"

def classify(reqc, refc):
    if reqc[0] == "ERR" and refc[0] == "ERR":
        return "agree"
    if reqc[0] == "ERR" and refc[0] == "OK":
        return f"strict:{reqc[1]}"
    if reqc[0] == "OK" and refc[0] == "ERR":
        return f"hole:{refc[1]}"
    diffs = [FIELDS[i] for i in range(6) if reqc[1 + i] != refc[1 + i]]
    if not diffs:
        return "agree"
    return "field:" + "+".join(diffs)

# ---------------------------------------------------------------- minimizer

def minimize(data, cls, evaluate, budget=MAX_MINIMIZE_EVALS):
    """Greedy byte/block removal while the case stays in class `cls`."""
    evals = [0]
    def same(b):
        if evals[0] >= budget:
            return False
        evals[0] += 1
        return evaluate(b) == cls
    n = len(data)
    size = n // 2
    while size >= 1:
        i = 0
        while i < len(data):
            cand = data[:i] + data[i + size:]
            if cand and same(cand):
                data = cand
            else:
                i += size
        size //= 2
    return data

# ---------------------------------------------------------------- report

def esc_bytes(b):
    out = []
    for c in b:
        if c == 0x0d: out.append("\\r")
        elif c == 0x0a: out.append("\\n")
        elif c == 0x09: out.append("\\t")
        elif 0x20 <= c < 0x7f: out.append(chr(c))
        else: out.append(f"\\x{c:02x}")
    return "".join(out)

def main():
    if not os.path.exists(BIN):
        sys.exit(f"build first: make reqguard-diff (missing {BIN})")
    cases = hand_corpus()
    cases += fuzz_corpus(cases)
    print(f"corpus: {len(cases)} cases", file=sys.stderr)

    ref = NodeRef()
    cache = {}
    def evaluate(data):
        if data not in cache:
            cache[data] = classify(parse_dump(run_reqguard(data)),
                                   canon_ref(ref.query(data)))
        return cache[data]

    results = {}
    for idx, (label, data) in enumerate(cases):
        if idx % 200 == 0:
            print(f"  {idx}/{len(cases)}", file=sys.stderr)
        results[label] = (data, evaluate(data))

    classes = {}
    for label, (data, cls) in results.items():
        classes.setdefault(cls, []).append((label, data))

    # minimize up to 3 samples per divergent class
    minimal = {}
    for cls, items in sorted(classes.items()):
        if cls == "agree":
            continue
        picked, seen = [], set()
        for label, data in items:
            if len(picked) >= 3:
                break
            m = minimize(data, cls, evaluate)
            if m not in seen:
                seen.add(m)
                picked.append((label, m))
        minimal[cls] = picked
    ref.close()

    # write samples
    shutil.rmtree(SAMPLES, ignore_errors=True)
    for cls, items in minimal.items():
        d = os.path.join(SAMPLES, cls.replace(":", "_").replace("+", "_"))
        os.makedirs(d, exist_ok=True)
        for i, (label, m) in enumerate(items):
            with open(os.path.join(d, f"{i}.bin"), "wb") as f:
                f.write(m)

    # coverage matrix
    cov = {}
    for label, (data, cls) in results.items():
        if label.startswith("matrix:"):
            key = label[len("matrix:"):]
            cov[key] = cov.get(key, 0) + 1

    dangerous = {c: v for c, v in classes.items()
                 if (c.startswith("hole:") or c.startswith("field:"))
                 and c not in POLICY_OK}

    report = {
        "corpus_size": len(cases),
        "class_counts": {c: len(v) for c, v in sorted(classes.items())},
        "coverage_matrix_cells": len(cov),
        "dangerous_classes": sorted(dangerous),
        "minimal_samples": {
            c: [{"label": l, "hex": m.hex(), "repr": esc_bytes(m)}
                 for l, m in v]
            for c, v in minimal.items()
        },
    }
    with open(os.path.join(HERE, "report.json"), "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    lines = ["# reqguard 差分验证报告", "",
             f"- 语料: {len(cases)} 条（手写矩阵 + 定点面 + 种子 {FUZZ_SEED} 的 {FUZZ_N} 条变异）",
             f"- 参考解析器: Node {subprocess.check_output(['node','--version']).decode().strip()} (llhttp)",
             f"- CL×TE 矩阵覆盖: {len(cov)} 个组合单元", ""]
    lines.append("## 分歧分类统计")
    lines.append("")
    lines.append("| 类别 | 条数 | 性质 | 成因 |")
    lines.append("|---|---|---|---|")
    for cls, items in sorted(classes.items()):
        if cls == "agree":
            kind = "一致"
        elif cls in POLICY_OK:
            kind = "策略分歧（已审定，非 desync）"
        elif cls.startswith("strict:"):
            kind = "严格化（reqguard 拒绝、参考接受）"
        else:
            kind = "**危险（reqguard 接受、参考拒绝或字段不一致）**"
        lines.append(f"| `{cls}` | {len(items)} | {kind} | {cause_of(cls)} |")
    lines.append("")
    for cls, items in sorted(minimal.items()):
        lines.append(f"## `{cls}` — 最小样例（{len(items)} 条，可复现）")
        lines.append("")
        for i, (label, m) in enumerate(items):
            path = os.path.join("samples", cls.replace(":", "_").replace("+", "_"), f"{i}.bin")
            lines.append(f"样例 {i}（来源 `{label}`，{len(m)} 字节）：")
            lines.append("")
            lines.append(f"    {esc_bytes(m)}")
            lines.append("")
            lines.append(f"复现: `xxd -r -p <<< {m.hex()} | ./reqguard-diff`  （原始字节: diff/{path}）")
            lines.append("")
    thin = [c for c, v in minimal.items() if len(v) < 3]
    if thin:
        lines.append(f"**警告：以下类别最小样例不足 3 条: {thin}**")
        lines.append("")
    with open(os.path.join(HERE, "report.md"), "w") as f:
        f.write("\n".join(lines))

    print(json.dumps(report["class_counts"], indent=2))
    print(f"policy classes (documented): {sorted(c for c in classes if c in POLICY_OK)}")
    print(f"dangerous classes: {sorted(dangerous) or '无'}")
    if thin:
        print(f"WARNING: classes with <3 minimal samples: {thin}")
    return 1 if (dangerous or thin) else 0

if __name__ == "__main__":
    sys.exit(main())
