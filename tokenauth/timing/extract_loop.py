#!/usr/bin/env python3
"""
extract_loop.py - 从完整函数反汇编中提取内联的常量时间比较循环窗口。

在 -O2 生产构建里 ct_equal 会被内联进 verify（还可能被自动向量化为
SSE：pxor/por，4 次 16 字节迭代）。本脚本定位“循环体含 xor/pxor 比较
加 or/por 累积”的反向跳转循环，并把循环后的归约段（psrldq/por/movd/
test/je）一并纳入窗口，输出交给 check_disasm.py 判定。

verify 里的 nonce 回放缓存搜索循环只有 cmp/je、没有异或累积，不会被误选。

用法: python3 extract_loop.py disasm_full_function.txt > window.txt
"""
import re
import sys

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\s+(\w+)(?:\s+(.*))?$")
JCC = {
    "je", "jne", "jl", "jle", "jg", "jge", "jb", "jbe", "ja", "jae",
    "js", "jns", "jo", "jno", "jp", "jnp",
}
REDUCTION = {"por", "psrldq", "movdqa", "movd", "test", "movzx"}


def parse(lines):
    rows = []
    for line in lines:
        m = LINE_RE.match(line)
        if m:
            addr = int(m.group(1), 16)
            mnem = m.group(2)
            target = None
            if mnem.startswith("j"):
                tm = re.search(r"([0-9a-f]+)\b", m.group(3) or "")
                if tm:
                    target = int(tm.group(1), 16)
            rows.append({"line": line.rstrip("\n"), "addr": addr,
                         "mnem": mnem, "target": target})
    return rows


def main():
    rows = parse(open(sys.argv[1]))
    # 1. 找循环体含异或比较 + OR 累积的反向条件跳转
    candidate = None
    for i, r in enumerate(rows):
        if r["mnem"] in JCC and r["target"] is not None and r["target"] < r["addr"]:
            body = [x for x in rows if r["target"] <= x["addr"] <= r["addr"]]
            mnems = {x["mnem"] for x in body}
            has_xor = bool(mnems & {"xor", "pxor"})
            has_or = bool(mnems & {"or", "por"})
            if has_xor and has_or:
                candidate = (r["target"], i)
                break
    if candidate is None:
        print("未找到异或+累积形态的比较循环", file=sys.stderr)
        sys.exit(2)

    loop_start, edge_idx = candidate
    start_idx = next(i for i, x in enumerate(rows) if x["addr"] == loop_start)

    # 2. 向后扩展，纳入循环外归约段，止于归约后的第一条条件跳转
    end_idx = edge_idx
    saw_test = False
    for j in range(edge_idx + 1, len(rows)):
        m = rows[j]["mnem"]
        if m in JCC:
            end_idx = j  # 归约结论跳转（循环外，基于全量累积结果）
            break
        if m == "test":
            saw_test = True
            end_idx = j
            continue
        if saw_test or m not in REDUCTION:
            break
        end_idx = j

    for x in rows[start_idx:end_idx + 1]:
        print(x["line"])


if __name__ == "__main__":
    main()
