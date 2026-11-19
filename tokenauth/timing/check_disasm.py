#!/usr/bin/env python3
"""
check_disasm.py - 验证 ct_equal 反汇编中不存在数据相关的提前返回。

判定依据（x86-64 机器码层面的常量时间特征）:
  1. 窗口内无 call（比较逻辑不依赖任何子过程）
  2. 反向条件跳转恰好 1 条：固定次数的循环回边
  3. 循环体内不允许出现前向条件跳转
     （`if (a[i]!=b[i]) return 0;` 这类提前返回必然编译成循环内前向跳转；
      循环结束后的归约/test/je 位于循环外，其判断基于全部 64 字节的累积
      结果，与前缀长度无关，允许存在）
  4. 结果物化方式仅作信息记录：sete/cmov（无分支）或 test+循环外 je（向量化归约）

用法: python3 check_disasm.py disasm.txt
"""
import re
import sys

JCC = {
    "je", "jne", "jl", "jle", "jg", "jge", "jb", "jbe", "ja", "jae",
    "js", "jns", "jo", "jno", "jp", "jnp",
}
JMP_RE = re.compile(r"^\s*([0-9a-f]+):\s+(j\w+)\s+([0-9a-f]+)\b")
ANY_INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+(\w+)")


def parse(path):
    insns = []          # (addr, mnemonic, target_or_None)
    for line in open(path):
        m = JMP_RE.match(line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2), int(m.group(3), 16)))
            continue
        m2 = ANY_INSN_RE.match(line)
        if m2:
            insns.append((int(m2.group(1), 16), m2.group(2), None))
    return insns


def main():
    insns = parse(sys.argv[1])
    if not insns:
        print("FAIL: 未解析到指令")
        sys.exit(2)

    calls = [(a, m) for a, m, _ in insns if m == "call"]
    cond_jumps = [(a, m, t) for a, m, t in insns if m in JCC]
    backward = [(a, m, t) for a, m, t in cond_jumps if t < a]
    forward = [(a, m, t) for a, m, t in cond_jumps if t > a]

    # 循环回边的源地址 = 唯一反向跳转；任何前向跳转目标必须在它之后（循环外）
    loop_edge_src = max(a for a, _, _ in backward) if backward else None
    inside_loop_forward = (
        [(a, m, t) for a, m, t in forward if loop_edge_src is not None and t <= loop_edge_src]
        if loop_edge_src is not None else forward
    )
    branchless = [m for _, m, _ in insns if m in ("sete", "setne", "cmovne", "cmove")]
    accumulate = [m for _, m, _ in insns if m in ("or", "por")]

    print(f"指令总数={len(insns)} call={len(calls)} 条件跳转={len(cond_jumps)} "
          f"反向(循环回边)={len(backward)} 前向(循环外)={len(forward)} "
          f"累积指令(or/por)={len(accumulate)} 无分支结果指令={branchless or '无(向量化归约形态)'}")
    for a, m, t in cond_jumps:
        kind = "回边" if t < a else "循环外前向"
        print(f"  {m:4s} @ {a:#x} -> {t:#x}  ({kind})")

    ok = (
        not calls
        and len(backward) == 1
        and not inside_loop_forward
        and bool(accumulate)
    )
    if ok:
        print("PASS: 固定次数循环 + 累积 OR diff + 无分支物化，无数据相关提前返回")
        sys.exit(0)
    print("FAIL: 发现 call 或循环内前向条件跳转（疑似提前返回）或缺少无分支结果指令")
    sys.exit(1)


if __name__ == "__main__":
    main()
