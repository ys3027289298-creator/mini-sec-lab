#!/usr/bin/env bash
#
# run.sh - 一键复现 ct_equal 常量时间时序实验。
#
# 步骤:
#   1. 按生产参数 (-O2) 构建 tokenauth 并保留测试构建产物
#   2. 采集反汇编证据（生产二进制内联点 + 测试二进制独立符号）
#   3. 运行 harness：k=0..64 共 65 组、每组 ROUNDS 次（默认 1000）
#   4. 纯标准库 Python 分析，输出报告
#
# 可覆盖: ROUNDS=2000 CC=clang ./run.sh
set -euo pipefail

cd "$(dirname "$0")"

ROUNDS="${ROUNDS:-1000}"
CC="${CC:-gcc}"
OUT="out"
mkdir -p "$OUT"

echo "== [1/4] 构建 =="
# 生产构建（与 tokenauth/Makefile 完全一致的参数）
make -C .. clean >/dev/null
make -C .. CC="$CC"
# 测试构建：保留独立 ct_equal 符号（volatile 函数指针已阻止内联，-fno-inline-functions 双保险）
"$CC" -O2 -std=c11 -Wall -Wextra -fno-inline-functions -g \
    timing_harness.c -o "$OUT/timing_harness" -lcrypto

echo "== [2/4] 反汇编证据 -> $OUT/disasm_*.txt =="
# 生产二进制：ct_equal 在 -O2 下被内联进 verify（可能带 .constprop 克隆后缀），
# objdump 以空行分隔函数
objdump -d --no-show-raw-insn -M intel ../tokenauth \
    | sed -n '/<verify\([.a-z0-9]*\)>:/,/^$/p' > "$OUT/disasm_production_verify.txt"
# 测试二进制：独立 ct_equal 符号
objdump -d --no-show-raw-insn -M intel "$OUT/timing_harness" \
    | sed -n '/<ct_equal>:/,/^$/p' > "$OUT/disasm_harness_ct_equal.txt"
# 正对照脆弱实现：应能看到循环体内的前向条件跳转（提前 return）
objdump -d --no-show-raw-insn -M intel "$OUT/timing_harness" \
    | sed -n '/<vuln_equal>:/,/^$/p' > "$OUT/disasm_harness_vuln.txt"

echo "--- 独立 ct_equal 反汇编 ---"
cat "$OUT/disasm_harness_ct_equal.txt"

# 结构检查（基于跳转方向语义，见 check_disasm.py 头部说明）
echo "--- 独立符号结构检查 ---"
python3 check_disasm.py "$OUT/disasm_harness_ct_equal.txt" | tee "$OUT/disasm_struct_check.txt"

# 生产二进制：ct_equal 已被内联进 verify（-O2 下可能自动向量化为 SSE），
# 先提取内联比较循环窗口，再用同一检查器判定无提前返回。
# verify 里的 nonce 回放搜索循环无异或累积，提取器不会误选。
python3 extract_loop.py "$OUT/disasm_production_verify.txt" \
    > "$OUT/disasm_production_inlined_loop.txt"
echo "--- 生产 verify() 内联比较循环（提取窗口）---"
cat "$OUT/disasm_production_inlined_loop.txt"
echo "--- 生产内联循环结构检查 ---"
python3 check_disasm.py "$OUT/disasm_production_inlined_loop.txt" | tee -a "$OUT/disasm_struct_check.txt"
echo "--- 正对照 vuln_equal 结构（预期：检查器报 FAIL，存在循环内前向跳转）---"
cat "$OUT/disasm_harness_vuln.txt"
if python3 check_disasm.py "$OUT/disasm_harness_vuln.txt" > "$OUT/vuln_struct_check.txt" 2>&1; then
    echo "意外：脆弱实现也通过了常量时间结构检查" >&2
    exit 1
else
    cat "$OUT/vuln_struct_check.txt"
    echo "（符合预期：vuln_equal 含数据相关提前返回）"
fi

echo "== [3/4] 运行测量 (ROUNDS=$ROUNDS, 每组样本数) =="
# taskset 再做一层核心绑定（harness 内部也会 sched_setaffinity）
taskset -c 0 "$OUT/timing_harness" "$ROUNDS" \
    2> "$OUT/harness_stderr.txt" | tee "$OUT/samples.csv" >/dev/null
cat "$OUT/harness_stderr.txt"

LINES=$(($(wc -l < "$OUT/samples.csv") - 1))
# noop ROUNDS 行 + 三个 65 组模式（ct_equal/vuln/verify）各 ROUNDS*65 行
EXPECTED=$((ROUNDS * (1 + 65 * 3)))
echo "CSV 数据行 = $LINES（预期 $EXPECTED）"
[ "$LINES" -eq "$EXPECTED" ]

echo "== [4/4] 统计分析 =="
python3 analyze.py "$OUT/samples.csv" --report "$OUT/report.txt"

echo
echo "产物: $OUT/  (samples.csv, report.txt, disasm_*.txt, harness_stderr.txt)"
