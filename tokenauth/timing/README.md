# ct_equal 常量时间比较的时序测量

验证 `../src/tokenauth.c` 中 `ct_equal()` 是否会通过时序泄露正确前缀长度。

## 复现

```bash
./run.sh                 # 默认每组 1000 次，约 10 秒
ROUNDS=2000 ./run.sh     # 自定义每组样本数
CC=clang ./run.sh        # 换编译器
```

产物全部在 `out/`：

| 文件 | 内容 |
|---|---|
| `samples.csv` | 原始样本（mode,round,order,k,cycles），196000 行 |
| `report.txt` | 统计分析报告（同 stdout） |
| `disasm_harness_ct_equal.txt` | 独立 `ct_equal` 反汇编 |
| `disasm_harness_vuln.txt` | 正对照脆弱实现 `vuln_equal` 反汇编 |
| `disasm_production_verify.txt` | 生产 `-O2` 二进制的 `verify` 全函数 |
| `disasm_production_inlined_loop.txt` | 从中提取的内联比较循环（SSE 向量化形态） |
| `disasm_struct_check.txt` / `vuln_struct_check.txt` | 结构自动检查结果 |

## 测量设计

- **被测代码就是生产源码**：`timing_harness.c` 直接 `#include "../src/tokenauth.c"`，
  不复制实现；生产构建参数 `-O2 -std=c11` 与 `tokenauth/Makefile` 一致。
- **65 个组**：正确前缀长度 k=0..64，所有组固定比较 n=64 字节，仅前 k 字节相同。
  每组 1000 次（`ROUNDS` 可调）。
- **计时**：`cpuid` 序列化 + `rdtsc`/`rdtscp` 读 invariant TSC 周期数
  （本机 CPU 支持 `constant_tsc`/`rdtscp`）；进程 `sched_setaffinity` 绑核，
  `run.sh` 再用 `taskset -c 0` 双保险。
- **防内联**：`ct_equal` 经 volatile 函数指针调用，编译器无法内联，
  测到的是独立函数的真实 call 开销；另加 `-fno-inline-functions` 双保险。
- **抗漂移**：固定种子 xorshift64 + Fisher-Yates，每轮把 65 组随机交错，
  时间漂移不与 k 相关；先做 10000 次预热。
- **三种测量模式**：
  - `ct_equal`：直接测目标函数（主证据）
  - `vuln`：正对照，故意写成逐字节提前返回的脆弱实现，验证管线能检出泄露
  - `verify`：端到端测真实 `verify()` 路径（旁证，HMAC 固定开销占主导）
  - 另有 `noop` 空函数基线，量化计时框架自身开销

## 判定方法与测量机限制

测量机为 WSL2，无实时调度权限（`chrt`/`nice` 均被拒），OS 中断产生正偏长尾。
实践中观察到两个陷阱，分析脚本（`analyze.py`，纯标准库）据此设计：

1. **原始均值不可靠**：长尾离群随机落在不同组，重复试验里曾出现原始均值
   Pearson p<0.05 的假阳性（同期稳健尺度零方差、KW 不显著）。
2. **裸 min-of-N 也会抖动**：某组 1000 次里恰好没抓到最低档样本时，
   min 停在次低档，产生与 k 无关的单组离群。

因此否决判据锚定**确定性尺度**：

- **主判据（2% 阈值）**：1% 分位数离散度与中位数离散度均 < 2%
  （`(max-min)/min`，跨 65 组）
- **显著性**：确定性尺度 `|r(k,p01)|`、`|r(k,median)|` < 0.2，
  且 Kruskal-Wallis p ≥ 0.05
- 原始均值、5% 截尾均值、裸 min 仅披露不参与否决；置换检验 2000 次、
  固定种子，p 值可复现

## 反汇编证据（无提前返回）

`check_disasm.py` 基于跳转方向语义做自动结构检查，判据：

1. 无 `call`；
2. 反向条件跳转恰好 1 条（固定次数循环回边）；
3. 循环体内无前向条件跳转——`if (a[i]!=b[i]) return 0;` 这类提前返回
   必然编译成循环内前向跳转；
4. 存在 `or`/`por` 累积指令。

- 独立 `ct_equal`：标量循环，`diff |= a[i]^b[i]` 累积，循环后一条 `sete`
  无分支物化结果，检查 **PASS**。
- 生产 `-O2` 内联进 `verify` 后被自动向量化：4 次 16 字节 SSE 迭代
  （`pxor`+`por`），固定回边，循环后 `psrldq` 归约 + 一条循环外 `je`
  （判断的是全部 64 字节的累积结果，与前缀长度无关），检查 **PASS**。
- 正对照 `vuln_equal`：循环体内存在前向 `je` 跳到提前 `ret`，检查 **FAIL**
  （符合预期，`run.sh` 以此确认检查器有效）。

## 本次结论

在本机（AMD Ryzen 9700X，WSL2，gcc 13，`-O2`）噪声水平下，**未观测到
`ct_equal` 与正确前缀长度相关的时序泄露**：p01/中位数离散度 0.000%、
确定性尺度相关为 0、KW 不显著；同一管线在正对照上稳定检出强信号
（r(k,p01)≈+0.83，离散度 100%+），阴性结论有效。
