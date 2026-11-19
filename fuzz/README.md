# fuzz/ — 变异模糊测试驱动

为 `reqguard`、`pathguard`、`tokenauth` 三个组件提供统一的模糊测试驱动。
引擎（`engine.c`）只用 libc + POSIX，不引入任何外部模糊器或额外库；
内存/未定义行为检测依赖编译器自带的 ASan/UBSan/LSan（`-fsanitize=`，
随 gcc/clang 发行，不属于新增依赖）。

## 文件

| 文件 | 作用 |
|---|---|
| `engine.h` / `engine.c` | 模糊测试引擎：种子加载、字节变异、fork 隔离、看门狗、故障分类、最小化、清单落盘 |
| `harness_reqguard.c` | reqguard 解析器入口（直接包含组件源码，`main` 改名让出进程入口） |
| `harness_pathguard.c` | pathguard 路径校验入口 |
| `harness_tokenauth.c` | tokenauth 令牌校验入口（每个 worker 独立初始化双密钥状态） |
| `harness_selftest.c` | 故意带缺陷的靶标，仅用于验证引擎本身（崩溃/超时/泄漏三类） |
| `Makefile` | 用 `-fsanitize=address,undefined` 构建全部驱动 |
| `run_fuzz.sh` | 活动编排：建种子、跑 campaign、复现校验、确定性校验 |

## 运行

```sh
make                      # 构建四个 fuzz-* 驱动（带 ASan/UBSan）
make seeds                # 从各 harness 的规范种子生成 corpus/
./run_fuzz.sh             # 完整活动：每个组件 100,000 次
./run_fuzz.sh smoke       # 快速冒烟：每个组件 2,000 次
./run_fuzz.sh selftest    # 引擎自测：在带缺陷靶标上验证全链路
```

退出码 0 表示全部组件零崩溃、零超时、零泄漏；任一发现则非零。

## 引擎设计

### 变异（从种子出发的字节变异）

- 每个输入从 `corpus/<target>/` 中的某个种子复制后变异；活动开始前
  所有种子还会**原样**先跑一遍（smoke pass）。
- xorshift64 PRNG 驱动，`--rng-seed` 决定整条变异序列，同种子重跑
  结果逐次确定（selftest 中校验两轮的发现迭代点一致）。
- 变异算子：位翻转/兴趣字节替换、插入、删除、块复制、块移动、
  算术增减、随机截断/扩展；单轮 1–4 个算子叠加。

### 故障记录（崩溃 / 超时 / 泄漏）

- 每批输入在一个 `fork()` 出的 worker 里执行，目标崩溃不会影响活动本身。
- 崩溃：worker 被信号杀死（ASan/UBSan 配置为 `abort_on_error=1`），
  父进程按信号分类为 `crash`。
- 超时：父进程看门狗（默认每输入 1000ms，批超时按输入数收窄），
  超时发 `SIGKILL`，分类为 `timeout`。
- 泄漏：LSan 在 worker `exit()` 时扫描；引擎通过读取该 worker 的
  sanitizer 日志（`log_path=<out>/logs/asan.<pid>`）中的
  `LeakSanitizer` 报告，把泄漏中止与普通崩溃区分开，分类为 `leak`。
- 批 worker 异常后用单输入隔离重放（pinpoint）定位具体输入，再保存。
- 每个发现保存原始样例 `<kind>-NN.raw`、最小化样例 `<kind>-NN.min`，
  并写入机器可读的 `manifest.json`（类型、信号码、迭代次数、大小、路径）。

### 失败样例自动最小化

两段式最小化，预算 20,000 次试跑：

1. ddmin 风格的分块删除（粒度从半长逐级收缩到单字节）；
2. 逐字节替换（向 `\0`、`\n`、`\r`、空格、`A`、`0` 等简单值靠拢）。

每一步都在带看门狗的独立进程中验证，只有**仍然触发同一类故障**的
缩减才保留。selftest 靶标上的实测效果：15→9 字节、16→4 字节、13→4 字节。

### 最小样例可复现

```sh
# 独立复现，退出码：0 干净 / 70 崩溃 / 76 超时 / 23 泄漏
ASAN_OPTIONS="...:log_path=<dir>/asan" FUZZ_LOG_DIR=<dir> \
    ./fuzz-<target> oneshot --input out/<target>/crash-00.min

# 对任意样例重新最小化
./fuzz-<target> minimize --input x.raw --output x.min --kind crash
```

`run_fuzz.sh selftest` 会对每个最小样例跑 oneshot 并核对退出码，
再跑一次 `minimize` 子命令验证可重复最小化。

## 输出目录

```
out/<target>/
├── manifest.json        # 活动参数与全部发现
├── <kind>-NN.raw        # 原始失败输入
├── <kind>-NN.min        # 最小化后的失败输入（oneshot 可直接复现）
└── logs/asan.<pid>      # 各 worker 的 sanitizer 日志
```

## 依赖边界

- 引擎包含的头文件全部是 libc/POSIX 标准头（`unistd.h`、`sys/wait.h`、
  `fcntl.h`、`time.h` 等），无任何第三方头文件或库。
- `fuzz-tokenauth` 额外链接 `-lcrypto`，与原组件的构建依赖完全相同。
- 去掉 sanitizer 也能编译运行（仅失去内存/UB 检测能力）：
  `gcc -O1 -std=c11 harness_pathguard.c engine.c -o fuzz-plain`。
