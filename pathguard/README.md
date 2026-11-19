# pathguard

不可信相对路径的策略校验，运行在进程级沙箱里。

`make test` 跑自检，`make bench` 跑性能对比。

## 设计要点

校验与打开发生在同一个已受约束的进程里：父进程摆好夹具后 fork，子进程先
自己进沙箱（user namespace → 清空 capabilities → Landlock → rlimit →
seccomp），之后才做名字校验、`openat2(2)` 和读取。校验通过的字节串直接交给
`openat2`，中间不存在"先 check 再 use"的窗口；即使校验本身被绕过，Landlock
仍然按内核里的目录策略拒绝越界。

分层：

| 层 | 作用 | 关掉后的失败用例 |
|---|---|---|
| user namespace | 对宿主对象没有特权 | 争抢 uid 映射 |
| capabilities | bounding/effective 全清、securebits 锁定 | `caps=0` 断言 |
| Landlock | 内核对整个进程做 deny-by-default 文件策略 | 符号链接绕过、TOCTOU |
| rlimit | 句柄/文件大小/CPU/进程数/地址空间 | `EMFILE`、`SIGXFSZ` 用例 |
| seccomp | 系统调用白名单，其余返回 `EPERM` | `socket`/`fork`/`ptrace`/`open` 探测 |

打开统一走 `openat2` 且带
`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`，
路径解析本身即为安全边界。`O_PATH` 打开符号链接在 `RESOLVE_NO_SYMLINKS`
下返回 `ELOOP`，因此也不能借 `O_PATH` + `openat` 二次打开绕过。

## 测试覆盖

- 策略层 12 个非法名（含 `%00`、`%2f`、空段）与 3 个合法名。
- 沙箱前：`naive` 模式复现审计问题（校验后普通打开，能读到 `outside-secret`）。
- 沙箱后：`sb_naive` 保留"不加固的打开"以证明 Landlock 单独也拦得住；
  `sb_full` 走完整链路，正向读取与 `scratch/` 写入仍可用，写 `data/` 被拒。
- 系统调用：`socket`/`chdir`/`ptrace`/`fork`/`open` 均 `EPERM`，且进程仍能
  继续输出并正常退出（白名单外的调用不是杀进程）。
- rlimit：`EMFILE`、超过 `RLIMIT_FSIZE` 时的 `SIGXFSZ`。
- TOCTOU：校验后由父进程用 `renameat2` 把目录换成指向外部的符号链接再打开，
  `naive` 泄漏、沙箱版被拒，结果与调度时序无关。

## 性能

`make bench`（本机 WSL2，内核 6.18.33.2-microsoft-standard-WSL2，Landlock
ABI 7，gcc 13.3 -O2，每次 20000 次 open+read，取 5 轮最优）：

| 路径 | ns/op | ops/s | 相对裸 openat2 |
|---|---|---|---|
| 裸 `openat2`（无校验、无 resolve） | ~2330 | ~429k | — |
| 校验 + resolve flags | ~2530 | ~395k | +8% |
| 再叠加 Landlock + seccomp + rlimit | ~3500 | ~286k | +50% |

沙箱建立本身是一次性开销：进入 user namespace 并清空 capabilities 约
70–90 µs；装 Landlock 规则、seccomp 过滤器和 rlimit 约 50–60 µs。按进程
摊销，不落在每次打开上。数字随内核和 CPU 浮动，以 `make bench` 现场输出为准。

## 内核与发行版要求

| 能力 | 最低内核 | 本机 |
|---|---|---|
| `openat2` + `RESOLVE_BENEATH/NO_SYMLINKS/NO_MAGICLINKS/NO_XDEV` | 5.6 | 6.18 ✓ |
| Landlock (ABI 1) | 5.13（需 `CONFIG_SECURITY_LANDLOCK=y`） | ABI 7 ✓ |
| Landlock `REFER` / `TRUNCATE` / `IOCTL_DEV` | ABI 2 / 3 / 5 | ABI 7 ✓ |
| seccomp filter + `SECCOMP_RET_ERRNO` | 3.5 | ✓ |
| 非特权 user namespace | 3.8（Debian/Ubuntu 若关闭需 sysctl） | ✓ |
| 非特权 seccomp 需 `no_new_privs` | 3.5 | ✓ |

兼容处理：Landlock ABI 通过 `LANDLOCK_CREATE_RULESET_VERSION` 探测，只向内核
申请它认识的访问位（多传位会 `EINVAL`）；无 user namespace 时降级为
"清空 capabilities + Landlock + seccomp"，仍为内核强制；Landlock 完全不可用
时 `pg_sandbox_lock` 返回失败而不是静默放行。

## 已知边界

- Landlock 是路径层级授权：被授权目录内部的硬链接可以读到目录外同 inode 的
  内容。夹具因此把秘密放在授权目录的**兄弟**目录，避免测试给出假阳性。
- `RLIMIT_NPROC=1` 在 root 下不生效；守护进程实际使用时按目标账户调整。
- seccomp 白名单刻意很短，工作进程用原始 `write(2)` 输出；若要让被沙箱化的
  代码使用完整 libc，需要按 `strace` 结果放宽白名单。
