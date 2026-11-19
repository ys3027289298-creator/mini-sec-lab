# checker — 安全不变量检查器

把散落在各组件自测里的安全不变量抽成统一的可执行断言，对三个组件用同一套机制调用。

## 设计

```
invariants.json           不变量目录：id、accept/reject 类型、期望错误码、中文描述
run_checks.py             检查器本体，不含任何组件特有逻辑
drv_json.h                三个 driver 共享的极简 JSONL 行协议（仅头文件）
<component>_drv.c         各组件的统一入口，复用组件自身源码
cases/<component>/*.json  用例清单：步骤 + 期望 + 引用的不变量
```

统一驱动协议（每行一个扁平 JSON 对象）：

- 检查器向 driver 的 stdin 写请求，从 stdout 读回复，一一对应；
- driver 只暴露"输入 → 状态码"的判定结果，例如
  `{"op":"check","path":"/etc/passwd"}` → `{"status":"absolute"}`；
- `run_checks.py` 对三个组件走完全相同的代码路径，没有组件分支。

## 不变量如何被断言

每条不变量在 `invariants.json` 中声明为：

- `accept`：合法输入必须被接受；
- `reject`：攻击输入必须被拒绝，并返回指定 `status`（如 `cl_te_conflict`、
  `absolute`、`replay`）。

用例通过 `invariant` 字段引用不变量。失败时检查器输出违反的不变量 id、
类型与描述，并附上该步骤的 send / expect / reply 对比：

```
FAIL [pathguard] zz_probe_wrong
     violated invariant reject-absolute-path (reject): 绝对路径（含百分号编码伪装的 /）必须被拒绝……
       step 1 send  : {"op": "check", "path": "/etc/passwd"}
       step 1 expect: {"status": "ok"}
       step 1 reply : {"status": "absolute"}
```

覆盖报告列出每条不变量是否至少被一个用例覆盖（`exercised` / `NO CASE`），
防止不变量声明了却没人测。

## 隔离保证

- 每个用例在独立的 driver 子进程中执行，tokenauth 的重放缓存等状态随进程消亡，
  用例之间互不污染；
- 单个用例失败、driver 崩溃或超时只记录该用例失败，其余用例继续执行；
- 检查器以退出码 1 汇总失败，0 表示全部通过。

## 扩展方式（均无需改检查器）

- 新增用例：在 `cases/<组件>/` 下新增一个 JSON 文件即可；
- 多步骤/有状态用例：步骤可带 `id`，后续步骤用 `"$id.field"` 引用前序回复
  （见 `cases/tokenauth/replay_rejected.json`）；
- 新增组件：实现同协议的 `<组件>_drv`，在 `invariants.json` 登记不变量，
  再放用例文件，检查器自动发现。

## 运行

```
make check        # 构建三个 driver 并运行全部用例
python3 -I run_checks.py
```

各组件原有的 `make test` 自测保持不变（源码中由 `SELF_TEST` 宏保留）。
