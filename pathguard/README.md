# pathguard

安全方向小项目，`make test` 跑自检。

## 两段式校验

1. **词法段 `pg_normalize`**：百分号解码 + 规范化，拒绝绝对路径、`..`、
   控制字符、反斜杠、空段、超长/超深。这一段只负责"拒绝"，从不单独放行，
   也不对文件系统下任何结论。
2. **文件系统段 `pg_walk`**：从根目录 fd 出发，用 `openat(2)` 相对父目录
   fd 逐段解析，全程 `O_NOFOLLOW`；所有元数据判断都是对刚打开的 fd 做
   `fstat`。拒绝符号链接、硬链接（普通文件 `st_nlink != 1`；目录
   `st_nlink < 2` 的异常计数）和非普通文件目标。调用方拿到的是校验过的
   fd 本身（`pg_open`），不是路径字符串。

## 为什么 TOCTOU 窗口为零

经典 TOCTOU 来自"先 `stat` 检查、再 `open` 使用"两个时间点之间路径被
攻击者换掉。本设计里不存在两个时间点：

- **检查与使用是同一个内核对象**：每段路径只由内核解析一次，`openat`
  返回的 fd 钉住该 inode；之后攻击者 `rename`/`unlink`/替换任何一级
  目录，都不影响已持有的 fd。
- **符号链接判断不是"看一眼类型"**：`O_NOFOLLOW` 让内核在打开瞬间原子
  地拒绝跟随（末段 `ELOOP`；中间段用 `O_PATH|O_NOFOLLOW` 打开符号链接
  本身再 `fstat` 判型，避免 `O_DIRECTORY` 把符号链接混同为 `ENOTDIR`）。
- **没有"之后再打开一次"**：返回给调用方的是 fd，不是路径，不存在
  校验后重新解析路径的环节。
- **create 模式同样无 check-then-act**：缺失的中间目录用 `mkdirat` 原子
  创建，`EEXIST` 后重新 `openat` 验证；末段用 `O_CREAT|O_EXCL` 原子
  创建，已存在即失败。

## 与真实文件系统一致

存在性、类型、链接数全部来自系统调用返回时的内核视图，不依赖字符串
推理、`realpath` 文本比较或缓存的元数据。词法段只缩小输入空间。

## 错误码：不存在与被拒可区分

| 类别 | 错误码 |
|---|---|
| 不存在 | `PG_NOTFOUND` |
| 被拒（策略） | `PG_SYMLINK` `PG_HARDLINK` `PG_NOTDIR` `PG_NOTREG` `PG_EXISTS` |
| 被拒（权限） | `PG_PERM` |
| 其他 errno | `PG_IO` |

create 模式（`PG_OPEN_CREATE`）允许末尾不存在的新建段（含多级新目录，
自动 `mkdirat`，权限 0700）；末段已存在则返回 `PG_EXISTS`。
