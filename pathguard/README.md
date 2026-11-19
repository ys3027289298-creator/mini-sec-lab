# pathguard

安全方向小项目，`make test` 跑自检。

## 路径配额（PgLimits，全部可配，超限显式失败，绝不截断）

| 配额 | 含义 | 超限错误码 | 默认值 |
|---|---|---|---|
| `max_comp` | 单个分量最大字节数 | `PG_TOO_LONG` | 64 |
| `max_total` | 整条路径最大字节数 | `PG_TOTAL_TOO_LONG` | 256 |
| `max_depth` | 最大目录层数（`a/b/c` 为 2） | `PG_TOO_DEEP` | 8 |
| `max_segments` | 最大分量段数 | `PG_TOO_MANY_SEGMENTS` | 32 |

语义：上限 N 表示 N 放行、N+1 拒绝；调大上限后行为线性可预期。
上限超过内部硬顶 `PG_ABS_MAX`（4096）时返回 `PG_BAD_LIMITS`，不做静默钳制。
