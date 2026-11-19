# tlsrecord

TLS record 层（RFC 5246 6.2.1），处理**解密后**的明文记录流。核心库零动态分配，
上下文大小固定且有编译期上界断言。

## 能力

- **分段重组**：`trl_feed()` 接受任意大小的分片（可逐字节喂入），跨调用拼出完整
  5 字节记录头与记录体；`trl_finish()` 捕获流末尾的半条记录。
- **类型白名单**：默认放行 20/21/22/23（CCS/alert/handshake/application_data），
  其余类型返回 `TRL_BAD_TYPE`；可通过 `trl_allow_type()` 显式扩展。
- **长度一致性校验**：记录长度 > 16384 拒绝；零长记录拒绝；CCS 必须恰为 1 字节、
  alert 必须恰为 2 字节；握手分片不得越过所属记录、分片区间不得超过声明总长。
- **握手分片重组**：按 `message_seq / fragment_offset / fragment_length` 重组，
  乱序（出现空洞）报 `TRL_HS_REORDER`，重叠且字节不一致报 `TRL_HS_OVERLAP`，
  完全相同的重传按重复分片接受并计数。
- **拒绝重协商**：`trl_mark_established()` 之后再收到 handshake 记录直接报
  `TRL_RENEGOTIATION`；建立后的 CCS 默认拒绝（可按策略放行）。
- **reqguard 入口**：application_data 明文累积后由 `trl_http_ingest()` 交给
  reqguard 解析，返回其错误名（`ok` / `cl_te_conflict` / …）。

## 错误码

| 码 | 名称 | 触发条件 |
|---|---|---|
| 1 | `record_too_large` | 记录长度字段 > 16384 |
| 2 | `bad_version` | 版本不是 0x0301/0x0303 |
| 3 | `bad_type` | 类型不在白名单 |
| 4 | `length_mismatch` | 零长记录或 CCS/alert 尺寸不符 |
| 5 | `handshake_truncated` | 握手分片越过记录边界 |
| 6 | `handshake_too_large` | 重组消息 > 65536 |
| 7 | `handshake_overlap` | 重叠分片字节不一致 |
| 8 | `handshake_reorder` | 分片空洞 / 乱序 |
| 9 | `handshake_length_conflict` | 类型/总长变化或区间越界 |
| 10 | `renegotiation_rejected` | 建立后收到 handshake |
| 11 | `ccs_after_established` | 建立后收到 CCS（默认策略） |
| 12 | `app_overflow` | 明文缓冲耗尽 |
| 13 | `truncated_stream` | 流结束时残留半条记录 |

每个错误同时在 `last_detail` 记录触发字段（如违规偏移量或长度）。

## 内存上界

`TlsRecordLayer` 为调用方持有的固定上下文，核心库不做任何 `malloc`：

```
sizeof(TlsRecordLayer) = 98720 B   (< TRL_MEM_BOUND_BYTES = 100000，编译期 static_assert)
  记录缓冲   16389 B   (16384 明文 + 5 头)
  握手缓冲   65536 B
  应用明文   16384 B
  状态/计数   其余
```

## 构建与测试

```
make            # 构建 tlsrecord（-Wall -Wextra，零告警）
make test       # 内置自检：30 项 key=value 断言（覆盖全部 13 个错误码）
make refcheck   # 生成 30 组报文，与独立 Python 参考解析器逐字段 diff
make bench      # 耗时、每记录纳秒、吞吐与内存上界
```

参考解析器 `tools/gen_vectors.py` 与 C 实现**无共享代码**，按 RFC 独立编写；
`make refcheck` 对 30 组报文（覆盖全部 13 个错误码、正常流、乱序/重叠/重传、
重协商、HTTP 走私）比对两侧的规范化 trace，要求 30/30 完全一致。

`dump` 模式输出逐字段 trace，可对外部报文单独核查：

```
./tlsrecord dump vectors/v19_hs_overlap.bin
```

## 文件

- `src/tlsrecord.h` / `tlsrecord.c` — 分配无关的 record 层核心
- `src/tlshttp.c` — reqguard 入口（原样包含 reqguard 源码，不修改上游）
- `src/main.c` — 自检 / dump / bench 驱动
- `tools/gen_vectors.py` — 独立参考解析器与 30 组报文生成器
- `tools/refcheck.sh` — C/Python 逐字段比对
