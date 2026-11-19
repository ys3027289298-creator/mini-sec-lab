# reqguard

安全方向小项目，`make test` 跑自检。

- **HTTP/1.1** 请求解析，防请求走私：拒绝 CL+TE、重复 Content-Length、obs-fold、
  控制字符、超长头行与超大缓冲区。
- **HTTP/2** 头部解压（HPACK，RFC 7541）与请求校验（RFC 9113 §8.2/§8.3）。

两者共用同一个入口 `parse_request()`；协议与 HPACK 连接状态放在
`ReqConn` 里，因此同一条连接上多个流（多个 field section）共享动态表。

## HPACK

`src/hpack.c` 是独立的解码器，`src/hpack_tables.h` 由 RFC 7541 附录 A/B
生成（`tools/gen_tables.py` 可复现）：

- 静态表 61 项；动态表按 RFC 7541 §4 管理：每项大小 `32 + 名字 + 值`，
  新项插到表头，超限从表尾逐出；单项大于表上限时清空表且不插入（§4.4）。
- 表大小更新（§6.3）：只允许出现在 field block 开头，最多两次（先最小后最终，
  §4.2）；超过对端 `SETTINGS_HEADER_TABLE_SIZE` 上限报错。
- 协商上限下调后，下一块必须以更新开场把表降到新上限，否则按 RFC 9113 §4.3.1
  报 `hpack_size_update_missing`。
- 整数（§5.1）超过 32 位或超过 5 个延续字节报 `hpack_integer_overflow`。
- Huffman（§5.2）：按附录 B 的 trie 逐位解码；载荷里出现 EOS、或尾部填充不是
  8 位以内的全 1（EOS 前缀）都报 `hpack_huffman`。
- 索引 0（§6.1）报 `hpack_index_zero`，越界报 `hpack_index_range`；
  截断在表示中间报 `hpack_truncated`。
- 解码器不分配内存：动态表、转义缓冲和 Table 槽位都在 `HpackDecoder` 里，
  大小固定（约 224 KiB，上限 `HPACK_MAX_TABLE_SIZE` = 64 KiB 表 + 两个
  64 KiB 字段缓冲）。

### 解码与校验的边界

HPACK 状态属于连接而不是单个流。因此当一个 field block 里出现非法字段
（大写名、连接相关头、伪头部顺序等）时，解码器仍会把整块解完并更新动态表，
之后才报告该流的错误；这样同连接后续流的索引仍然正确。真正的 HPACK 解码
错误（表/整数/Huffman 等）按 RFC 9113 §4.3 视为连接级 `COMPRESSION_ERROR`。

## HTTP/2 请求字段校验（RFC 9113 §8.2、§8.3）

- 字段名必须小写，且不含 `0x00-0x20`、`0x41-0x5a`、`0x7f-0xff`；普通字段名
  不得含冒号。
- 字段值不得含 NUL/CR/LF，不得以 SP/HTAB 开头或结尾。
- 禁止连接相关字段：`connection`、`proxy-connection`、`keep-alive`、
  `transfer-encoding`、`upgrade`；`te` 只允许值 `trailers`。
- 伪头部必须全部位于普通字段之前、不得重复、不得出现未定义的伪头部；
  请求必须有 `:method`，非 CONNECT 还必须有 `:scheme` 与 `:path`（`*` 或
  以 `/` 开头），CONNECT 必须有 `:authority` 且不得带 `:scheme`/`:path`。
- 继续沿用 HTTP/1.1 的框架检查：重复 `content-length`、非法 `content-length`
  值同名同错。

## 测试

- `make test`：C 自检（HTTP/1.1 回归 + HPACK 与 HTTP/2 用例，含 RFC 7541
  附录 C 的请求序列），再用 `tools/hpack_crosscheck.py` 把 61 组连接脚本同时
  喂给 C 实现和独立 Python 参考 `tools/ref_hpack.py`，逐行比对字段、结论与
  动态表状态。
- `make fuzz`：ASan/UBSan 构建 + 基于表示语法的变异输入，参考实现与 C 实现
  逐行比对，且不得触发 sanitizer。
- `make bench`：一条连接上跑 10,000 个流，输出吞吐与上下文占用。

`./reqguard h2trace` 从 stdin 读脚本（`table N` 调整协商上限，`block HEX`
解码一个 field section），输出逐字段轨迹，供参考实现比对。
`./reqguard bench [N]` 直接跑吞吐基准。
