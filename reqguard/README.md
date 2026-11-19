# reqguard

安全方向小项目，`make test` 跑自检。

HTTP/1.1 请求解析，防请求走私：拒绝 CL+TE、重复 Content-Length、obs-fold、
控制字符、超长头行与超大缓冲区。

## 分块传输解析

`reqguard.c` 里的 `ChunkParser` 按 RFC 7230 §4.1 增量解析 chunked 请求体：

- 块长按十六进制读取（`1*HEXDIG`，大小写均可，允许前导零），可带 `;name[=value]` 形式的 chunk-ext；
- 块数据后必须紧跟 CRLF，缺失或只有裸 LF 报 `chunk_crlf`；
- 末块 `0\r\n` 之后读取尾随头，再以空行结束整个消息；
- 非法块长报 `bad_chunk_size`（无十六进制位、`0x` 前缀、`+5`、前导空格、16 位溢出等）；
- 单块超过 `MAX_CHUNK_SIZE` 直接报 `chunk_too_large`，绝不读入后截断；累计体超 `MAX_BODY` 报 `too_large`；
- 状态保存在调用方持有的 `ChunkParser` 里，`chunk_feed()` 可被任意切片反复调用，跨调用保持；终止 CRLF 之后的字节不计入 `consumed`，可留给流水线中的下一条请求。

`Transfer-Encoding` 只接受 "chunked"（且仅出现一次），其他编码或重复值报 `bad_transfer_encoding`；
尾随头里出现 `Content-Length` / `Transfer-Encoding`、obs-fold 或非法字段名报 `bad_trailer`。

## 测试

- `make test`：C 自检（含上述分块用例与增量一致性），再用 `tests/ref_chunked.py`
  这份独立参考解析器对二十组用例逐项比对 `tests/crosscheck.py`。
- `make fuzz`：ASan/UBSan 构建 + 随机变异输入，参考实现与 C 实现比对，并检查不同切片大小下的增量结果一致。

`./reqguard --decode [--split=N]` 从 stdin 读十六进制字节、输出解析结果，供测试脚本调用。
