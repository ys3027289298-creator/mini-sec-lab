# reqguard 差分验证报告

- 语料: 1754 条（手写矩阵 + 定点面 + 种子 20261119 的 1500 条变异）
- 参考解析器: Node v18.19.1 (llhttp)
- CL×TE 矩阵覆盖: 56 个组合单元

## 分歧分类统计

| 类别 | 条数 | 性质 | 成因 |
|---|---|---|---|
| `agree` | 1624 | 一致 | — |
| `hole:HPE_INVALID_METHOD` | 17 | 策略分歧（已审定，非 desync） | llhttp 只接受已知方法名白名单（GET/POST/PROPFIND/...）；reqguard 接受任意 token 方法。两侧看到的字节完全一致，方法不参与分帧，不存在解析漂移——属方法策略差异，非走私面。 |
| `strict:bad_content_length` | 6 | 严格化（reqguard 拒绝、参考接受） | CL 超出 int64 或语法非法：llhttp 放宽到 uint64，reqguard 拒绝（溢出即走私原语）。 |
| `strict:bad_header` | 18 | 严格化（reqguard 拒绝、参考接受） | 头部名非法（冒号前空白、空名、无冒号等）：RFC 7230 拒绝，llhttp 部分容忍。 |
| `strict:bad_target` | 7 | 严格化（reqguard 拒绝、参考接受） | 目标非 origin-form（绝对形式、*、含空白）：reqguard 只收 / 开头。 |
| `strict:bad_transfer_encoding` | 53 | 严格化（reqguard 拒绝、参考接受） | TE 非 chunked、列表、重复或为空：reqguard 只收单个 chunked。 |
| `strict:bad_version` | 3 | 严格化（reqguard 拒绝、参考接受） | HTTP 版本非 1.0/1.1。 |
| `strict:control_char` | 11 | 严格化（reqguard 拒绝、参考接受） | 裸 CR/LF、NUL 等控制字符：reqguard 拒绝，llhttp 部分场景容忍。 |
| `strict:line_too_long` | 3 | 严格化（reqguard 拒绝、参考接受） | 单行超 256 字节（reqguard 限制）。 |
| `strict:obs_fold` | 5 | 严格化（reqguard 拒绝、参考接受） | 折叠头（obs-fold）：RFC 7230 已废弃，reqguard 拒绝。 |
| `strict:too_many_headers` | 7 | 严格化（reqguard 拒绝、参考接受） | 头部数超 32（reqguard 限制）。 |

## `hole:HPE_INVALID_METHOD` — 最小样例（3 条，可复现）

样例 0（来源 `lower-method`，20 字节）：

    t / HTTP/1.1\r\nH:\r\n\r\n

复现: `xxd -r -p <<< 74202f20485454502f312e310d0a483a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_METHOD/0.bin）

样例 1（来源 `unknown-method`，20 字节）：

    R / HTTP/1.1\r\nH:\r\n\r\n

复现: `xxd -r -p <<< 52202f20485454502f312e310d0a483a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_METHOD/1.bin）

样例 2（来源 `method-pipe`，20 字节）：

    T / HTTP/1.1\r\nt:\r\n\r\n

复现: `xxd -r -p <<< 54202f20485454502f312e310d0a743a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_METHOD/2.bin）

## `strict:bad_content_length` — 最小样例（3 条，可复现）

样例 0（来源 `cl-value:b'18446744073709551615'`，60 字节）：

    POST / HTTP/1.1\r\nt:\r\nContent-Length:18446744073709551615\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a436f6e74656e742d4c656e6774683a31383434363734343037333730393535313631350d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_content_length/0.bin）

样例 1（来源 `cl-value:b'9223372036854775808'`，59 字节）：

    POST / HTTP/1.1\r\nt:\r\nContent-Length:9223372036854775808\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a436f6e74656e742d4c656e6774683a393232333337323033363835343737353830380d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_content_length/1.bin）

样例 2（来源 `fuzz:20261119:356`，56 字节）：

    POST / HTTP/1.1\r\nContent-Length:18446744073709551615\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a436f6e74656e742d4c656e6774683a31383434363734343037333730393535313631350d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_content_length/2.bin）

## `strict:bad_header` — 最小样例（3 条，可复现）

样例 0（来源 `cl-name:b'Content Length'`，26 字节）：

    POST / HTTP/1.1\r\n:\r\nt:\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a3a0d0a743a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_header/0.bin）

样例 1（来源 `cl-name-te:b'Content Length'`，24 字节）：

    POST / HTTP/1.1\r\nt :\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a74203a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_header/1.bin）

样例 2（来源 `te-name:b'Transfer Encoding'`，24 字节）：

    POST / HTTP/1.1\r\ns :\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a73203a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_header/2.bin）

## `strict:bad_target` — 最小样例（3 条，可复现）

样例 0（来源 `double-space-1`，12 字节）：

    GET /\r\n:\r\n\r\n

复现: `xxd -r -p <<< 474554202f0d0a3a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_target/0.bin）

样例 1（来源 `absolute-target`，15 字节）：

    GET p://\r\n:\r\n\r\n

复现: `xxd -r -p <<< 47455420703a2f2f0d0a3a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_target/1.bin）

样例 2（来源 `asterisk-target`，16 字节）：

    OPTIONS *\r\n:\r\n\r\n

复现: `xxd -r -p <<< 4f5054494f4e53202a0d0a3a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_target/2.bin）

## `strict:bad_transfer_encoding` — 最小样例（3 条，可复现）

样例 0（来源 `matrix:cl-absent+te-empty`，43 字节）：

    POST / HTTP/1.1\r\nt:\r\nTransfer-Encoding:\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a5472616e736665722d456e636f64696e673a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_transfer_encoding/0.bin）

样例 1（来源 `matrix:cl-leading-zero+te-empty`，43 字节）：

    POST / HTTP/1.1\r\nh:\r\nTransfer-Encoding:\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a683a0d0a5472616e736665722d456e636f64696e673a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_transfer_encoding/1.bin）

样例 2（来源 `matrix-rev:cl-leading-zero+te-empty`，46 字节）：

    POST / HTTP/1.1\r\nt:\r\nTransfer-Encoding:\r\n:\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a5472616e736665722d456e636f64696e673a0d0a3a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_transfer_encoding/2.bin）

## `strict:bad_version` — 最小样例（3 条，可复现）

样例 0（来源 `double-space-2`，22 字节）：

    GET /  HTTP/1.1\r\n:\r\n\r\n

复现: `xxd -r -p <<< 474554202f2020485454502f312e310d0a3a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_version/0.bin）

样例 1（来源 `http09`，21 字节）：

    GET / HTTP/0.9\r\n:\r\n\r\n

复现: `xxd -r -p <<< 474554202f20485454502f302e390d0a3a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_version/1.bin）

样例 2（来源 `http20`，21 字节）：

    GET / HTTP/2.0\r\n:\r\n\r\n

复现: `xxd -r -p <<< 474554202f20485454502f322e300d0a3a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_version/2.bin）

## `strict:control_char` — 最小样例（3 条，可复现）

样例 0（来源 `fuzz:20261119:7`，9 字节）：

    POST /\n\rT

复现: `xxd -r -p <<< 504f5354202f0a0d54 | ./reqguard-diff`  （原始字节: diff/samples/strict_control_char/0.bin）

样例 1（来源 `fuzz:20261119:116`，8 字节）：

    POST /\n\n

复现: `xxd -r -p <<< 504f5354202f0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_control_char/1.bin）

样例 2（来源 `fuzz:20261119:189`，8 字节）：

    GET /\n\rk

复现: `xxd -r -p <<< 474554202f0a0d6b | ./reqguard-diff`  （原始字节: diff/samples/strict_control_char/2.bin）

## `strict:line_too_long` — 最小样例（3 条，可复现）

样例 0（来源 `long-line`，278 字节）：

    POST / HTTP/1.1\r\n: xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a3a207861616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_line_too_long/0.bin）

样例 1（来源 `fuzz:20261119:1000`，278 字节）：

    POST / HTTP/1.1\r\nt: xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a207861616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161612b616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_line_too_long/1.bin）

样例 2（来源 `fuzz:20261119:1340`，278 字节）：

    POST / HTTP/1.1\r\nHost: xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaUaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a486f73743a2078616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161615561616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_line_too_long/2.bin）

## `strict:obs_fold` — 最小样例（3 条，可复现）

样例 0（来源 `obs-fold-space`，26 字节）：

    GET / HTTP/1.1\r\nX:a\r\n \r\n\r\n

复现: `xxd -r -p <<< 474554202f20485454502f312e310d0a583a610d0a200d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_obs_fold/0.bin）

样例 1（来源 `obs-fold-tab`，26 字节）：

    GET / HTTP/1.1\r\nX:a\r\n\t\r\n\r\n

复现: `xxd -r -p <<< 474554202f20485454502f312e310d0a583a610d0a090d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_obs_fold/1.bin）

样例 2（来源 `obs-fold-te`，27 字节）：

    POST / HTTP/1.1\r\ng:d\r\n \r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a673a640d0a200d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_obs_fold/2.bin）

## `strict:too_many_headers` — 最小样例（3 条，可复现）

样例 0（来源 `many-headers-33`，183 字节）：

    POST / HTTP/1.1\r\nt:\r\n1:\r\n2:\r\n3:\r\n4:\r\n5:\r\n6:\r\n7:\r\n8:\r\n9:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a313a0d0a323a0d0a333a0d0a343a0d0a353a0d0a363a0d0a373a0d0a383a0d0a393a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_too_many_headers/0.bin）

样例 1（来源 `many-headers-40`，175 字节）：

    POST / HTTP/1.1\r\nt:\r\n0:\r\n1:\r\n8:\r\n9:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a303a0d0a313a0d0a383a0d0a393a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_too_many_headers/1.bin）

样例 2（来源 `many-headers-64`，151 字节）：

    POST / HTTP/1.1\r\n1:\r\n2:\r\n4:\r\n5:\r\n7:\r\n8:\r\n9:\r\n0:\r\n1:\r\n2:\r\n3:\r\n4:\r\n5:\r\n6:\r\n7:\r\n8:\r\nX:\r\n8:\r\n9:\r\n0:\r\n1:\r\n2:\r\n3:\r\n4:\r\n5:\r\n6:\r\n7:\r\n8:\r\n9:\r\n0:\r\n1:\r\n2:\r\n3:\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a313a0d0a323a0d0a343a0d0a353a0d0a373a0d0a383a0d0a393a0d0a303a0d0a313a0d0a323a0d0a333a0d0a343a0d0a353a0d0a363a0d0a373a0d0a383a0d0a583a0d0a383a0d0a393a0d0a303a0d0a313a0d0a323a0d0a333a0d0a343a0d0a353a0d0a363a0d0a373a0d0a383a0d0a393a0d0a303a0d0a313a0d0a323a0d0a333a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_too_many_headers/2.bin）
