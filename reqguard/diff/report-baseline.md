# reqguard 差分验证报告

- 语料: 1749 条（手写矩阵 + 定点面 + 种子 20261119 的 1500 条变异）
- 参考解析器: Node v18.19.1 (llhttp)
- CL×TE 矩阵覆盖: 56 个组合单元

## 分歧分类统计

| 类别 | 条数 | 性质 |
|---|---|---|
| `agree` | 1584 | 一致 |
| `field:cl` | 7 | **危险（reqguard 接受、参考拒绝或字段不一致）** |
| `field:headers` | 19 | **危险（reqguard 接受、参考拒绝或字段不一致）** |
| `field:target` | 4 | **危险（reqguard 接受、参考拒绝或字段不一致）** |
| `hole:HPE_INVALID_CONTENT_LENGTH` | 21 | **危险（reqguard 接受、参考拒绝或字段不一致）** |
| `hole:HPE_INVALID_HEADER_TOKEN` | 15 | **危险（reqguard 接受、参考拒绝或字段不一致）** |
| `hole:HPE_INVALID_METHOD` | 22 | **危险（reqguard 接受、参考拒绝或字段不一致）** |
| `hole:HPE_INVALID_TRANSFER_ENCODING` | 9 | **危险（reqguard 接受、参考拒绝或字段不一致）** |
| `hole:HPE_LF_EXPECTED` | 10 | **危险（reqguard 接受、参考拒绝或字段不一致）** |
| `strict:bad_header` | 22 | 严格化（reqguard 拒绝、参考接受） |
| `strict:bad_target` | 7 | 严格化（reqguard 拒绝、参考接受） |
| `strict:bad_version` | 3 | 严格化（reqguard 拒绝、参考接受） |
| `strict:cl_te_conflict` | 6 | 严格化（reqguard 拒绝、参考接受） |
| `strict:line_too_long` | 13 | 严格化（reqguard 拒绝、参考接受） |
| `strict:obs_fold` | 6 | 严格化（reqguard 拒绝、参考接受） |
| `strict:too_many_headers` | 1 | 严格化（reqguard 拒绝、参考接受） |

## `field:cl` — 最小样例（3 条，可复现）

样例 0（来源 `cl-value:b'18446744073709551615'`，60 字节）：

    POST / HTTP/1.1\r\nt:\r\nContent-Length:18446744073709551615\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a436f6e74656e742d4c656e6774683a31383434363734343037333730393535313631350d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/field_cl/0.bin）

样例 1（来源 `cl-value:b'9223372036854775808'`，59 字节）：

    POST / HTTP/1.1\r\nt:\r\nContent-Length:9223372036854775808\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a436f6e74656e742d4c656e6774683a393232333337323033363835343737353830380d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/field_cl/1.bin）

样例 2（来源 `fuzz:20261119:355`，56 字节）：

    POST / HTTP/1.1\r\nContent-Length:18446744073709551615\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a436f6e74656e742d4c656e6774683a31383434363734343037333730393535313631350d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/field_cl/2.bin）

## `field:headers` — 最小样例（3 条，可复现）

样例 0（来源 `high-byte-value`，23 字节）：

    GET / HTTP/1.1\r\nX:\xff\r\n\r\n

复现: `xxd -r -p <<< 474554202f20485454502f312e310d0a583aff0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/field_headers/0.bin）

样例 1（来源 `fuzz:20261119:82`，23 字节）：

    GET / HTTP/1.1\r\nX:\xb2\r\n\r\n

复现: `xxd -r -p <<< 474554202f20485454502f312e310d0a583ab20d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/field_headers/1.bin）

样例 2（来源 `fuzz:20261119:152`，24 字节）：

    POST / HTTP/1.1\r\ng:\x90\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a673a900d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/field_headers/2.bin）

## `field:target` — 最小样例（3 条，可复现）

样例 0（来源 `high-byte-target`，23 字节）：

    GET /\x80 HTTP/1.1\r\nH:\r\n\r\n

复现: `xxd -r -p <<< 474554202f8020485454502f312e310d0a483a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/field_target/0.bin）

样例 1（来源 `fuzz:20261119:354`，23 字节）：

    GET /\x80 HTTP/1.1\r\nt:\r\n\r\n

复现: `xxd -r -p <<< 474554202f8020485454502f312e310d0a743a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/field_target/1.bin）

样例 2（来源 `fuzz:20261119:601`，24 字节）：

    POST /\xce HTTP/1.1\r\no:\r\n\r\n

复现: `xxd -r -p <<< 504f5354202fce20485454502f312e310d0a6f3a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/field_target/2.bin）

## `hole:HPE_INVALID_CONTENT_LENGTH` — 最小样例（3 条，可复现）

样例 0（来源 `matrix:cl-overflow+te-absent`，56 字节）：

    POST / HTTP/1.1\r\nContent-Length:99999999999999999999\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a436f6e74656e742d4c656e6774683a39393939393939393939393939393939393939390d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_CONTENT_LENGTH/0.bin）

样例 1（来源 `matrix:cl-plus+te-absent`，42 字节）：

    POST / HTTP/1.1\r\nt:\r\nContent-Length:+5\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a436f6e74656e742d4c656e6774683a2b350d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_CONTENT_LENGTH/1.bin）

样例 2（来源 `cl-value:b'\t5\t'`，42 字节）：

    POST / HTTP/1.1\r\nt:\r\nContent-Length:5\t\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a436f6e74656e742d4c656e6774683a35090d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_CONTENT_LENGTH/2.bin）

## `hole:HPE_INVALID_HEADER_TOKEN` — 最小样例（3 条，可复现）

样例 0（来源 `bare-lf-between-headers`，23 字节）：

    GET / HTTP/1.1\r\nt:\n\r\n\r\n

复现: `xxd -r -p <<< 474554202f20485454502f312e310d0a743a0a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_HEADER_TOKEN/0.bin）

样例 1（来源 `bare-lf-in-value`，23 字节）：

    GET / HTTP/1.1\r\nX:\n\r\n\r\n

复现: `xxd -r -p <<< 474554202f20485454502f312e310d0a583a0a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_HEADER_TOKEN/1.bin）

样例 2（来源 `fuzz:20261119:89`，24 字节）：

    POST / HTTP/1.1\r\nt:\n\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_HEADER_TOKEN/2.bin）

## `hole:HPE_INVALID_METHOD` — 最小样例（3 条，可复现）

样例 0（来源 `lower-method`，20 字节）：

    t / HTTP/1.1\r\nH:\r\n\r\n

复现: `xxd -r -p <<< 74202f20485454502f312e310d0a483a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_METHOD/0.bin）

样例 1（来源 `unknown-method`，20 字节）：

    R / HTTP/1.1\r\nH:\r\n\r\n

复现: `xxd -r -p <<< 52202f20485454502f312e310d0a483a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_METHOD/1.bin）

样例 2（来源 `fuzz:20261119:108`，20 字节）：

    T / HTTP/1.1\r\nt:\r\n\r\n

复现: `xxd -r -p <<< 54202f20485454502f312e310d0a743a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_METHOD/2.bin）

## `hole:HPE_INVALID_TRANSFER_ENCODING` — 最小样例（3 条，可复现）

样例 0（来源 `matrix:cl-absent+te-chunked-gzip`，51 字节）：

    POST / HTTP/1.1\r\nt:\r\nTransfer-Encoding:chunked,\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a5472616e736665722d456e636f64696e673a6368756e6b65642c0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_TRANSFER_ENCODING/0.bin）

样例 1（来源 `matrix:cl-absent+te-dup`，71 字节）：

    POST / HTTP/1.1\r\nt:\r\nTransfer-Encoding:chunked\r\nTransfer-Encoding:d\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a5472616e736665722d456e636f64696e673a6368756e6b65640d0a5472616e736665722d456e636f64696e673a640d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_TRANSFER_ENCODING/1.bin）

样例 2（来源 `fuzz:20261119:1493`，47 字节）：

    POST / HTTP/1.1\r\nTransfer-Encoding:chunked,\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a5472616e736665722d456e636f64696e673a6368756e6b65642c0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_INVALID_TRANSFER_ENCODING/2.bin）

## `hole:HPE_LF_EXPECTED` — 最小样例（3 条，可复现）

样例 0（来源 `bare-cr-in-value`，24 字节）：

    GET / HTTP/1.1\r\nX:a\r\r\n\r\n

复现: `xxd -r -p <<< 474554202f20485454502f312e310d0a583a610d0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_LF_EXPECTED/0.bin）

样例 1（来源 `fuzz:20261119:264`，25 字节）：

    POST / HTTP/1.1\r\ng:d\r\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a673a640d0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_LF_EXPECTED/1.bin）

样例 2（来源 `fuzz:20261119:402`，25 字节）：

    POST / HTTP/1.1\r\nt:x\r\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a780d0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/hole_HPE_LF_EXPECTED/2.bin）

## `strict:bad_header` — 最小样例（3 条，可复现）

样例 0（来源 `cl-name:b'Content Length'`，25 字节）：

    POST / HTTP/1.1\r\n:\r\nt:\r\n\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a3a0d0a743a0d0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_header/0.bin）

样例 1（来源 `cl-name-te:b'Content Length'`，23 字节）：

    POST / HTTP/1.1\r\nt :\r\n\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a74203a0d0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_header/1.bin）

样例 2（来源 `te-name:b'Transfer Encoding'`，23 字节）：

    POST / HTTP/1.1\r\ns :\r\n\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a73203a0d0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_header/2.bin）

## `strict:bad_target` — 最小样例（3 条，可复现）

样例 0（来源 `double-space-1`，10 字节）：

    GET /\n:\r\n\n

复现: `xxd -r -p <<< 474554202f0a3a0d0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_target/0.bin）

样例 1（来源 `absolute-target`，11 字节）：

    GET p://\n\r\n

复现: `xxd -r -p <<< 47455420703a2f2f0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_target/1.bin）

样例 2（来源 `asterisk-target`，14 字节）：

    OPTIONS *\n:\r\n\n

复现: `xxd -r -p <<< 4f5054494f4e53202a0a3a0d0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_target/2.bin）

## `strict:bad_version` — 最小样例（3 条，可复现）

样例 0（来源 `double-space-2`，20 字节）：

    GET /  HTTP/1.1\n:\r\n\n

复现: `xxd -r -p <<< 474554202f2020485454502f312e310a3a0d0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_version/0.bin）

样例 1（来源 `http09`，19 字节）：

    GET / HTTP/0.9\n:\r\n\n

复现: `xxd -r -p <<< 474554202f20485454502f302e390a3a0d0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_version/1.bin）

样例 2（来源 `http20`，19 字节）：

    GET / HTTP/2.0\n:\r\n\n

复现: `xxd -r -p <<< 474554202f20485454502f322e300a3a0d0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_bad_version/2.bin）

## `strict:cl_te_conflict` — 最小样例（3 条，可复现）

样例 0（来源 `matrix:cl-leading-zero+te-empty`，61 字节）：

    POST / HTTP/1.1\r\nt:\r\nContent-Length:5\r\nTransfer-Encoding:\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a436f6e74656e742d4c656e6774683a350d0a5472616e736665722d456e636f64696e673a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_cl_te_conflict/0.bin）

样例 1（来源 `matrix-rev:cl-leading-zero+te-empty`，61 字节）：

    POST / HTTP/1.1\r\nt:\r\nTransfer-Encoding:\r\nContent-Length:5\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a5472616e736665722d456e636f64696e673a0d0a436f6e74656e742d4c656e6774683a350d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_cl_te_conflict/1.bin）

样例 2（来源 `fuzz:20261119:1128`，65 字节）：

    POST / HTTP/1.1\r\nt:\r\nTransfer-Encoding:\r\nContent-Length:5\r\nC:\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a5472616e736665722d456e636f64696e673a0d0a436f6e74656e742d4c656e6774683a350d0a433a0d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_cl_te_conflict/2.bin）

## `strict:line_too_long` — 最小样例（3 条，可复现）

样例 0（来源 `long-line`，261 字节）：

    POST / HTTP/1.1\n:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310a3a6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_line_too_long/0.bin）

样例 1（来源 `fuzz:20261119:40`，261 字节）：

    POST / HTTP/1.1\n:aaaaaaaxaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaachunkedaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+aaaaa+aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310a3a6161616161616178616161616161616161616161616161616161616161616161616161616161616161616161616161616161616368756e6b656461616161616161616161616161616161616161616161616161616161616161616161616161616161616161612b61616161612b61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_line_too_long/1.bin）

样例 2（来源 `fuzz:20261119:116`，26 字节）：

    POST / HTTP/1.1\r\ng:\r\nt:\r\n\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a673a0d0a743a0d0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_line_too_long/2.bin）

## `strict:obs_fold` — 最小样例（3 条，可复现）

样例 0（来源 `obs-fold-space`，25 字节）：

    GET / HTTP/1.1\r\nX:a\r\n \r\n\n

复现: `xxd -r -p <<< 474554202f20485454502f312e310d0a583a610d0a200d0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_obs_fold/0.bin）

样例 1（来源 `obs-fold-tab`，25 字节）：

    GET / HTTP/1.1\r\nX:a\r\n\t\r\n\n

复现: `xxd -r -p <<< 474554202f20485454502f312e310d0a583a610d0a090d0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_obs_fold/1.bin）

样例 2（来源 `obs-fold-te`，26 字节）：

    POST / HTTP/1.1\r\ng:d\r\n \r\n\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a673a640d0a200d0a0a | ./reqguard-diff`  （原始字节: diff/samples/strict_obs_fold/2.bin）

## `strict:too_many_headers` — 最小样例（1 条，可复现）

样例 0（来源 `many-headers`，175 字节）：

    POST / HTTP/1.1\r\nt:\r\n0:\r\n1:\r\n8:\r\n9:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX:\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\nX: v\r\n\r\n

复现: `xxd -r -p <<< 504f5354202f20485454502f312e310d0a743a0d0a303a0d0a313a0d0a383a0d0a393a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a0d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a583a20760d0a0d0a | ./reqguard-diff`  （原始字节: diff/samples/strict_too_many_headers/0.bin）
