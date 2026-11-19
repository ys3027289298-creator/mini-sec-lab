# reqguard

安全方向小项目，`make test` 跑自检。

## 差分验证

`make diff` 对 reqguard 与参考解析器（Node llhttp）做差分验证：
同一份原始字节同时喂给两个解析器，逐字段（method/target/version/CL/TE/头部表）
比对，分歧按成因分类，每类保留 ≥3 条最小可复现样例。

- `diff/difftest.py` — 语料（CL×TE 全组合矩阵 + 定点走私面 + 固定种子变异）、
  比对、分类、样例最小化；任一类危险分歧（reqguard 接受而参考拒绝、或双方接受
  但字段不一致）或样例不足 3 条时退出码非零。
- `diff/ref_server.mjs` — 参考解析器（Node http server，llhttp）。
- `diff/report.md` / `diff/report.json` — 最新结果；`diff/report-baseline.*`
  是加固前的基线（8 类危险分歧，已全部修复或审定）。
- `diff/samples/<类别>/N.bin` — 最小样例原始字节，
  复现：`xxd -r -p <<< <hex> | ./reqguard-diff`。

基线差分发现并已修复的走私面：裸 CR/LF 不属于 CRLF 对、CL 接受 `+5`/制表符/
溢出（strtol 未查 errno）、TE 值未校验（列表/identity/重复 TE）。
