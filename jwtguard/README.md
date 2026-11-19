# jwtguard

网关侧第三方 JWT 验签。只接受非对称算法（RS256 / ES256），信任锚是本地
keyring 白名单，令牌自身不能引入或覆盖任何信任配置。`make test` 跑参考库
（PyJWT）对拍与篡改变异测试。

## 威胁模型与规则

1. **alg 混淆与 none**：`alg: none`（任意大小写）一律拒绝；非白名单算法
   （HS256 等）一律拒绝；令牌头 `alg` 必须与 keyring 中该 `kid` 固定的
   算法一致——HMAC 永远无法钉到非对称公钥上。
2. **kid 选钥与轮转**：令牌必须带非空字符串 `kid`，只用于在 keyring 中
   查条目；查不到即拒。轮转期同时挂新旧两把公钥，两个世代签发的令牌
   都能验。
3. **白名单不可被令牌覆盖**：头中出现 `jwk` / `jku` / `x5u` / `x5c`
   直接拒绝，公钥只来自本地 PEM。
4. **时间声明**：`exp` 与 `nbf` 必填，按可配置时钟偏差（leeway）校验；
   越界分别报 `expired` / `not_yet`。
5. **签名**：RS256 = RSASSA-PKCS1-v1_5 + SHA-256；ES256 = P-256 ECDSA +
   SHA-256，JWT 的裸 `R||S`（64 字节）先转 DER 再交给 OpenSSL。签名输入
   是完整的 `header.payload` 字节串。
6. **JSON 严格性**：header/payload 内出现重复成员名直接判 `malformed`。
   RFC 8259 未规定同名键语义（解析器各自 first/last-wins），重复键是
   header splitting 的经典分歧面，因此比 PyJWT 更严格、刻意不对齐。

## keyring 配置格式

每行一个条目（`#` 开头注释）：

```
<kid> <RS256|ES256> <public-key.pem 路径>
```

加载时校验：RSA 必须 ≥2048 位、EC 必须是 `prime256v1`（P-256）、kid 不
允许重复。

## 用法

```
./jwtguard verify <keyring.conf> <token> [leeway [now_epoch]]
./jwtguard batch  <keyring.conf> <cases.tsv>
```

`batch` 的 TSV 每行 `id<TAB>leeway<TAB>now<TAB>token`，输出
`id<TAB>ok|reject<TAB>reason`，供测试框架对拍。

返回原因码：`ok` / `malformed` / `alg_none` / `alg_confusion` /
`missing_kid` / `unknown_kid` / `untrusted_header` / `missing_claim` /
`bad_sig` / `expired` / `not_yet`。

## 测试

```
make test
```

- `tests/harness.py` 用 `cryptography` 生成 old/new/rogue 共 6 把密钥，
  用 PyJWT 构造 20 个固定令牌（含两轮转世代、skew 边界、none、alg 混淆、
  jwk 注入、kid 缺失/未知、签名/载荷/头部篡改、exp/nbf 越界、畸形），
  C 实现与同策略 Python 参考实现逐条比对，原因码必须完全一致。
- 对 4 个合法令牌的每个分段逐字符替换/截断/增删（3000+ 变异），任何
  字段被篡改都必须拒绝，且参考库同样拒绝。
