# mini-sec-lab

安全方向的小项目集合，每个子目录独立构建、可自测。

| 目录 | 内容 | 子方向 |
|---|---|---|
| `reqguard/` | HTTP/1.1 请求解析，防请求走私 | 网络与通信安全 |
| `pathguard/` | 不可信路径的策略校验 | 系统安全 |
| `tokenauth/` | HMAC 令牌、常量时间比较、重放缓存、密钥轮转 | 身份认证 |
| `jwtguard/` | 第三方 RS256/ES256 JWT 验签、kid 选钥与轮转、nbf/exp 时钟偏差、alg 混淆与 none 防护 | 身份认证 |
