# mini-sec-lab

安全方向的小项目集合，每个子目录独立构建、可自测。

| 目录 | 内容 | 子方向 |
|---|---|---|
| `reqguard/` | HTTP/1.1 请求解析，防请求走私 | 网络与通信安全 |
| `pathguard/` | 不可信路径的策略校验 | 系统安全 |
| `tokenauth/` | HMAC 令牌、常量时间比较、重放缓存、密钥轮转 | 身份认证 |
| `checker/` | 跨组件安全不变量检查器，统一驱动三个组件 | 安全测试 |

各组件 `make test` 跑内置自测；`cd checker && make check` 运行统一不变量检查器
（见 `checker/README.md`）。
