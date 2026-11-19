# reqguard

HTTP/1.1 请求头的**流式**解析器，防请求走私，也防大请求头耗尽内存。`make test` 跑自检（含 ASan/UBSan 构建与 4000 例流式/整包一致性 fuzz）。

## 流式上限

解析器不要求先把整个请求读进内存。字节通过 `req_feed()` 任意分块喂入（可以一次一个字节），两个上限都在**字节入口处**判定：

- `ReqLimits.max_total`：整个请求头的总字节数（含 CRLF）。第 `max_total+1` 个字节在入口即被拒绝、不落任何缓冲区，峰值保留字节恰好等于上限。
- `ReqLimits.max_line`：单行长度（不含 CRLF）。超线的那个字节在写入行缓冲前被拒。

保证：

- **常数内存**：解析器内存只来自构造时的 `ReqLimits`（一个 `max_line+1` 行缓冲 + 定长 header 表），与请求实际大小无关。自测对 128 MB 输入断言 RSS 基本不增长。
- **超限即停**：一旦出错解析器进入终态，后续 `req_feed` 直接返回同一错误、不再累积；调用方据此停止读取该连接的请求头。
- **结果一致**：整包 `parse_all()` 与逐字节/变块 `req_feed()` 走同一条代码路径，fuzz 对同一输入比对三种喂法的错误码。
- **上限不可被请求绕过**：限制只来自 `ReqLimits`，请求里的 `Content-Length` 等任何字段都无法抬高或重置它；CRLF 计入总长，分块边界无法稀释计数。

## 接口

```c
ReqLimits lim;
req_limits_defaults(&lim);          /* 默认 max_total=4096, max_line=256 */
/* lim 可按需修改；max_line 不得大于 max_total，二者必须非零 */

Request* req = req_new(&lim);       /* 内存只按 limits 分配 */
ReqErr e;
while ((n = read(fd, buf, sizeof buf)) > 0) {
    e = req_feed(req, buf, n);
    if (e != REQ_OK) { /* 超限或语法错：停止读取、关连接 */ break; }
    if (req_done(req)) { /* 请求头完整 */ break; }
}
req_free(req);
```

## 拒绝项

CL+TE 冲突、重复 `Content-Length`、obs-fold 折叠、非法控制字符、裸 CR / 单独 LF、超长行、超大请求头、过多 header、畸形请求行与版本。
