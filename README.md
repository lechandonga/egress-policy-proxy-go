# 出口网络策略代理（egress-policy-proxy-go）

一个本地可运行的 HTTP/HTTPS 正向代理：所有出站请求先经过策略判定，再决定放行或拒绝。
设计目标是在**域名解析、策略热更新、上游故障交织时结论始终确定且可解释**。

- 仅依赖 Go 标准库（Go 1.25+）。
- 纯标准库即可运行；测试全部使用本地 upstream 与可注入的离线解析器，**不依赖外部网络**。

## 快速开始

```bash
go build -o egress-proxy ./cmd/egress-proxy
./egress-proxy -listen 127.0.0.1:8080 -admin-listen 127.0.0.1:8081 -policy policy.example.json

# HTTP 正向代理
curl -x http://127.0.0.1:8080 http://api.saas.example/
# HTTPS（CONNECT 隧道，TLS 端到端，代理只看到主机名与端口）
curl -x http://127.0.0.1:8080 https://api.saas.example/
```

启动时若策略无法加载，进程直接退出——**不会退化成全部放行**。

## 策略格式

策略为单个 JSON 文件，顶层 `rules` 为规则数组，至少包含一条规则：

```json
{
  "rules": [
    {
      "id": "deny-danger-nets",
      "action": "deny",
      "domains": ["*.internal.example.com", "admin.example.com"],
      "cidrs": ["169.254.0.0/16"],
      "ports": [443, "8000-8999"],
      "priority": 100
    }
  ]
}
```

字段说明：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `id` | 是 | 规则唯一标识，重复 id 会导致整个策略加载失败 |
| `action` | 是 | `allow` 或 `deny`，其他值非法 |
| `domains` | 与 `cidrs` 至少一个 | 域名列表。精确名 `a.com` 只匹配自身；`*.a.com` 匹配 `a.com` 及其任意层级子域（`x.a.com`、`x.y.a.com`），但不匹配 `evila.com` |
| `cidrs` | 与 `domains` 至少一个 | IP 或 CIDR 列表，如 `203.0.113.0/24`、`127.0.0.1`。`0.0.0.0/0`、`::/0` 被拒绝 |
| `ports` | 否 | 端口列表，元素为数字 `443` 或闭区间字符串 `"8000-9000"`；省略表示任意端口。端口 0 与 low>high 非法 |
| `priority` | 否 | 整数，默认 0；越大越优先 |

一条规则内所有已设置的约束必须**同时**满足（AND）。只设置 `domains`
的规则不会匹配字面 IP 请求，只设置 `cidrs` 的规则不会在拿不到 IP 时匹配。

非法规则不会被静默忽略：任何一条规则畸形（JSON 语法错误、未知字段、缺 id、
重复 id、非法 action、非法域名/CIDR/端口等）都会让**整份策略加载失败**。

## 冲突判定（唯一、可解释）

一个请求会带着 `(域名, 实际解析 IP, 端口)` 参与判定。所有匹配的规则按如下
**全序**排序，排第一的规则即为唯一生效规则，其 `id` 会通过响应头
`X-Egress-Rule` 返回，详细原因在 JSON 响应体的 `detail` 中：

1. `priority` 高者胜（显式优先级压过一切，可用于强制封禁）；
2. 同优先级时，**约束更具体者胜**（具体度按 域名精确>通配>未设、CIDR 前缀长度、单端口>区间>未设 的总分比较，再逐维比较），因此宽泛 deny 不会遮蔽一条精确 allow；
3. 具体度也相同时，**deny 胜 allow**（安全侧默认）；
4. 仍相同时按规则 `id` 字典序——保证结论永远唯一。

没有任何规则匹配时为**默认拒绝（fail closed）**。

### 域名与实际解析地址双重判定

请求先解析域名，随后对**每一个解析结果地址**都做判定：

- 只要有一个地址落入拒绝范围，整个请求被拒绝（防止 DNS rebinding / 多 A 记录绕过）；
- 域名本身被允许、但解析 IP 命中 deny CIDR 时同样拒绝，生效规则是该 deny 规则。

## 错误分类（结果可区分）

代理对错误情况返回不同 HTTP 状态码与 `X-Egress-Reason` 响应头：

| 情况 | HTTP 状态 | `X-Egress-Reason` | 统计桶 |
| --- | --- | --- | --- |
| 策略拒绝（含默认拒绝） | 403 | `policy_deny`（附 `X-Egress-Rule`） | `denied_policy` |
| 域名不存在 | 502 | `resolve_nxdomain` | `resolve_failed` |
| 解析器故障/超时/空结果 | 502 | `resolve_failure` | `resolve_failed` |
| 上游不可达（拒绝连接、网络不可达） | 502 | `upstream_unreachable` | `upstream_dial` |
| 上游拨号/IO 超时 | 504 / 502 | `upstream_timeout` | `upstream_io_timeout` |
| 策略尚未加载（fail closed） | 503 | `policy_unavailable` | `client_error` |
| 代理请求本身畸形 | 400 | `bad_request` | `client_error` |

每个请求都有总超时（`-request-timeout`），拨号有独立超时
（`-dial-timeout`），CONNECT 隧道有双向空闲超时（`-idle-timeout`），
任何请求都不会永久挂起；隧道任一半关闭即关闭两端连接，无 goroutine/连接泄漏。

## 热更新语义

两种触发方式：

- 向管理端发送 `POST /reload`；
- 向进程发送 `SIGHUP`。

语义：

- **全量编译、原子切换**：新策略先完整解析+校验，成功后才整体替换；失败则明确返回错误并继续沿用旧版本，进行中的请求不会看到新旧混合规则；
- 进行中的请求持有开始时拿到的不可变快照（`atomic.Pointer[*Policy]`）；
- `/reload` 返回体用 `error_kind` 区分 `validation`（策略内容非法）与 `io`（文件读取失败），并给出 `active_version` 证明旧策略仍在生效。

策略版本为 `路径@内容哈希前缀`，可通过 `GET /version` 查询。

## 管理 API

默认监听 `127.0.0.1:8081`（`-admin-listen`）：

- `GET /stats`：计数快照。`total` 为请求总数；`counts` 按上述桶分类；
  `rules` 为每条**生效规则**的命中次数及 allow/deny 拆分。每个请求恰好计数一次，
  桶之和恒等于总数（代码内有不变量校验）。
- `POST /reload`：热更新，返回新版本或可区分的失败原因。
- `GET /version`：当前生效策略版本。

## 本地验证

```bash
# 单元测试（全部离线：本地 HTTP/HTTPS testserver + 可注入解析器/拨号器）
go test -count=1 ./...

# 竞态检测（需要 cgo）
CGO_ENABLED=1 go test -race -count=1 ./...

# 查看每个业务场景的用例与通过情况
go test -v -count=1 ./internal/policy ./internal/proxy ./internal/admin
```

测试覆盖的业务场景：

- **规则引擎**：精确/通配域名匹配（含 `evila.com` 式后缀攻击）、子域与多级子域、
  端口单值/区间、IP/CIDR、默认拒绝、deny 与 allow 冲突、显式优先级、具体度决胜、
  id 字典序兜底、“域名允许但解析 IP 拒绝”；
- **畸形策略**：非法 JSON、未知字段、缺/重 id、非法 action、空规则集、无约束规则、
  非法 CIDR、`0.0.0.0/0`、通配位置错误、端口 0/倒序区间——全部返回 `LoadError`
  且与文件 I/O 错误可区分；
- **代理转发**：HTTP 放行与拒绝、HTTPS CONNECT 放行与拒绝、生效规则回传；
- **解析与故障**：NXDOMAIN 与解析器故障可区分、连接拒绝（502）与拨号超时（504）可区分、
  CONNECT 隧道空闲超时不卡死不泄漏、无策略时 503 fail closed；
- **并发**：高并发请求与反复策略重载同时进行（`-race` 下验证无数据竞争），
  统计总数精确等于请求数，规则归因不重复、不漏计；
- **热更新**：损坏文件加载失败并沿用旧版本（校验 `active_version` 未变），
  合法文件整体切换且版本变化。

## 目录结构

```
cmd/egress-proxy/        命令行入口（启动加载、SIGHUP 重载、优雅退出）
internal/policy/         规则模型、编译校验、冲突判定、原子快照存储与热更新
internal/resolver/       解析抽象（标准实现 + 离线 Map/Func，错误分类）
internal/proxy/          HTTP 转发与 HTTPS CONNECT、双重判定、超时与错误分类
internal/stats/          无锁计数与按规则归因（单请求单次计数）
internal/admin/          /stats、/reload、/version 管理接口
policy.example.json      策略示例
```
