# Egress Policy Proxy（出口网络策略代理）

一个本地可运行的正向代理：本地客户端的出站 HTTP / HTTPS 请求统一经过它，按策略
**确定性地放行或拒绝**。在「域名解析、策略热更新、上游故障」交织时，结论始终唯一、
可解释，且任何请求都不会卡死。

- HTTP：标准正向代理（客户端用绝对 URI 访问）。
- HTTPS：`CONNECT` 隧道；在建立隧道**之前**完成解析与策略判定。
- 判定对 HTTP 与 HTTPS 使用**同一条**「解析 → 判定 → 拨号」路径。

---

## 1. 快速开始

```bash
# 构建
go build ./...

# 启动（初始策略必须合法，否则进程直接退出——绝不退化成全部放行）
go run ./cmd/egress-proxy \
  -policy configs/policy.json \
  -listen 127.0.0.1:18080 \
  -admin  127.0.0.1:18081

# 让客户端走代理
export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
curl -i http://example.com/
curl -i https://example.org/   # 走 CONNECT
```

管理接口：

| 方法 | 路径 | 说明 |
| ---- | ---- | ---- |
| GET  | `/admin/stats`  | 放行/拒绝/各错误分类计数、按规则命中计数 |
| GET  | `/admin/status` | 当前策略修订号、最近一次重载结果、活动连接数 |
| POST | `/admin/reload` | 从文件原子重载策略 |

也可以发送 `SIGHUP` 触发同样的文件重载。

---

## 2. 策略格式

策略是单个 JSON 对象（见 `configs/policy.json`）：

```json
{
  "version": 1,
  "default_action": "deny",
  "rules": [
    {
      "id": "allow-example-https",
      "action": "allow",
      "domains": ["example.com", "*.example.org", ".cdn.net"],
      "ips": ["10.0.0.0/8", "1.2.3.4"],
      "ports": [443, "8000-9000"]
    }
  ]
}
```

- `version`：当前仅支持 `1`。
- `default_action`：`allow` 或 `deny`。无任何规则匹配时采用该动作。
- `rules[].id`：**必须非空且全局唯一**。
- `rules[].action`：`allow` 或 `deny`。
- `domains`：域名匹配器（见下）。
- `ips`：IP 或 CIDR；单 IP 视为 `/32`/`/128`。IPv4-mapped IPv6 会归一化。
- `ports`：端口选择器，支持数字 `443` 或闭区间字符串 `"8000-9000"`；范围 `1-65535`。

一条规则内 `domains`、`ips`、`ports` 之间是 **AND** 语义（声明了就都要命中；
三者全空的规则非法）。`domains` 列表内部、`ips` 列表内部为 OR。

### 域名语法

| 写法 | 含义 |
| ---- | ---- |
| `example.com`   | 精确匹配 `example.com`，**并**匹配其所有层级子域 `a.example.com`、`a.b.example.com` |
| `*.example.org` | **单层**通配，仅匹配 `a.example.org`，不匹配 `example.org`，也不匹配 `a.b.example.org` |
| `.cdn.net`      | 仅子域，匹配 `x.cdn.net`，不匹配 `cdn.net` 自身 |

匹配前 host 会转小写并去空白。

### 校验原则：畸形/非法规则绝不静默忽略

加载（启动或重载）时整体校验，**任何一处非法即整体失败**，并汇总全部错误原因，
每条都带定位（如 `rules[3](my-id).ips[1] ...`）。包括但不限于：

- JSON 语法错误、**未知字段**；
- 不支持的版本、非法 `default_action` / `action`；
- 规则 `id` 为空或重复；
- 域名语法非法（空标签、非法字符、`*` 位置错误等）；
- IP/CIDR 非法、端口越界或区间起点大于终点；
- 同一规则内域名 / IP / 端口重复；
- 规则三要素全空。

---

## 3. 冲突判定（唯一结论 + 可解释）

当多条规则同时命中时，按以下**全序**比较，胜出者唯一：

1. **IP/CIDR 命中优先于域名命中**（防止“域名允许、但实际解析到恶意/内网地址”绕过）：
   - IP 精确（`/32`、`/128`）= 3
   - CIDR 区间 = 2
   - 未命中 IP = 0
2. 其次域名精度：精确 = 2，子域/单层通配 = 1，未命中 = 0。
3. 其次端口：命中显式端口选择器 = 1，否则 0。
4. 以上全部相同（同优先级）时，**声明顺序靠前者唯一胜出（first-match-wins）**。

> 关键效果：即使域名规则是 `allow`，只要解析得到的任一地址命中 `deny` 的 IP/CIDR，
> 由于 IP 优先级更高，请求一律拒绝。HTTP 与 HTTPS 都在拨号/建立隧道前执行该判定，
> 拒绝的连接永远不会到达上游。

被拒绝时响应为 `403`，响应头 `X-Egress-Reason: policy_denied`，body 给出：

```json
{
  "result": "denied",
  "reason": "policy_denied",
  "host": "app.example.com",
  "port": 443,
  "explanation": "host=... 共 2 条规则匹配；生效规则 deny-cidr（动作 deny，优先级 ip=2/...）",
  "winner": { "rule_id": "deny-cidr", "action": "deny", "ip_hit": "解析地址 10.2.3.4 命中 10.0.0.0/8" },
  "all_matched": [ { "rule_id": "..." } ]
}
```

---

## 4. 错误分类（可区分，且请求不卡死）

代理对每类失败返回独立状态码与 `X-Egress-Reason`，并分别计数：

| 场景 | HTTP 状态 | `X-Egress-Reason` | 统计分类 |
| ---- | -------- | ----------------- | -------- |
| 策略拒绝 | 403 | `policy_denied` | `denied_policy` |
| 域名解析失败 | 502 | `dns_failed` | `dns_failed` |
| 上游不可达（拒绝连接/重置） | 502 | `upstream_unreachable` | `upstream_fail` |
| 上游超时（拨号/读响应/整体） | 504 | `upstream_timeout` | `upstream_timeout` |
| 请求畸形（无法确定 host/port） | 400 | `bad_request` | `bad_request` |

- 解析超时由解析器超时控制；拨号超时 `-dial-timeout`；
  单次请求整体受 `-request-timeout` 约束（默认 30s）。
- 读上游响应放在可被 `ctx` 取消的路径中：超时会主动关闭上游连接以打断阻塞读，
  因此**没有任何请求会永久挂起**，也不会遗留 goroutine 或连接。
- 上游连接在隧道/转发结束后关闭；`/admin/status` 的 `active_conns` 用于观察泄漏。

---

## 5. 热更新语义

- 策略保存在 `atomic.Pointer[Policy]` 指向的**不可变快照**中。
- 请求在处理开始时取一次快照，整个请求只使用该版本，因此进行中的请求
  **绝不会看到新旧混合的规则**。
- 重载先**整体解析+校验**，成功才原子替换（修订号 +1）；失败则明确返回全部原因，
  修订号不变，**继续沿用上一版策略**。
- 启动即失败时进程退出，**安全默认是拒绝全部，而不是放行全部**。
- 重载接口串行化，并发重载不会产生中间态。

`POST /admin/reload` 返回示例：

```json
{ "Success": true, "Revision": 3, "Replaced": true, "Reason": "" }
```

失败时 HTTP 422，`Success=false`，`Reason` 为全部校验错误，`Revision` 仍为当前生效版。

---

## 6. 统计

`GET /admin/stats`：

```json
{
  "total": 52,
  "by_outcome": {
    "allowed": 27, "denied_policy": 25,
    "dns_failed": 0, "upstream_fail": 0, "upstream_timeout": 0, "bad_request": 0
  },
  "rule_hits": { "allow-a": 27, "deny-b": 25 },
  "allowed": 27,
  "denied": 25
}
```

- 每个请求终态只进入一个互斥分类，因此不会重复计数；终态在同一路径落账，不会漏计。
- `rule_hits` 为生效规则的命中次数，其合计等于「有生效规则的请求数」。
- 客户端中途断开记为内部分类 `client_gone`，不计入放行/拒绝。

---

## 7. 本地验证（无需外部网络）

测试全部使用本地 `httptest` 源站与**内存解析器**（把域名映射到 `127.0.0.1`），
不访问真实网络即可复现「解析地址与域名不一致」「上游拒绝/超时」「并发热更」等场景。

```bash
# 普通测试
go test -count=1 ./...

# 竞态检测（需要 cgo/gcc，本机已具备）
CGO_ENABLED=1 go test -race -count=1 ./...

# 按业务分组、打印“覆盖了哪些业务 / 每个用例结果”的脚本
./scripts/test.sh
./scripts/test.sh -race
```

脚本按以下业务分组输出用例与通过情况：

1. 策略格式校验与畸形规则整体拒绝
2. 域名匹配（精确 / 子域 / 单层通配）
3. 规则冲突唯一判定与生效规则解释
4. 热更新原子性、失败回退与并发快照
5. HTTP 转发放行 / 拒绝 / 统计 / 可解释
6. 防解析差异绕过（域名允许但解析 IP 拒绝，含 IP 字面量）
7. 错误分类（DNS / 上游不可达 / 超时 / 畸形请求）
8. HTTPS CONNECT 判定与防绕过（真实本地 TLS 往返）
9. 高并发请求 × 热更：竞态、连接泄漏、计数守恒
10. 统计并发守恒
11. 端到端：启动拦截 / 管理接口热更 / 统计查询

---

## 8. 代码结构

```
cmd/egress-proxy/main.go      入口、参数与信号接线
configs/policy.json                示例策略
internal/policy/
  policy.go                        解析、整体校验、LoadError
  domain.go                        域名/子域/通配匹配器
  eval.go                          全序冲突判定与解释
  store.go                         原子快照热更新
internal/proxy/
  resolver.go                      解析器抽象（系统解析器 + 测试用内存解析器）
  proxy.go                         HTTP 转发 + CONNECT 隧道 + 错误分类/超时/统计
internal/server/server.go          代理与管理接口装配、reload/SIGHUP
internal/stats/stats.go            并发安全、互斥分类统计
scripts/test.sh                    按业务分组的本地测试脚本
```
