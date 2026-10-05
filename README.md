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
  `rules` 为每条**生效规则**的命中次数及 allow/deny 拆分。每个请求恰好计数一次。
  **快照保证：不失败且自洽**——计数与快照在同一互斥域内更新，任何一次查询拿到的都是
  单一时间点的视图，各分类之和恒等于 `total`，各规则命中之和与总数同源一致；
  无论并发转发与并发查询多密集，查询永远不会失败、不会返回自相矛盾的数字，
  进程也不会因为统计查询而崩溃。
- `GET /stats?window=5m`：在累计快照之外额外返回 `window` 字段——最近一段时间
  （Go duration，如 `30s`、`5m`、`90s`）内的观测窗口快照：`window.total`、
  `window.counts`（各分类）、`window.rules`（窗口内各生效规则命中及 allow/deny 拆分）。
  窗口内分类之和恒等于窗口总数；一次查询读到的是一份自洽快照。
  窗口长度服务端上限为 **1h**；`window<=0`、格式非法或超过上限一律返回 `400`，
  不会被截断或悄悄改默认值。窗口边界为半开区间 `(now-window, now]`，按 1 秒
  分桶对齐；窗口数据保存在固定大小（3600 桶）的环形缓冲里，运行多久、查询多频繁
  内存都有上界。不带 `window` 时响应字段与口径与旧版本**完全一致**。
- `GET /evaluate?host=<主机名>&port=<端口>[&addr=<IP>&addr=<IP>...]`：**策略试算
  （只问不做）**。不拨号、不转发，也**不计入**任何放行/拒绝统计。
  返回 `allowed`、`action`、`winning_rule`（没有规则命中时为空且 `default_deny=true`，
  明确标识默认拒绝）、`reason`、逐地址的判定明细 `addresses`，以及本次判定实际依据的
  `version`。
  - 试算与真实转发共用同一份判定函数（`Policy.Adjudicate`）：同一组主机/端口/地址，
    试算结论与生效规则和真发一个请求完全一致。**不给 `addr` 时按真实转发的那套处理**：
    先通过配置的解析器解析域名（生产为系统 DNS，测试可注入离线解析器），再对解析到的
    每一个地址做判定——所以"域名命中 allow、但实际解析地址落在拒绝网段"在试算里同样是
    拒绝，生效规则就是那条 deny 规则；解析失败（NXDOMAIN / 解析器故障）返回 `502` 及
    可区分的 `reason`（`resolve_nxdomain` / `resolve_failure`），绝不伪装成放行/拒绝结论；
    给了一组 `addr` 时等价于"假设解析到这些地址"：**主机名本身允许、但任一假设地址
    落入拒绝范围，整体即拒绝**，多个地址中第一个被拒的地址决定生效规则，此时完全不查 DNS。
  - `host` 是字面 IP 时按纯地址请求判定，且不允许再带 `addr`。
  - 版本绑定：每次试算只取一次不可变快照，即使判定途中发生重载，结论与返回的
    `version` 也整体属于同一份策略，不会新旧混合。
  - 参数非法（缺 host/port、端口不是 1–65535、`addr` 不是合法 IP、字面 IP 再带 addr）
    一律 `400` 并给明确错误，**绝不会返回一个放行结论蒙混过去**。
- `POST /reload`：热更新，返回新版本或可区分的失败原因。
- `GET /reload-history[?limit=n]`：最近若干次重载（默认 20、最大 128）的可追溯
  记录，按时间倒序：`seq`（触发序号）、`time`、`result`（success/failure）、
  `version`（该次重载之后生效的版本；失败时为继续沿用的旧版本）、`loaded_version`
  （成功加载的版本，失败为空）、失败时的 `error_kind`（细分类别：`io`、
  `invalid_json`、`invalid_port`、`invalid_cidr`、`invalid_domain`、`invalid_id`、
  `invalid_action`、`missing_constraint`、`empty_policy`）与 `error` 文案；
  响应还带 `current_version`。最近一次成功事件的 `version` 必然等于 `current_version`，
  历史最多保留最近 512 次（内存有上界）。
- `GET /version`：当前生效策略版本。

### 重载的并发与可靠性语义

- 每次触发（`POST /reload` 或 `SIGHUP`）都是一次**有结果的独立重载**：要么完整切到
  新版本，要么明确失败并继续使用旧版本；任何一次都不会停服、不会让进程退出。
  `SIGHUP` 在独立 goroutine 中处理、信号通道有缓冲，加载在途时继续接收后续信号，
  所以脚本里间隔发出的多次重载都会各自落库；注意 Unix 信号本身不排队，若多个
  SIGHUP 在进程尚未接管前的同一瞬间到达，OS 会将其合并（这是内核语义，管理接口
  路径不存在此限制）。
- 并发触发在服务端**串行化**：同一时刻只有一次加载/切换。调用方收到成功时，
  返回的版本就是当时生效的版本；最终生效版本必然对应历史里某一次完整成功的加载，
  不存在"收到成功但实际没生效"。**结果确定性**：文件读取、校验、原子切换与历史记录
  在同一把锁内完成，因此不存在"后完成的旧内容覆盖先完成的新内容"的交错——每次成功
  返回的版本在完成那一刻确实生效，历史里最近一次成功事件的版本必然等于当前生效版本
  （版本溯源规则），失败则继续沿用旧版本且历史里记录当时沿用的版本。
- 失败响应保留原字段：`error_kind` 仍是 `validation` / `io` 两分类（旧调用方不受影响），
  新增 `error_kind_detail` 给出上面列出的细分类别。

### 严格校验（本轮收紧）

任何一种非法写法都会让**整次重载失败**并返回可区分的原因，绝不自动修正、补默认值
或悄悄接受：

- 端口：浮点数、负数、`>65535`、字符串单值 `"443"`、`"80-abc"`、`"80-90-100"`、
  `"80-90x"`、`0`、倒序区间、布尔值等全部拒绝；
- 地址段：非法 IP/掩码长度（`1.2.3.4/99`）、**带主机位的网段**（`10.0.0.5/24` 不再
  被自动掩码，必须写 `10.0.0.0/24`）、首尾空格、`0.0.0.0`、`::`、带 zone 的地址
  （`fe80::1%eth0`）等全部拒绝；裸 IP（`127.0.0.1`、`::1`）与规范 CIDR 仍合法；
- 域名/通配符：空串、`*.`、中间/结尾通配符（`a.*.com`、`a.test*`）、前导/结尾/连续
  点、非法字符、空格、超过 63 字符的标签、连字符打头的标签等全部拒绝。大小写归一化
  保留（`Example.COM` 合法）。

重载失败后旧策略原封不动继续生效（测试会断言旧策略的判定语义不变）。

## 本地验证

```bash
# 单元测试（全部离线：本地 HTTP/HTTPS testserver + 可注入解析器/拨号器）
go test -count=1 ./...

# 竞态检测（需要 cgo）
CGO_ENABLED=1 go test -race -count=1 ./...

# 查看每个业务场景的用例与通过情况
go test -v -count=1 ./internal/policy ./internal/proxy ./internal/admin

# 只跑本轮新增行为
go test -v -count=1 -run 'Adjudicate|StrictValidation|Reloader' ./internal/policy
go test -v -count=1 -run 'Window' ./internal/stats
go test -v -count=1 -run 'Evaluate|Window|History|ConcurrentReload' ./internal/admin
go test -v -count=1 -run 'DryRun|TrafficWithHighFrequency|ReloadStorm' ./internal/proxy

# 本轮新增：快照自洽竞态压测 / 试算解析一致性 / 双路径重载确定性
go test -v -count=1 -run 'SnapshotConsistent|WindowInvalid' ./internal/stats
go test -v -count=1 -run 'EvaluateWithoutAddr|EvaluateWithAddr|ReloadDeterminism' ./internal/admin
go test -v -count=1 -run 'AdminEvaluateWithoutAddr' ./internal/proxy
go test -v -count=1 -run 'ChangingContent' ./internal/policy
```

手工验证（全部本地）：

```bash
go build -o egress-proxy ./cmd/egress-proxy
./egress-proxy -policy policy.example.json

# 试算：允许 / 命中默认拒绝 / 假设地址落在拒绝范围
curl -s 'http://127.0.0.1:8081/evaluate?host=api.saas.example&port=443&addr=1.2.3.4'
curl -s 'http://127.0.0.1:8081/evaluate?host=api.saas.example&port=443&addr=127.0.0.1'
curl -i 'http://127.0.0.1:8081/evaluate?host=api.saas.example&port=70000'   # 400
# 不带 addr：按真实解析结果判定（这里用系统 DNS；解析失败返回 502 + reason）
curl -s 'http://127.0.0.1:8081/evaluate?host=api.saas.example&port=443'

# 窗口统计 / 重载历史
curl -s 'http://127.0.0.1:8081/stats?window=5m' | jq .window
curl -s -X POST http://127.0.0.1:8081/reload
for i in $(seq 1 10); do curl -s -X POST http://127.0.0.1:8081/reload >/dev/null; done
curl -s 'http://127.0.0.1:8081/reload-history?limit=20' | jq .

# 信号触发（连发多次，每次都有结果且进程不退出）
pkill -HUP egress-proxy; pkill -HUP egress-proxy
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

本轮新增测试覆盖：

- **统计快照不失败且自洽**：8 路高频计数 + 4 路并发累计/窗口快照交叉压测，每份快照
  分类之和恒等于总数、规则命中与总数同源，查询零失败（`-race` 下验证）；
- **试算不带假设地址**：通过注入的离线解析器走与真实转发相同的"解析→逐地址判定"
  路径——域名 allow 但解析 IP 命中 deny CIDR 时试算同样拒绝且生效规则一致；多地址任一
  命中即拒；NXDOMAIN/解析器故障返回 502 与可区分 reason、不给结论；带 `addr` 时完全不
  查 DNS；试算零计数污染；返回版本恒等于当前生效版本；管理端 `/evaluate` 不带 addr 与
  真实转发逐案对比一致；
- **双路径重载确定性**：`POST /reload` 与 SIGHUP 等价路径并发触发、期间策略文件持续
  变化（含损坏内容），每次触发都有确定结果、历史无丢失、序号连续；串行成功时返回版本
  与 `/version` 一致；风暴结束后当前生效版本 == 历史最近一次成功版本 == 端点上报告的
  `current_version`；
- **试算一致性**：试算与真实转发的放行/拒绝结论与生效规则一致；假设地址命中拒绝
  CIDR 时整体拒绝；多个假设地址中任一命中即拒绝（与顺序无关）；不给假设地址时按真实解析结果判定（与转发一致）；
  默认拒绝显式标识；试算前后转发计数零增长；参数非法一律 400；重载并发时试算结果的
  结论与版本同属一份策略；
- **窗口统计**：窗口内各分类之和恒等于总数、规则 allow/deny 拆分守恒、时间边界
  （旧事件不进窗）、非法/超上限窗口被拒；多路口持续转发叠加高频 `/stats?window=`
  查询时查询不失败、每个快照自洽、环形缓冲大小固定；
- **重载可靠性**：管理接口路径下连续 50 次混合合法/非法触发每次都有结果、失败不换版本；
  12 路并发共 300 次触发无丢失、序号连续、调用方收到成功即与当前版本一致、当前版本
  可追溯到某次成功事件；历史有界；
- **边转发边查统计**：12 路转发 + 4 路高频统计查询长压测，计数精确等于完成请求数，
  静默后旧窗口自然清空（验证内存不随时间/查询累积）；
- **严格校验矩阵**：端口、地址段、域名/通配符的二十余种非法写法全部整次加载失败且
  带细分错误类别；连续多次不同类别的非法加载后旧策略快照与判定语义保持不变。

## 目录结构

```
cmd/egress-proxy/        命令行入口（启动加载、SIGHUP 重载、优雅退出）
internal/policy/         规则模型、编译校验、冲突判定、原子快照存储与热更新
internal/resolver/       解析抽象（标准实现 + 离线 Map/Func，错误分类）
internal/proxy/          HTTP 转发与 HTTPS CONNECT、双重判定、超时与错误分类
internal/stats/          互斥一致的计数与按规则归因（单请求单次计数，快照自洽）
internal/admin/          /stats、/reload、/version 管理接口
（另含 /evaluate 试算、/stats?window= 窗口、/reload-history 重载历史）
policy.example.json      策略示例
```
