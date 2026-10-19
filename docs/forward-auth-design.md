# WAF 部署形态与可插拔架构设计（forward-auth 前置校验 · Nginx + Traefik · 含请求体检测）

> 版本：v0.4（第一步方案）
> 依据：`docs/waf-feature-list.md`、`reference/coraza-traefik-WAF`（forward-auth 参考实现）、`reference/honeypot`（限流 / 通知 / 日志 参考实现）
> 进度状态（后续追加）：文中「步骤 1 / 2 / 3」已分别落地为 **M1 / M2 / M3**，**全部完成**（见 `docs/development-roadmap.md` §10.8 / §10.9 / §10.11）；
> 「步骤 4 / 5」对应 **M4 / M5**，尚未开始。实施过程中的少量偏差（Excel 导出格式选型、syslog 平台拆分、`Notifier` 接口的实际形态等）
> 统一记录在路线图 §10.11「关键设计取舍」与「文件清单」两节，阅读本文时请以该节为最新事实。
>
> 定位：部署形态为 **forward-auth 前置校验**，不做反向代理；**同时支持 Nginx 与 Traefik**；**请求体检测为必需能力**；**限速状态多实例共享**；**封禁仅在本 WAF 内部生效（不操作系统防火墙）**；**拦截统一返回 JSON 错误体**；所有功能项与插件统一为「配置启用 + 抽象接口 + 多实现 + 多实例串联」。

---

## 1. 需求识别

### 1.1 总体诉求 → 设计落点

| # | 诉求 | 设计落点 |
| --- | --- | --- |
| R1 | 部署形式为 **forward-auth 方案，做前置校验** | WAF 暴露单一鉴权端点，由 Nginx / Traefik 以子请求方式调用；只返回放行/拦截，不承载业务流量 |
| R2 | **不做反向代理方案** | 不实现 `httputil.ReverseProxy`、不做 TLS 卸载、不做路由转发、不接管连接 |
| R3 | **同时支持 Nginx 与 Traefik** | `ingress.type` 抽象为 `RequestExtractor` 多实现；两种代理的差异（注入头、体转发能力、错误体送达方式）全部在适配层收敛 |
| R4 | **需要请求体检测** | 体不是引擎内的可选项而是一等能力：`PhaseBody` 阶段 + 体缓冲抽象 + 双代理体转发方案（见 §3） |
| R5 | 功能项和插件做出**配置启用方案** | 所有功能以 YAML 开关 + 插件实例声明的方式装配，默认全关，按需开启 |
| R6 | **全部可自由配置启用** | 每个插件实例具备 `enabled` / `order` / `phase` / `settings` / `on_error`；`pipeline: []` 即纯放行 |
| R7 | **抽离抽象接口，配置不同实现方案** | 每个能力域定义 Go 接口 + 工厂注册表；`type` 字段选实现；新增实现不改动主流程 |
| R8 | **可配置多个，多个则串联** | `pipeline` 为有序数组，按 `phase` + `order` 串联执行；同类型可声明多实例；通知/日志类能力并联扇出 |

### 1.2 本轮新增确认要求（工程与实现约束）

| # | 要求 | 落地方式 |
| --- | --- | --- |
| R9 | **Traefik / Nginx 版本可升级** | 按体检测需求锁定最低版本（Traefik >= v2.11 支持 `forwardBody`；Nginx 用 OpenResty）。升级纳入变更流程 |
| R10 | **`reference/` 代码仅作参考，复用需复制一份** | 禁止直接 import / replace；复用代码复制到本项目目录后重命名、改造、补中文注释与单测，并标注来源（见 §2.1） |
| R11 | **命名符合编码规范** | 目录 / 文件 / 包 / 函数 / 变量 / 接口命名遵循统一规范（见 §2.3） |
| R12 | **注释全部为中文，且详细** | 包、类型、字段、函数、常量、复杂逻辑、配置项全部中文注释（见 §2.4） |
| R13 | **不做大体积读取；缓存大小与最大文件大小可配置** | 流式 + 限额 + 超限策略；所有「大小 / 容量 / 阈值 / 超时」进入配置文件（见 §2.5、§2.6） |
| R14 | **参考常用 Go Docker 模式** | 多阶段构建 + `CGO_ENABLED=0` 静态单二进制 + distroless + 非 root + 健康检查 + 离线镜像（见 §2.9） |
| R15 | **支持 CLI / 配置文件 / 环境变量三种配置来源** | 三通道统一由 `internal/config` 承载（见 §2.7） |
| R16 | **冲突优先级：CLI > 配置文件 > 环境变量** | 按「默认值 -> 环境变量 -> 配置文件 -> CLI」叠加（见 §2.7） |
| **R17** | **限速状态必须多实例共享** | 限速计数与封禁状态统一走**共享存储**（Redis），本地仅做短 TTL 缓存以减少往返（见 §7.3、§8.1） |
| **R18** | **封禁只在 WAF 内部生效，不执行系统防火墙操作** | 删除 `Blocker` 抽象与 iptables/firewalld/ufw 相关实现；封禁 = 写入共享存储的封禁名单，由 `banlist` 校验单元拦截（见 §7.3） |
| **R19** | **封禁时长可配置，默认取恰当值** | `ban.default_ttl` 默认 **30m**（兼顾劝退效果与 NAT 出口误封风险）；支持 `max_ttl` 与可选累进封禁（见 §7.5） |
| **R20** | **不提供拦截页面，统一返回 JSON 错误响应体** | Responder 仅实现 JSON 错误体；含代理侧送达方案（OpenResty 直接回写 / Traefik 走 `/waf/deny` 渲染端点）（见 §4） |
| **R21** | **日志分两类、分级、JSON 格式** | ① 系统日志（`system`）② 访问/拦截日志（`access`）；等级 debug/info/warn/error/fatal；全部 JSON（见 §5） |

### 1.3 部署形态确认（依据《功能列表》文档 §6）

| 形态 | 是否采用 | 理由 |
| --- | --- | --- |
| **forward-auth 前置校验** | 采用 | 已有 Nginx/Traefik 入口，WAF 只做鉴权子请求；改动面最小 |
| 反向代理 | 不采用 | 需自研 TLS/路由/连接管理；与「前置校验」定位冲突 |
| Go 中间件库 | 不采用 | 需改造业务代码，升级耦合 |
| HAProxy SPOE | 暂不采用 | 可作为后续新增的 ingress 适配器（接口已预留） |

### 1.4 双代理接入矩阵

| 代理 | 集成方式 | 请求体可见 | 体检测 | 说明 |
| --- | --- | --- | --- | --- |
| **Traefik** v2.11+ / v3.x | `ForwardAuth` + `forwardBody: true` + `errors` | 是 | **原生支持** | 体随鉴权子请求送达；错误体需 `errors` 中间件回源 `/waf/deny` |
| **Nginx**（OpenResty） | `access_by_lua_block` + `ngx.location.capture` | 是 | **推荐** | Lua 可直接回写子请求响应体，JSON 错误体一步到位 |
| **Nginx**（原生） | `auth_request` | 否 | 不支持 | 子请求 `header_only = 1`：既不转发请求体，也丢弃响应体 |
| **Nginx**（原生）+ `mirror` | `mirror` 异步外送 | 异步 | 仅事后观察 | 无法在本次请求内拦截，仅用于 DetectionOnly 采样 |

> 结论：**两台代理都支持，且都能做请求体检测**（Nginx 侧升级到 OpenResty）。原生 Nginx 降级路径仅作兜底，且**无法返回 JSON 错误体**（需在文档标注）。

### 1.5 forward-auth 契约（WAF 对外协议）

```
反向代理 (Nginx / Traefik)                    WAF(forward-auth)
   |  POST /waf/auth  (子请求)                 |
   |  Host / X-Forwarded-Host,                |
   |  X-Forwarded-Uri / X-Original-URI,       |
   |  X-Forwarded-Method, X-Forwarded-Proto,  |
   |  X-Forwarded-For / X-Real-IP,            |
   |  Content-Type / Content-Length,          |
   |  请求体（仅体转发通道）                     |
   |----------------------------------------->|
   |                                          |  还原原始请求 -> 头校验 -> 体校验
   |<-----------------------------------------|
   |  200 = 放行                              |
   |  403 = 拦截   + JSON 错误体               |
   |  401 = 认证挑战 + JSON 错误体             |
   |  429 = 限速   + JSON 错误体 + Retry-After |
   |  503 = 失败关闭 + JSON 错误体             |
   |  回传头：X-WAF-Request-Id / X-WAF-Verdict |
   |          X-WAF-Code / X-WAF-Rule-Id       |
```

| 判定 | HTTP | 响应体 | 说明 |
| --- | --- | --- | --- |
| Allow | `200` | 空 | 允许代理继续转发 |
| Observe | `200` | 空 | 仅落访问日志（detection_only 模式） |
| Block / Drop | `403` | JSON | 拦截主体 |
| Unauthorized | `401` + `WWW-Authenticate` | JSON | Basic Auth / 站点口令 |
| RateLimited | `429` + `Retry-After` | JSON | 限速 / CC 触发 |
| BadRequest | `400` | JSON | 请求体超限 / 畸形 / 被拒 |
| Unavailable | `503` | JSON | 失败关闭（`on_error: block` 且引擎不可用） |

> **代理差异（重要）**：两种代理都会**丢弃鉴权子请求的响应体**，但 **Nginx 可以读取鉴权响应头**（`auth_request_set $upstream_http_*`）。因此采用「**鉴权响应头 + 代理侧渲染**」方案，详见 §4.3。
>
> **Nginx 限制（必须遵守）**：`auth_request` 只透传 `401`/`403`，其它状态码（429/503 等）一律转成 `500`。因此 WAF 对 Nginx 通道统一返回 `403`，真实原因由响应头 `X-WAF-Code` 表达，最终对外状态码由渲染端点决定。

---
## 2. 工程规范与配置体系

### 2.1 reference 代码复用方式

`reference/` 下两个工程（`coraza-traefik-WAF`、`honeypot`）**只作为参考实现**，用于理解做法与验证可行性。

| 规则 | 说明 |
| --- | --- |
| 禁止直接依赖 | 不在 `go.mod` 中 `require` / `replace` 指向 `reference/`；不 `import` 其包路径 |
| 复用必须复制 | 需要复用的代码**复制一份**到本项目对应目录，再改造 |
| 复制后必须改造 | ① 重命名为本项目命名规范；② 适配本项目抽象接口；③ 统一错误包装与日志；④ 补齐中文详细注释；⑤ 补齐单元测试；⑥ 文件头标注来源与改动点 |
| 不参与构建 | `reference/` 各自含独立 `go.mod`，不属于根模块；根目录 `go build ./...` 不会进入子模块 |
| 目录归属 | 建议后续将 `reference/` 移出主仓库或标记为只读参考，避免误改 |

典型复用清单（已按 R18 调整，**防火墙模块不再复用**）：

| 参考来源 | 能力 | 复制目标 |
| --- | --- | --- |
| `reference/honeypot/internal/ratelimit` | 频率追踪（需改造为多维度令牌桶 + 共享存储） | `internal/check/ratelimit/` |
| `reference/honeypot/internal/notify` | 企业微信 / 通用 JSON / HFish / HoneyWire 告警 | `internal/notify/` |
| `reference/honeypot/internal/logger` | 按日轮转 JSON 日志（需改造为双通道 + 分级） | `internal/logging/` |
| `reference/honeypot/internal/config` | 分层配置加载思路（优先级需按 R16 反转） | `internal/config/` |
| `reference/coraza-traefik-WAF/main.go` | Coraza 事务构造 + 规则加载 + 热更新 | `internal/check/coraza/` |

> `reference/honeypot/internal/firewall`（iptables / firewalld / ufw）**明确不复用**：本方案不做系统防火墙联动（R18）。

### 2.2 编码规范

| 项 | 规范 |
| --- | --- |
| 基础风格 | 遵循 Effective Go / Go Code Review Comments / Uber Go Style Guide |
| 格式化 | `gofmt`（必须）+ `goimports`；提交前统一执行 |
| 静态检查 | `go vet`、`staticcheck`、`golangci-lint`（离线二进制），CI 必须全绿 |
| 包组织 | `cmd/<二进制名>` 只做装配；`internal/<领域>` 放实现；接口定义在**使用方**包（`internal/core`） |
| 接口设计 | 小接口优先（1-3 个方法）；按能力域拆分，避免上帝接口 |
| 错误处理 | 一律 `fmt.Errorf("...: %w", err)` 包装；禁止吞错；禁止 `panic`（仅不可恢复的启动期断言例外） |
| 上下文 | `context.Context` 作为首个参数并透传；禁止存入结构体 |
| 并发 | 共享状态用 `sync.RWMutex` / `atomic`；并发假设必须写入注释 |
| 资源释放 | `io.Closer` 一律 `defer Close()`；临时文件必须清理 |
| 依赖 | 优先标准库（日志用标准库 `log/slog`）；新增第三方依赖需评估离线可用性与许可证 |
| 禁止使用 | **禁止 `os/exec` 执行系统命令**（如 iptables/firewalld），符合 R18 |
| 测试 | 单测与源码同目录 `xxx_test.go`；表驱动；关键路径必须有契约测试 |
| 禁止事项 | 禁止硬编码大小/超时/路径；禁止魔法数字；禁止无注释的复杂逻辑 |

### 2.3 命名规范

| 对象 | 规范 | 示例 |
| --- | --- | --- |
| 目录 | Go 目录用单数小写单词 | `internal/ingress/forwardauth` |
| 包名 | 小写单数，与目录名一致，无下划线 | `package forwardauth` |
| 文件 | 全小写，多词用下划线 | `body_spool.go`、`extractor_test.go` |
| 导出类型/函数 | 大驼峰 | `RequestExtractor`、`NewPipeline` |
| 未导出 | 小驼峰 | `parseBodyMeta` |
| 接口 | 能力名或名词，避免 `I` 前缀 | `Check`、`Store`、`Notifier` |
| 常量 | 大驼峰，枚举用类型前缀 | `PhaseBody`、`VerdictBlock` |
| 变量 | 语义化；循环用 `i/j/k`；接收者 1-2 字母且全文件一致 | `bodyMeta`、`trustedProxies` |
| 配置项（YAML） | 全小写 + 下划线 | `max_bytes`、`default_ttl` |
| 环境变量 | `WAF_` 前缀 + 大写 + 下划线 | `WAF_STORES_0_ADDR` |
| CLI flag | 小写 + `-`，与配置路径对应 | `--ban-default-ttl` |
| 插件 `type` 名 | 全小写 + `-` | `coraza`、`ratelimit`、`banlist` |

### 2.4 注释规范（全部中文、详细）

| 对象 | 要求 |
| --- | --- |
| 包 | 必须有包注释：`// Package xxx 提供 ...`，说明职责、使用方式、并发安全性 |
| 导出类型/函数/常量 | 必须有 godoc 风格中文注释，首词为标识符名 |
| 结构体字段 | 逐字段注释；可配置项注明默认值、单位、取值范围 |
| 接口方法 | 注释说明语义、参数含义、返回条件、错误场景、并发安全 |
| 复杂逻辑 | 注释「为什么这样做」而非「做了什么」；算法需说明边界条件 |
| 配置文件 | YAML 每一项必须有中文注释，且与 Go struct 注释语义一致 |
| 平台差异 | 涉及 Nginx / Traefik 差异处必须注明原因（如 `header_only = 1`） |
| TODO | `// TODO(责任人/日期): 说明` |
| 禁止 | 无意义注释（如 `// i 自增`）、与代码不一致的过期注释 |

示例（接口与函数注释）：

```go
// BodySpool 负责将请求体缓冲到内存或临时文件。
//
// 设计约束：
//   - 禁止一次性读取超大请求体，超过 MaxBytes 时按策略截断或拒绝；
//   - 内存模式仅在体小于 MemoryThreshold 时启用，避免大体内存驻留；
//   - 落盘模式使用 os.CreateTemp 生成临时文件，调用方必须在请求结束时调用 Close 清理。
//
// 并发安全性：实现必须可被多个 goroutine 并发调用。
type BodySpool interface {
	// Store 从 r 读取请求体并按策略缓冲。
	//
	// 参数说明：
	//   r            原始请求体读取器，可为 nil（表示无请求体）
	//   declaredLen  代理声明的 Content-Length，-1 表示未知（分块传输）
	//   policy       限额与超限处置策略
	//
	// 返回的 Body 在读取完成后必须调用 Close 释放资源。
	Store(r io.Reader, declaredLen int64, policy BodyPolicy) (*Body, error)
}
```

### 2.5 大文件与内存约束

**硬性约束：禁止将大文件或大请求体整体读入内存。**

| 场景 | 做法 |
| --- | --- |
| 请求体 | 流式读取；上限 `ingress.body.max_bytes`；超限按 `truncate` / `reject` / `skip` 处置；超过 `memory_threshold` 落临时文件 |
| CRS 规则文件 | 逐文件流式加载，**不合并为单个大字符串**；单文件上限 `limits.max_rule_file_bytes`，总量上限 `limits.max_rules_total_bytes`；超限跳过并告警 |
| IP/CIDR 情报文件 | `bufio.Scanner` 逐行扫描；单行上限 `limits.max_scan_token_bytes`；总量上限 `limits.max_intel_file_bytes` |
| GeoIP MMDB | 只读内存映射（mmap），**禁止** `io.ReadAll`；上限 `limits.max_mmdb_bytes` |
| 日志文件 | `bufio.Writer` 写入；按日 + 按大小双维度轮转；单文件上限 `logging.system.max_file_bytes` / `logging.access.max_file_bytes` |
| 访问日志 | 默认仅记录请求元信息，**不记录请求体内容**（`include_body: false`）；如需记录按 `max_body_snippet_bytes` 截断 |
| 缓存 | 内存缓存必须有条目数与字节数双上限（`cache.*`），超限按 LRU 淘汰 |
| 配置读取 | 配置文件上限 `limits.max_config_file_bytes`，超限直接报错退出 |

### 2.6 可配置限额清单（全部落在配置文件，禁止硬编码）

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `ingress.body.max_bytes` | `1048576` | 单请求体读取上限（1 MiB） |
| `ingress.body.memory_threshold` | `65536` | 超过该值转为落盘缓冲 |
| `ingress.body.chunk_bytes` | `32768` | 流式读取的单块大小，禁止一次性读入整个请求体 |
| `ingress.body.spool_dir` | `""` | 临时文件目录，空则使用系统临时目录 |
| `ingress.body.read_timeout` | `2s` | 请求体读取超时 |
| `engine.body.limit_bytes` | `13107200` | Coraza 请求体上限（对应 `SecRequestBodyLimit`） |
| `engine.body.in_memory_limit_bytes` | `131072` | 体内存阈值（对应 `SecRequestBodyInMemoryLimit`） |
| `limits.max_rule_file_bytes` | `2097152` | 单个规则文件上限（2 MiB） |
| `limits.max_rules_total_bytes` | `67108864` | 规则目录总量上限（64 MiB） |
| `limits.max_scan_token_bytes` | `1048576` | 逐行扫描单行上限（1 MiB） |
| `limits.max_intel_file_bytes` | `67108864` | 情报文件上限（64 MiB） |
| `limits.max_mmdb_bytes` | `268435456` | MMDB 文件上限（256 MiB） |
| `limits.max_config_file_bytes` | `1048576` | 配置文件上限（1 MiB） |
| `limits.max_header_bytes` | `1048576` | 单请求头总量上限 |
| `logging.system.max_file_bytes` | `134217728` | 系统日志单文件上限（128 MiB） |
| `logging.access.max_file_bytes` | `134217728` | 访问日志单文件上限（128 MiB） |
| `logging.access.max_body_snippet_bytes` | `4096` | 访问日志中请求体片段上限 |
| `cache.rule_cache_entries` | `10000` | 规则/匹配结果缓存条目数 |
| `cache.ban_cache_entries` | `100000` | 封禁名单本地缓存条目数 |
| `cache.max_bytes` | `33554432` | 缓存总内存上限（32 MiB） |
| `cache.ttl` | `5m` | 缓存条目存活时间 |
| `stores.redis.pool_size` | `64` | 共享存储连接池大小 |
| `stores.redis.dial_timeout` | `500ms` | 共享存储拨号超时 |
| `stores.redis.read_timeout` | `300ms` | 共享存储读超时 |
| `stores.redis.write_timeout` | `300ms` | 共享存储写超时 |
| `stores.redis.local_cache_ttl` | `5s` | 本地缓存 TTL（减少往返，兼顾一致性） |
| `stores.memory.max_entries` | `1000000` | 内存计数表最大条目数 |
| `ban.default_ttl` | `30m` | 封禁默认时长（见 §7.5） |
| `ban.max_ttl` | `24h` | 封禁时长上限 |
| `server.read_header_timeout` | `3s` | 读取请求头超时 |

> 约定：所有容量/阈值/超时类配置**必须**出现在配置文件中（即使使用默认值），并在 `docs/configuration.md` 中逐项说明单位与取值范围。

### 2.7 配置三通道与优先级

**三种来源**，任一配置项均可通过三通道设置：

| 来源 | 形式 | 示例 |
| --- | --- | --- |
| CLI | flag，与配置路径对应 | `--server-listen=:9081` |
| 配置文件 | YAML（默认 `/etc/waf/waf.yaml`，可用 `-c` 多次指定） | `server: { listen: ":9081" }` |
| 环境变量 | `WAF_` 前缀 + 大写 + 下划线 | `WAF_SERVER_LISTEN=:9081` |

**优先级（用户确认，按此实现）**：

| 优先级 | 来源 | 说明 |
| --- | --- | --- |
| 1（最高） | CLI flag | 覆盖配置文件与环境变量 |
| 2 | 配置文件 | 覆盖环境变量；多次 `-c` 时后者覆盖前者 |
| 3 | 环境变量 | 最低优先级，仅高于内置默认值 |
| 4（兜底） | 内置默认值 | 代码中定义 |

**读取顺序**：按 `内置默认值 -> 环境变量 -> 配置文件 -> CLI flag` 依次叠加，后者覆盖前者，最终结果等价于上表优先级。

> **与 honeypot 的差异（必须留意）**：`reference/honeypot` 的优先级是 **环境变量 > 配置文件 > 默认值**，与本项目要求的 **CLI > 配置文件 > 环境变量** 相反。本项目按用户要求实现（CLI 最高），并必须在 `docs/configuration.md` 中显式标注，避免运维照搬 honeypot 经验导致配置不生效。

其他约定：

- 启动时打印「生效配置来源摘要」（逐项标注来自 CLI / 文件 / env / 默认值），敏感项脱敏；该摘要以系统日志 JSON 形式输出。
- 配置校验失败：打印**具体配置项 + 来源 + 期望格式**，退出码 `2`。
- 结构化列表（`pipeline` / `stores` / `notifiers` 等）仅支持配置文件声明；标量项支持三通道。
- 环境变量与 CLI 的命名由配置路径机械推导（`ban.default_ttl` -> `WAF_BAN_DEFAULT_TTL` / `--ban-default-ttl`），保证一一对应。

### 2.8 CLI 设计

| 命令 | 说明 |
| --- | --- |
| `waf run` | 默认命令，启动 forward-auth 服务；`--config` / `-c` 可多次指定 |
| `waf check-config` | 仅加载并校验配置，输出生效配置与来源摘要后退出 |
| `waf version` | 输出版本、提交号、构建时间 |
| `waf healthz` | 供容器 `HEALTHCHECK` 调用，探测本地 `/healthz` |
| `waf ban list` / `waf ban add --ip X --ttl 1h` / `waf ban remove --ip X` | 运维封禁名单管理（读写共享存储，多实例即时生效） |
| `waf reload` | 向运行中进程发送 `SIGHUP` 触发配置热加载（后续步骤） |

### 2.9 Docker 与构建模式（常用 Go 模式）

```dockerfile
# ---------- 构建阶段 ----------
FROM golang:1.24-alpine AS builder
WORKDIR /src
# 先拷贝依赖描述文件，最大化利用构建缓存
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown
# 静态编译：CGO 关闭，去除符号表，注入版本信息
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME}" \
      -o /out/waf ./cmd/waf

# ---------- 运行阶段 ----------
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/waf /waf
USER nonroot:nonroot
EXPOSE 9080 9090
HEALTHCHECK --interval=10s --timeout=2s --retries=3 CMD ["/waf", "healthz"]
ENTRYPOINT ["/waf"]
CMD ["run", "--config", "/etc/waf/waf.yaml"]
```

| 要求 | 说明 |
| --- | --- |
| 多阶段构建 | builder（含工具链）与 runtime（最小镜像）分离 |
| 静态单二进制 | `CGO_ENABLED=0`，无动态库依赖，可 `scratch` / `distroless` 运行 |
| 最小运行镜像 | 首选 `gcr.io/distroless/static:nonroot`；离线场景预置到内网镜像仓库 |
| 非 root | 使用 `nonroot`（UID 65532）；只读根文件系统；`/tmp` 单独挂载供体落盘；日志目录用卷挂载 |
| 体积优化 | `-trimpath -ldflags="-s -w"`；构建缓存分层（先 `go mod download` 再 `COPY .`） |
| 版本注入 | `main.version` / `main.commit` / `main.buildTime`，由 `internal/version` 暴露 |
| 健康检查 | `HEALTHCHECK` 调用 `/healthz`；同时提供 `/readyz` |
| 多架构 | 支持 `linux/amd64`、`linux/arm64`（`--platform=$TARGETPLATFORM`） |
| 离线交付 | `docker save` / `docker load` 镜像 tar；`go mod vendor` 或预置 module cache，构建全程不联网 |
| 编排示例 | 提供 `docker-compose.yml`（waf + redis + 卷挂载配置/日志）与可选 K8s manifest |
| 替换旧模板 | 根目录现有 `Dockerfile` 为 GitHub Action 模板，需整体替换 |

---
## 3. 请求体检测方案（Nginx + Traefik）

### 3.1 问题本质

原生 Nginx `auth_request` 创建子请求时设置 `header_only = 1` 且不挂载 `r->request_body`，因此：

- 鉴权子请求**不带请求体**；
- 鉴权响应体**被丢弃**。

这意味着「请求体检测」与「回传 JSON 错误体」都不能靠原生 `auth_request` 实现。Nginx 侧的标准做法是 OpenResty 在 `access` 阶段用 `ngx.location.capture` 转发（该方式可同时拿到响应体）。

### 3.2 体转发通道选择

| 通道 | 代理 | 体是否入 WAF | 能在本次请求内拦截 | 依赖 |
| --- | --- | --- | --- | --- |
| `traefik-forwardauth` | Traefik >= v2.11 | 是 | 是 | 无（错误体另见 §4.3） |
| `nginx-openresty` | OpenResty | 是 | 是 | 无（内置 `ngx.location.capture`） |
| `nginx-openresty-restyhttp` | OpenResty | 是 | 是 | `lua-resty-http`（可选，长连接池更优） |
| `nginx-mirror` | 原生 Nginx >= 1.13.4 | 异步 | 否 | 无 |
| `none` | 任意 | 否 | 否 | 无（仅头校验） |

> WAF 侧不感知通道实现，只看「鉴权请求里有没有体」。差异通过 `ingress.body.mode` + 启动自检 + 运行期缺失指标呈现。

### 3.3 Traefik：`ForwardAuth` + `forwardBody`

```yaml
http:
  middlewares:
    waf-auth:
      forwardAuth:
        address: "http://waf:9080/waf/auth"
        forwardBody: true            # 关键：把请求体转发给鉴权服务
        maxBodySize: 1048576         # 建议限定，避免大体拖慢关键路径
        trustForwardHeader: true
        authRequestHeaders:
          - "Content-Type"
          - "Content-Length"
        authResponseHeaders:         # 回传头放到上游请求（非客户端响应）
          - "X-WAF-Request-Id"
          - "X-WAF-Verdict"
    waf-errors:                      # 关键：把 WAF 返回的 403/429 渲染为 JSON 错误体
      errors:
        status: ["403", "429", "503"]
        service: waf
        query: "/waf/deny?code={status}"
  routers:
    app:
      rule: "Host(`app.example.com`)"
      middlewares: ["waf-errors", "waf-auth"]   # errors 必须在外层，见下方要点
      service: app
  services:
    waf:
      loadBalancer:
        servers:
          - url: "http://waf:9080"
```

要点：

- `forwardBody: true` 让 Traefik 把原始请求体随鉴权子请求送出，并正确设置 `Content-Length`。
- **按需开启**：只为需要体检测的路由挂载体检测中间件；纯静态/下载类路由使用不带 `forwardBody` 的中间件。
- Traefik 会在转发前缓冲请求体，`maxBodySize` 直接决定内存占用与保护边界。
- Traefik 的 `forwardAuth` **不会**把鉴权响应体传给客户端，因此 JSON 错误体与蜜罐页面都必须由 `errors` 中间件回源 `/waf/deny` 渲染（见 §4.3）。
- **中间件顺序（易踩坑）**：Traefik 采用 alice 风格的链式包装，`middlewares` 列表中靠前的中间件位于链的**外层**（`New(m1, m2).Then(app) == m1(m2(app))`）。`forwardAuth` 判定失败时直接 `WriteHeader` 返回、**不会调用下游**，因此只有把 `errors` 写在 `waf-auth` 之前，它才能观察到 403/429 并回源渲染 JSON；顺序写反的表现是「JSON 错误体丢失，只剩 Traefik 默认错误页」。
- `errors` 中间件的 `query` 模板拿不到鉴权响应头（Traefik 没有 `auth_request_set` 等价能力），因此只能把 `{status}` 当 `code` 传给 `/waf/deny`；对 403 由渲染端点再执行一次蜜罐重匹配，命中则返回规则页面，未命中才按状态码反推错误码（§4.3.3）。

### 3.4 Nginx：OpenResty 子请求转发（目标形态）

`deploy/forward-auth/nginx-openresty.conf`：

```nginx
# 内部鉴权通道：把子请求代理到 WAF
location = /_waf_auth {
    internal;
    proxy_pass              http://waf:9080/waf/auth;
    proxy_http_version      1.1;
    proxy_connect_timeout   200ms;
    proxy_read_timeout      2s;
    proxy_set_header        Host $host;
}

server {
    listen 80;
    server_name app.example.com;

    location / {
        access_by_lua_block { require("waf_auth").check("/_waf_auth") }

        proxy_pass http://backend;
        proxy_set_header Host $host;
    }
}
```

`deploy/forward-auth/waf_auth.lua`（仅用 OpenResty 内置 API，离线可用）：

```lua
local _M = {}

function _M.check(auth_uri)
    -- 1) 读出请求体（内存优先，落盘则读临时文件）
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        local f = ngx.req.get_body_file()
        if f then
            local fh = io.open(f, "rb")
            if fh then body = fh:read("*a"); fh:close() end
        end
    end

    -- 2) 注入原始请求信息（与 Traefik 的 X-Forwarded-* 语义对齐）
    ngx.req.set_header("X-Forwarded-For",    ngx.var.remote_addr)
    ngx.req.set_header("X-Forwarded-Proto",  ngx.var.scheme)
    ngx.req.set_header("X-Forwarded-Host",   ngx.var.host)
    ngx.req.set_header("X-Forwarded-Uri",    ngx.var.request_uri)
    ngx.req.set_header("X-Forwarded-Method", ngx.req.get_method())
    ngx.req.set_header("X-Original-URI",     ngx.var.request_uri)
    ngx.req.set_header("X-WAF-Body-Length",  tostring(ngx.var.content_length or ""))

    -- 3) 子请求（body 传入；返回状态码即判定）
    local res = ngx.location.capture(auth_uri, {
        method = ngx.req.get_method(),
        body   = body,
    })
    if not res then
        -- 失败策略：默认失败开放；如需失败关闭改成返回 JSON 503 错误体
        ngx.log(ngx.ERR, "waf auth subrequest failed")
        return
    end

    -- 4) 判定：2xx 放行
    if res.status >= 200 and res.status < 300 then
        return
    end

    -- 5) 拦截：原样回写 WAF 的 JSON 错误体（OpenResty 可直接拿到子请求响应体）
    ngx.status = res.status
    local hdr = res.headers or {}
    ngx.header["Content-Type"] = hdr["Content-Type"] or "application/json; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    for k, v in pairs(hdr) do
        if type(k) == "string" and k:lower():sub(1, 6) == "x-waf-" then
            ngx.header[k] = v
        end
    end
    ngx.print(res.body or "")
    ngx.exit(res.status)
end

return _M
```

要点与注意事项：

- **这是唯一能让 Nginx 客户端直接收到 JSON 错误体**的集成方式（`auth_request` 做不到，见 §4.3）。
- `lua_need_request_body on;` 可作为 `ngx.req.read_body()` 的替代，但显式调用更可控。
- `client_body_buffer_size` 决定体是否落盘：超出即写入临时文件，`ngx.req.get_body_file()` 分支必须处理。
- 必须放行 `client_max_body_size`，否则 Nginx 在鉴权前就返回 413；需与 `ingress.body.max_bytes` 协同。
- `ngx.location.capture` 是**阻塞式子请求**，`proxy_read_timeout` 需与 WAF 延迟预算匹配（建议 <= 2s）。
- 子请求失败默认**失败开放**；`on_error: block` 时应在 Lua 中返回 JSON 503（与 §4.2 的 `WAF_UNAVAILABLE` 保持一致）。

### 3.5 原生 Nginx 降级方案（兜底，非目标形态）

若现场暂时无法升级到 OpenResty：

1. `auth_request` 只做**头/URL/访问控制**校验（IP 名单、限速、封禁名单、UA、CRS header 阶段）。
2. 体检测降级为**异步观察**：`mirror /_waf_body_observe;` 把（截断后的）体异步送 WAF，走 `engine.mode: detection_only` + 访问日志。
3. **JSON 错误体同样无法回写**：客户端只会看到代理默认错误页。必须在文档与启动日志中显式标注该限制。

### 3.6 WAF 侧请求体处理

| 环节 | 设计 |
| --- | --- |
| 来源 | `ingress.body.source: request-body`；`none` 表示关闭体检测 |
| 按需读取 | `ingress.body.lazy: true`：仅当 pipeline 中存在**启用的 `PhaseBody` 插件**时才读取体；否则完全不碰体（零开销） |
| 限额 | `ingress.body.max_bytes`；超限策略 `on_exceed: truncate / reject / skip` |
| 分块传输 | 无 `Content-Length`（`Transfer-Encoding: chunked`）时按 `max_bytes` 流式读取（`io.LimitReader` + 分块拷贝） |
| 声明长度 | 由接入适配器还原为 `Declared`：`0` = 客户端明确声明空体（没有参数是正常现象）、`-1` = 未知（chunked，或通道不转发 `Content-Length`）、`>0` = 具体长度；是「请求体缺失」判定的条件之一（见 §3.7） |
| 消息框架头 | 重建请求时把 `Content-Length` / `Transfer-Encoding` 还原回去（见 §3.8）：代理没转发请求体时两者皆缺，若不还原会被 CRS 920180 误判为「POST 缺少框架头」→ 403 |
| 缓冲 | `ingress.body.spool: memory / disk / auto` + `memory_threshold`；读取粒度由 `ingress.body.chunk_bytes` 控制 |
| 复用 | 体只读取一次（分块），缓冲结果写入 `RequestContext.Stream`，供多个 `PhaseBody` 插件共享；**由 pipeline 在每个体阶段插件执行前统一调用 `Stream.Rewind()` 复位游标**，插件只需按顺序读取 |
| 解析 | Coraza 侧 `SecRequestBodyAccess On`、JSON/form/multipart/XML；上限 `SecRequestBodyLimit`，内存阈值 `SecRequestBodyInMemoryLimit` |
| 压缩体 | `Content-Encoding: gzip/br` 默认**不解压**（步骤 2 接入 CRS `body-decompress` 插件） |
| 超时 | `ingress.body.read_timeout`，超时按 `on_error` 处理 |
| 清理 | 临时文件在请求结束（`defer`）删除 |

### 3.7 启动自检与可观测

#### 启动能力清单

启动时以**系统日志**打印当前接入通道的能力清单（`cmd/waf/cmd_run.go` 的 `reportIngressCapabilities`），
三项能力分别是 `body_detection`（能否拿到请求体）、`json_error_body`（能否送达 WAF 渲染的 JSON 错误体）、
`trusted_content_length`（子请求携带的 `Content-Length` 是否等于原始请求声明的长度）。

| 通道 | `body_detection` | `json_error_body` | `trusted_content_length` |
| --- | --- | --- | --- |
| `traefik`（`forwardBody: true`） | ✅ | ✅（经 `errors` 中间件回源 `/waf/deny`） | ✅ |
| `nginx-openresty` | ✅ | ✅ | ✅ |
| `nginx-auth-only` | ❌ | ❌ | ❌ |
| 直通 `direct`（本地自检） | ✅ | ✅ | ✅ |

接入类型由配置项 `ingress.type` 决定（`auto` 时按注入头逐请求判定），三通道优先级为**CLI > 配置文件 > 环境变量**，
因此也可以直接用环境变量覆盖：`WAF_INGRESS_TYPE=traefik`。
当 `ingress.type = nginx-auth-only` 而 `ingress.body.mode = required` 时，启动日志会额外打一条 **WARN**：
该通道不转发请求体，`required` 语义无法成立；`ingress.type = auto` 时则会提示「auto 无法区分
`nginx-openresty` 与 `nginx-auth-only`，生产环境请显式声明」。

`trusted_content_length = false` 的含义（关系到下一节的缺失判定）：原生 Nginx 的 `auth_request`
通道既不转发请求体、也不转发 `Content-Length`，子请求的 `Content-Length` 恒为 `0`。
这个 `0` 只代表**未知**，WAF 会把它统一还原为 `-1`，绝不会当成「客户端声明了空请求体」。

#### `ingress.body.mode`

| 取值 | 语义 |
| --- | --- |
| `required` | 预期本部署能拿到请求体；缺失时记 `waf_body_missing_total` 并告警（判定条件见下） |
| `optional` | 有则检测，无则跳过 |
| `disabled` | 强制关闭体检测 |

`required` **不构成**任何异常判定。一次请求要被记为「请求体缺失」，必须**同时**满足三个条件
（实现：`internal/ingress/forwardauth/extractor.go` 的 `pickContentLength` +
`internal/ingress/body/spool.go` 的 `markMissingIfRequired`）：

1. **方法维度**：原始方法属于 `ingress.body.missing_methods`（默认 POST / PUT / PATCH）。
   GET / HEAD / OPTIONS / DELETE 本来就不携带请求体，把它们也算作缺失会让指标与日志被正常流量刷屏，
   真正的问题（代理没转发请求体）反而被掩盖。
2. **声明维度**：客户端没有明确声明空请求体，即 `Content-Length != 0`。
   `Content-Length: 0` 表示客户端主动声明「本次请求没有请求体」——没有请求体就没有请求参数，
   「拿不到请求参数」是正常现象，不告警、不计数，更不构成拦截理由。
3. **通道维度**：接入通道确实能带来原始 `Content-Length`（即 `trusted_content_length = true`）。
   `nginx-auth-only` 通道下长度恒为「未知」，无法证明客户端声明了空体，因此仍按方法维度计数。

`Declared` 的取值语义：`0` = 客户端明确声明空体；`-1` = 未知（`Transfer-Encoding: chunked`，
或通道不转发 `Content-Length`）；`> 0` = 声明了具体长度。**未知不等于空体**。

缺失只是可观测信号，**不参与拦截判定**；参数类检测仅在变量存在时匹配，不存在「参数缺失即异常」的路径。

### 3.8 重建请求的消息框架头还原（缺陷修复）

**问题**：鉴权子请求是代理**合成**的报文，它的 `Content-Length` / `Transfer-Encoding`
描述的是「代理 → WAF」这一段链路，而不是客户端与代理之间的原始报文。代理没有转发请求体时
（原生 Nginx `auth_request` 的 `proxy_set_header Content-Length ""`、Traefik 未开 `forwardBody`、
未做体捕获的 OpenResty 配置），两个框架头都不存在；Go 的 `net/http` 还会把
`Transfer-Encoding` 从 Header 中剥离（只留 `r.TransferEncoding`），并把这种形态的
`ContentLength` 记为 `0`。

后果是 CRS 的 **920180**（`POST without Content-Length or Transfer-Encoding headers`）
把每一次「拿不到请求体」的 POST 判成协议违规：该规则是 `WARNING`（5 分），
正好等于默认评分阈值 → 整条 POST 接口被 `403 / WAF_BLOCKED`（实测复现，见 §10.17 实施记录）。

**处置**：接入适配器在重建请求时把框架头还原回去（`internal/ingress/forwardauth/extractor.go`
的 `restoreFramingHeaders`），判定顺序如下：

| 情形 | 处置 | 理由 |
| --- | --- | --- |
| 代理已转发任一框架头 | 原样保留 | Traefik `forwardBody` / OpenResty 体捕获通道属于这一类，框架信息是真实的 |
| 方法以无请求体为常态（GET / HEAD / OPTIONS / TRACE） | 不补 | 这些方法缺框架头是合法形态，CRS 的 920170 / 920171 正用于管控它们的请求体 |
| 子请求是分块传输 | 补 `Transfer-Encoding: chunked` | 与原始报文的框架语义一致 |
| 其余（代理完全没转发请求体与框架头） | 补 `Content-Length: 0` | 对「WAF 实际收到的这条报文」而言它确实不带请求体 |

**边界**：

1. 该还原只作用于**重建形态**；直通形态（`direct` / `internal/server/direct.go`）保留客户端
   原始框架头，真实的协议违规（客户端确实发了既无 CL 也无 TE 的 POST）照旧命中。
2. 还原只改变「送给检测引擎的报文形态」，**不影响**「请求体缺失」的判定——后者只看
   `core.RawRequest.ContentLength`（见 §3.7），因此不会掩盖「代理没转发请求体」这个真实故障。
3. 这里的 `Content-Length: 0` 含义是「WAF 收到的报文没有请求体」，不是「客户端声明了空体」；
   两者的区别由 `Declared` 承载，告警语义不受影响。

**验收**：契约测试 `TestPostWithoutFramingHeadersIsNotBlocked`（裸 TCP 构造「无框架头」与
「分块」两种形态，断言 `200` + `X-WAF-Verdict: allow`）；单元测试
`TestExtractRestoresFramingHeaders`（无框架头 / 声明空体 / 真实长度 / 分块 / GET / auth-only 通道六种矩阵）。
#### 指标

`waf_body_bytes`（直方图）、`waf_body_truncated_total`、`waf_body_missing_total`、`waf_body_spooled_total`、`waf_body_read_seconds`。

---

## 4. 拦截响应与 JSON 错误体

### 4.1 设计原则

- **不提供拦截页面**：不放 HTML，不做品牌化页面，不配置 `error_page` 静态页。
- 所有拒绝统一返回**结构化 JSON 错误体**，便于前端/调用方按 `code` 分支处理。
- **默认不泄露检测细节**（规则 ID / 规则描述 / 命中位置）：默认只返回通用文案 + `request_id`；排查时凭 `request_id` 查访问日志。

### 4.2 JSON 错误体规范

统一字段（对外）：

```json
{
  "code": "WAF_BLOCKED",
  "message": "请求被安全策略拦截",
  "request_id": "01J8Z9Q2K7V4M3N5P6R8T1W0XY",
  "timestamp": "2026-10-15T10:00:00.123+08:00"
}
```

`code` 取值表：

| 判定 | HTTP | code | message（默认文案） |
| --- | --- | --- | --- |
| Block / Drop | `403` | `WAF_BLOCKED` | 请求被安全策略拦截 |
| Unauthorized | `401` | `WAF_UNAUTHORIZED` | 需要身份认证 |
| RateLimited | `429` | `WAF_RATE_LIMITED` | 请求过于频繁，请稍后再试 |
| BadRequest | `400` | `WAF_BAD_REQUEST` | 请求不符合安全要求 |
| Unavailable | `503` | `WAF_UNAVAILABLE` | 安全检测服务暂时不可用 |

响应头：`Content-Type: application/json; charset=utf-8`、`Cache-Control: no-store`、`X-WAF-Request-Id`、`X-WAF-Verdict`、`429` 时附加 `Retry-After`。

可选详情字段（`responder.include_details` 默认 `false`）：`rule_id` / `rule_msg` / `check` / `score` / `client_ip`。开启后需评估信息泄露风险；**生产建议保持关闭**。

配置：

```yaml
responder:
  type: json                 # 本期仅实现 json（接口保留扩展位）
  include_details: false     # 是否在响应体中暴露规则细节（默认关闭）
  messages:                  # 文案可配置（便于多语言/统一风格）
    WAF_BLOCKED: "请求被安全策略拦截"
    WAF_RATE_LIMITED: "请求过于频繁，请稍后再试"
    WAF_UNAUTHORIZED: "需要身份认证"
    WAF_BAD_REQUEST: "请求不符合安全要求"
    WAF_UNAVAILABLE: "安全检测服务暂时不可用"
```

### 4.3 错误体送达（鉴权响应头 + 代理侧渲染）

**方案选定**：WAF 不依赖"响应体透传"，而是用**鉴权响应头**承载判定语义，由代理侧渲染 JSON 错误体。

#### 4.3.1 WAF 必须回传的响应头

| 响应头 | 取值 | 必填 | 说明 |
| --- | --- | --- | --- |
| `X-WAF-Code` | `WAF_BLOCKED` / `WAF_RATE_LIMITED` / `WAF_UNAUTHORIZED` / `WAF_BAD_REQUEST` / `WAF_UNAVAILABLE` | 是 | 与响应体 `code` 同值；代理据此决定最终状态码与文案 |
| `X-WAF-Request-Id` | 请求 ID | 是 | 与访问日志 `request_id` 一致，用于排障关联 |
| `X-WAF-Verdict` | `BLOCKED` / `RATE_LIMITED` / ... | 是 | 人类可读判定 |
| `X-WAF-Rule-Id` | 规则 ID | 否 | 仅 `responder.include_details: true` 时返回 |
| `X-WAF-Target` | 检测目标 | 否 | 例如 `ARGS:id`、`REQUEST_URI`、`client_ip+path` |
| `X-WAF-Ban-Scope` | 封禁维度 | 否 | 封禁名单 / 自动封禁命中时返回 |
| `X-WAF-Retry-After` | 秒 | 否 | 限速场景 |

> Nginx 变量名转换规则：`X-WAF-Code` -> `$upstream_http_x_waf_code`（全小写、`-` 转 `_`）。

#### 4.3.2 Nginx 标准做法

**写法 B（推荐，无额外跳数）**：`error_page` + 内部命名 location 模板渲染。

```nginx
location / {
    auth_request /_waf_auth;

    # 从鉴权子请求的响应头取值（nginx 官方支持：auth_request_set 可用 $upstream_http_*）
    auth_request_set $waf_code    $upstream_http_x_waf_code;
    auth_request_set $waf_req_id  $upstream_http_x_waf_request_id;
    auth_request_set $waf_verdict $upstream_http_x_waf_verdict;

    # 403 交给本地模板渲染；'=' 表示最终状态码取自渲染 location 的响应
    error_page 403 = @waf_deny;

    proxy_pass http://backend;
}

location @waf_deny {
    internal;
    default_type "application/json; charset=utf-8";
    # 实际实现中按 $waf_code 分支映射状态码与文案
    return 403 '{"code":"$waf_code","message":"请求被安全策略拦截","request_id":"$waf_req_id","verdict":"$waf_verdict"}';
}
```

**写法 C（回源渲染）**：把 `@waf_deny` 改为回源 WAF，复用同一份模板与日志。

```nginx
location @waf_deny {
    internal;
    proxy_pass http://waf:9080/waf/deny?code=$waf_code&request_id=$waf_req_id;
}
```

**写法 A/D（静态页或跳转）**：只需要固定文案，或字面意义的"定向到错误页"。

```nginx
error_page 403 /waf-blocked.html;          # 静态页
# error_page 401 =302 /waf-blocked.html;   # 由 nginx 发起 302（不是 WAF 返回 302）
```

> **关键约束**：`auth_request` 会把 429/503 等状态码转成 **500**。因此走 `auth_request` 通道时，WAF **必须统一返回 403**，真实语义由 `X-WAF-Code` 表达，最终对外状态码由渲染 location 决定（`=` 语法）。

**依据与业界参考**：nginx 官方文档说明 `auth_request_set` 的取值可包含鉴权请求的变量（如 `$upstream_http_*`）。两份最典型的落地参考：**oauth2-proxy**（`error_page 401 = /oauth2/sign_in;`，由鉴权服务第二个 internal 端点渲染登录页 = 写法 C）与 **Authelia**（`error_page 401 =302 https://login.example.com/?rd=$target_url;` = 写法 D）。**发起方始终是代理，不是鉴权服务。**

#### 4.3.3 Traefik 侧（响应头方案不适用）

Traefik 的 `forwardAuth` 在失败路径上不透传鉴权响应头，也没有 `auth_request_set` 等价能力，因此改由 `errors` 中间件兜底：

```yaml
http:
  middlewares:
    waf-errors:
      errors:
        status: ["401", "403", "429", "503"]
        service: waf
        query: "/waf/deny?status={status}"   # {status} 由 Traefik 替换为实际状态码
```

**`request_id` 关联（最近拦截事件缓存）**：`errors` 中间件拿不到鉴权响应头，因此 WAF 在拦截时把 `{client_ip, method, path} -> request_id` 写入本地 TTL 缓存（`responder.recent_block_ttl`，默认 `10s`）；`/waf/deny` 按同样维度反查真实 `request_id`，未命中则新生成并在响应中标注 `"correlated": false`。

**蜜罐重匹配**：WAF 对蜜罐统一返回 403；`errors` 回源后，`/waf/deny` 读取 `X-Forwarded-Uri` / `X-Forwarded-Method`，按同一份蜜罐规则重新匹配。命中时返回规则自己的状态码（包括 200）、响应头与正文；未命中时继续走普通 JSON 错误体。因此 Traefik 不需要自定义插件，也不需要把正文塞进响应头。

#### 4.3.4 渲染端点 `GET /waf/deny`

| 项 | 说明 |
| --- | --- |
| 入参 | `code` / `request_id`（Nginx、OpenResty）；`{status}`（Traefik `errors` 中间件）；原始请求信息通过 `X-Forwarded-*` / `X-Original-*` 传递 |
| 输出 | 普通拦截为 §4.2 的 JSON；蜜罐命中为规则定义的任意响应（状态码 / 响应头 / 正文） |
| 状态码 | 普通拦截：`WAF_BLOCKED`->403、`WAF_RATE_LIMITED`->429、`WAF_UNAUTHORIZED`->401、`WAF_BAD_REQUEST`->400、`WAF_UNAVAILABLE`->503；蜜罐：规则 `status` |
| 幂等性 | 无副作用、纯渲染；不写访问日志（避免重复计数），仅累加 `waf_deny_render_total`；蜜罐渲染不产生评分 / 告警 / 封禁 |
| 安全 | 不回显任意输入；`include_details: false` 时不返回规则详情；只对 `WAF_HONEYPOT`、403、418 或空 code 尝试蜜罐重匹配 |

#### 4.3.5 各通道能力对照

| 通道 | 请求体 | 错误体 / 蜜罐页面送达 | 最终对外状态码 | 复杂度 |
| --- | --- | --- | --- | --- |
| Nginx + OpenResty（Lua） | 是 | Lua 回源 `/__waf_deny` -> `/waf/deny` | 由渲染端点决定（可 200/429） | 低 |
| Nginx 原生 `auth_request` | 否 | `error_page` -> `/waf/deny` | 由渲染端点决定（可 200/429） | 中 |
| Traefik + `forwardBody` | 是 | `errors` 中间件 -> `/waf/deny` | 由渲染端点决定（可 200） | 中 |
| Nginx 原生 + `mirror`（兜底） | 异步 | 不可送达 | - | - |

---
## 5. 日志体系（系统日志 / 访问日志 · 分级 · JSON）

### 5.1 两类日志

| 类别 | logger 名 | 内容 | 默认落盘 |
| --- | --- | --- | --- |
| **系统日志** | `system` | 进程生命周期、配置加载与来源摘要、插件构建、引擎与规则加载、共享存储连接、热加载、优雅关停、组件错误 | `logs/waf-system-YYYY-MM-DD.json` + stdout |
| **访问日志** | `access` | 每个请求一条：放行/拦截判定、命中规则、评分、耗时、客户端 IP、请求元信息、请求体元信息（不记内容） | `logs/waf-access-YYYY-MM-DD.json` |

**分离理由**：系统日志用于运维排障与审计留痕，访问日志用于安全分析与统计取证；两者的量级、保留周期、等级阈值完全不同，必须独立配置、独立轮转。

### 5.2 日志等级

| 等级 | 数值（slog） | 用途 |
| --- | --- | --- |
| `debug` | -4 | 放行请求明细、插件内部细节、配置项来源逐项、共享存储往返 |
| `info` | 0 | 启动/关停、配置生效、规则加载完成、共享存储连接成功 |
| `warn` | 4 | 拦截命中、限速触发、封禁生效/解封、体截断/缺失、降级路径启用 |
| `error` | 8 | 引擎错误、共享存储不可用、渲染端点异常、失败关闭 |
| `fatal` | 12 | 不可恢复（配置非法、端口占用）；记录后进程退出（退出码非 0） |

> Go 标准库 `log/slog` 无 `fatal` 级别，本项目在 `internal/logging` 中约定：以 `error` 级别记录 `fatal` 语义事件，随后调用进程退出逻辑，并在 JSON 中保留 `"fatal": true` 标记。

### 5.3 访问日志的等级映射

访问日志每条记录的级别由**判定结果**推导，`logging.access.level` 只作为输出阈值；
其中「放行」是否记录由独立开关 `logging.access.allow_level` 决定。
每条记录都带 `action` 字段，便于按动作直接检索与聚合：

| 判定结果 | `action` | 记录级别 | 默认是否输出 |
| --- | --- | --- | --- |
| Allow（放行） | `allow` | `info` | 是（`allow_level: info`，**过与不过都留痕**） |
| Observe（观察命中） | `observe` | `info` | 是 |
| Block / Drop | `block` | `info` | 是 |
| Observe 且「本应拦截」（DetectionOnly） | `observe` | `warn` | 是 |
| 引擎错误 / 存储错误 / 失败关闭 | `error` | `warn` | 是 |

`logging.access.allow_level` 取值（**只影响放行记录，不影响其它等级语义**）：

| 取值 | 语义 | 通道级别 |
| --- | --- | --- |
| `info`（默认） | 放行以 `info` 级写入，默认可见 | 不变 |
| `debug` | 放行以 `debug` 级写入（需要时可见） | 自动下探到 `debug` |
| `off` | 完全不记录放行（只留拦截 / 观察 / 异常） | 不变 |

> 默认记录放行是刻意选择：只记拦截会让访问日志出现「完全没有任何记录」的请求，
> 排查延迟与流量构成时无从下手。需要压缩日志体积时显式改为 `debug` 或 `off`。

### 5.4 JSON 字段规范

公共字段（两类日志统一）：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `ts` | string | RFC3339 带时区、毫秒精度（如 `2026-10-15T10:00:00.123+08:00`） |
| `level` | string | 大写等级：DEBUG / INFO / WARN / ERROR |
| `logger` | string | `system` 或 `access` |
| `msg` | string | 中文简述 |

访问日志（`access`）附加字段：

| 字段 | 说明 |
| --- | --- |
| `request_id` | 请求唯一 ID（与响应头 `X-WAF-Request-Id` 一致） |
| `site` | 命中的站点名 |
| `client_ip` / `method` / `host` / `path` / `query` / `proto` | 请求元信息 |
| `verdict` / `status` | 判定结果与返回状态码 |
| `action` | 判定动作：`allow` / `block` / `observe` / `error`（供报表与检索统一按动作归类） |
| `check` / `rule_id` / `rule_msg` / `tags` / `score` | 命中的校验单元与规则信息 |
| `duration_ms` | 处理耗时（毫秒，浮点） |
| `body` | 请求体元信息：`{declared, read, truncated, spooled, content_type}` |
| `user_agent` | User-Agent（可脱敏截断） |
| `banned` / `ban_ttl` | 本次是否触发封禁及封禁时长 |

系统日志（`system`）附加字段：`component`（config / engine / pipeline / store / ingress / logging）、以及组件相关键值（如 `rules`、`duration_ms`、`addr`）。

示例：

```json
{"ts":"2026-10-15T10:00:00.123+08:00","level":"INFO","logger":"system","component":"config","msg":"配置加载完成","sources":{"server.listen":"cli","engine.mode":"file","ban.default_ttl":"default"}}
{"ts":"2026-10-15T10:00:01.456+08:00","level":"INFO","logger":"access","msg":"请求拦截","action":"block","request_id":"01J8Z9Q2K7V4M3N5P6R8T1W0XY","site":"default","client_ip":"203.0.113.9","method":"POST","host":"app.example.com","path":"/api/login","verdict":"BLOCKED","status":403,"check":"crs-body","rule_id":942100,"tags":["attack-sqli"],"score":7,"duration_ms":1.82,"body":{"declared":1234,"read":1234,"truncated":false,"spooled":false,"content_type":"application/json"}}
```

### 5.5 实现方式

- 使用 Go 标准库 `log/slog` + `slog.NewJSONHandler`，通过 `ReplaceAttr` 定制：时间格式（RFC3339 毫秒）、等级大写、去除冗余属性；**不引入第三方日志库**（离线友好、依赖更少）。
- `internal/logging` 提供两个构造函数：`NewSystem(cfg) (*slog.Logger, io.Closer, error)` 与 `NewAccess(cfg) (*slog.Logger, io.Closer, error)`，分别绑定独立的 level、输出与轮转 writer。
- 轮转 writer：复制改造 `reference/honeypot/internal/logger` 思路（按日切分），并扩展为**按日 + 按大小**双维度；写满 `max_file_bytes` 立即滚动。
- 关闭顺序：优先 `Close` 日志 writer（`defer` 顺序保证），确保关停日志完整落盘。

### 5.6 轮转与保留

| 配置项 | 默认 | 说明 |
| --- | --- | --- |
| `rotate` | `daily` | `daily` / `size` / `both` |
| `max_file_bytes` | `134217728` | 单文件上限（128 MiB），`rotate` 含 `size` 时生效 |
| `keep_days` | system `30` / access `90` | 保留天数，超期清理 |
| `max_total_bytes` | `0`（不限制） | 目录总容量上限，超限按最旧优先清理 |
| `compress` | `false` | 是否压缩历史文件（gzip） |

### 5.7 脱敏与隐私

- 默认**不记录请求体内容**（仅记录体元信息：长度、是否截断、是否落盘、Content-Type）。
- 默认**不记录请求头全文**；如开启 `include_headers`，则按 `redact` 列表脱敏。
- 默认脱敏字段：`Cookie`、`Authorization`、`Proxy-Authorization`、`Set-Cookie`、`X-Api-Key`、`X-Auth-Token`；可通过 `redact` 增删。
- `client_ip` 为安全分析必需字段，默认保留；如需合规裁剪，提供 `logging.mask_ip` 选项（如掩码末段）。

---

## 6. 总体架构

```
                +------------------- cmd/waf (单二进制, CGO_ENABLED=0) --------------------+
 Nginx/Traefik  |                                                                          |
 子请求(可带体)   | internal/server (HTTP Handler / /healthz / /readyz / /metrics / /waf/deny) |
 -------------> |        |                                                                 |
                |        v                                                                 |
                |   internal/ingress  -- 还原原始请求(方法/URI/Host/客户端IP/可信代理)        |
                |        |               +-- forwardauth(traefik) / forwardauth(nginx)      |
                |        |               +-- BodySpool(memory/disk/auto, 限额/截断/分块)      |
                |        v                                                                 |
                |   internal/sites    -- 命中站点策略(域名/端口/路径)                         |
                |        v                                                                 |
                |   internal/pipeline -- 按 phase+order 串联执行 Check 链                    |
                |        |            +-- Pre:     banlist / ipaccess / ratelimit             |
                |        |            +-- Request: coraza(header) / ua / geoip                |
                |        |            +-- Body:    coraza(body) / upload / decode  <- 按需读体 |
                |        |            +-- Post:    threshold / autoban / notify              |
                |        v                                                                 |
                |   internal/responder -- Verdict -> HTTP 状态码 + JSON 错误体               |
                |                                                                          |
                |   横切能力(接口+多实现):                                                 |
                |     Store(redis 共享 / memory / file)  <- 限速计数 + 内部封禁名单           |
                |     Notifier(wechat/generic/...)                                         |
                |     Logger(system / access, 分级, JSON)                                  |
                |     Metrics(prometheus)                                                  |
                +--------------------------------------------------------------------------+
```

**分层原则**

- `cmd`（装配）→ `internal/core`（契约）→ `internal/*`（实现），依赖方向单向；实现包只在 `cmd` 中通过 `blank import` 注册。
- Coraza 引擎只是 `Check` 的一种实现，可整体禁用。
- **封禁不触及系统防火墙**：仅通过共享存储中的封禁名单 + `banlist` 校验单元实现（R18）。
- 参考实现（限流 / 通知 / 日志）按 §2.1 复制改造后纳入本项目抽象接口。

---
## 7. 抽象接口设计（核心）

### 7.1 领域模型

```go
package core

// Verdict 是校验单元的判定结果。
type Verdict int

const (
	VerdictContinue  Verdict = iota // 无意见，继续后续校验
	VerdictObserve                  // 命中但仅记录（DetectionOnly / 旁路观察）
	VerdictAllow                    // 显式放行，短路返回 200
	VerdictBlock                    // 拦截 403
	VerdictDrop                     // 拦截（forward-auth 下等价 403）
	VerdictUnauthorized             // 401 认证挑战
	VerdictRateLimited              // 429 限速
	VerdictChallenge                // 人机校验挑战
	VerdictBadRequest               // 400（体超限/畸形）
	VerdictUnavailable              // 503（失败关闭）
)

// Result 是单个校验单元的输出，可被 pipeline 合并。
type Result struct {
	Verdict  Verdict
	Status   int         // 覆盖默认状态码；0 表示按 Verdict 取值
	RuleID   int         // 命中规则 ID（Coraza 规则 ID / 自研规则 ID）
	RuleMsg  string      // 规则描述
	Tags     []string    // 规则标签（crs/attack-sqli/...）
	Severity int         // 严重级别
	Score    float64     // 入站异常分增量（供阈值插件聚合）
	RetryAfter time.Duration // 429 时的 Retry-After
	Findings []Finding   // 结构化命中明细（落访问日志 / 告警）
	Headers  http.Header // 需要回传给代理的响应头
	LogData  string      // 附加日志
	Notify   []NotifyHint
	Ban      *BanRequest // 需要写入封禁名单（由 store 落地）
	Err      error       // 引擎错误（由 pipeline 按 on_error 处理）
}

// BanRequest 描述一次内部封禁请求（不涉及任何系统防火墙操作）。
type BanRequest struct {
	Key    string        // 封禁键，默认等于客户端 IP
	TTL    time.Duration // 封禁时长；0 表示使用配置默认值 ban.default_ttl
	Reason string        // 触发原因（写入日志与告警）
}

// BodyMeta 描述请求体的可用性与读取结果。
type BodyMeta struct {
	Available   bool   // 体是否可用
	Source      string // request-body | none
	Declared    int64  // Content-Length（-1 未知，chunked）
	Read        int64  // 实际读取字节
	Truncated   bool   // 是否被限额截断
	Spooled     bool   // 是否落临时文件
	Encoding    string // Content-Encoding
	ContentType string // Content-Type
}
```

```go
// RequestContext 是所有 Check 共享的请求视图 + 可变状态袋。
type RequestContext struct {
	Context context.Context
	ID      string // 请求 ID（同时用于 JSON 错误体与访问日志）

	Method     string
	Scheme     string // http / https
	Host       string
	Path       string
	Query      string
	Proto      string
	Headers    http.Header
	ClientIP   netip.Addr // 已按 trusted_proxies 还原
	RemoteAddr string

	Site *Site // 命中的站点策略

	// 请求体：lazy 模式下仅在存在启用的 PhaseBody 插件时被填充
	Body     *Body
	BodyMeta BodyMeta

	Banned   bool          // 是否命中封禁名单
	BanTTL   time.Duration // 剩余封禁时长

	Vars  map[string]any // 插件间传值（如 coraza tx / 评分累计）
	State *PipelineState // 累计评分、命中集合、告警集合、待封禁列表
}
```

### 7.2 校验单元（串联的核心）

```go
// Phase 决定串联时的执行阶段。
type Phase int

const (
	PhasePre     Phase = iota // 引擎前：封禁名单、IP 名单、限速
	PhaseRequest              // 请求头阶段：Coraza header phase、UA/方法/协议校验、GeoIP
	PhaseBody                 // 请求体阶段：Coraza body phase、上传检查、解码
	PhasePost                 // 引擎后：评分阈值判定、自动封禁、告警
)

// Check 是「可插拔校验单元」。每个功能项 = 一个 Check 实现。
type Check interface {
	Name() string // 实例名（配置中的 name，用于日志/指标）
	Type() string // 实现类型（配置中的 type，用于注册表查找）
	Phase() Phase
	Order() int
	Evaluate(ctx *RequestContext) (*Result, error)
	Close() error
}

// CheckFactory 由各插件包通过 RegisterCheck 注册。
type CheckFactory func(inst InstanceConfig, deps *Deps) (Check, error)
```

内置实现（可自由启停与串联）：`banlist`、`ipaccess`、`ratelimit`、`coraza`、`threshold`、`autoban`、`passthrough`（后续扩展 `geoip` / `upload`）。

**注册表（离线、编译期装配，无动态加载）**

```go
package core

func RegisterCheck(typeName string, f CheckFactory)
func NewCheck(inst InstanceConfig, deps *Deps) (Check, error) // 未注册 -> 启动即报错
```

> 通过 `cmd/waf/plugins.go` 中的 `import _ ".../check/coraza"` 等空白导入完成注册，保持 `CGO_ENABLED=0` 单二进制、无 `plugin` 包、无 `.so` 依赖。

### 7.3 横切能力接口（每个都有多实现）

```go
// Store 提供共享状态：限速计数 + 内部封禁名单。
//
// 实现与启用策略（R17）：
//   - redis  : 多实例共享；由 stores[].enabled 控制是否启用；
//   - memory : 本地存储，作为 redis 未启用或运行期降级时的默认实现；
//   - file   : 单机持久化（不用于多实例共享）。
//
// 启用规则：
//   - stores[].enabled=false  -> 不连接 Redis，直接使用 fallback 指定的本地实现，
//     并以 warn 级写系统日志提示"多实例共享未启用"；
//   - 运行期 Redis 故障 -> 按 on_error 处理（fail_open / fail_closed / fallback_local）。
//
// 并发安全性：实现必须可被多个 goroutine 并发调用。
type Store interface {
	// Incr 在滑动窗口内对 key 计数，返回当前计数与窗口剩余时间。
	Incr(ctx context.Context, key string, window time.Duration) (count int64, ttl time.Duration, err error)
	// Ban 将 key 加入封禁名单并设置 TTL（ttl <= 0 时使用 ban.default_ttl）。
	Ban(ctx context.Context, key string, ttl time.Duration) error
	// IsBanned 查询封禁状态与剩余时长。
	IsBanned(ctx context.Context, key string) (banned bool, remaining time.Duration, err error)
	// Unban 解除封禁（运维手工操作）。
	Unban(ctx context.Context, key string) error
	// Close 释放连接与本地缓存。
	Close() error
}

// Notifier：告警外送（并联扇出）。实现：wechat / generic / base64get / hfish / honeywire / smtp / syslog
type Notifier interface {
	Notify(alert core.Alert) error
	Name() string
}

// RequestExtractor：把代理注入的头/体还原成原始请求。
// 实现：traefik-forwardauth / nginx-auth-only / nginx-openresty / generic
type RequestExtractor interface {
	Extract(r *http.Request) (*core.RawRequest, error)
}

// Responder：Verdict -> HTTP 响应（含 JSON 错误体）。
// 实现：json（本期唯一实现，接口保留扩展位）
type Responder interface {
	// Respond 写入状态码、响应头与 JSON 错误体。
	Respond(w http.ResponseWriter, ctx *core.RequestContext, res *core.Result)
	// Render 供 /waf/deny 渲染端点使用：仅按 request_id 渲染幂等的 JSON 错误体。
	Render(w http.ResponseWriter, requestID string, code string)
}

// SiteResolver：站点策略解析。实现：static-config
type SiteResolver interface {
	Resolve(host, path string) (*core.Site, error)
}
```

> 说明：**不再定义 `Blocker` 接口**（R18）。封禁通过 `Store.Ban/IsBanned/Unban` + `banlist` 校验单元完成，因此天然具备多实例共享能力。
> 日志不使用自定义接口，直接使用标准库 `*slog.Logger`（系统日志与访问日志各一个实例，见 §5.5）。

### 7.4 串联语义（多个插件如何串）

`pipeline` 为有序数组，执行规则：

1. **排序**：先按 `Phase`（Pre → Request → Body → Post），同 phase 内按 `order` 升序；`order` 相同按配置顺序。
2. **跳过**：`enabled: false` 直接跳过，不产生任何开销。
3. **按需读体**：仅当存在启用的 `PhaseBody` 插件时才读取请求体（`lazy` 模式）。若 Pre/Request 阶段已短路，则**永不读体**。
4. **合并**：
   - `VerdictContinue` / `VerdictObserve`：继续执行；`Score` 累加；`Findings` / `Notify` / `Ban` 收集。
   - `VerdictAllow`：**短路**返回放行。
   - `VerdictBlock` / `Drop` / `Unauthorized` / `RateLimited` / `BadRequest` / `Challenge`：**短路**返回对应 JSON 错误体。
   - `Err != nil`：按该实例的 `on_error`（`pass` 失败开放 / `block` 失败关闭）处理，并以 `error` 级写入访问日志。
5. **阈值聚合**（`threshold`，PhasePost）：累计 `Score` 超阈值则提升为 `Block`。
6. **封禁落地**（`autoban`，PhasePost）：把 `State.Ban` 写入共享 `Store`，并对所有实例即时生效。
7. **`short_circuit: false`**：需要「收集全部命中再决策」时使用（旁路观察、攻击面统计）。

```
[banlist] -> [ipaccess] -> [ratelimit-ip] -> [ratelimit-login] -> [coraza-header] -> [coraza-body]
   pre          pre            pre                pre                 request            body
   -> [threshold] -> [autoban] -> [notify]
          post          post        post
```

> **串联 vs 并联**：`Check` 之间是**串联**（顺序、可短路）；通知类（多个 `notifier`）是**并联**（全部执行、互不影响）。

### 7.5 封禁策略与时长（R19）

| 项 | 取值 | 说明 |
| --- | --- | --- |
| 默认封禁时长 | **`30m`** | 选取理由：足够让扫描器/爆破脚本放弃，又不会因办公网/NAT 出口共享 IP 造成长时间误封 |
| 上限 | `ban.max_ttl: 24h` | 防止误配置导致长期封禁 |
| 封禁维度 | `ban.ban_key: client_ip` + `ban.ban_keys` | 主维度决定 CLI 写入口径；`ban_keys` 是运行期查询的维度集合（可多个），可选 `client_ip` / `client_ip+site` / `client_ip+path` / `client_ip+method` |
| 累进封禁 | `ban.escalate: false`（默认关） | 开启后同一来源 24h 内重复命中按 `escalate_steps: [30m, 2h, 24h]` 递增 |
| 触发条件 | `autoban.trigger_on: [block]` | 也可配置为 `[block, ratelimit]` |
| 触发严重度门槛 | `autoban.min_severity`（默认不设） | 只有存在该级别及以上命中才计入，避免「低危规则凑次数」误封 |
| 触发阈值 | `autoban.threshold: 3` / `window: 5m` | 各维度的默认值；`autoban.dimensions[]` 可为每个维度单独覆盖 |
| 重复封禁抑制 | `autoban.skip_when_banned: true`（默认开） | 来源已在名单中时跳过计数，避免命中次数虚高与名单被反复续期 |
| 自动解封 | 由 TTL 控制 | 共享存储的 key TTL 到期即自动失效，无需额外任务 |
| 手工操作 | `waf ban add/list/remove` | 通过 CLI 直接读写共享存储，多实例即时生效 |

存储键设计（Redis）：

| 键 | 类型 | TTL | 说明 |
| --- | --- | --- | --- |
| `waf:rl:{dimension}:{value}:{window}` | string（计数器） | 窗口长度 | 限速计数 |
| `waf:ban:{ban_key}` | string（值=原因） | `ban_ttl` | 封禁名单，TTL 到期自动解封（`ban_key` 含维度，例如 `ip:1.2.3.4\|path:/api/user`） |
| `waf:ab:{维度}\|{ban_key}\|{窗口}` | string（计数器） | 窗口长度 | 自动封禁的命中次数计数（计数口径按维度隔离） |

性能与一致性：

- `banlist` 与 `ratelimit` 每次请求会访问共享存储；为降低往返，本地维护**短 TTL 缓存**（`stores.redis.local_cache_ttl` 默认 `5s`）：
  - 封禁查询命中本地缓存则直接拒绝；
  - 限速计数**不做本地缓存**（必须强一致计数），仅对「已封禁」结论做缓存。
- 共享存储未启用或不可用时的策略：`stores[].enabled: false` 时直接降级为 `fallback` 指定的本地实现（并写 warn 级系统日志）；运行期故障按 `stores[].on_error: fail_open / fail_closed / fallback_local` 处理。

---
## 8. 配置启用方案（全部可开关）

### 8.1 配置文件骨架 `configs/waf.example.yaml`

```yaml
version: 1

server:
  listen: ":9080"            # forward-auth 鉴权端点
  metrics_listen: ":9090"
  read_header_timeout: 3s
  shutdown_timeout: 10s

# (1) 接入适配：还原原始请求 + 请求体通道
ingress:
  type: auto                 # auto | traefik-forwardauth | nginx-auth-only | nginx-openresty
  path: "/waf/auth"
  deny_path: "/waf/deny"     # JSON 错误体渲染端点（Traefik errors 中间件回源用）
  headers:
    uri: [X-Forwarded-Uri, X-Original-URI]
    method: [X-Forwarded-Method, X-Original-Method]
    host: [X-Forwarded-Host]
    proto: [X-Forwarded-Proto]
  client_ip:
    order: [X-Forwarded-For, X-Real-IP]
    trusted_proxies: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  body:
    mode: required           # required | optional | disabled
    source: request-body     # request-body | none
    lazy: true               # 无 PhaseBody 插件时不读取
    max_bytes: 1048576
    on_exceed: truncate      # truncate | reject | skip
    spool: auto              # memory | disk | auto
    memory_threshold: 65536
    chunk_bytes: 32768       # 流式读取单块大小
    spool_dir: ""
    read_timeout: 2s

# (2) 拦截响应：统一 JSON 错误体，不提供拦截页面
responder:
  type: json                 # 本期仅实现 json
  include_details: false     # 是否暴露 rule_id / check / score（默认关闭，防信息泄露）
  messages:
    WAF_BLOCKED: "请求被安全策略拦截"
    WAF_RATE_LIMITED: "请求过于频繁，请稍后再试"
    WAF_UNAUTHORIZED: "需要身份认证"
    WAF_BAD_REQUEST: "请求不符合安全要求"
    WAF_UNAVAILABLE: "安全检测服务暂时不可用"

# (3) 检测引擎（可整体关闭 -> 纯前置访问控制）
engine:
  enabled: true
  mode: on                   # on | detection_only
  paranoia_level: 1
  rules:
    dirs: ["rules"]
    include: ["*.conf"]
    crs_setup: crs-setup.conf
  inline_directives:
    - "SecRequestBodyAccess On"
  body:
    access: true
    limit_bytes: 13107200
    in_memory_limit_bytes: 131072
    limit_action: reject     # reject | processPartial
    json_depth_limit: 4096
    parse_multipart: false
  hot_reload:
    enabled: true
    debounce: 1s

# (4) 站点策略（多站点差异化）
sites:
  - name: default
    hosts: ["*"]
    engine_mode: inherit
    pipeline: default

# (5) 校验链：有序数组 = 串联；enabled 控制启用；可同类型多实例
pipeline:
  - name: ban-list
    type: banlist
    enabled: true
    order: 5
    phase: pre
    on_error: pass           # 共享存储不可用时的策略由 stores.*.on_error 决定
    settings:
      store: default

  - name: ip-allow
    type: ipaccess
    enabled: true
    order: 10
    phase: pre
    on_error: pass
    settings:
      allowlist: ["192.168.0.0/16"]
      blocklist_file: /etc/waf/ip/blocklist.txt
      action: block

  - name: rl-ip
    type: ratelimit
    enabled: true
    order: 20
    phase: pre
    on_error: pass
    settings:
      dimensions: [ip]
      window: 60s
      limit: 600
      burst: 60
      action: ratelimit      # ratelimit -> 429
      store: default

  - name: rl-login
    type: ratelimit
    enabled: true
    order: 21
    phase: pre
    on_error: pass
    settings:
      dimensions: [ip, path]
      path_match: ["^/login$", "^/api/auth/"]
      window: 300s
      limit: 20
      action: block
      store: default

  - name: crs-header
    type: coraza
    enabled: true
    order: 30
    phase: request
    on_error: block
    settings:
      process_body: false
      score_key: inbound_anomaly_score

  - name: crs-body
    type: coraza
    enabled: true
    order: 31
    phase: body
    on_error: block
    settings:
      process_body: true
      score_key: inbound_anomaly_score

  - name: threshold
    type: threshold
    enabled: true
    order: 40
    phase: post
    settings:
      score_key: inbound_anomaly_score
      inbound_threshold: 5
      action: block

  - name: autoban
    type: autoban
    enabled: true
    order: 90
    phase: post
    settings:
      trigger_on: [block, ratelimit]
      min_severity: medium   # 只有 medium 及以上命中才计入（留空表示不设门槛）
      dimensions:            # 触发维度：可多个；每个维度可单独覆盖阈值 / 窗口 / 时长
        - scope: client_ip
          threshold: 3
          window: 5m
        - scope: client_ip+path
          threshold: 5
          window: 10m
      ttl: 30m               # 留空则使用 ban.default_ttl
      skip_when_banned: true # 已在名单中的来源不再重复计数与写名单
      store: default
      notify: [wechat]

# (6) 共享状态存储（限速计数 + 内部封禁名单；多实例共享，R17）
# 启用规则：enabled=false 时不连接 Redis，直接使用 fallback 指定的本地存储（仅本实例生效）
stores:
  - name: default
    type: redis               # redis | memory | file
    enabled: true             # 关闭则降级为 fallback 指定的本地存储，并打印 warn 级系统日志
    fallback: memory          # 降级实现：memory | file
    on_error: fallback_local  # fail_open | fail_closed | fallback_local
    settings:
      # 拓扑：standalone(单机) | sentinel(哨兵) | cluster(集群)
      # 三种拓扑均同时支持「Docker 容器化部署」与「直接部署（裸机/虚拟机）」，差异只体现在地址与拓扑上
      topology: standalone
      addrs:
        - "redis:6379"          # standalone 取第一个；cluster 填全部种子节点
      username: ""              # Redis 6+ ACL 用户名，无则留空
      password: ""
      db: 0                     # cluster 拓扑下必须为 0
      master_name: ""           # sentinel 拓扑必填：主节点名称
      sentinel_password: ""     # sentinel 拓扑可选：哨兵自身密码
      prefix: "waf:"
      pool_size: 64
      min_idle_conns: 4
      dial_timeout: 500ms
      read_timeout: 300ms
      write_timeout: 300ms
      max_retries: 2
      tls:
        enabled: false          # 内网需要加密链路时开启
        ca_file: ""
        cert_file: ""
        key_file: ""
        insecure_skip_verify: false
      local_cache_ttl: 5s       # 本地封禁结论缓存，降低往返
      local_cache_entries: 100000

# 无 Redis 的单机场景示例：直接使用本地内存存储（多实例不共享）
# stores:
#   - name: default
#     type: memory
#     enabled: true
#     settings:
#       shards: 64
#       max_entries: 1000000

# (7) 封禁策略（仅 WAF 内部封禁，不操作任何系统防火墙，R18/R19）
ban:
  default_ttl: 30m            # 默认封禁时长（恰当取值，见 §7.5）
  max_ttl: 24h
  ban_key: client_ip          # 主维度：client_ip | client_ip+site | client_ip+path | client_ip+method
  ban_keys: [client_ip]       # 运行期查询的维度集合（可多个，按顺序短路；留空等价于 [ban_key]）
  escalate: false             # 累进封禁开关
  escalate_steps: [30m, 2h, 24h]
  escalate_window: 24h

# (8) 告警外送（并联，可多个）
notifiers:
  - name: wechat
    type: wechat
    enabled: true
    settings:
      url: "http://qyapi.weixin.qq.com/..."
      push_interval_sec: 5

# (9) 日志：两类、分级、JSON（R21）
logging:
  # 系统运行日志
  system:
    enabled: true
    level: info              # debug | info | warn | error
    format: json             # 本期仅支持 json
    outputs: [stdout, file]  # stdout | file
    dir: logs
    file: waf-system
    rotate: daily            # daily | size | both
    max_file_bytes: 134217728
    keep_days: 30
    max_total_bytes: 0
    compress: false
  # 请求访问 / 拦截日志
  access:
    enabled: true
    level: info              # debug | info | warn | error（通道自身阈值）
    allow_level: info        # info(默认,放行也记录) | debug | off
    format: json
    outputs: [file]
    dir: logs
    file: waf-access
    rotate: daily
    max_file_bytes: 134217728
    keep_days: 90
    max_total_bytes: 0
    compress: false
    include_headers: false
    include_body: false      # 默认不记录请求体内容，仅记录体元信息
    max_body_snippet_bytes: 4096
    mask_ip: false
    redact: [Cookie, Authorization, Proxy-Authorization, Set-Cookie, X-Api-Key, X-Auth-Token]

metrics:
  enabled: true

# (10) 资源与容量限额（禁止硬编码，全部可配置，见 §2.6）
limits:
  max_rule_file_bytes: 2097152
  max_rules_total_bytes: 67108864
  max_scan_token_bytes: 1048576
  max_intel_file_bytes: 67108864
  max_mmdb_bytes: 268435456
  max_config_file_bytes: 1048576
  max_header_bytes: 1048576

# (11) 缓存
cache:
  enabled: true
  rule_cache_entries: 10000
  ban_cache_entries: 100000
  max_bytes: 33554432
  ttl: 5m
```

### 8.2 功能开关矩阵（功能列表 -> 配置位置）

| 功能项（优先级） | 配置落点 | 默认 | 交付步骤 |
| --- | --- | --- | --- |
| 检测引擎 Coraza + CRS（P0） | `engine.*` / `pipeline[type=coraza]` | 开 | 步骤 1（骨架）/ 步骤 2（CRS 全量） |
| 请求体解析与检测（P0） | `ingress.body.*` + `engine.body.*` + `pipeline[phase=body]` | 开 | 步骤 1 |
| 请求体限额（P0） | `ingress.body.max_bytes` + `engine.body.limit_bytes` | 开 | 步骤 1 |
| 旁路观察 DetectionOnly（P0） | `engine.mode: detection_only` | 关 | 步骤 1 |
| IP/CIDR 黑白名单（P0） | `pipeline[type=ipaccess]` | 关 | 步骤 1 |
| 速率限制 / CC（P0，多实例共享） | `pipeline[type=ratelimit]` + `stores` | 关 | 步骤 1 |
| **内部封禁（不联动防火墙，P0）** | `pipeline[type=banlist]` + `pipeline[type=autoban]` + `ban.*` + `stores` | 开 | 步骤 1 |
| **JSON 错误体（P0）** | `responder.*` + `ingress.deny_path` | 开 | 步骤 1 |
| **双类分级 JSON 日志（P0）** | `logging.system.*` / `logging.access.*` | 开 | 步骤 1 |
| 异常评分阈值（P0） | `pipeline[type=threshold]` | 开 | 步骤 1（骨架）/ 步骤 2（调优） |
| 规则热更新（P0） | `engine.hot_reload.*` | 开 | 步骤 2 |
| 上传文件处理（P1） | `engine.body.parse_multipart` + `SecUploadDir` | 关 | 步骤 2 |
| 压缩体解压 gzip/br（P1） | CRS `body-decompress` 插件 | 关 | 步骤 2 |
| 多重编码绕过（P1） | CRS `auto-decoding` 插件 | 关 | 步骤 2 |
| 规则误报例外（P0） | `engine.inline_directives` / `sites[].rules.exclude` | - | 步骤 2 |
| 告警通知（P0） | `notifiers` | 关 | 步骤 3 |
| Prometheus 指标（P0） | `metrics` | 开 | 步骤 1 |
| 多站点策略（P1） | `sites` | - | 步骤 4 |
| GeoIP 地域（P1） | `pipeline[type=geoip]` | 关 | 步骤 4 |
| 本地威胁情报（P1） | `pipeline[type=ipaccess].settings.intel_file` | 关 | 步骤 4 |
| 管理面 / RBAC（P1） | 独立进程，复用本项目 API | - | 步骤 5 |

> **交付状态**：上表中「步骤 1 / 2 / 3」的项目已全部交付（M1 / M2 / M3，见路线图 §10.8 / §10.9 / §10.11）；「步骤 4 / 5」的 GeoIP、情报、多站点、管理面尚未开始。
>
> 响应侧与内容安全（内容泄漏、脱敏、动态防护）在 forward-auth 形态下不交付（代理会丢弃鉴权响应体），仅保留接口占位与文档说明。
> 系统防火墙联动（iptables/firewalld/ufw）**按需求排除**，不在任何步骤交付。

---
## 9. 第一步详细方案（步骤 1：骨架 + 插件链 + 请求体检测 + 共享状态 + JSON 错误体 + 双类日志）

### 9.1 目标

打通「代理子请求（Nginx / Traefik，可带请求体）→ 请求还原 → 有序插件链（含体检测）→ 判定（含共享限速与内部封禁）→ JSON 错误体 → 双类分级 JSON 日志」的完整闭环，并落地工程规范（§2）。

### 9.2 交付物

1. **代码骨架**（Go module `github.com/weiyongkang/waf`，`CGO_ENABLED=0`）：

```
cmd/waf/main.go                    # 装配入口：版本信息 -> 配置加载 -> 注册插件 -> 构建 pipeline -> 启动
cmd/waf/cmd_run.go                 # run 子命令：启动 forward-auth 服务
cmd/waf/cmd_check_config.go        # check-config：校验配置并输出生效来源摘要
cmd/waf/cmd_version.go             # version：版本/提交号/构建时间
cmd/waf/cmd_healthz.go             # healthz：供容器 HEALTHCHECK 调用
cmd/waf/cmd_ban.go                 # ban list/add/remove：封禁名单运维（读写共享存储）
cmd/waf/plugins.go                 # 空白导入注册内置插件（编译期装配）
internal/config/                   # 三通道配置（env/文件/CLI）+ 优先级叠加 + 校验 + 来源摘要
internal/core/                     # Verdict/Result/BodyMeta/RequestContext/Phase/Check/Registry/Deps
internal/pipeline/                 # 串联执行器 + 决策合并 + on_error + 按需读体
internal/ingress/forwardauth/      # Traefik / Nginx 注入头还原 + trusted_proxies 客户端 IP
internal/ingress/body/             # BodySpool: memory / disk / auto + 限额 / 截断 / chunked
internal/sites/                    # 站点解析（默认单站点 + host glob）
internal/responder/                # JSON 错误体 + /waf/deny 渲染端点
internal/server/                   # HTTP Handler / healthz / readyz / metrics / deny
internal/store/                    # Store 实现：redis（共享，默认）/ memory / file
internal/store/redis/              # Redis 共享存储（计数 + 封禁名单 + 本地短 TTL 缓存）
internal/check/passthrough/        # 空实现（冒烟/调试）
internal/check/ipaccess/           # allowlist/blocklist CIDR 匹配（含流式文件加载）
internal/check/banlist/            # 内部封禁名单校验（读共享存储）
internal/check/ratelimit/          # 多维度限速（ip / ip+path / header），计数走共享存储
internal/check/coraza/             # Coraza 引擎封装（header + body 阶段 + 流式规则加载）
internal/check/threshold/          # 异常评分阈值聚合
internal/check/autoban/            # 自动封禁（写入共享存储）
internal/logging/                  # 系统日志 + 访问日志（slog JSON + 按日/按大小轮转）
internal/observe/                  # 指标接口 + prometheus 实现 + noop
internal/version/                  # 版本 / 提交号 / 构建时间（ldflags 注入）
configs/waf.example.yaml           # 完整示例配置（含全部限额项）
deploy/forward-auth/traefik-forwardauth.yml  # Traefik: forwardBody + errors 中间件
deploy/forward-auth/nginx-openresty.conf     # Nginx(OpenResty): 子请求转发 + JSON 回写
deploy/forward-auth/waf_auth.lua             # 上述 nginx 的 Lua 鉴权脚本
deploy/forward-auth/nginx-auth-only.conf     # Nginx 原生兜底：仅头校验（无体/无 JSON 说明）
Dockerfile                         # 多阶段构建 + distroless 非 root（替换旧 Action 模板）
docker-compose.yml                 # waf + redis + 卷挂载（配置/日志）
scripts/build.sh                   # 构建脚本（版本注入 + 静态编译）
scripts/build-offline.sh           # 离线打包（镜像 tar + 二进制 + 校验和）
.golangci.yml                      # 静态检查配置
```

2. **契约测试**：用 `httptest` + 内嵌 Redis（或 miniredis）模拟 Traefik `ForwardAuth(+body)` 与 Nginx OpenResty 子请求两种流量，断言放行 / 拦截 / JSON 错误体 / 回传头 / 体检测 / 跨实例共享。
3. **文档**：`docs/configuration.md`（字段级说明、单位、默认值、三通道与优先级、与 honeypot 的差异、代理集成前置条件与限制）。

### 9.3 关键实现要点

| 要点 | 做法 |
| --- | --- |
| 插件注册 | `core.RegisterCheck(type, factory)`；`cmd/waf/plugins.go` 空白导入；未注册类型启动即报错（fail fast） |
| 配置校验 | 未知 `type` / 重复 `name` / 非法 `phase` / 引用不存在的 `store` / 超限值不合理 -> 启动失败并给出「配置项 + 来源」精确错误 |
| 配置优先级 | 按 §2.7 实现，逐项记录来源；`check-config` 输出完整来源摘要 |
| 双代理还原 | URI 优先 `X-Forwarded-Uri` -> `X-Original-URI` -> `RequestURI`；Method 同理；`ingress.type: auto` 按注入头存在性判定 |
| 客户端 IP 安全 | 仅信任 `trusted_proxies` 内的来源头，从右往左取第一个非可信地址 |
| 按需读体 | pipeline 先静态分析「是否存在启用的 PhaseBody 插件」；无则完全不读体（零拷贝） |
| 流式读取 | 体读取使用 `io.LimitReader` + 分块拷贝；超限按 `truncate`/`reject`/`skip`；落盘走临时文件并 `defer` 清理 |
| 共享限速 | 计数一律走 `Store.Incr`（Redis）；不做本地缓存以保证强一致；键含维度与窗口 |
| 内部封禁 | `banlist` 读共享存储；`autoban` 写共享存储；本地仅缓存「已封禁」结论（`local_cache_ttl` 默认 5s） |
| 禁止系统命令 | 全仓库不引用 `os/exec`；CI 增加静态检查（`golangci-lint` 规则 + grep 校验） |
| JSON 错误体 | `responder` 统一渲染；`/waf/deny` 为幂等渲染端点，供 Traefik `errors` 回源 |
| 双类日志 | `internal/logging` 提供 `NewSystem` / `NewAccess`，均基于 `slog.NewJSONHandler` + 自定义轮转 writer |
| 串联执行 | `pipeline.Run`：稳定排序 -> 跳过 disabled -> 合并 Result -> 短路/失败策略 -> 返回最终 Result |
| 规则加载 | 逐文件流式加载 + 单文件/总量上限；超限跳过并以 `warn` 级写系统日志 |
| 可观测 | `waf_requests_total{site,verdict}`、`waf_check_duration_seconds{check}`、`waf_check_errors_total{check}`、`waf_blocked_total{check,rule_id}`、`waf_body_bytes`、`waf_body_truncated_total`、`waf_body_missing_total`、`waf_ban_total`、`waf_deny_render_total`、`waf_store_errors_total` |
| 热加载 | 步骤 1 仅实现配置热加载（`SIGHUP` 重建 pipeline，失败保留旧配置）；规则热加载留步骤 2 |
| 失败策略 | `on_error: pass/block`；`engine` 与 `crs-*` 默认 `block`；`stores.*.on_error` 默认 `fail_open` |
| 优雅关停 | 捕获 `SIGINT/SIGTERM`，`server.Shutdown` + 各 `Check.Close()` + `Store.Close()` + 日志 writer `Close()` |
| 命名与注释 | 全部按 §2.3、§2.4 执行；CI 中通过 lint 与人工抽查双重保证 |

### 9.4 Coraza 插件在步骤 1 的边界

- 复制并改造 `reference/coraza-traefik-WAF` 的事务构造方式：`ProcessConnection` -> `ProcessURI` -> `AddRequestHeader` -> `ProcessRequestHeaders` -> `WriteRequestBody` -> `ProcessRequestBody`。
- 步骤 1 同时打通 **header 阶段与 body 阶段**，可加载参考实现现有规则集（`crs-setup.conf` + `REQUEST-9xx`），但规则加载方式需按 §2.5 重构为流式 + 限额。
- `engine.mode: detection_only` 时命中降级为 `VerdictObserve`，以 `info` 级写访问日志。
- 体处理遵循 `RequestBodyLimit` / `InMemoryLimit` / `LimitAction`；multipart 与压缩体在步骤 2 增强。
- 引擎原子替换（`fsnotify` + 加载失败保留旧引擎）在步骤 2 完善。

### 9.5 明确不做（步骤 1 的非目标）

- 不做反向代理 / TLS 卸载 / 路由转发。
- **不做任何系统防火墙操作**（iptables/firewalld/ufw/nftables 全部排除）。
- 不做拦截 HTML 页面 / 品牌化错误页。
- 不做响应体检测、内容脱敏、动态防护（forward-auth 形态下不可达）。
- 不做压缩体解压、multipart 上传落盘与病毒扫描（步骤 2/4）。
- 不做多租户、管理面 Web UI、RBAC、报表。
- 不做 CRS 全量离线打包与 `go:embed`（步骤 2）。

### 9.6 验收标准

| # | 验收项 | 方法 |
| --- | --- | --- |
| A1 | `CGO_ENABLED=0 go build ./...` 通过，产出静态单二进制 | CI |
| A2 | `go vet ./...` + `golangci-lint run` + `go test ./...` 全绿 | CI |
| A3 | 未启用任何插件时一律返回 200（纯放行） | 契约测试 |
| A4 | `ipaccess` 命中黑名单 -> 403 + JSON 错误体 | 契约测试 |
| A5 | `ratelimit` 超阈 -> 429 + `Retry-After` + JSON 错误体 | 契约测试（伪造时钟） |
| A6 | 插件顺序与短路语义符合 §7.4（含 `on_error` 两种策略） | 单元测试 |
| A7 | 未知 `type` / 非法引用 -> 启动失败且报错精确（含来源） | 配置测试 |
| A8 | Traefik 与 Nginx 两种注入头均能正确还原 URI/Method/ClientIP | 契约测试 |
| A9 | `/healthz`、`/readyz`、`/metrics` 可用；`SIGTERM` 优雅退出 | 冒烟测试 |
| A10 | 伪造 `X-Forwarded-For` 且来源非可信时不被采纳 | 安全测试 |
| A11 | Traefik `forwardBody` 场景：POST body 含 SQLi/XSS -> 403 | 契约测试 |
| A12 | Nginx/OpenResty 场景：POST body 含 SQLi/XSS -> 403 且客户端收到 JSON 错误体 | 契约测试 |
| A13 | 超 `ingress.body.max_bytes` 时 `truncate`/`reject`/`skip` 行为正确并计数 | 单元测试 |
| A14 | 无 PhaseBody 插件时全程不读取请求体 | 单元测试（读计数器断言） |
| A15 | `Transfer-Encoding: chunked` 请求体可正确读取并检测 | 契约测试 |
| A16 | `ingress.body.mode: required` 且未收到体 -> `waf_body_missing_total` 递增并告警 | 集成测试 |
| A17 | 三通道配置均生效且优先级正确：CLI 覆盖文件、文件覆盖 env | 单元测试 |
| A18 | 大体积请求体/规则文件/情报文件不被整体读入内存 | 单元测试 + 压测 |
| A19 | 全部限额项（§2.6）均可通过配置文件调整并立即生效 | 配置测试 |
| A20 | 镜像为静态二进制 + 非 root，`HEALTHCHECK` 通过 | 构建检查 |
| A21 | `waf check-config` 输出生效配置与来源摘要，错误时退出码 2 | 冒烟测试 |
| A22 | 注释规范：导出标识符中文注释覆盖率 100%，lint 通过 | 静态检查 + 抽查 |
| **A23** | **限速计数多实例共享**：两个实例共用同一 Redis，计数叠加、阈值一致触发 | 集成测试（双实例） |
| **A24** | **封禁跨实例即时生效**：实例 A 触发封禁，实例 B 在 `local_cache_ttl` 内生效；TTL 到期自动解封 | 集成测试（双实例） |
| **A25** | **全程不执行系统命令**：静态扫描无 `os/exec`；封禁不产生任何防火墙副作用 | 代码扫描 + 用例 |
| **A26** | **JSON 错误体两条路径均正确**：OpenResty 直接回写、Traefik `/waf/deny` 渲染；`Content-Type`/`code`/`request_id` 齐全 | 契约测试 |
| **A27** | **双类日志**：系统日志与访问日志分别落盘为 JSON；`info` 不记录放行、`debug` 记录放行 | 集成测试 |
| **A28** | **封禁默认时长 30m 且可配置**：修改 `ban.default_ttl` 后生效值出现在访问日志与命令输出中 | 配置测试 |
| **A29** | **`waf ban add/list/remove` 可用**，且跨实例即时生效 | 冒烟测试 |
| **A30** | **鉴权响应头方案生效**：Nginx 侧 `auth_request_set` 能取到 `X-WAF-Code` / `X-WAF-Request-Id`，`error_page` 渲染出正确 JSON 与对外状态码 | 契约测试 |
| **A31** | **Redis 可配置启用/降级**：`stores[].enabled=false` 时不连 Redis、降级本地存储并打印 warn 级系统日志；`=true` 时多实例共享生效 | 集成测试 |

### 9.7 任务拆解（WBS）

| 序号 | 任务 | 产出 | 依赖 |
| --- | --- | --- | --- |
| T1 | 重构工程骨架：`cmd/waf` + `internal/*`，移除 GitHub Action 模板 | 可编译空服务 | - |
| T2 | `internal/core`：Verdict/Result/BodyMeta/Context/Phase/Check/Registry/Deps | 契约包 + 单测 | T1 |
| T3 | `internal/config`：三通道（env/文件/CLI）+ 优先级 + 校验 + 来源摘要 | 配置包 + 单测 | T1 |
| T4 | CLI 子命令：`run` / `check-config` / `version` / `healthz` / `ban` | CLI 包 | T3 |
| T5 | `internal/ingress/forwardauth`：Traefik/Nginx 还原 + 可信代理 | 还原包 + 单测 | T2 |
| T6 | `internal/ingress/body`：BodySpool + 限额/截断/分块 | 体缓冲包 + 单测 | T2 |
| T7 | `internal/pipeline`：串联执行 + 决策合并 + on_error + 按需读体 | 执行器 + 单测 | T2,T6 |
| T8 | `internal/responder`：JSON 错误体 + `/waf/deny` 渲染端点 | 响应包 + 单测 | T2 |
| T9 | `internal/server`：Handler / healthz / readyz / metrics / deny | 服务包 | T3,T7,T8 |
| T10 | `internal/store`：接口 + `redis`（默认，含本地短 TTL 缓存）/ `memory` / `file` | 存储包 + 单测 | T2 |
| T11 | 插件：`passthrough` / `ipaccess` / `banlist` | 3 个插件 + 单测 | T2,T5,T10 |
| T12 | 插件：`ratelimit`（多维度 + 共享计数） | 限速插件 + 单测 | T2,T10 |
| T13 | 插件：`coraza`（header + body + 流式规则加载） | 引擎插件 | T2,T6 |
| T14 | 插件：`threshold` + `autoban`（写共享存储） | 2 个插件 + 单测 | T2,T10 |
| T15 | `internal/logging`：系统日志 + 访问日志（slog JSON + 双维度轮转） | 日志包 + 单测 | T2 |
| T16 | `internal/observe`：Prometheus 指标 | 指标包 | T2 |
| T17 | 示例配置 + 三份接入示例（Traefik / Nginx-OpenResty / Nginx 原生） | `configs/` `deploy/` | T9,T11,T12,T13 |
| T18 | Docker / 构建脚本 / 离线打包（多阶段、distroless、非 root） | `Dockerfile` `scripts/` | T4 |
| T19 | 契约与集成测试（双代理 + 体检测 + 双实例共享 + JSON 错误体 + 双类日志） | 测试套件 | 全部 |
| T20 | 文档 `docs/configuration.md`（三通道、优先级、限额、封禁策略、代理集成与限制） | 文档 | 全部 |

### 9.8 风险与待确认

| 风险 / 问题 | 处置 |
| --- | --- |
| **共享存储（Redis）在离线环境是否可部署？** | 已改为**可配置启用**：`stores[].enabled=false` 时不连接 Redis，自动降级为本地存储（`fallback: memory`），文档标注"多实例不共享"；启用则要求内网可离线部署 Redis |
| **默认封禁 30m 是否符合业务预期？** | 已按"恰当值"取 30m 并可配置；如需更激进（如 2h）或更保守（如 10m），直接改 `ban.default_ttl` |
| **本地缓存导致封禁生效有最长 `local_cache_ttl`（默认 5s）延迟** | 如需强即时，可将 `local_cache_ttl` 置 0（代价是每次请求多一次 Redis 往返） |
| **Traefik 的 JSON 错误体依赖 `errors` 中间件** | 需实测确认：① `errors` 中间件可用且 `query` 模板占位符写法（`{status}` 或 `{urlquery ...}`）；② `forwardAuth` 失败路径**是否透传鉴权响应头**（不要依赖它）。不支持则退化为 Traefik 默认错误响应 |
| **配置优先级与 honeypot 相反** | 已按 R16 实现（CLI 最高），文档显式标注 |
| 体转发带来额外带宽开销 | 按路由按需开启 `forwardBody`；限制 `maxBodySize` / `max_bytes`；`lazy` 读体 |
| 共享存储未启用/不可用 | 静态：`enabled=false` 时降级本地存储；运行期：`on_error` 默认 `fallback_local`（降级本地并告警），可选 `fail_open` / `fail_closed` |
| `reference/` 目录最终归属 | 待定；步骤 1 保持只读参考、不参与构建 |

---

## 10. 后续步骤概览

| 步骤 | 主题 | 关键交付 |
| --- | --- | --- |
| **1** | **骨架 + 插件链 + 体检测 + 共享状态 + JSON 错误体 + 双类日志** | 本文件 §9 |
| 2 | Coraza + CRS 生产化 | 规则离线打包、热加载原子替换、误报例外、评分阈值调优、PL1-PL4、压缩体/多重编码/multipart |
| 3 | 告警与运营 | 通知渠道接入、封禁可视化、误报压降流程、审计报表 |
| 4 | 多站点与本地情报 | 站点级策略、GeoIP(MMDB)、IP/CIDR 情报导入、虚拟补丁 |
| 5 | 管理面 | 本地 Web UI、规则/名单管理、RBAC、取证包导出 |

> 每一步沿用同一套抽象接口与配置模型：新增能力 = 新增一个已注册的 `Check` / `Store` / `Notifier` 实现，无需改动主流程。
>
> **开发优先级（P0/P1/P2）、阶段划分（M0–M5）、逐文件交付清单与门禁，见 `docs/development-roadmap.md`。**
