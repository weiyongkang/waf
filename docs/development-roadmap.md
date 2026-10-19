# WAF 开发优先级与交付路线图（forward-auth 前置校验 · Nginx + Traefik）

> 版本：v0.10（优先级基线；已并入 R24–R26、P3 分级，并记录 M1.3 / M1.4 / M1.5 / M1.6 / **M2** / **M3** / **M4 能力实现** 完成情况，见 §10.3、§10.4、§10.7、§10.8、§10.9、**§10.11**、**§10.18**；后续缺陷修复与文档收口见 §10.14–§10.17）
> 配套文档：`docs/forward-auth-design.md`（v0.4：部署形态、架构、抽象接口、第一步详案）、`docs/waf-feature-list.md`（功能全景与原始 P0/P1/P2 分级）
> 用途：把已确认的全部需求（R1–R21 与本轮新增 R22/R23）转成「**优先级 → 阶段 → 交付文件 → 验收项**」，作为排期与评审的确认基线。
> 说明：本文件只给出**优先级与交付物落点**的结论；设计细节一律以 `docs/forward-auth-design.md` 为准。

---

## 1. 需求全景确认

### 1.1 已确认需求清单（R1–R21）

| 编号 | 需求要点 | 类别 | 设计落点 | 状态 |
| --- | --- | --- | --- | --- |
| R1 | 部署形态为 **forward-auth 前置校验** | 形态 | 单一鉴权端点（`POST /waf/auth`），只回放行/拦截 | 已确认 |
| R2 | **不做反向代理** | 形态 | 不实现 `httputil.ReverseProxy`、不做 TLS 卸载/路由/连接接管 | 已确认 |
| R3 | **同时支持 Nginx 与 Traefik** | 形态 | `ingress.type` + `RequestExtractor` 多实现，差异收敛在适配层 | 已确认 |
| R4 | **请求体检测为必需能力** | 能力 | `PhaseBody` + `internal/ingress/body` 体缓冲 + 双代理体转发 | 已确认 |
| R5 | 功能项与插件走**配置启用方案** | 架构 | YAML `pipeline[]` 声明式装配，默认全关 | 已确认 |
| R6 | **全部可自由配置启用** | 架构 | 每个实例 `enabled/order/phase/settings/on_error`；`pipeline: []` 即纯放行 | 已确认 |
| R7 | **抽离抽象接口**，可换实现 | 架构 | `Check/Store/Notifier/RequestExtractor/Responder/SiteResolver` + 工厂注册表 | 已确认 |
| R8 | 可配置多个，**多个则串联** | 架构 | `pipeline` 有序数组按 `phase`+`order` 串联；通知类并联扇出 | 已确认 |
| R9 | 代理版本可升级 | 部署 | Traefik ≥ v2.11（`forwardBody`）；Nginx **强制 OpenResty**（见 R24）；升级纳入变更流程 | 已确认 |
| R10 | `reference/` 仅参考，**复用必须复制一份** | 工程 | 禁止 import/replace；复制到 `internal/*` 后改造并标注来源 | 已确认 |
| R11 | 命名符合编码规范 | 工程 | 目录/文件/包/函数/变量/接口统一命名规范 | 已确认 |
| R12 | **注释全部中文且详细** | 工程 | 包/类型/字段/函数/常量/配置项/复杂逻辑全中文注释 | 已确认 |
| R13 | 不做大体积读取；**缓存大小与最大文件大小可配置** | 工程 | 流式 + 限额 + 超限策略；限额全部进配置文件，禁止硬编码 | 已确认 |
| R14 | 参考常用 Go Docker 模式 | 交付 | 多阶段 + `CGO_ENABLED=0` + distroless + 非 root + HEALTHCHECK | 已确认 |
| R15 | **CLI / 配置文件 / 环境变量**三通道 | 配置 | `internal/config` 统一承载 | 已确认 |
| R16 | 冲突优先级 **CLI > 配置文件 > 环境变量** | 配置 | 默认值 → env → 文件 → CLI 逐层叠加，逐项记录来源 | 已确认 |
| R17 | **限速状态多实例共享** | 状态 | `Store` 抽象 + Redis 共享计数；本地仅短 TTL 缓存「已封禁」结论 | 已确认 |
| R18 | **封禁仅在 WAF 内部生效，不动系统防火墙** | 状态 | 删除 `Blocker` 抽象；禁用 `os/exec`；封禁 = 共享存储中的名单 | 已确认 |
| R19 | 封禁时长可配置，默认取**恰当值** | 状态 | `ban.default_ttl: 30m`、`ban.max_ttl: 24h`、可选累进封禁 | 已确认 |
| R20 | **不提供拦截页面**，统一 **JSON 错误体** | 响应 | `internal/responder` 仅实现 JSON；`code → HTTP 状态` 映射表 | 已确认 |
| R21 | 日志**分两类、分级、JSON** | 观测 | `system` / `access` 两个 `slog.NewJSONHandler` 实例 | 已确认 |

### 1.2 本轮新增确认（R22 / R23 / R24 / R25 / R26）

| 编号 | 需求要点 | 关键约束 | 设计落点 | 状态 |
| --- | --- | --- | --- | --- |
| R22 | 拦截送达采用**鉴权响应头方案**（代理侧渲染） | 两种代理都会**丢弃鉴权响应体**，但 **Nginx 可读鉴权响应头**（`auth_request_set $upstream_http_x_waf_code`） | WAF 回传 `X-WAF-Code` / `X-WAF-Request-Id` / `X-WAF-Verdict` / `X-WAF-Rule-Id`；Nginx 用 `error_page` + `/waf/deny` 渲染；Traefik 用 `errors` 中间件回源 `/waf/deny` | 已确认 |
| R23 | **Redis 共享「配置启用」**，未启用则本地存储 | `stores[].enabled=false` → 不连 Redis、降级 `fallback` 本地实现（memory/file）并以 `warn` 写系统日志；运行期故障按 `on_error`（`fail_open` / `fail_closed` / `fallback_local`） | `stores` 配置 + `internal/store`（redis/memory/file） | 已确认 |
| R24 | **Nginx 侧强制使用 OpenResty** | 请求体检测与 JSON 错误体回写都依赖 `ngx.location.capture`；原生 Nginx 仅作**降级兜底**（无体检测、无 JSON 响应体），文档必须标注该限制 | `deploy/forward-auth/nginx-openresty.conf` + `waf_auth.lua`；兜底 `nginx-auth-only.conf` | 已确认 |
| R25 | **Redis 部署形态不限**：Docker 容器化 / 直接部署，拓扑支持 单机 / 哨兵 / 集群 | `stores[].settings.topology: standalone \| sentinel \| cluster`；地址、认证、TLS、连接池全部配置化，切换拓扑不改代码 | `internal/store/redis` + `configs/waf.example.yaml` | 已确认 |
| R26 | **管理面下调为 P3**（新增 P3 级别） | Web UI / RBAC / 取证包不阻塞防护能力上线；M1–M4 的运维入口由 CLI 子命令承担 | 阶段 M5（P3），见 §3.4 | 已确认 |

### 1.3 硬约束小结（必须贯穿所有阶段）

| 约束 | 具体要求 | 强制手段 |
| --- | --- | --- |
| 无系统命令 | 全仓库禁止 `os/exec`；封禁不产生任何防火墙副作用 | `golangci-lint` + CI 文本扫描双校验 |
| 无大文件读取 | 请求体 / 规则文件 / 情报文件一律流式 + 限额 + 超限策略 | 单元测试断言 + 压测 |
| 无硬编码限额 | 大小 / 容量 / 阈值 / 超时全部来自配置 | `check-config` 输出全部生效值 |
| 全中文详细注释 | 导出标识符注释覆盖率 100% | lint + 人工抽查 |
| 代理差异收敛在适配层 | 上层 `Check` 不感知 Nginx / Traefik 差异 | 代码评审 + 契约测试 |
| Nginx 状态码限制 | 走 `auth_request` 时统一回 **403**，真实语义放 `X-WAF-Code` | 契约测试（A30） |

---
## 2. 优先级评估方法

### 2.1 评估维度

| 维度 | 含义 | 权重 |
| --- | --- | --- |
| **安全价值** | 该能力直接削减多少真实攻击面（「有 WAF」与「没 WAF」的差别贡献） | 高 |
| **依赖前置** | 是否为其它能力的运行前提（阻塞面越大越靠前） | 高 |
| **上线风险** | 缺失时的最坏后果（误报打死业务 / 漏拦截 / 故障不可见） | 高 |
| **实现成本** | 人日与外部依赖（Redis / OpenResty / 规则包 / MMDB） | 中 |
| **可验证性** | 能否用离线契约测试与单元测试闭环验证 | 中 |
| **运维必要度** | 生产运行是否离不开它（排障、扩容、合规） | 中 |

### 2.2 分级定义

| 级别 | 定义 | 判据 | 缺失后果 |
| --- | --- | --- | --- |
| **P0** | MVP 阻断项 | 不做则无法形成「可跑、可拦、可查」的最小闭环，或违反 R1–R23 中的硬性要求 | 无法交付可用系统 |
| **P1** | 生产上线阻断项 | 防护效果或运营能力不足以上生产：规则不准、误报无法治理、故障与攻击不可见 | 上线即被打爆，或被误报拖垮业务 |
| **P2** | 加固与体验增强 | 不改变拦截能力，属效率、可视化、合规与差异化能力 | 功能上可接受，只是运营体验差 |

> 三级之间是**串行依赖**：P0 不完成，P1 无处挂载；P1 不完成，不建议对真实业务流量开启 `SecRuleEngine On`。

### 2.3 与业界常用方案的对照（为什么这样排）

| 决策点 | 业界常见做法 | 本项目取舍与理由 |
| --- | --- | --- |
| 检测引擎 | 直接使用 OWASP Coraza + CRS（与 libcoraza/nginx、Traefik WASM 同源思路） | **P0 就接 Coraza**，但 M1 只打通 header + body 事务骨架（配少量 CRS 规则），全量 CRS 生产化放 M2，避免 M1 被规则兼容性与误报拖死 |
| 插件化 | APISIX / Envoy FilterChain 的「声明式有序插件链 + 短路」 | 采用 `pipeline[]` + `Phase`/`Order` + 短路语义，**P0** |
| 共享限速 | APISIX `limit-req` 用 Redis 计数器；Nginx `limit_req` 是进程内计数（多实例不共享，故不采用） | **P0** 就用 Redis `INCR + EXPIRE` 计数，满足 R17 |
| 内部封禁 | SafeLine（雷池）等自研 WAF 使用内部黑名单；商用云 WAF 同样只在云端封禁 | 按 R18 **只做内部封禁**，不做 iptables/firewalld 联动，因此天然具备多实例共享能力 |
| 失败策略 | forward-auth 生态（oauth2-proxy、Authelia、traefik-forward-auth）默认 **fail-closed**，可按路径覆盖 | 引擎类默认 `on_error: block`（fail-closed）；存储类默认 `fail_open`（避免 Redis 抖动导致全站 503），两者均可配置 |
| 拦截送达 | oauth2-proxy 走 `--custom-templates-dir` 渲染 HTML；Authelia 走门户页 | 按 R20 **不做页面**，只回 JSON；送达方式按 R22 用「鉴权响应头 + 代理侧渲染」，避免 WAF 自身返回 302（会被代理当作放行处理） |
| 日志 | WAF / 网关普遍采用「系统日志 + 访问日志」双通道并 JSON 化便于采集 | 按 R21 双类 + 分级 + JSON，**P0** |
| 配置优先级 | 十二要素 / 常用 Go 服务的默认约定：CLI > 文件 > 环境变量 | 按 R16 实现。**注意与 `reference/honeypot` 相反**（honeypot 是 env 最高），不可照搬其配置包 |

---

## 3. 优先级结论

### 3.1 P0 — MVP 阻断项（阶段 M0–M1）

| # | 能力 | 对应用户需求 | 阶段 |
| --- | --- | --- | --- |
| P0-1 | 工程骨架与规范门禁（目录 / 命名 / 注释 / lint / CI） | R10–R12、R14 | M0 |
| P0-2 | 抽象接口与注册表（`internal/core`） | R7 | M1 |
| P0-3 | 三通道配置与优先级（`internal/config`） | R15、R16 | M1 |
| P0-4 | CLI 子命令（`run` / `check-config` / `version` / `healthz` / `ban`） | R15 | M1 |
| P0-5 | 双代理请求还原（`internal/ingress/forwardauth`） | R1、R3 | M1 |
| P0-6 | 请求体缓冲与限额（`internal/ingress/body`） | R4、R13 | M1 |
| P0-7 | 串联执行器（`internal/pipeline`） | R5、R6、R8 | M1 |
| P0-8 | JSON 错误体 + `/waf/deny` 渲染端点（`internal/responder`） | R20、R22 | M1 |
| P0-9 | HTTP 服务（`internal/server`）：`/waf/auth`、`/waf/deny`、`healthz`、`readyz`、`metrics` | R1 | M1 |
| P0-10 | 共享存储抽象与三实现（`internal/store`：memory / file / redis，含 `enabled`/`fallback`/`on_error`） | R17、R18、R23 | M1 |
| P0-11 | 插件：`banlist` / `ipaccess` / `ratelimit` / `passthrough` | R5、R6、R17、R18 | M1 |
| P0-12 | 插件：`coraza`（header + body 事务骨架） | R4 | M1 |
| P0-13 | 插件：`threshold` / `autoban`（写共享存储） | R18、R19 | M1 |
| P0-14 | 双类分级 JSON 日志（`internal/logging`） | R21 | M1 |
| P0-15 | Prometheus 指标（`internal/observe`） | 可运维性 | M1 |
| P0-16 | 接入示例与交付物（Traefik yml / OpenResty conf + lua / 原生兜底 / Dockerfile / compose / 构建脚本 / 示例配置） | R9、R14、R22 | M1 |
| P0-17 | 契约与集成测试（双代理 + 体检测 + 双实例共享 + JSON 送达 + 双类日志） | 验收 A1–A31 | M1 |
### 3.2 P1 — 生产上线阻断项（阶段 M2–M3）

| # | 能力 | 对应需求 | 阶段 |
| --- | --- | --- | --- |
| P1-1 | CRS 全量离线打包（`go:embed` 或随包分发）+ 版本清单 | 功能列表 P0-2 / P0-3、R13 | M2 |
| P1-2 | 规则热加载与引擎**原子替换**（加载失败保留旧引擎） | 功能列表 P0-3 | M2 |
| P1-3 | Paranoia Level 1–4 与异常评分阈值调优 | 功能列表 P0-2 | M2 |
| P1-4 | 误报例外治理（按 rule id / tag / target / URL，可审计） | 功能列表 P1-16 | M2 |
| P1-5 | 压缩体（gzip/br）、多重编码、multipart 上传处理 | 功能列表 P1-18 / P1-20 | M2 |
| P1-6 | DetectionOnly 旁路观察**闭环**（「若拦截」清单 + 误报压降流程） | 功能列表 P0-4 | M2 |
| P1-7 | 告警通知（webhook / 企业微信 / syslog / smtp，多通道并联 + 聚合抑制） | 功能列表 P0-11 | M3 |
| P1-8 | 封禁与限速的运营可见性（`ban list` 增强、命中排行、Top 攻击源） | 功能列表 P1-24 | M3 |
| P1-9 | 审计与报表（导出、留存策略、合规证据） | 功能列表 P1-24 | M3 |
| P1-10 | 性能基线与容量模型（wrk / hey / k6 离线；P99 时延、规则规模上限） | 功能列表 P1-26 | M3 |

> **阶段状态**：**P1-1 ~ P1-6 已完成**（M2，见 §10.9）；**P1-7 ~ P1-10 已完成**（M3，见 §10.11）。
> P1 全部条目均已闭环，生产上线阻断项不再有未完成项；下一阶段（M4 / M5）为 P2 / P3 加固与体验增强。

### 3.3 P2 — 加固与增强（阶段 M4–M5，按需）

| # | 能力 | 备注 |
| --- | --- | --- |
| P2-1 | 多站点差异化策略（`sites[]`：域名/端口绑定规则集、限速、黑白名单） | M4 |
| P2-2 | GeoIP 地域控制（`coraza-geoip` + 本地 MMDB） | M4，需提前准备离线 MMDB |
| P2-3 | 本地威胁情报导入（CIDR / ASN / 域名，定时刷新） | M4 |
| P2-4 | 虚拟补丁（CVE 定向规则模板与一键启用） | M4 |
| P2-5 | 本地人机校验 / 站点口令保护 | 按需 |
| P2-6 | API 安全（OpenAPI/Schema 基线、`@validateSchema` / `@restpath`） | 按需 |
| P2-7 | 会话安全、敏感数据脱敏、动态防护、ML 评分、多租户 | 按需（部分能力在 forward-auth 形态下不可达） |

> **实现状态**：P2-1 ~ P2-4 已实现（M4，见 §10.18）；P2-5 完成 Basic / HMAC Cookie
> 站点口令版本（不含 CAPTCHA / JS 无感挑战）；P2-6 完成 OpenAPI 3.x 请求侧契约校验
> （JSON Schema 常用子集，不含接口资产发现与响应侧校验）。P2-7 仍按需推进。

### 3.4 P3 — 体验与运营增强（阶段 M5，不阻塞前序阶段）

| # | 能力 | 备注 |
| --- | --- | --- |
| P3-1 | 管理面 Web UI（仪表盘、攻击日志检索、规则 / 名单管理、系统状态） | M5 |
| P3-2 | 本地账号 + RBAC + 操作审计 | M5 |
| P3-3 | 攻击态势可视化（Top 攻击源 IP / 国家、类型分布、趋势图） | M5 |
| P3-4 | 原始请求取证包导出 | M5 |
| P3-5 | 合规报表（按需：PCI DSS 证据链、月度安全报表） | 按需 |

> P3 定位：**不改变拦截能力，只改善运营体验**。M1–M4 期间的封禁 / 名单 / 规则 / 报表运维入口由 `waf ban`、`waf rules`、`waf report` 等 CLI 子命令承担。

### 3.5 明确不做（Non-Goals）

| 项 | 原因 |
| --- | --- |
| 反向代理 / TLS 卸载 / 路由转发 / 连接管理 | R2 |
| 系统防火墙联动（iptables / firewalld / ufw / nftables） | R18 |
| 拦截 HTML 页面 / 品牌化错误页 | R20 |
| 响应体检测、内容脱敏、动态防护（作为本期交付物） | forward-auth 形态下代理丢弃鉴权响应体，不可达；仅保留接口占位与文档说明 |
| 动态加载 `.so` / Go `plugin` 包 | 与 `CGO_ENABLED=0` 单二进制目标冲突 |

---
## 4. 阶段与里程碑

### 4.1 阶段总览

| 阶段 | 名称 | 覆盖优先级 | 出口标志 |
| --- | --- | --- | --- |
| **M0** | 工程准备 | P0-1 | 仓库摆脱 GitHub Action 模板；`go build ./...` 通过；命名/注释/lint/CI 门禁生效；`.golangci.yml` 落地 |
| **M1** | MVP 闭环（= 设计文档「步骤 1」） | P0-2 ~ P0-17 | 双代理均可完成「体检测 → 判定 → JSON 送达 → 双类日志」，验收 A1–A31 全绿 |
| **M2** | 检测引擎生产化（= 步骤 2） | P1-1 ~ P1-6 | CRS 可离线升级 / 热加载 / 回滚；误报例外可配；压缩体覆盖；DetectionOnly 试运行闭环（**已完成**，见 §10.9） |
| **M3** | 运营与告警（= 步骤 3） | P1-7 ~ P1-10 | 告警多通道可用；封禁/限速可视化；性能基线与容量模型有数据（**已完成**，见 §10.11） |
| **M4** | 多站点与本地情报（= 步骤 4） | P2-1 ~ P2-6（P2-5/P2-6 基础版） | 站点级策略生效；GeoIP 与本地情报可导入并定时刷新；**代码与单元测试已完成，见 §10.18**；G4 的真实 MMDB / 外部情报数据验收待部署环境补跑 |
| **M5** | 管理面（= 步骤 5） | **P3**（P3-1 ~ P3-5） | 本地 Web UI + RBAC + 取证包导出；**不阻塞 M1–M4 任何阶段** |

> M0 与 M1 可以合并排期，但 **M0 必须是第一个提交**：此后所有代码都要满足「命名规范 + 全中文注释 + 无 `os/exec` + 无硬编码限额」，越晚补成本越高。

### 4.2 验收门禁（Gate）

| 门禁 | 位置 | 通过标准 |
| --- | --- | --- |
| **G0** | M0 出口 | A1、A2 通过；CI 含 `os/exec` 静态拦截；`.golangci.yml` 生效 |
| **G1** | M1 出口 | A3–A31 全部通过；两份接入示例（Traefik ≥ v2.11 + OpenResty）在真机实测可用 |
| **G2**（**已通过**，见 §10.9） | M2 出口 | 规则包可离线升级并回滚（`waf rules manifest/verify/install/rollback`）；`go-ftw` 在册用例全部通过（离线执行器 `test/ftw`，10 个阶段全绿）；DetectionOnly 试运行报告产出（`waf report detection` + `would_block` 日志字段与指标） |
| **G3**（**已通过**，见 §10.11） | M3 出口 | 告警五条契约用例全绿（送达 / 默认关闭 / 多通道扇出 / 聚合抑制 / 指标计数）；`waf report ban` 与 `--format csv\|xlsx` 导出可被 Excel 直接打开；`scripts/bench/*` 离线压测脚本产出 QPS / P99 与容量档位表 |
| **G4** | M4 出口 | 站点级策略与虚拟补丁用例通过；GeoIP / 情报在真实数据集上通过（实现已完成，见 §10.18；真实 MMDB / 外部情报数据验收待补） |
| **G5** | M5 出口（P3，可延后） | 管理面权限与审计用例通过；M1–M4 交付不受其阻塞 |

### 4.3 M1 内部里程碑细分（建议）

| 子里程碑 | 内容 | 出口判据（对应 A 编号） |
| --- | --- | --- |
| **M1.1** | 骨架 + `core` + `config` + `check-config` | A1、A2、A7、A17、A19、A21、A22 |
| **M1.2** | `ingress` + `body` + `pipeline` | A3、A6、A8、A10、A13、A14、A15、A16、A18 |
| **M1.3**（已完成） | `store` + `fsx`/`netx` + `ban` + `banlist`/`ipaccess`/`ratelimit`/`threshold`/`autoban` + `waf ban` 运维命令 | A4、A5、A23、A24、A25、A27、A28、A29、A31 |
| **M1.4**（已完成） | `sites` 站点解析（`responder` / `server` / 代理侧渲染示例已于 M1.1 提前交付，因此本子里程碑只剩站点差异化） | A30（复测）、站点级 `engine_mode` / 参数覆盖用例 |
| **M1.5**（已完成） | `observe`（Prometheus）+ `coraza`（请求体检测）+ `docs/configuration.md` | A24、A28、A29、A31 |
| **M1.6**（已完成） | 契约与集成测试收口 + 两份接入示例实测 | G1 全量回归（见 §10.8） |

---
## 5. 交付文件清单（按优先级标注）

> 全部路径以仓库根 `E:\work\project\waf` 为基准。**P0 文件 = M1 结束必须存在并通过门禁的交付物**；P1 / P2 文件为后续阶段交付物。
> 命名与中文注释规范见 `docs/forward-auth-design.md` §2.3、§2.4；所有复用自 `reference/` 的代码必须复制到下列路径后改造（R10）。

### 5.1 P0 文件清单（阶段 M0–M1）

| 文件 / 目录 | 职责 | 需求 | 阶段 | 验收 |
| --- | --- | --- | --- | --- |
| `.golangci.yml` | 静态检查：命名、注释、`os/exec` 禁用、复杂度与圈复杂度上限 | R10–R12、R18 | M0 | A2、A22、A25 |
| `cmd/waf/main.go` | 装配入口：版本信息 → 配置加载 → 注册插件 → 构建 pipeline → 启动 | R7 | M1 | A1 |
| `cmd/waf/cmd_run.go` | `run` 子命令：启动 forward-auth 服务、信号处理、优雅关停 | R1 | M1 | A9 |
| `cmd/waf/cmd_check_config.go` | `check-config`：校验配置并输出**生效值与来源摘要**，错误退出码 2 | R15、R16 | M1 | A7、A21 |
| `cmd/waf/cmd_version.go` | `version`：版本 / 提交号 / 构建时间（ldflags 注入） | R14 | M1 | A1 |
| `cmd/waf/cmd_healthz.go` | `healthz`：供容器 HEALTHCHECK 调用的进程内探测 | R14 | M1 | A20 |
| `cmd/waf/cmd_ban.go` | `ban list/add/remove`：读写共享存储的封禁名单 | R18、R19 | M1 | A29 |
| `cmd/waf/plugins.go` | 空白导入注册内置插件（编译期装配，无动态加载） | R7 | M1 | A7 |
| `internal/version/version.go` | 版本信息变量与格式化输出 | R14 | M1 | A1 |
| `internal/core/*.go` | `Verdict`/`Result`/`BodyMeta`/`RequestContext`/`Phase`/`Check`/`Registry`/`Deps` 与领域模型 | R7、R8 | M1 | A6 |
| `internal/config/*.go` | 三通道加载（env / 文件 / CLI）+ 优先级叠加 + 校验 + 来源摘要 | R13、R15、R16 | M1 | A7、A17、A19、A21 |
| `internal/pipeline/*.go` | 串联执行、决策合并、短路、`on_error`、**按需读体** | R5、R6、R8 | M1 | A3、A6、A14 |
| `internal/ingress/forwardauth/*.go` | Traefik / OpenResty 注入头还原；`trusted_proxies` 客户端 IP 推导 | R1、R3 | M1 | A8、A10 |
| `internal/ingress/body/*.go` | `BodySpool`：memory / disk / auto、限额、截断策略、chunked 读取 | R4、R13 | M1 | A13、A14、A15、A18 |
| `internal/sites/*.go` | 站点解析（默认单站点 + host glob，M1 仅骨架） | R6 | M1 | A19 |
| `internal/responder/*.go` | JSON 错误体渲染 + `GET /waf/deny` 幂等渲染端点 + 鉴权响应头回传 | R20、R22 | M1 | A26、A30 |
| `internal/server/*.go` | HTTP Handler：`/waf/auth`、`/waf/deny`、`/healthz`、`/readyz`、`/metrics` | R1、R22 | M1 | A9、A30 |
| `internal/store/store.go` | `Store` 接口 + 注册表 + 工厂 + `enabled`/`fallback` 语义 | R17、R23 | M1 | A23、A31 |
| `internal/store/memory/*.go` | 本地内存实现（分片 + 容量上限）；未启用 Redis 时的默认降级目标 | R13、R23 | M1 | A31 |
| `internal/store/file/*.go` | 单机持久化实现（明确不用于多实例共享） | R23 | M1 | A31 |
| `internal/store/redis/*.go` | Redis 共享实现：`Incr`（滑动窗口）+ `Ban`/`IsBanned`/`Unban` + 本地短 TTL 缓存 + `on_error` 策略 | R17、R18、R23 | M1 | A23、A24、A31 |
| `internal/check/passthrough/*.go` | 空实现（冒烟 / 基线对照，验证「零插件纯放行」） | R6 | M1 | A3 |
| `internal/check/ipaccess/*.go` | allowlist / blocklist CIDR 匹配（名单文件**流式**加载 + 限额） | R5、R13 | M1 | A4 |
| `internal/check/banlist/*.go` | 内部封禁名单校验（读共享存储），PhasePre | R18 | M1 | A24 |
| `internal/check/ratelimit/*.go` | 多维度限速（ip / ip+path / header），计数走共享存储 | R17 | M1 | A5、A23 |
| `internal/check/coraza/*.go` | Coraza 引擎封装（header + body 阶段、流式规则加载、体限额） | R4、R13 | M1 | A11、A12 |
| `internal/check/threshold/*.go` | 异常评分阈值聚合（PhasePost） | R8 | M1 | A6 |
| `internal/check/autoban/*.go` | 自动封禁（写共享存储，TTL 自动解封） | R18、R19 | M1 | A24、A28 |
| `internal/logging/*.go` | 系统日志 + 访问日志（`slog` JSON + 按日/按大小轮转 + 脱敏） | R21 | M1 | A27 |
| `internal/observe/*.go` | 指标接口 + Prometheus 实现 + noop 实现 | 可运维性 | M1 | A9 |
| `configs/waf.example.yaml` | 完整示例配置（含全部限额项、三通道说明、`stores` 启用示例） | R13、R15、R23 | M1 | A19、A21 |
| `deploy/forward-auth/traefik-forwardauth.yml` | Traefik `forwardAuth(+forwardBody)` + `errors` 中间件 + Router 示例 | R3、R4、R22 | M1 | A11、A26 |
| `deploy/forward-auth/nginx-openresty.conf` | OpenResty `access_by_lua_block` 子请求转发配置 | R3、R4 | M1 | A12 |
| `deploy/forward-auth/waf_auth.lua` | Lua 鉴权脚本：捕获子请求响应并**直接回写 JSON 错误体** | R22 | M1 | A12、A26 |
| `deploy/forward-auth/nginx-auth-only.conf` | 原生 Nginx 兜底：`auth_request` + `auth_request_set` + `error_page` 渲染 | R22 | M1 | A30 |
| `Dockerfile` | 多阶段构建 + `CGO_ENABLED=0` + distroless + 非 root + HEALTHCHECK | R14 | M1 | A20 |
| `docker-compose.yml` | `waf` + `redis` + 卷挂载（配置 / 日志） | R14、R23 | M1 | A20、A31 |
| `scripts/build.sh` | 构建脚本（版本注入 + 静态编译） | R14 | M1 | A1 |
| `scripts/build-offline.sh` | 离线打包（镜像 tar + 二进制 + 校验和） | R14 | M1 | A20 |
| `docs/configuration.md` | 字段级配置说明：单位、默认值、三通道优先级、与 honeypot 的差异、代理集成前置条件与限制 | R12、R15 | M1 | A21 |
| `docs/forward-auth-design.md` | 设计与第一步详案（已存在，随实现同步修订） | 全部 | M0/M1 | - |
| `.tmp/rr4/out/roadmap.md` | 本文件：优先级与交付基线 | 全部 | M0 | - |

**测试与 CI（P0）**

| 文件 | 职责 | 验收 |
| --- | --- | --- |
| `.github/workflows/ci.yml`（或内网 CI 等价文件） | `build` + `vet` + `lint` + `test` + 静态禁用 `os/exec` | A1、A2、A25 |
| `internal/**/*_test.go` | 单元测试：配置优先级、串联语义、体限额、存储、日志、请求还原 | A6、A13、A14、A17、A19 |
| `test/contract/*_test.go` | 契约测试：Traefik / OpenResty 两种流量 + JSON 送达 + 双实例共享 | A3–A5、A8、A10–A12、A23、A24、A26、A27、A30、A31 |
### 5.2 P1 文件清单（阶段 M2–M3）

| 文件 / 目录 | 职责 | 阶段 | 状态 |
| --- | --- | --- | --- |
| `internal/rules/bundle.go` | 规则包清单（`manifest.yaml`）：生成 / 校验（缺失·摘要不一致·多余三态）/ **原子替换安装** / 回滚 | M2 | **已完成**，`bundle_test.go` 覆盖 |
| `internal/rules/watch.go` | 规则目录指纹轮询（非 fsnotify）+ 去抖动 + 标记文件触发 | M2 | **已完成**，`watch_test.go` 覆盖 |
| `internal/rules/crs/**` | CRS 规则集随包分发（`go:embed` 23 文件 / 697963 字节）+ `crs-setup.conf` | M2 | **已完成**（M1.5 提前交付） |
| `internal/rules/exceptions/*.go` | 误报例外（rule id / tag / target / URL）编译为 SecLang 指令 + 审计三态 | M2 | **已完成**，`exceptions_test.go` + coraza 端到端用例覆盖 |
| `internal/check/upload/*.go`（本阶段不做） | 上传文件处理 | M2 | **偏差：不单独建包**。multipart 由 `engine.body.parse_multipart` 交给 Coraza 内置解析器处理（落盘/限额由引擎的 `SecRequestBodyLimit*` 保证），单独一层上传插件没有增量能力 |
| `internal/ingress/body/decompress.go` | 压缩体解压（gzip / deflate）、多重编码 fail-closed、解压后限额 | M2 | **已完成**（**偏差**：放在接入层而非 `pipeline`。解压结果是链中**所有** `phase: body` 单元的共同输入，放在接入层只需解压一次；`br` 因需第三方依赖不支持，配置写入会在校验阶段报错） |
| `cmd/waf/cmd_rules.go` | `rules list/verify/manifest/install/rollback/reload` 运维子命令 | M2 | **已完成** |
| `configs/ftw/*` + `test/ftw/*` | `go-ftw` 兼容用例集 + **离线执行器**（进程内驱动真实校验链） | M2 | **已完成**，10 个阶段全绿 |
| `internal/notify/*.go` | `Notifier` 多实现并联扇出 + 聚合抑制 | M3 | **已完成**，`manager_test.go` / `suppress_test.go` 覆盖 |
| `internal/notify/{webhook,wechat,syslog,smtp}/*.go` | 各告警通道实现（复用 honeypot notify 思路，**复制后改造**并补中文注释） | M3 | **已完成**；syslog 按平台拆文件（Windows/Plan9 明确报不支持） |
| `internal/observe/report/*.go` | 审计报表与导出（CSV / Excel） | M3 | **已完成**（**偏差**：Excel 不用 SpreadsheetML 2003，而是**手写最小 OOXML xlsx**——SpreadsheetML 在新版 Excel 会报「格式与扩展名不匹配」，无法满足「可被 Excel 直接打开」这条验收） |
| `cmd/waf/cmd_report.go` | `report` 子命令（Top 攻击源 / IP / 规则命中、时间范围过滤） | M3 | **已完成（提前）**，`cmd_report_test.go` 覆盖 |
| `scripts/bench/*` | 压测脚本与容量模型（wrk / hey / k6 离线） | M3 | **已完成**（`run-bench.sh` / `run-bench.ps1` / wrk lua / k6 js / 三个 payload / README） |
| `docs/operations.md` | 运维手册：告警接入、误报压降流程、封禁运维、容量规划 | M3 | **已完成**（8 节：上线前动作 / 告警接入 / 误报压降 / 封禁运维 / 容量规划 / 日常巡检 / 应急预案 / 文档关系） |

> 清单中划掉的条目是本阶段**明确不做**的项，偏差原因见上表右列的说明；所有偏差同样记录在 §10.9。

### 5.3 P2 文件清单（阶段 M4–M5，按需）

| 文件 / 目录 | 职责 | 阶段 |
| --- | --- | --- |
| `internal/sites/*.go`（增强） | 站点级策略：域名绑定规则集、黑白名单、参数覆盖（**已完成**） | M4 |
| `internal/pipeline/router.go` | 站点 → 具名校验链路由与站点 IP 名单（**已完成**） | M4 |
| `internal/geoip/*.go` + `internal/check/geoip/*.go` | 本地 MMDB 加载、国家/洲控制与原子热更新（**已完成**，未依赖 `coraza-geoip`） | M4 |
| `internal/intel/*.go` + `internal/check/threatintel/*.go` | 本地威胁情报（IP/CIDR/ASN/域名）与定时刷新（**已完成**） | M4 |
| `internal/vpatch/*.go` | 内置 CVE 模板与自定义 SecLang 补丁（**已完成**） | M4 |
| `internal/apisec/*.go` + `internal/check/apisec/*.go` | OpenAPI 3.x 请求侧契约校验（**已完成基础版**） | P2-6 |
| `internal/check/challenge/*.go` | Basic / HMAC Cookie 站点口令（**已完成基础版**，不含 CAPTCHA / JS 挑战） | P2-5 |
| `internal/check/session/*.go` | 会话安全（固定 / 劫持检测） | 按需 |
| `internal/mask/*.go` | 敏感数据脱敏（若未来引入响应侧通道） | 按需 |
| `deploy/forward-auth/apisix-*.yaml` | APISIX 等新入口适配（抽象接口已预留 `RequestExtractor`） | 按需 |

### 5.4 P3 文件清单（阶段 M5，可延后）

| 文件 / 目录 | 职责 | 阶段 |
| --- | --- | --- |
| `cmd/waf-admin/main.go` | 管理面独立进程入口（复用本项目抽象接口，经本地 API 读写） | M5 |
| `internal/admin/httpapi/*.go` | 管理面本地 HTTP API（规则 / 名单 / 状态 / 日志检索） | M5 |
| `internal/admin/webui/*` | 管理面前端静态资源（`go:embed` 内嵌，保持单二进制交付） | M5 |
| `internal/admin/auth/*.go` | 本地账号 + RBAC + 操作审计 | M5 |
| `internal/admin/forensics/*.go` | 原始请求取证包导出 | M5 |

---
## 6. WBS 与关键路径

### 6.1 T1–T20 优先级与依赖（对应设计文档 §9.7）

| 序 | 任务 | 优先级 | 依赖 | 归属流 |
| --- | --- | --- | --- | --- |
| T1 | 重构工程骨架：`cmd/waf` + `internal/*`，移除 GitHub Action 模板 | P0 | - | A 核心 |
| T2 | `internal/core`：契约包 + 单测 | P0 | T1 | A 核心 |
| T3 | `internal/config`：三通道 + 优先级 + 校验 + 来源摘要 | P0 | T1 | B 配置交付 |
| T4 | CLI 子命令 `run` / `check-config` / `version` / `healthz` / `ban` | P0 | T3 | B 配置交付 |
| T5 | `internal/ingress/forwardauth`：双代理还原 + 可信代理 | P0 | T2 | A 核心 |
| T6 | `internal/ingress/body`：`BodySpool` + 限额 / 截断 / 分块 | P0 | T2 | A 核心 |
| T7 | `internal/pipeline`：串联 + 合并 + `on_error` + 按需读体 | P0 | T2、T6 | A 核心 |
| T8 | `internal/responder`：JSON 错误体 + `/waf/deny` | P0 | T2 | A 核心 |
| T9 | `internal/server`：Handler / healthz / readyz / metrics / deny | P0 | T3、T5、T7、T8 | A 核心 |
| T10 | `internal/store`：接口 + redis / memory / file | P0 | T2 | C 状态 |
| T11 | 插件 `passthrough` / `ipaccess` / `banlist` | P0 | T2、T5、T10 | C 状态 |
| T12 | 插件 `ratelimit`（多维度 + 共享计数） | P0 | T2、T10 | C 状态 |
| T13 | 插件 `coraza`（header + body + 流式规则加载） | P0（骨架） | T2、T6 | E 引擎 |
| T14 | 插件 `threshold` + `autoban` | P0 | T2、T10 | C 状态 |
| T15 | `internal/logging`：系统日志 + 访问日志 | P0 | T2 | D 观测 |
| T16 | `internal/observe`：Prometheus 指标 | P0 | T2 | D 观测 |
| T17 | 示例配置 + 三份接入示例（Traefik / OpenResty / 原生） | P0 | T9、T11、T12、T13 | 收口 |
| T18 | Docker / 构建脚本 / 离线打包 | P0 | T4 | B 配置交付 |
| T19 | 契约与集成测试 | P0 | 全部 | 收口 |
| T20 | `docs/configuration.md` | P0 | 全部 | 收口 |

### 6.2 关键路径

```
T1 ──▶ T2 ──▶ T6 ──▶ T7 ──▶ T9 ──▶ T17 ──▶ T19
       │                      ▲
T1 ──▶ T3 ───────────────────┘
```

**说明**：`core` 契约（T2）冻结后其余任务可并行；`body`（T6）与 `pipeline`（T7）承载「体检测」这一核心差异能力，必须最早闭环；`server`（T9）是集成汇聚点，因此 T3（配置）也必须在此之前完成。旁支任务 T5 / T8 / T10 / T15 / T16 不阻塞关键路径，可与 T6 / T7 并行；T13 引擎骨架可与 T11 / T12 并行。

### 6.3 并行工作流（建议 2–3 人并行）

| 流 | 内容 | 负责人画像 |
| --- | --- | --- |
| **A 核心链路** | T1 → T2 → T5 / T6 → T7 → T8 → T9 | 主程（掌握整体架构与契约） |
| **B 配置与交付** | T3 → T4 → T18 | 擅长工程化 / 容器化 |
| **C 状态与插件** | T10 → T11 / T12 / T14 | 熟悉 Redis 与并发编程 |
| **D 观测与日志** | T15 → T16 | 熟悉 `slog` 与 Prometheus |
| **E 引擎** | T13（骨架）→ M2 生产化 | 熟悉 Coraza / CRS |

> 单人开发的串行顺序建议：T1 → T2 → T3 → T6 → T7 → T5 → T8 → T10 → T11 → T12 → T13 → T14 → T15 → T16 → T9 → T17 → T18 → T19 → T20。

---

## 7. 工作量粗估（供排期参考）

> 单位：人日，**粗估**，按「1 名熟悉 Go 与 WAF 的工程师」折算；请按团队规模与熟练度校准。

| 阶段 | 内容 | 粗估人日 | 主要变量 |
| --- | --- | --- | --- |
| M0 | 骨架 + 规范门禁 | 3–5 | 一次性投入，收益贯穿全程 |
| M1 | MVP 闭环（T1–T20） | 45–70 | 双代理适配与体检测是主要变量 |
| M2 | 引擎生产化 | 20–35 | 规则兼容性与误报治理耗时不可控 |
| M3 | 运营与告警 | 10–18 | 通道数量与报表复杂度 |
| M4 | 多站点与情报 | 12–20 | 依赖离线 GeoIP / 情报数据准备 |
| M5（P3） | 管理面 | 25–45 | **不阻塞前序阶段**，建议单独立项排期 |

**M1 折算参考**：单人约 9–14 周；2 人并行（A + B/C）约 5–7 周；3 人并行约 4–5 周。

---
## 8. 风险与待确认问题

### 8.1 主要风险

| 风险 | 影响 | 处置 |
| --- | --- | --- |
| Nginx 原生 `auth_request` 只能透传 401/403 | 429 / 503 被改写为 500，语义丢失 | 统一回 403，真实语义走 `X-WAF-Code`（R22，验收 A30） |
| 两种代理都丢弃鉴权响应体 | 无法直接送达 JSON 错误体 | 鉴权响应头 + 代理侧渲染；Traefik 走 `errors` + `/waf/deny`。（业界同款：oauth2-proxy 用模板渲染 HTML，Authelia 用门户页——本项目按 R20 只回 JSON） |
| Traefik `errors` 中间件与 `forwardAuth` 组合行为需实测 | 可能导致 JSON 错误体送不到客户端 | M1 内做真机验证；不支持则退化为 Traefik 默认错误响应（已备降级预案） |
| 请求体转发的带宽与内存开销 | 大文件上传拖慢链路 | 按路由按需开 `forwardBody` + `max_bytes` + `lazy` 读体 + 超限策略 |
| Redis 未启用 / 抖动 | 限速与封禁降级为单机 | `enabled` / `fallback` / `on_error` 三态；默认 `fallback_local` 并写 warn 系统日志 |
| CRS 全量规则引入误报 | 上线后被业务投诉 | M2 先 DetectionOnly 试运行 + 例外治理，通过 G2 才开 `SecRuleEngine On` |
| 规则 / 情报文件体积大 | 违反 R13 | 流式加载 + 单文件与总量上限 + 超限跳过并写 warn |
| `reference/` 代码过度耦合 | 违反 R10 / R11 / R12 | 复制后改名重构并补中文注释与单测；禁止 import / replace |
| 本地缓存导致封禁生效有 `local_cache_ttl`（默认 5s）延迟 | 极端场景下拦截不及时 | 需要强即时可将 `local_cache_ttl` 置 0（代价是每次请求多一次 Redis 往返） |
| 告警外送拖慢请求判定 | 接收端变慢会让 WAF 一起变慢，最坏情况被拖死 | 外送走**有界队列 + 异步 worker**，队满**丢弃并计数**（`waf_alert_total{result="dropped"}`），请求路径永不等待外送（见 §10.11） |
| 告警外送把敏感数据交给第三方 | 合规风险 | 告警载荷只带元数据（`request_id` / 站点 / 路径 / 客户端 IP / 规则），**不含** `body` / `headers` / `raw_request`；契约测试对此有专门断言 |
| 抑制表不跨实例共享 | 多副本部署下同类告警可能各发一次 | 抑制定位是「压降」而非「精确去重」，最坏情况重复 1 次；如需精确一次，后续可把抑制表接入 `Store` 抽象 |
| 运维以为「告警配好了」实际没生效 | 静默失败会让故障发现时间被拉到最长 | ① 总开关打开但**声明了通道却一个都没启用** → 校验期直接报错；`notifiers` 本身为空则视为「未接通道」的合法状态，由启动日志的 `channels` 字段暴露；② `check-config` 输出已注册通道类型；③ 外送结果全部计入 `waf_alert_total{notifier,result}`；④ `docs/operations.md` §2「三步验证」给出手工验证步骤 |

### 8.2 需用户确认的开放问题

| # | 问题 | 备选项 | 建议 |
| --- | --- | --- | --- |
| ~~Q1~~ | ~~Nginx 侧是否强制使用 OpenResty？~~ | ✅ **已确认：强制 OpenResty**（R24）。原生 Nginx 仅作降级兜底，必须在文档标注「无体检测 / 无 JSON 响应体」 | **已关闭** |
| **Q2** | Traefik 目标版本 | ① v2.11 系列 ② v3.x | 建议同时验证 v2.11 与 v3 最新稳定版 |
| **Q3** | 默认封禁 30m 是否接受 | ① 30m ② 10m ③ 2h | 建议 30m，并保留累进封禁开关 |
| **Q4** | 是否启用累进封禁 | ① 关闭（默认）② 开启 `[30m, 2h, 24h]` | 建议 M1 关闭，M2 视误报与攻击态势再开 |
| ~~Q5~~ | ~~共享存储形态~~ | ✅ **已确认：Docker / 直接部署均可，单机 / 哨兵 / 集群全部支持**（R25）。由 `settings.topology` 驱动，地址、认证、TLS、连接池全部配置化 | **已关闭** |
| ~~Q6~~ | ~~管理面优先级~~ | ✅ **已确认：新增 P3 级别，管理面下调 P3**（R26）。P3-1 ~ P3-5 放 M5，不阻塞 M1–M4 | **已关闭** |
| **Q7** | 部署规模（实例数、目标 QPS、并发） | - | 用于校准限速窗口、连接池、缓存大小等默认值 |
| ~~Q8~~ | ~~告警通道清单~~ | ✅ **已实现并全部可配置**（M3）：企业微信 / 通用 webhook / Syslog / SMTP 四种 `type` 均已落地，`notifiers[]` 可配任意多个并联扇出，默认全部 `enabled: false` | **已关闭**（见 §10.11） |
| **Q9** | CI 平台 | GitHub Actions / 内网 GitLab CI / Jenkins | 影响 `.github/workflows` 与构建脚本形态 |
| **Q10** | `reference/` 目录最终归属 | ① 保留在仓库（只读）② 移出交付物 ③ 删除 | 建议保留但排除在构建与交付物之外 |
| **Q11** | `/metrics` 是否需要鉴权 | ① 仅内网监听 ② Basic Auth ③ Bearer Token | 建议 ② 或仅内网暴露 |
| **Q12** | 是否需要 `waf ban` 之外的管理 API | ① 仅 CLI（M1）② 额外提供本地 HTTP API | 建议 M1 仅 CLI，M5 引入 UI 时再补 API |

### 8.3 优先级相对《功能列表》的调整说明

| 项 | 原分级 | 本路线图 | 理由 |
| --- | --- | --- | --- |
| 管理面 / RBAC / 攻击可视面（功能列表 §4 第 23/24 项） | P1 | **P3** | 不改变拦截能力、成本高，CLI 已可替代运维入口；已确认（R26 / Q6） |
| 响应侧防护（功能列表 §4 第 19 项） | P1 | **Non-Goal** | forward-auth 形态下代理丢弃鉴权响应体，技术上不可达 |
| 自动封禁中的防火墙下发（功能列表 §4 第 7 项） | P0（原表述含「可选下发 iptables/firewalld/ufw」） | **Non-Goal** | 与 R18 冲突，明确排除 |
| 限速 / 封禁参考实现（功能列表 §5.2「复用 honeypot ratelimit + firewall」） | 复用 | **复制后自研**：「限速思路」可复用，「firewall 整块弃用」 | R10（复用需复制一份）+ R18（不操作防火墙） |
| 反向代理接入层（功能列表 §5.2「自研接入层 `httputil.ReverseProxy`」） | 自研 | **Non-Goal** | 与 R1 / R2 冲突（本方案为 forward-auth） |

---

## 9. 下一步动作

1. ~~确认 P0 / P1 / P2 分级与 §8.2 开放问题~~ → **Q1 / Q5 / Q6 已确认并关闭**（R24 / R25 / R26），P3 级别已建立。
2. ~~M0（T1 骨架重构，替换 GitHub Action 模板）→ M1.1~~ → **已完成**，见 §10.1。
3. **阶段进度**：**M0 / M1（含 M1.1–M1.6）/ M2 / M3 全部已完成**，对应门禁
   **G0 / G1 / G2 / G3 全部通过**（见 §10.1、§10.8、§10.9、§10.11）。**M4 的能力实现已完成**
   （P2-1 ~ P2-6 主体，见 §10.18），G4 的真实 MMDB / 外部情报数据验收待部署环境补跑。
   **P0 与 P1 级需求已全部闭环**，具备生产上线条件。
4. **下一步（按需推进，均不阻塞已交付能力）**：
   - **M4 验收收口**：使用真实 GeoLite2 Country / ASN MMDB 与生产情报样本补跑 G4；
   - **按需增强**：CAPTCHA / JS 无感挑战、API 资产发现与响应侧契约校验；
   - **M5**（P3）：管理面 Web UI + RBAC + 取证包导出（已明确下调，不阻塞 M4）；
   - **上线动作**：按 `docs/operations.md` §1「上线前动作」逐项确认；用 `scripts/bench/*` 在目标机型实测一次以校准容量档位。
5. 仍待答复且**不阻塞**的问题：Q2、Q3、Q4、Q7、Q8、Q9、Q10、Q11、Q12（见 §8.2）。
6. 后续任何阶段本文件与 `docs/forward-auth-design.md` 同步维护：优先级变更、验收项增加，全部回写本文件 §3 与 §4.2，并在 §8.3 记录调整理由。

---

> 本文件为**优先级基线 v0.10**。任何优先级调整必须在本文件 §8.3 记录并注明理由，保证「需求 → 优先级 → 文件 → 验收」四者可追溯。

---

## 10. 实施记录

### 10.1 已完成：M0 + M1.1

| 里程碑 | 状态 | 交付与验证 |
| --- | --- | --- |
| M0 工程准备 | 已完成 | 移除 GitHub Action 模板（`main.go` / `main_test.go` / `action.yml`）；落地 `.golangci.yml`（含 `os/exec` 禁用规则）与 `.github/workflows/ci.yml`（含 `os/exec` 文本级兜底检查） |
| M1.1 骨架 + 契约 + 配置 | 已完成 | `cmd/waf`（`run` / `check-config` / `version` / `healthz` / `ban`）、`internal/core`、`internal/config`、`internal/version` |
| 提前交付（原 M1.5 内容） | 已完成 | `internal/logging`（系统/访问双类 JSON 日志 + 按天/按大小轮转 + 保留清理）、`internal/responder`（JSON 错误体 + `/waf/deny`）、`internal/server`（鉴权端点 / 渲染端点 / 探针 / 指标路由） |
| 交付物 | 已完成 | `configs/waf.example.yaml`、`deploy/forward-auth/`（Traefik / OpenResty+Lua / 原生兜底）、`Dockerfile`、`docker-compose.yml`、`scripts/build.sh`、`scripts/build-offline.sh` |

**已通过的门禁判据**：A1（`CGO_ENABLED=0 go build ./...`）、A2（`go vet` + `go test`）、A3（空校验链返回 200）、A7（未知配置项报错含路径）、A9（探针与优雅关停）、A17（三通道优先级）、A19（限额可配置）、A21（`check-config` 输出来源摘要，退出码 2）、A22（`gofmt` 干净）、A25（无 `os/exec`）、A26/A30（JSON 错误体与响应头方案可用）。

真机验证（Windows 本地）：`version` / `check-config`（三通道优先级三组对照）/ `run` + `/healthz` / `/readyz` / `/waf/auth` 放行 200 / `/waf/deny?code=WAF_RATE_LIMITED` 返回 429 + `X-WAF-Code` + 规范 JSON。

### 10.2 已完成：M1.2（接入还原 / 请求体缓冲 / 串联执行器）

| 子里程碑 | 状态 | 交付与验证 |
| --- | --- | --- |
| T5 接入还原 | 已完成 | `internal/ingress/forwardauth`：`Extractor`（auto / 显式类型判定、URI / Method / Host / Proto 还原、注入头剔除、URI 与控制字符校验）+ `ClientIPResolver`（可信代理校验、XFF 从右往左取首个非可信地址、支持单 IP 与 CIDR） |
| T6 请求体缓冲 | 已完成 | `internal/ingress/body`：`Spool` 实现 `core.BodyStream`；`memory` / `disk` / `auto` 三种缓冲位置，`truncate` / `reject` / `skip` 三种超限策略，`Rewind` 零拷贝复位，落盘临时文件在 `Close` 时清理 |
| T7 串联执行器 | 已完成 | `internal/pipeline`：`Pipeline` 实现 `core.Decider`；按 `Phase` + `Order` 稳定排序串联、终态短路、`on_error` 三级解析（实例配置 → 实现自报 → `pass`）、按需读体（无启用 `PhaseBody` 单元时不读体） |
| 插件与装配 | 已完成 | `internal/check/passthrough`（空实现，用于装配冒烟与压测基线对照）并接入 `cmd/waf/plugins.go`；`cmd/waf/cmd_run.go` 装配接入适配器、依赖集合、校验链与 HTTP 服务 |

**已通过的门禁判据**：A3（零插件放行 200）、A6（串联 + 短路 + `on_error` 两种策略）、A8（双代理还原 URI / Method / ClientIP）、A10（伪造 XFF 不被采纳）、A13（超限三种策略）、A14（无 `PhaseBody` 不读体）、A15（chunked 体 / 长度未知）、A16（`required` 但未收到体）、A18（分块读取，不整体读入）。

**新增单元测试**：`internal/ingress/forwardauth/extractor_test.go`、`internal/ingress/body/spool_test.go`、`internal/pipeline/pipeline_test.go`；`go test ./... -count=1` 全绿，`go vet ./...` 与 `gofmt -l ./cmd ./internal` 干净。

**真机验证（Windows 本地）**：以 `ingress.type: traefik-forwardauth` + 三个 `passthrough` 实例（其中一个 `phase: body`、一个 `enabled: false`）启动；`POST /waf/auth` 携带 Traefik 注入头与 JSON 体返回 `200` + `X-WAF-Verdict: allow`；访问日志记录的是**还原后**的方法 / 路径 / Host / 客户端 IP（`POST` / `/api/user` / `example.com` / `203.0.113.9`），且 `X-Forwarded-For: 203.0.113.9, 10.1.2.3` 中位于可信网段的一跳被正确跳过；`enabled: false` 的实例未出现在启动日志的 `pipeline_entries` 中；请求体越过 `memory_threshold` 后按 `spool: auto` 落盘；`/waf/deny?code=WAF_RATE_LIMITED` 返回 `429` + 规范 JSON。

### 10.3 已完成：M1.3（共享存储 / 内部封禁 / 前置校验插件）

| 子里里程碑 | 状态 | 交付与验证 |
| --- | --- | --- |
| T10 共享存储 | 已完成 | `internal/store`：`core.StoreResolver` 实现 + 三种后端（`memory` 分片内存、`file` 追加日志 + 回放 + 压缩重写、`redis` standalone / sentinel / cluster + Lua 原子 INCR+PTTL）+ 三种故障策略（`fallback_local` / `fail_open` / `fail_closed`）+ 本地「已封禁」短 TTL 缓存；`stores[].enabled=false` 时直接使用本地实现并写 warn 日志 |
| T11 内部封禁 | 已完成 | `internal/ban.Manager`（实现 `core.BanController`）：封禁键统一构造（`client_ip` / `client_ip+site`）、TTL 裁剪（`default_ttl` / `max_ttl`）、累进封禁（`escalate` + `escalate_steps` + `escalate_window`，计数走共享存储）、单条失败不影响其余动作 |
| T12 前置校验插件 | 已完成 | `internal/check/banlist`（名单查询，PhasePre）、`internal/check/ipaccess`（IP 黑白名单，白名单命中即短路放行）、`internal/check/ratelimit`（多维限速：`ip` / `path` / `host` / `site` / `ua` + `path_match` 正则 + `limit`/`burst`，计数键 `rl:<维度>=<值>:<窗口>`，UA 维度先按 `limits.max_scan_token_bytes` 截断再做 FNV 哈希入键） |
| T12b 收尾插件 | 已完成 | `internal/check/threshold`（异常评分阈值 + `min_severity` 门槛，PhasePost）、`internal/check/autoban`（窗口内命中次数达阈值后产出 `core.BanRequest`，计数走共享存储，PhasePost） |
| 基础工具 | 已完成 | `internal/fsx`（受限额的逐行扫描 / 整体读取）、`internal/netx`（IP / CIDR 匹配集合） |
| 装配与运维 | 已完成 | `cmd/waf/stores.go`（共享存储 + 封禁装配的唯一入口，`run` 与 `ban` 共用同一套实例与键构造规则）、`cmd/waf/plugins.go` 追加 5 个插件空白导入、`cmd/waf/cmd_ban.go` 接入真实实现（`list` / `add` / `remove` + `--ip` / `--ttl` / `--reason` / `--site` / `--store`）、启动日志新增 `stores` / `ban_key` / `ban_default_ttl` / `ban_max_ttl` |

**执行器语义补充（M1.2 → M1.3 的必要扩展）**：

- **PhasePost 收尾语义**：链一旦短路，中间阶段单元全部跳过，但 PhasePost 单元仍然执行。否则「命中即拦截」的规则永远不会触发自动封禁与告警。
- **评分汇总**：执行器在合并每个单元的 `Result.Score` 时同步调用 `RequestContext.AddScore`，使 PhasePost 的阈值单元能读到整条链的评分总量。约定：**插件只填写 `Result.Score`，不得自行调用 `AddScore`**（否则同一次命中会被计入两次）。

**已通过的门禁判据**：A4（`ipaccess` 黑名单命中 → 403 + JSON 错误体）、A5（`ratelimit` 超阈 → 429 + `Retry-After` + JSON 错误体，窗口边界由可伪造时钟的单测覆盖）、A23（限速计数一律走 `core.Store`，双实例共享的集成用例留待 M1.6）、A24（封禁经共享存储落地，`local_cache_ttl` 与 TTL 到期自动解封已单测，双实例用例留待 M1.6）、A25（全程不执行系统命令：`.golangci.yml` 与 CI 双重禁止 `os/exec`，封禁只写内部名单）、A27（双类 JSON 日志：`info` 不记录放行、`debug` 记录放行）、A28（`ban.default_ttl` 默认 30m 且可配置，生效值出现在启动日志与命令输出）、A29（`waf ban add/list/remove` 可用，跨实例即时生效随 M1.6 集成用例收口）、A31（`stores[].enabled=false` 时不连 Redis、降级本地实现并写 warn 级系统日志）。

**新增单元测试**：`internal/store/store_test.go`（窗口累加与过期、封禁生命周期、容量保护、优雅关闭、文件回放与解封持久化、`enabled=false` 降级、非法拓扑、`fallback_local` 降级）、`internal/ban/manager_test.go`（键构造、TTL 裁剪、累进阶梯、部分失败隔离、写入键与查询键一致）、`internal/netx/cidr_test.go`、`internal/fsx/scan_test.go`、`internal/check/{banlist,ipaccess,ratelimit,threshold,autoban}/*_test.go`、`cmd/waf/cmd_ban_test.go`（业务参数与配置参数拆分）、`internal/pipeline/pipeline_test.go`（收尾语义 + 评分汇总）。`go test ./... -count=1` 全绿，`go vet ./...` 与 `gofmt -l ./cmd ./internal` 干净。

**真机验证（Windows 本地）**：

1. 串联链路：以 `banlist` + `ratelimit(limit=2, burst=0)` + `autoban(trigger_on=[ratelimit], threshold=2, ttl=1m)` 启动，5 次请求依次得到 `200 / 200 / 429 / 429 / 403`——第 3、4 次触发限速，第 4 次同时达到自动封禁阈值并写入内部名单，第 5 次由 `banlist` 拦截；第 5 次响应体为规范 JSON（`code: WAF_BLOCKED`，`details.rule_id: internal_banlist`）。
2. 日志：系统日志含启动摘要（`stores` / `ban_key` / `ban_default_ttl` / `ban_max_ttl` / `pipeline_entries`）与 `触发限速` / `自动封禁计数未达阈值` / `触发自动封禁` / `已写入内部封禁名单` 等结构化记录；访问日志按等级区分放行（debug）与拦截（info），并记录**还原后**的方法 / 路径 / Host / 客户端 IP。
3. 共享存储降级：以示例配置（Redis 未部署）启动，启动探活失败写 WARN 并继续服务，运行期查询失败写 ERROR，请求仍按 `fallback_local` 正常处理并返回 `200`。
4. 运维命令：`ban add / list / remove` 在**独立进程**之间经 `file` 后端共享状态；`--ttl 48h` 被裁剪到 `ban.max_ttl`（24h）；`--set ban.default_ttl=45m` 生效；非法 `--ttl` 与缺失 `--ip` 分别给出明确报错与退出码 2。
5. fail fast：把示例配置中的 `coraza` 实例改为 `enabled: true` 后启动，进程在装配阶段直接失败并提示「校验单元类型 "coraza" 未注册（可用类型：[autoban banlist ipaccess passthrough ratelimit threshold]）」，退出码 2。

### 10.4 已完成：M1.4（站点解析 / 站点级策略覆盖）

| 子里里程碑 | 状态 | 交付与验证 |
| --- | --- | --- |
| T13 站点解析 | 已完成 | `internal/sites`：`Resolver` 实现 `core.SiteResolver`，`New` 完成 fail fast 校验与索引构建，`Resolve(host)` 做域名匹配 |
| 站点级策略覆盖 | 已完成 | `core.Site` 新增 `Param(key)` 统一取值入口；`internal/check/ratelimit` 支持站点级覆盖 `ratelimit.limit` / `ratelimit.burst` / `ratelimit.window`；计数键与命中明细 `Data` 加入 `site` 维度 |
| 装配与配置 | 已完成 | `internal/server` 新增 `Options.Sites` + `resolveSite(host)`，`handleAuth` 在还原 `raw` 后填充 `rctx.Site`；`cmd/waf/cmd_run.go` 改用 `sites.New`（删除临时 `buildSites`），启动日志站点名由 `Resolver.Names()` 输出；`configs/waf.example.yaml` 站点段补注释并新增 `shop` 覆盖示例 |

**站点匹配语义（唯一定义，务必以此为准）**：

1. **匹配优先级**：精确 `host` > 最长通配后缀（`*.example.com`，取后缀最长者）> 声明为 `hosts: ["*"]` 的站点 > 内置默认站点（`core.DefaultSiteName`）。未命中任何声明站点时回落到内置默认站点，保证请求永远不会「无站点可依」。
2. **Host 规范化**：先去掉 `:port`、统一小写、去掉结尾 `.`、去掉 IPv6 的 `[]`（覆盖 `X-Forwarded-Host` / `Host` 的各种书写差异）。
3. **fail fast 校验清单**：站点名为空或重复、站点没有任何 `hosts`、出现多个 `"*"` 站点、`"*"` 与其它模式混用、通配形态非法（`*` 不在最左标签或出现多个 `*`）、域名标签非法、同一 Host 被多个站点声明——以上任一情况均在启动装配阶段直接失败，避免「配置写了却不生效」。

**已通过的门禁判据**：A30（`X-Forwarded-Host` / `Host` 正确映射到站点）、站点级**参数覆盖**用例（同一 IP 在收紧站点第 2 次即 `429`、在默认站点第 6 次才 `429`）、封禁键含站点维度（`ip:<IP>|site:shop`）。

> ⚠️ **勘误（M3 复测发现）**：本站子里程碑当时把「站点级 `engine_mode` 覆盖」也写成了已生效，这是不准确的。
> `sites[].engine_mode`（`core.Site.EngineMode`）目前只在配置层被解析、校验与解析到站点对象上，
> **运行期没有任何消费方**（`coraza` 与 `threshold` 都只读全局 `engine.mode`）。
> 实测：全局 `engine.mode: on` + 站点 `engine_mode: detection_only` 时，SQLi 仍返回 `403 / WAF_BLOCKED`。
> 该行为属于「配了但不生效」的静默失效类问题，已登记为待修项（见 §10.11 已知边界）；
> 在修复前请勿依赖站点级引擎模式，按站点灰度请「单独起实例 + 代理侧按 Host 分流」。

**新增单元测试**：`internal/sites/sites_test.go`（精确命中、最长通配前缀、`"*"` 回落、默认站点回落、Host 规范化、重复 Host / 无 hosts / 多 `"*"` / 非法标签等 fail fast 分支共 8 例）、`internal/check/ratelimit/ratelimit_test.go` 新增 `TestEvaluateSiteParamOverride` 与 `TestEvaluateInvalidSiteParamFallsBack`。`go test ./... -count=1` 全绿。

**真机验证（Windows 本地，端口 19084）**：

1. 站点解析：启动日志 `sites` 字段输出 `["default","shop"]`。
2. 站点级限速覆盖：`shop` 站点经 `params` 把窗口内上限从 `5` 收紧到 `1`，`X-Forwarded-Host: shop.example.com` 第 2 次请求即 `429`（日志 `key: rl:ip=203.0.113.99|site=shop:60, allowed: 1`）；同一 IP 改带 `X-Forwarded-Host: other.example.com`（落到默认站点，上限 `5`）到第 6 次才 `429`。
3. 封禁键站点隔离：`autoban` 以 `ban_key: client_ip+site` 写入 `ip:203.0.113.99|site:shop`，随后 `banlist` 对 `site=shop` 短路返回 `403`（`code: WAF_BLOCKED`），而 `site=default` 请求不受该封禁影响。

### 10.5 相对设计文档的落地偏差（已确认可接受）

| 项 | 设计文档 | 实际落地 | 原因 |
| --- | --- | --- | --- |
| `Store` 接口位置 | `internal/store/store.go` | `internal/core/store.go` | 校验单元与存储实现都需要引用该接口，放在 `core` 可避免 `store` ↔ `check` 之间的循环依赖；`internal/store` 只承载实现与注册表 |
| Dockerfile 版本注入路径 | `main.version` | `internal/version.Version` | 版本变量统一收敛在 `internal/version`，便于 `healthz` / 指标 / 响应头复用 |
| 插件配置片段解码 | 未明确 | `core.DecodeSettings`（yaml 严格模式） | 严格模式可让 settings 中的字段拼写错误在启动阶段报错，避免「以为开了防护其实没开」 |
| 环境变量命名 | `WAF_BAN_DEFAULT_TTL` | 一致 | 由配置路径机械推导；`responder.messages` 这类用户自定义键不参与推导，只能写配置文件 |
| Traefik 错误码传递 | 未明确 | `/waf/deny` 支持「数字状态码 → 错误码」反推 | Traefik `errors` 中间件的 query 模板无法读鉴权响应头，只能传 `{status}` |
| 请求体读取游标复位 | 未明确 | 由 pipeline 在**每个体阶段单元执行前**统一调用 `Stream.Rewind()` | 插件无需关心「自己是第几个体检测单元」，多体检测单元的完整性由执行器统一保证，插件只负责读 |
| `RequestContext` 请求上下文 | 未明确 | 新增 `Context context.Context` 字段（`NewRequestContext` 兜底 `context.Background()`，`Pipeline.Decide` 绑定真实 ctx） | `Check.Evaluate` 只接收 `RequestContext`，后续依赖共享存储 / 外部服务的校验单元必须能感知取消与超时 |
| 请求体读取粒度 | 未明确 | 新增配置项 `ingress.body.chunk_bytes`（默认 `32768`） | 落实 R13：「不做大体积读取」不仅是总量约束，读取粒度同样需要可配置、不允许硬编码 |
| 指标接口 | 未明确 | `core.MetricsRecorder` 新增 `IncBodySkipped()` | `on_exceed: skip`（完全不参与检测）与 `truncate`（部分内容参与检测）的安全含义不同，合并计数会掩盖「体检测整体失效」 |
| 访问日志等级判定顺序 | 「按判定结论分级」 | 「校验单元异常」优先于「放行」判定 | 失败开放虽然放过了请求，但必须以 `warn` 级留痕，否则错误会被 debug 级的放行日志淹没 |
| `PhasePost` 的收尾语义 | 「遇终态立即短路」 | 短路后仍执行全部 `PhasePost` 单元 | 评分聚合、封禁落地、告警外送都必须在拦截之后依然发生，否则「命中即拦截」的规则无法触发自动封禁与告警 |
| 异常评分的唯一权威来源 | 未明确 | 执行器合并 `Result.Score` 时同步 `RequestContext.AddScore`；插件不得自行调用 `AddScore` | 避免各插件分别记账导致同一次命中被计入两次而提前触发阈值（误伤） |
| 运维子命令的参数解析 | 未明确 | 新增 `config.FlagSet.IsConfigFlag`，并在 `cmd/waf` 侧做「业务参数 / 配置体系参数」两段式拆分 | 标准库 `flag` 遇到未定义的参数会直接报错，否则 `waf ban list -c x.yaml` 不可用 |
| 封禁键的唯一构造入口 | 未明确 | `ban.Manager.KeyForClientIP` / `KeyFor`，`banlist` 查询、`autoban` 写入与 CLI 增删全部复用 | 「写进去却查不到」是多实例封禁最难排查的问题，键的构造必须只有一处实现 |
| 单行长度限额的真实生效 | 未明确 | `fsx.ScanLines` 的初始缓冲取 `min(4096, maxLineBytes)` | `bufio.Scanner` 仅在缓冲区写满时才判定超长；初始缓冲大于上限会让单行限额形同虚设（R13 要求限额真实生效，不能只是声明） |
| `autoban` 的命中计数 | 未明确 | 计数键 `ab:<封禁键>:<窗口>`，与封禁键同源，走共享存储 | 多实例部署下阈值必须全局累计，否则「3 次才封禁」会被放大成「每实例 3 次」 |

### 10.6 下一步（M1.6 → M2 → M3）

> M1.6、M2、M3 均已完成，详见 §10.8、§10.9、§10.11。本小节保留为阶段衔接的历史记录。

1. **M1.6**：契约测试（双代理 + 体检测 + 双实例共享）与 `deploy/forward-auth/` 三份示例的真机实测；示例需按 M1.3–M1.5 的实际端点行为复测。 —— **已完成（§10.8）**
2. **M2**：规则包（热加载 + Paranoia Level 闭环 + 误报例外 + 压缩体 + DetectionOnly 闭环）、`cmd/waf rules` 子命令、`configs/ftw/*`。 —— **已完成（§10.9）**；其中 multipart 走引擎内置解析器、`br` 明确不支持，两项偏差及理由见该节。
3. **M3**：通知与报表（`internal/notify/*` 并联扇出、`cmd/waf report`、`docs/operations.md`、`scripts/bench/*`）。 —— **已完成（§10.11）**；其中 `cmd/waf report` 于 M2 提前交付，Excel 导出由计划中的 SpreadsheetML 改为手写最小 OOXML xlsx（理由见 §10.11）。

---

### 10.7 已完成：M1.5（Prometheus 指标 / Coraza 检测引擎 / 配置手册）

| 子里里程碑 | 状态 | 交付与验证 |
| --- | --- | --- |
| 指标（`internal/observe`） | 已完成 | `Options{Enabled,Namespace,Path,Version,Commit,Logger}` + 自建 `Registry`（不用全局注册表，避免与宿主进程冲突）；`Recorder()` 返回 `core.MetricsRecorder`；`Handler()` 在 `enabled=false` 时返回 404 + `WAF_METRICS_DISABLED`。指标见 `docs/configuration.md` §2.11 |
| 指标配置与校验 | 已完成 | `metrics.namespace` / `metrics.path` 新增；校验规则：路径非空、以 `/` 开头、不与 `ingress.path` / `ingress.deny_path` / `/healthz` / `/readyz` / `/version` 冲突，命名空间匹配 `^[a-zA-Z_][a-zA-Z0-9_]*$` |
| 服务端点装配 | 已完成 | `server.Options` 新增 `MetricsHandler` / `MetricsPath`；`cmd/waf/cmd_run.go` 装配 `observe.New` 并把 `Recorder()` 注入 `core.Deps.Metrics`（替换此前的 `core.NoopMetrics{}`） |
| 规则加载（`internal/rules`） | 已完成 | `Source{Dirs,CustomDirs,Include,DataInclude,CRSSetup}` + `Set{FS,Setup,Files,Rules,FileCount,TotalBytes,Source}`；`Dirs` 为空时使用编译期嵌入的 CRS；`readLimited` 按「读 limit+1 字节」判断超限（限额真实生效）；重名规则文件冲突检测；**23 个文件 / 697963 字节**（13 个 `.conf` + 10 个 `.data`） |
| CRS 离线打包 | 已完成 | 按 R10 从 `reference/coraza-traefik-WAF/rules/` **复制一份**到 `internal/rules/crs/`（`go:embed` 编入二进制），附 `README.md` 说明来源、许可与升级方式；本包不 import / replace 参考工程 |
| 检测引擎（`internal/check/coraza`） | 已完成 | `New` 完成 fail fast 装配（`process_body` 与阶段强一致、`engine.enabled=false` 冲突、`process_body=true` 与 `body_access=false` 冲突）；`Settings` 支持实例级覆盖模式 / 偏执等级 / 规则目录 / 内联指令 / 请求体开关 / 处理器路由 |
| 指令生成顺序 | 已完成 | `buildDirectives` 五段顺序：`crs-setup` → 引擎基础设置 → 运维自定义指令 → 偏执等级覆盖（`SecAction id:900100`）→ **请求体处理器路由** → 规则文件。顺序由单测 `TestBuildDirectives` / `TestBodyProcessorsRouting` 锁定 |
| 请求体检测（需求 R4） | 已完成 | 无条件执行 Coraza phase 2 求值（`evaluateBody`），并新增**请求体处理器路由**：`Content-Type` 命中 JSON / XML 正则时生成 `ctl:requestBodyProcessor=<NAME>` 规则（ID 从 `900200` 起）。**这是请求体检测能否生效的关键**——Coraza 只自动识别 URLENCODED / MULTIPART，JSON / XML 必须显式指定 |
| JSON 深度守卫 | 已完成 | `maxJSONDepth` 单遍扫描（正确跳过字符串与转义），`engine.body.json_depth_limit` 可配；命中直接返回 400 并写入命中明细 `json_depth_exceeded` |
| multipart 开关落地 | 已完成 | `engine.body.parse_multipart=false` 时本实例不把 multipart 请求体交给引擎（消除此前的「死配置」）；实例级同样可覆盖 |
| 命中明细降噪 | 已完成 | `reportableRule` 过滤掉 CRS 初始化区间 `[900000, 901999]` 的规则与无 `msg` 规则；`passedResult` 不再凭空造出「无规则明细」的命中。修复前每次拦截会附带 16 条初始化规则命中（日志放大） |
| HTTP 版本规范化 | 已完成 | 新增 `httpVersionOf`：forward-auth 通道下 `X-Forwarded-Proto` 传的是**协议方案**（http/https），而引擎 `ProcessURI` 期望 HTTP 版本号。不规范化会让 CRS 的 `920430`（协议白名单）拦掉**所有**请求 |
| 配置手册 | 已完成 | 新增 `docs/configuration.md`：三通道与优先级、全量配置项、插件 `settings` 参考、常见组合、排错速查 |
| 示例配置 | 已完成 | `configs/waf.example.yaml` 补齐 `engine.rules.data_include`、`engine.body.processors`（带中文注释），两个 `coraza` 实例保持 `enabled: true` |

**真机冒烟结论（端口 19185，`ingress.type: auto` 判定为 `nginx-openresty`）**：

| 用例 | 结果 |
| --- | --- |
| `GET /api/user?id=1%27%20OR%20%271%27%3D%271`（**仅头实例**） | `403`，命中 `942100`（SQL 注入）——证明「头实例也能拦查询串注入」的修复生效 |
| 良性 JSON 请求体 | `200` |
| JSON 请求体中的 SQL 注入 | `403`，命中 `942100`（`check: crs-body`） |
| 表单请求体中的 XSS | `403`，命中 `941100` |
| JSON 嵌套深度 4（上限 3） | `400`，`rule_id: json_depth_exceeded` |
| JSON 嵌套深度 2 | `200` |
| `multipart/form-data`（`parse_multipart: false`） | `200`（请求体不进入引擎） |

**新增单元测试**：`internal/observe/observe_test.go`（4 例）、`internal/check/coraza/coraza_test.go` 扩展至 17 例（新增 `TestHTTPVersionOf`、`TestPassedResultHasNoInitFindings`、`TestBodyProcessorsRouting`、`TestMultipartSkippedWhenDisabled`，并把评分断言从 `rctx.Score()` 改为 `result.Score`——评分由执行器统一汇总，插件不得自行 `AddScore`）。

---

### 10.8 已完成：M1.6（接入契约测试 + 双代理示例收口）

**目标**：把「代理侧只看得到状态码、看不到鉴权响应体」这类**只有接入还原 + 校验链 + 响应渲染 + 状态码策略全部串起来才会暴露**的问题固化成可回归的契约。

| 子里里程碑 | 状态 | 交付与验证 |
| --- | --- | --- |
| 契约测试骨架 | 已完成 | 新增 `test/contract/harness_test.go`：按**真实装配路径**构建服务（`config.Load` → `logging.Build` → `observe.New` → `forwardauth.New` → `store.Build` → `ban.New` → `sites.New` → `pipeline.New` → `server.New` → `httptest.NewServer`），并提供 `harness.flushLogs()` / `readAccessLog()` 等断言辅助 |
| 插件装配点 | 已完成 | 新增 `test/contract/plugins_test.go`：与 `cmd/waf/plugins.go` 一致的空白导入清单，保证契约测试的插件注册与生产完全同源（否则会出现「测试通过、线上类型未注册」的假象） |
| 案例集（13 个用例 + 4 个子用例） | 已完成 | `test/contract/forwardauth_test.go`：Traefik 通道放行/查询串注入拦截、OpenResty 通道表单 XSS / JSON 体 SQLi / 良性 JSON / 深层嵌套 JSON、`nginx-auth-only` 状态码收敛 403、`/waf/deny` 按状态码渲染、共享存储计数与封禁跨实例、独立存储不共享**反例**、指标与探针、访问日志 JSON 结构化、未知路径 JSON 404 |
| 配置覆盖方式 | 已完成 | 契约测试改用**多配置文件合并**表达用例差异（`config.Options.ConfigFiles` 支持多文件，后者覆盖前者），不再往模板末尾追加同名字段——同一个 YAML 文件里出现重复映射键会被严格解析器判为格式错误 |
| Traefik 示例修正 | 已完成 | `deploy/forward-auth/traefik-forwardauth.yml`：**中间件顺序改为 `[waf-errors, waf-auth]`**。Traefik 采用 alice 风格链式包装，靠前的中间件在链的**外层**；`forwardAuth` 失败时直接 `WriteHeader` 返回、不调用下游，只有 `errors` 在外层才能观察到 403/429 并回源 `/waf/deny` 渲染 JSON。顺序写反的表现是「JSON 错误体静默丢失、只剩 Traefik 默认错误页」 |
| OpenResty 示例修正 | 已完成 | `deploy/forward-auth/{nginx-openresty.conf,waf_auth.lua}`：原始请求信息统一由 Lua 在**父请求**上通过 `ngx.req.set_header` 注入，内部 `location` 只读 `$http_x_forwarded_*` / `$http_x_real_ip`。不能直接用 `$request_uri` / `$request_method`——子请求里那是内部路径与方法 |
| 设计文档同步 | 已完成 | `docs/forward-auth-design.md` §3.3 同步中间件顺序与 `query: "/waf/deny?code={status}"`，并补「为什么 `errors` 必须在外层」的要点说明 |

**真机冒烟结论（端口 19185，二进制实进程 + `curl`/`Invoke-WebRequest`，`ingress.type: auto`）**：

| 用例 | 期望 | 实测 |
| --- | --- | --- |
| Traefik 头形态 + 查询串 SQLi | 403 | `403`，`X-WAF-Code: WAF_BLOCKED`、`X-WAF-Rule-Id: 942100`、`check: crs-header` |
| OpenResty 头形态（含 `X-Original-URI`）+ 查询串 SQLi | 403 | `403`，同上 |
| JSON 请求体 SQLi | 403 | `403`，`check: crs-body`、`942100` |
| 表单请求体 XSS | 403 | `403`，`check: crs-body`、`941100` |
| 良性 JSON 请求体 | 200 | `200`，`X-WAF-Code: WAF_ALLOW`、无响应体 |
| `/waf/deny?code=429`（数字状态码） | 429 | `429`，`WAF_RATE_LIMITED` |
| `/waf/deny?code=WAF_RATE_LIMITED`（错误码字面量） | 429 | `429`，同上 |
| `/waf/unknown` | 404 JSON | `404`，`{"code":"WAF_NOT_FOUND",...}` |
| 日志落盘 | 两类分级 JSON | 访问日志含 `level/verdict/request_id/rule_id`；系统日志按 `DEBUG/WARN` 分级记录评分与体缺失 |

**回归门禁（G1 相关）**：

- `gofmt -w ./cmd ./internal ./test` 后 `gofmt -l` 为空；
- `go build ./...`、`go vet ./...` 全部通过；
- `go test ./... -count=1` 全部通过（含 `test/contract` 新增用例）。

**遗留说明**：Traefik / OpenResty 本体未在本机落地，因此「中间件顺序」「`errors` 中间件 `query` 模板占位符写法」两项需在真机按上表逐条复测；若目标 Traefik 版本不支持 `query`，退化路径见 `docs/forward-auth-design.md` §4.3.3。

---

### 10.9 已完成：M2（检测引擎生产化，门禁 G2）

**目标**：把「能检测」推进到「**可运维地持续检测**」——规则可离线升级/回滚/热加载、误报可登记可审计、
请求体检测不留绕过面（压缩体）、上生产前有量化试运行依据。

#### 交付总览（P1-1 至 P1-6）

| 优先级 | 能力 | 交付物 | 状态 |
| --- | --- | --- | --- |
| **P1-1** | CRS 规则包离线治理：清单 / 校验 / 原子替换 / 回滚 | `internal/rules/bundle.go`、`cmd/waf/cmd_rules.go` | 已完成 |
| **P1-2** | 规则热加载（目录变化即原子替换引擎） | `internal/rules/watch.go`、`internal/check/coraza/reload.go`、`engine.hot_reload.*` | 已完成 |
| **P1-3** | 偏执等级 + 异常评分阈值闭环 | `engine.paranoia_level`、`engine.anomaly_score_threshold`（规则 ID `900110`） | 已完成 |
| **P1-4** | 误报例外（全局 / 作用域两类） | `internal/rules/exceptions/*`、`engine.exceptions[]`、`waf rules list` 审计清单 | 已完成 |
| **P1-5** | 压缩请求体解压 | `internal/ingress/body/decompress.go`、`ingress.body.decompress.*` | 已完成 |
| **P1-6** | DetectionOnly 试运行闭环 | `core.Result.WouldBlock`、`waf_would_block_total`、`waf report detection` | 已完成 |
| **G2 支撑** | `go-ftw` 兼容用例离线回归 | `configs/ftw/*.yaml`、`test/ftw/ftw_test.go` | 已完成（10 阶段全绿） |

#### 关键设计取舍（为什么这样做）

| 决策点 | 结论 | 理由 |
| --- | --- | --- |
| 规则变化检测 | **轮询指纹**（`stat` 大小 + 纳秒修改时间，路径排序后 SHA-256） | ① 交付物是 `CGO_ENABLED=0` 静态单二进制，引入 `fsnotify` 增加依赖面（R10/R14）；② 轮询在容器挂载卷 / overlayfs / NFS 下行为一致，而 inotify 在这三类环境会漏事件；③ 几十个文件的 `stat` 代价可忽略，且**不读文件内容**（R13） |
| 指纹是否包含修改时间 | **必须包含** | 只比大小会漏掉「等长内容替换」（例如把规则里的评分阈值 5 改成 8）——这类变更恰恰是最常见的规则微调 |
| 热加载失败处理 | **保留旧引擎继续服务**，只在系统日志留 ERROR | 规则文件写坏了不应该让线上失去防护；`coraza.reloader` 用 `atomic.Pointer` 原子替换，替换成功后才 `Close` 旧实例 |
| 手动重载入口 | **标记文件时间戳**（`waf rules reload`），不做 HTTP API、不发信号 | 管理面已下调到 P3，M2 不该被它阻塞；Windows 无 `SIGHUP`，信号方案跨平台一致性差；标记文件与「目录指纹变化」走同一条重载路径，行为完全一致 |
| 例外指令的放置顺序 | 作用域例外（`ctl`）→ **规则文件之前**；全局例外（`SecRuleRemove*`）→ **规则文件之后** | SecLang 语义：`ctl` 是运行期动作，同一 phase 内按顺序求值，必须先于目标规则；`SecRuleRemove*` 是配置期指令，只对**已解析出来的规则**生效。顺序写反的表现是「配置合法、但例外不生效」，属于最难排查的一类 |
| 作用域例外的粒度 | 每个 `ctl` 动作**独立成一条规则**（ID 从 `900300` 起） | 某个动作在目标引擎上不被支持时，影响面收敛到单条规则；同时日志/清单里能精确定位 |
| 例外状态口径 | 三态 `applied` / `disabled` / `expired`，且**过期优先于启用开关** | 报表要能回答「这条是到期自动失效，还是被人为关掉」；`enabled` 缺省为 `false`（例外默认不生效）是刻意的安全默认 |
| 解压实现位置 | **接入层**（`ingress.body.decompress`），不是 `pipeline` 或引擎内部 | 解压结果是链中所有 `phase: body` 单元的共同输入，放在接入层只需解压一次；放在引擎里会被多实例重复解压 |
| 解压超限的处理 | **拒绝，绝不截断** | 截断得到的是「不完整明文」，用它检测会产生「检测过了但没检出」的假安全感（与 `ingress.body.on_exceed=truncate` 的语义刻意区分：后者是代理侧硬边界） |
| 多重编码（`gzip, deflate`） | **一律按不支持处理**（fail closed） | 「悄悄只解一层」会让攻击者用多层压缩把内层载荷彻底藏起来 |
| `br`（brotli） | **不支持**，写进配置在校验阶段直接报错 | 需要第三方依赖，与 R10/R14 冲突；实际收到 `br` 请求时按 `unsupported_action`（默认 `block`）处理 |
| `go-ftw` 用例回归 | **自研最小离线执行器**（`test/ftw`），不依赖 go-ftw 二进制 | go-ftw 需要下载二进制与网络目标地址，与「可完全离线构建与回归」冲突；执行器直接吃 go-ftw 的 YAML 格式，在进程内驱动真实校验链（`config.Load` → `pipeline` → `coraza`），保留「用例格式与社区一致」的好处 |
| 报表数据源 | 直接消费**访问日志 JSON Lines**，不引入数据库/时序库 | 日志是唯一「已落盘、可归档」的事实来源，报表可复现、不依赖在线服务；与「管理面 P3」的判断一致 |
| 报表遇到坏行 | **直接报错并指出文件 + 行号** | 静默跳过会让「统计偏小」这类问题在生产里极难发现 |

#### 本轮新增 / 修改文件

| 文件 | 说明 |
| --- | --- |
| `internal/rules/bundle.go` | 清单生成 / `LoadManifest`（严格模式）/ `Verify`（缺失·摘要不一致·多余）/ `Install`（`.new` → `.previous` 原子切换 + 失败自动回滚）/ `Rollback`（当前版改名为 `.failed` 保留排障） |
| `internal/rules/watch.go` | `Fingerprint`、`Watcher`（`Start`/`Stop` 幂等、去抖动复核、`MarkerFile`）、`DirFiles` |
| `internal/rules/exceptions/exceptions.go` | `Compile` → `Set{Pre, Post, Entries, Applied}`；全局 / 作用域两路指令生成；`ValidatePattern` |
| `internal/check/coraza/reload.go` | `atomic.Pointer[Check]` 热加载包装：失败保留旧引擎、成功后才关闭旧实例 |
| `internal/check/coraza/engine.go` | `buildDirectives` 新增第 4.2 段（阈值 `900110`）、第 4.5 段（Pre 例外）、第 6 段（Post 例外） |
| `internal/ingress/body/decompress.go` | `Decode` + `decoded` 流（可重复读取）；gzip / deflate（zlib 优先、裸 flate 兜底）；`ErrUnsupportedEncoding` 哨兵错误 |
| `cmd/waf/cmd_rules.go` | `rules list/verify/manifest/install/rollback/reload`；`verify` 退出码 `0/2/3`；参数冲突检测 |
| `cmd/waf/cmd_report.go` | `report detection` / `report attack`，全部支持 `--json`、`--since`、`--top` |
| `configs/ftw/*.yaml` | SQLi（4 阶段）+ XSS / RCE / 协议攻击 / 良性流量（6 阶段）用例集 |
| `test/ftw/ftw_test.go` | 离线执行器（go-ftw 用例格式，进程内驱动真实校验链） |
| `test/contract/*` | 沿用 M1.6 骨架；`waf-override.yaml` 多文件合并表达用例差异 |
| `internal/core/{engine,result,deps}.go` | `ExceptionSetting`（含 `Enabled`）、`HotReloadSetting`、`Result.WouldBlock` / `MarkWouldBlock`、`IncWouldBlock` / `IncRuleReload` 指标接口 |
| `internal/observe/metrics.go` | 新增 `waf_would_block_total{check,rule_id}`、`waf_rule_reload_total{result}` |
| `internal/server/server.go` | 访问日志新增 `would_block` / `would_block_reason`，并把该情形日志级别升为 `warn` |
| `configs/waf.example.yaml`、`docs/configuration.md` | 新增 `ingress.body.decompress`、`engine.anomaly_score_threshold`、`engine.exceptions`、`engine.hot_reload.poll_interval/marker_file`，并补齐 `rules` / `report` 子命令与排错速查 |

#### 本阶段发现并修复的真缺陷（值得记录）

1. **`--version` 与配置项 `version` 重名**：`splitConfigArgs` 会把业务参数 `--version` 归入配置通道，
   表现为「命令不报错、但版本号拿不到」。改为 `--package-version`，并新增
   `ensureBusinessFlagsDistinct` 在构造参数集合时做**冲突检测**（把静默问题变成启动期硬错误）。
2. **契约测试 YAML 重复键**：用例通过「追加 override 片段」覆盖模板时会产生同名映射键，
   严格解析器直接报错。改为**多配置文件合并**（后者覆盖前者）表达用例差异。
3. **Traefik 中间件顺序**：`forwardAuth` 失败时直接 `WriteHeader` 不调下游，
   只有 `errors` 在外层才能观察到 403/429 并回源 `/waf/deny` 渲染 JSON（详见 §10.8）。
4. **`VerifyReport` / `Manifest` 缺 JSON 标签**：`--json` 输出是 PascalCase，
   与项目其它 CLI JSON（小写下划线）不一致；补齐 `json` 标签并把三个切片初始化为空切片（输出 `[]` 而非 `null`）。
5. **`Verify` 的「多余文件」语义**：`OK()` 只覆盖缺失与摘要不一致，「多余文件」用独立退出码 `3` 表达
   （语义是「目录不干净」而非「包损坏」，两者的处置动作完全不同）。

#### 回归门禁（G2 相关，已全绿）

- `gofmt -l ./cmd ./internal ./test` 为空；
- `go build ./...`、`go vet ./...` 通过；
- `go test ./... -count=1` 全部通过；其中 `test/ftw` 10 个阶段全绿、`test/contract` 13 用例 + 4 子用例全绿；
- 新增单测：`internal/rules/{watch,bundle}_test.go`、`internal/rules/exceptions/exceptions_test.go`、
  `internal/ingress/body/decompress_test.go`、`internal/check/coraza/exceptions_directive_test.go`、
  `cmd/waf/{cmd_rules,cmd_report}_test.go`；
- `waf check-config -c configs/waf.example.yaml` 退出码 0；`waf rules list` 能正确输出「生效 0 条、disabled 2 条」的例外审计清单。

#### 仍存在的已知边界（不阻塞 G2）

| 边界 | 说明 | 处置 |
| --- | --- | --- |
| `br`（brotli）不支持 | 需第三方依赖（R10/R14 冲突） | 配置阶段报错；运行期按 `unsupported_action`（默认 `block`）处理 |
| 多重编码不解压 | 只做单层编码 | 一律判为不支持（fail closed）；未来若确需支持，按「逐层解压 + 每层同一限额」实现 |
| 规则包不支持子目录 | `@pmFromFile` 的相对路径语义要求扁平目录 | `Install` 明确报错；如需多级目录，先展开为扁平结构 |
| 例外只作用于 Coraza | 例外编译为 SecLang 指令 | 其它插件（如 `threshold`）有自己的 `settings`，不共用例外清单 |
| 热加载按秒级生效 | 受 `poll_interval` 约束（默认 5s） | 需要更快生效时调小 `poll_interval`，或用 `waf rules reload` 立即触发 |

---

### 10.10 计划：M3（运营与告警，门禁 G3）〔**已实施完成，结果见 §10.11**〕

**目标**：把「能检测」推进到「**可运营、可告警、有容量依据**」。M3 不引入新的检测能力，
只做「让检测结果被看见、被处置」的运营闭环。

| 优先级 | 内容 | 交付物 | 验收点 |
| --- | --- | --- | --- |
| **P1-7** | 告警外送：`Notifier` 抽象 + 多实现**并联扇出** + 聚合抑制（同类告警在窗口内只发一次） | `internal/notify/*.go`、`internal/notify/{webhook,wechat,syslog,smtp}/*.go`、`notifiers[]` 落地 | 触发点接 `core.Alert`（`pipeline` 已产出）；至少 2 个通道真机送达；抑制生效（窗口内不重复） |
| **P1-8** | 封禁 / 限速可视化运维 | `waf ban`（已有）+ 报表侧 Top 来源 IP / 时间线；必要时补 `waf report ban` | 能回答「当前封了谁、为什么、还有多久」 |
| **P1-9** | 审计报表与导出（CSV / Excel） | `internal/observe/report/*.go`（CSV 用 `encoding/csv`；Excel 若无第三方依赖则落地为 SpreadsheetML / 最小 xlsx 或明确降级为 CSV） | 导出文件可被 Excel 直接打开；字段与访问日志一一对应 |
| **P1-10** | 性能基线与容量模型 | `scripts/bench/*`（wrk / hey / k6 离线脚本）、`docs/operations.md` 容量章节 | 产出 QPS / P99 / 规则规模曲线与档位建议（含 `--bench` 说明） |
| **文档** | 运维手册：告警接入、误报压降流程、封禁运维、容量规划 | `docs/operations.md` | 运维按手册可独立完成一次「告警接入 + 误报压降」 |

**M3 的约束（沿用全局硬约束）**：

- 全部通道**配置即开关**（`notifiers[].enabled`），默认不发送；
- 告警内容不得包含原始请求体全文（只带 `request_id` 等定位信息，避免把敏感数据外送）；
- 无第三方依赖优先：`webhook` / `syslog` 用标准库即可；`smtp` 用 `net/smtp`；企业微信 `webhook` 同为 HTTP POST；
- 压测脚本必须可离线运行（不下载工具），无法运行的场景在文档里给出替代命令。
---

### 10.11 已完成：M3（运营与告警，门禁 G3）

**目标回顾**：把「能检测」推进到「**可运营、可告警、有容量依据**」。M3 不新增检测能力，
只补齐「让检测结果被看见、被处置」的运营闭环。本节是 §10.10 计划的实施结果。

#### 交付总览（P1-7 至 P1-10 + 文档）

| 优先级 | 能力 | 交付物 | 状态 |
| --- | --- | --- | --- |
| **P1-7** | 告警外送：`AlertSink` 抽象 + 四通道并联扇出 + 聚合抑制 + 重试 + 指标 | `internal/core/alert.go`、`internal/notify/*.go`、`internal/notify/{webhook,wechat,syslog,smtp}/*.go`、`internal/notifycfg/notifycfg.go`、`notify.*` + `notifiers[]`、`waf_alert_total{notifier,result}` | 已完成 |
| **P1-8** | 封禁 / 限速运营可视化 | `waf ban list\|add\|del\|flush`（已有）+ `waf report ban`（封禁命中 Top 来源 IP / 按小时时间线 / Top 站点 / Top 规则） | 已完成 |
| **P1-9** | 审计报表与导出 | `internal/observe/report/{report,csv,xlsx}.go`、`waf report detection\|attack\|ban --format table\|csv\|xlsx --out <文件>` | 已完成 |
| **P1-10** | 性能基线与容量模型 | `scripts/bench/{run-bench.sh,run-bench.ps1,auth-request.lua,k6-auth-request.js,payloads/*,README.md}`、`docs/operations.md` 容量章节 | 已完成 |
| **文档** | 运维手册 + 配置手册增补 + 运行/测试/打包手册 | `docs/operations.md`（8 节）、`docs/configuration.md` §2.9 扩写为四大子节、§1.4 子命令表补 `report ban` 与导出说明、§5 排错表补 9 行、`docs/dev-guide.md`（构建 / 运行 / 测试 / 打包） | 已完成 |

#### 关键设计取舍（为什么这样做）

| 决策点 | 结论 | 理由 |
| --- | --- | --- |
| Excel 导出格式 | **手写最小 OOXML xlsx**（`archive/zip` + 5 个 XML 部件，单元格用 `inlineStr`） | 计划里留的 SpreadsheetML 2003 兜底方案在新版 Excel 会弹「文件格式与扩展名不匹配」，**不满足「可被 Excel 直接打开」这条验收**；xlsx 是当前 Excel 的原生格式。不生成 `sharedStrings` / `styles` 是因为这两张表是「体积优化」而非「可打开性」的必需部件，省掉能显著降低手写 XML 的出错面 |
| 告警触发点 | **`server` 在 `rctx.AppendResult(result)` 之后、`recordAccess` 之前**调用一次 `alerts.Notify(result.Alerts)` | 必须在 `AppendResult` 之后：`mergeResult` 是**追加合并**各单元的告警，早调用会漏掉链尾单元（如 `autoban`）；必须在 `recordAccess` 之前：日志是「事实记录」，告警是「旁路外送」，先落日志再外送，即使外送阻塞也不会让日志缺行 |
| 扇出与阻塞 | **队列 + 异步 worker**，队满**丢弃并计数**（`waf_alert_total{result="dropped"}`） | 告警是旁路行为，绝不能拖慢请求判定（与 R18 同源取舍：安全判定优先级最高）。丢弃是可观测的有损降级，比「阻塞 WAF」或「静默丢失」都好 |
| 抑制表作用域 | **每个通道独立一张**抑制表（各自的 `min_level` 与 `suppress_window`） | 通道语义不同：值班群要「少而准」（窗口大），审计 syslog 要「全量留痕」（窗口 0）。共用一张表就必然要在其中一方妥协 |
| 聚合键定义 | `级别 + 站点 + 标题 + 命中规则` | 「同一站点被同一规则反复拦」是最常见的告警风暴形态；把「级别」纳入键，是为了让同一规则的 `warn` 与 `error` 不被互相抑制掉 |
| 通道级 `suppress_window` 如何表达「不抑制」 | **不设哨兵值**，`0` 一律表示「继承全局」；要全局不抑制就改 `notify.suppress_window: 0` | 「抑制到底开没开」只能有一个权威来源，否则运维要记住某个特殊数字的含义 |
| 配置与实现的依赖方向 | 新增 `internal/notifycfg` 包做「配置 → 管理器」映射 | `internal/notify` 不认识 `config`（便于单测直接构造），`internal/config` 也不反向依赖具体告警实现（避免核心配置被通道实现污染）。生产装配与契约测试共用同一个 `Build` 入口，保证「测试里能跑的配置」就是「生产里跑的配置」 |
| syslog 的跨平台处理 | **按 build tag 拆文件**；Windows / Plan9 上 `openSink` 直接返回明确的「本平台不支持」错误 | `log/syslog` 在 Windows 不存在。**静默丢弃**会让运维以为「告警配好了但收不到」，属最难排查的一类；启动期硬失败 + 排错表条目才是正确做法 |
| 告警载荷内容 | 只带 `request_id` / 站点 / 路径 / 客户端 IP / 规则等**元数据**，不含 `body` / `headers` / `raw_request` | 告警外送的接收端通常是第三方（企业微信、邮件、SaaS 告警平台），把请求体外送等于把可能的敏感数据交给第三方；定位问题用 `request_id` 去访问日志里捞即可（契约测试对此有专门断言） |
| `notify` 与 `notifiers` 分离 | `notify.*` 是**公共策略**（队列、并发、超时、重试、抑制、级别门槛），`notifiers[]` 是**通道声明** | 一份策略 + 多个通道，避免在每个通道里重复抄同一组参数而写歪；通道只声明「我是谁、我关心什么级别的告警」 |
| 总开关与通道开关的关系 | `notify.enabled=true` 且**声明了通道但没有任何 `enabled: true`** → 校验期直接报错；`notifiers` 本身为空则视为「未接通道」的合法状态，由启动日志的 `channels` 字段暴露 | 「配了总开关但忘了开通道」是极高概率的运维失误，静默通过会让人以为告警已生效；而「一个通道都没声明」是合法部署形态（例如先开总开关再逐个接通道），此时不应阻断启动 |
| `report ban` 的数据来源 | **不新增日志字段**，用现有访问日志里的 `verdict` + `check` 判定封禁命中 | 报表消费的是已经落盘的历史日志。新增字段意味着「改之前的历史日志全部算不出来」，报表价值会被打折；`check` 字段本就记录了「是哪个单元拦的」，含 `ban` 即为封禁命中 |
| 导出限额来源 | 复用 `limits.max_scan_token_bytes`（单元格）与 `--top`（行数），**不新增配置开关** | R13 要求「限额必须可配」，但「可配」不等于「必须新增一个只服务导出的开关」。复用同一语义的值可以让「为什么这个字段被截断了」只有一个解释 |
| CSV 编码 | 强制写 **UTF-8 BOM** | 不带 BOM 的 UTF-8 CSV 在中文 Windows 上双击打开是乱码——而「双击打开」正是运维最常用的姿势 |

#### 文件清单

**新建**

| 文件 | 职责 |
| --- | --- |
| `internal/core/alert.go` | `AlertSink` 接口 + `NoopAlertSink`（未配置告警时的零开销实现） |
| `internal/notify/notify.go` | `Sender` 接口、`Instance`、`Deps`、工厂注册表（`Register` / `New` / `RegisteredTypes`） |
| `internal/notify/level.go` | 告警级别解析与比较（`ParseLevel` / `MeetsLevel`） |
| `internal/notify/payload.go` | 统一告警载荷（JSON 小写下划线）+ `BuildPayload` |
| `internal/notify/manager.go` | 扇出、级别门槛、抑制、重试队列、指标计数（实现 `core.AlertSink`） |
| `internal/notify/suppress.go` | 每通道独立的聚合抑制表（按最早写入淘汰 + 定期清理过期键） |
| `internal/notify/httpclient.go` | 各 HTTP 类通道共用的客户端构造（超时 / 跳过证书校验） |
| `internal/notify/webhook/webhook.go` | 通用 Webhook 通道（自定义 method / headers / content-type） |
| `internal/notify/wechat/wechat.go` | 企业微信机器人通道（markdown / text，额外判定 `errcode != 0`） |
| `internal/notify/syslog/{syslog.go,platform_unix.go,platform_windows.go}` | 系统日志通道（facility / severity / 网络类型可配） |
| `internal/notify/smtp/smtp.go` | 邮件通道（none / starttls / tls，主题按 RFC 2047 编码，过滤邮件头注入） |
| `internal/notifycfg/notifycfg.go` | 配置 → 告警管理器的唯一映射入口（生产与契约测试共用） |
| `internal/observe/report/report.go` | 报表文档模型（`Document` / `Sheet` / `Options`）与格式分派 |
| `internal/observe/report/csv.go` | CSV 导出（UTF-8 BOM、多表分隔、注释行） |
| `internal/observe/report/xlsx.go` | 最小 OOXML xlsx 导出（无第三方依赖） |
| `cmd/waf/notify.go` | 告警管理器的构造与关停封装 |
| `cmd/waf/cmd_report_export.go` | `report --format/--out` 导出后端（格式推断 + 限额） |
| `scripts/bench/*` | 离线压测脚本与示例载荷 |
| `docs/operations.md` | 运维手册 |
| `docs/dev-guide.md` | 开发、运行、测试与打包手册（环境准备 / 构建 / 三种运行入口 / 冒烟验证 / 分层测试 / 打包与离线交付 / CI / 排错） |

**修改**

| 文件 | 变更 |
| --- | --- |
| `internal/core/deps.go` | `Deps.Alerts` + `AlertsOr()`；`MetricsRecorder.IncAlert(notifier, result)` |
| `internal/observe/metrics.go` | 新增 `waf_alert_total{notifier,result}` |
| `internal/server/server.go` | `Options.Alerts` + 结果落定后外送告警 |
| `internal/config/{config,defaults,validate}.go` | `NotifyConfig` / `NotifierConfig` + 校验（含「声明了通道但一个都没启用」报错） |
| `cmd/waf/cmd_run.go` | 装配并注入告警管理器，关停时按超时 flush |
| `cmd/waf/plugins.go` + `test/contract/plugins_test.go` | 空白导入四个通道实现 |
| `cmd/waf/cmd_check_config.go` | 输出「已注册的告警通道类型」 |
| `cmd/waf/cmd_report.go` | 新增 `report ban` 子命令 + 三处导出钩子 |
| `configs/waf.example.yaml` | 完整 `notify:` 段 + 四种通道示例（全部 `enabled: false`） |
| `test/contract/harness_test.go` | 契约测试装配告警管理器 |
| `test/contract/notify_test.go` | 告警契约用例（新建） |
| `cmd/waf/cmd_report_ban_test.go` | 封禁报表与导出用例（新建） |
| `docs/configuration.md` | §2.9 扩写、§1.4 与 §5 增补 |

#### 本轮发现并修复的真缺陷（值得记录）

1. **SMTP 邮件头截断只判末字节**：按字节截断 UTF-8 中文主题时，只检查「最后一个字节是不是高位字节」并不能保证结果是合法 UTF-8
   （截断点可能落在多字节字符的中间）。改为用 `utf8.ValidString` 逐字节回退到最近一个合法边界。
2. **xlsx 数值判定会误判 `Inf` / `NaN`**：`strconv.ParseFloat` 能成功解析 `Inf` / `NaN`，把它们写成数值单元格会让 Excel 报文件损坏。
   改为「字符白名单 + `ParseFloat` + 排除 `Inf`/`NaN`」三重判定。
3. **CSV 缺 BOM 导致中文乱码**：`encoding/csv` 默认不写 BOM，Excel 在中文 Windows 上会按 ANSI 解码。
   已在 `csv.go` 里强制写 `0xEF 0xBB 0xBF`。
4. **`--out` 扩展名无法识别时的行为**：最初设想「无法识别就退回人读表格」，但这会让批量导出脚本**静默拿到人读文本而不是文件**。
   改为直接报错并提示显式 `--format`。
5. **企业微信 HTTP 200 不等于发送成功**：机器人接口用响应体里的 `errcode` 表达业务错误（如 token 失效）。
   只判状态码会让「告警全丢」表现为「指标一切正常」，因此在通道内额外判定 `errcode != 0`。
6. **`report ban` 的判定条件不足**：只按 `verdict ∈ {block,drop,observe}` 会把「被规则拦」也算成「被封禁拦」。
   补上 `check` 字段含 `ban` 的与条件后，报表才真正回答「封禁在起作用吗」。

#### 回归门禁（G3 相关，已全绿）

- `gofmt -l ./cmd ./internal ./test` 为空；`go build ./...`、`go vet ./...` 通过；
- `go test ./... -count=1` 全部通过；其中 M3 新增包：`internal/notify`、`internal/notify/{webhook,wechat,syslog,smtp}`、`internal/observe/report`；
- `test/contract/notify_test.go` 五条用例全绿：告警送达 webhook（并断言载荷**不含** `body` / `headers` / `raw_request`）、
  默认不发送、多通道扇出、重复告警被聚合抑制、指标按 result 计数；
- `cmd/waf/cmd_report_ban_test.go` 覆盖封禁报表统计与 `--format csv` / `--out` 导出路径；
- `waf check-config -c configs/waf.example.yaml` 退出码 0，并能列出四种已注册告警通道类型；
- `waf report ban --dir <日志目录> --since 24h` 在空目录上按预期报「未找到访问日志文件」而不是崩溃。

**真机冒烟（Windows 本地实进程，使用 `file` 存储 + 本地 webhook 接收端；脚本与日志全部落在 `.tmp/`，已被 `.gitignore` 排除）**：

| 用例 | 期望 | 实测 |
| --- | --- | --- |
| `report ban`（封禁命中日志） | 输出 Top 来源 IP / 时间线 / Top 站点 / Top 规则 | 2 条命中；Top IP `198.51.100.8`、按小时时间线 `13:00`、Top 站点 `default`、Top 规则 `internal_banlist` |
| 告警送达（webhook → 本地接收端） | 拦截后告警到达接收端 | 收到告警 JSON；`waf_alert_total{notifier="smoke-webhook",result="sent"} 1`；载荷**不含** `body` / `headers` / `raw_request` |
| 聚合抑制生效（`--notify-suppress-window=5m`，同规则连发 3 次） | 只送 1 条 | `sent 1` + `suppressed 2`，接收端仅新增 1 行 |
| 抑制关闭（`suppress_window: 0s`，同规则连发 3 次） | 3 条全部送达 | 接收端新增 3 行（累计 `sent 4`） |
| 「声明了通道但一个都没启用」 | 校验失败并拒绝启动 | `配置校验失败：notify.enabled = true，但 notifiers 中没有任何 enabled = true 的通道`，退出码 2 |
| 通道列表为空 + 总开关打开 | 不阻断启动，但日志暴露 | 启动日志 `告警外送已装配 enabled=true channels=[]` |
| 三通道优先级（CLI 覆盖配置文件） | `--notify-suppress-window=5m` 生效 | 启动日志 `suppress_window: "5m0s"`（配置文件中写的是 `0s`） |
| xlsx 结构正确性 | 可被 Excel 直接打开的 OOXML 包 | 9 个部件齐全；全部 XML 经 `XmlDocument.LoadXml` 校验良构 |
| CSV 编码 | 带 UTF-8 BOM | 首三字节为 `EF BB BF` |
| `--out` 未知扩展名 | 报错而非静默降级 | 退出码 2，提示显式 `--format csv` / `--format xlsx` |

> 说明：封禁状态通过 `file` 后端的**启动回放**生效（`回放封禁持久化文件完成 bans=1`）——
> 该后端只保证「单机重启不丢封禁」，**不保证运行期跨进程同步**，多实例共享必须使用 `redis` 后端（需求 R23）。
> 这一条已在 `docs/operations.md` 的封禁运维章节写明。

#### 仍存在的已知边界（不阻塞 G3）

| 边界 | 说明 | 处置 |
| --- | --- | --- |
| syslog 不支持 Windows / Plan9 | `log/syslog` 属类 Unix 专有 | 该平台上该通道**启动即失败**（明确报错）；改用 webhook / wechat / smtp，或用 `network: tcp` 指向远端 syslog |
| 抑制表不跨实例共享 | 抑制表在进程内存中，多副本部署时各副本独立抑制 | 抑制是「压降」而非「去重」，多副本下最坏情况是重复 1 次；如需精确一次，可后续把抑制表也接入 `Store` 抽象 |
| 告警队列不持久化 | 进程重启会丢掉队列内尚未外送的告警 | 告警是旁路通知，持久化会引入「重启后重放旧告警」的新问题；真需要不丢的通道，可接入接收端自身的可靠性保证 |
| 通道类型有限 | 目前 webhook / wechat / syslog / smtp 四种 | 新增通道只需实现 `notify.Sender` 并 `init()` 注册，`notifiers[].type` 即可选用；无需改动管理器 |
| **`sites[].engine_mode` 是静默失效配置**（M3 复测发现） | 该字段会被严格校验、也会被解析进 `core.Site.EngineMode`，但**运行期无消费方**：`coraza` 与 `threshold` 都只读全局 `engine.mode`。实测全局 `on` + 站点 `detection_only` 时 SQLi 仍 `403` | **待修**（属「配了但不生效」，与本项目一贯的 fail-fast 原则冲突）。修复前不要依赖它：站点级灰度请用「单独实例 + 代理按 Host 分流」；全局灰度用 `engine.mode: detection_only` **加** `pipeline[type=threshold].settings.action: observe`（配方见 `docs/dev-guide.md` §3.6） |
| 报表读的是「当前日志目录」 | 依赖外部日志轮转/归档策略 | 归档后的历史报表请对归档目录再执行一次 `report`（报表完全离线、可重复执行） |
| 压测需外部工具或 .NET 模式 | `wrk` / `hey` / `k6` 属外部可执行文件，本仓库**不下载**任何东西 | 无工具时脚本退出码 3 并打印替代命令；Windows 提供纯 .NET `builtin` 模式兜底 |
| 容量档位表是「量级参考」 | `docs/operations.md` 的档位基于通用经验而非本机实测 | 上线前必须用 `scripts/bench/*` 在目标机型上实测一次，再据此校准档位 |

---

### 10.12 已完成：自动封禁「触发维度」可配置（M3 后补，缺陷修复）

**触发原因（用户反馈）**：自动封禁只支持「**单一 IP** 在窗口内累计命中达阈值」这一种形态。
这带来两个具体问题：

1. **维度不可选**：想按「IP + 路径」等更细的粒度封禁（只封这个人访问这个接口）时无配置可用；
2. **重复写名单**：来源一旦被封禁，后续每个被拦请求仍会继续计数（`hit_count` 3→4→5→6）并重复写名单，
   使「命中次数」失去参考意义；若开启累进封禁，还会表现为封禁时长被无限加长。

#### 本次改动（交付物）

| 能力 | 交付物 | 说明 |
| --- | --- | --- |
| **封禁维度抽象** | `internal/ban/keys.go` | 新增 `KeyScope` 与唯一键构造入口 `ClientIPScopeKey`；维度：`client_ip` / `client_ip+site` / `client_ip+path` / `client_ip+method` |
| **多维度封禁配置** | `ban.ban_keys`（`internal/config/config.go`、`validate.go`） | 运行期生效的维度集合，可配置多个；为空时回落 `ban.ban_key`（旧配置零改动） |
| **多维度名单查询** | `core.BanController.CheckScopes`、`internal/ban`、`internal/check/banlist` | 按声明顺序逐个维度查询，命中任一维度即拦截并回传命中维度（`internal_banlist` 的 `ban_scope`） |
| **多维度自动封禁** | `internal/check/autoban` 的 `settings.dimensions[]` | 每个维度独立阈值 / 窗口 / 时长；多个维度同时达标则一并产出封禁动作 |
| **严重度门槛** | `settings.min_severity`；`core.Severity.Rank()` / `core.SeverityNames()` / `core.ParseSeverity` | 只有存在该级别及以上命中才计入，避免「低危规则凑次数」误封 |
| **重复封禁抑制** | `settings.skip_when_banned`（默认 `true`） | 来源已在该维度名单中时跳过计数与重复写名单 |

#### 关键设计取舍

| 决策点 | 结论 | 理由 |
| --- | --- | --- |
| 维度的抽象位置 | 放在 `internal/ban`（而非各校验单元自行拼键） | 键的构造必须只有一处实现，否则必然出现「CLI 写进去、banlist 查不到」。这与 §10.3 已确立的「封禁键唯一构造入口」原则一致 |
| 维度的键格式 | `ip:<ip>` / `ip:<ip>\|site:<站点>` / `ip:<ip>\|path:<路径>` / `ip:<ip>\|method:<方法>` | 前两种与既有格式**逐字节兼容**（老名单不用迁移）；后两种沿用「前缀 + 竖线分段」风格，便于 `ban list` 人工阅读与按前缀排查 |
| 谁来声明「哪些维度会被查询」 | 全局 `ban.ban_keys`，`autoban` 的维度必须是它的子集 | 查询集合与写入维度是两处配置，二者不一致就是静默失效。放在全局并强制子集校验，可以在启动阶段（而不是线上）暴露问题 |
| 多维度与阈值的关系 | **每个维度独立计数、独立判定**（不共享计数器） | 维度不同则键不同、阈值语义也不同（「IP 5 分钟内 3 次」≠「路径 10 分钟内 5 次」），共用计数器会互相污染 |
| 计数键为什么编入维度与窗口 | `ab:<维度>\|<键>\|<窗口>` | 编入维度避免维度间污染；编入窗口避免运维调整窗口后沿用旧计数，导致阈值被瞬间击穿 |
| `min_severity` 的判定口径 | **任意一条**命中达标即通过（而不是「全部都要达标」） | 攻击者常同时触发低危与高危规则（协议异常 + SQLi），要求全部达标会让门槛形同虚设 |
| 已封禁时是否续期 | 默认**跳过**（`skip_when_banned: true`），可显式关闭 | 默认行为要「可解释」：封禁生效期间本就会被 banlist 拦截，继续计数只会让命中次数虚高；需要「持续攻击即持续续期」的团队可显式打开 |
| `ban_keys` 只支持配置文件 | 数组无法由环境变量 / CLI 机械表达（设计文档 §2.7） | 与既有 `ban.escalate_steps` 保持同一取舍，不为此引入「字符串拆数组」这类隐式约定 |

#### 验证结果

**门禁**：`gofmt -l` 为空；`go build ./...` / `go vet ./...` 退出码 0；`go test ./... -count=1` 全绿（29 包）。

**新增单测**：

- `internal/ban/keys_test.go`：维度解析容错、四类键构造、缺字段兜底、`ban_keys` 回落与去重、多维度查询命中路径维度；
- `internal/check/autoban/autoban_test.go`：多维度同时达标产出 2 条封禁动作（含维度级 `ttl` 覆盖）、`min_severity` 门槛、`skip_when_banned` 开关、维度相关非法配置 fail fast；
- `internal/check/banlist/banlist_test.go`：命中维度与键写入命中明细；
- `internal/config/ban_test.go`：`ban_keys` 非法取值 / 重复 / 未包含主维度三类配置错误的报错文案。

**真机冒烟（Windows 本地实进程，`memory` 存储）**：

| 用例 | 期望 | 实测 |
| --- | --- | --- |
| 同一 IP 连续 6 次 SQLi（`client_ip` 阈值 3 / `client_ip+path` 阈值 5） | 第 3 次按 IP 封禁、第 5 次按路径封禁 | 日志：`ban_scope=client_ip hit_count=3`、`ban_scope=client_ip+path ban_key=ip:198.51.100.77\|path:/api/user hit_count=5`；`waf_bans_total{scope="client_ip"} 1`、`{scope="client_ip+path"} 1` |
| 第 4 / 6 次请求 | 不再重复写名单、命中次数不再增长 | 无新增「已写入内部封禁名单」记录（`skip_when_banned` 生效） |
| 仅启用 `client_ip+path` 维度时，同一 IP 打 `/api/user` 3 次 | 该 IP 只被封「/api/user」 | 第 4 次 `/api/user` → `ban-list/internal_banlist`；`/api/other` 携带 SQLi → `crs-header/920100`（**未命中名单**）；`/api/other?id=1` → 200 放行 |
| 启动日志 | 输出生效维度 | `"ban_keys":"client_ip,client_ip+path"` |

#### 已知边界

| 边界 | 说明 | 处置 |
| --- | --- | --- |
| `waf ban remove` 只解主维度 | 命令行参数只有 `--ip`（+`--site`），按主维度 `ban.ban_key` 构造键 | 其他维度按 `ban list` 输出的原样键处理（Redis `DEL`），或等 TTL 到期；已在 `docs/operations.md` §4.2 写明 |
| `ban_keys` 维度越多，单请求查询次数越多 | banlist 在 pre 阶段按维度顺序查询（命中即短路） | 只启用真正需要的维度；高频路径建议把最可能命中的维度放在前面 |
| 维度粒度不含「子网 / UA / 请求头」 | 当前四种维度都围绕「客户端 IP + 请求属性」 | 新增维度只需在 `keyScopes` 加一行 + 一个 `switch` 分支（`internal/ban/keys.go`），并在 `config.BanKeyKinds()` 登记 |

---

### 10.13 已完成：鉴权请求「过与不过都留痕」（缺陷修复）

**触发原因（用户反馈）**：forward-auth 鉴权端点的访问日志里，**放行请求默认完全不留痕**。
实现上放行走的是 `Debug("请求放行", ...)`，而 `logging.access.level` 默认为 `info`，
于是默认配置下日志里只剩「拦截」记录，所有放行流量都成为不可解释的空白——
排查「某个接口为什么忽快忽慢」「放行流量有多大」时没有任何依据。

#### 本次改动（交付物）

| 能力 | 交付物 | 说明 |
| --- | --- | --- |
| **放行记录策略可配置** | `logging.access.allow_level`（`internal/config/config.go`、`defaults.go`、`validate.go`） | 取值 `info` / `debug` / `off`，**默认 `info`**，可自由配置启用与否 |
| **放行写入访问日志** | `internal/server/server.go` 的 `recordAllow` | `info` 时以 `info` 级写「请求通过」；`debug` 时以 `debug` 级写；`off` 时直接跳过 |
| **通道级别自动下探** | `internal/logging/logging.go` 的 `applyAllowLevel` | `allow_level=debug` 时把访问日志通道级别下探到 `debug`，避免请求记录被 slog 静态过滤 |
| **判定动作字段** | `internal/server/server.go` 的 `accessAction` | 每条访问日志新增 `action`（`allow` / `block` / `observe` / `error`），四类记录字段对称 |

#### 关键设计取舍

| 决策点 | 结论 | 理由 |
| --- | --- | --- |
| 默认值为什么是 `info` 而不是沿用 `debug` | **默认记录放行** | 「功能即开关」不等于「默认全关」：可解释性是访问日志的第一价值，默认漏掉一半请求属于缺陷而非特性。需要省体积的团队显式调 `off` |
| 为什么要新增 `action` 字段 | 与 `verdict` 并存，不替代 | `verdict` 是判定结论，`action` 是消费方语义；报表 / grep 统一按 `action` 检索，未来 `verdict` 扩展取值时下游不用跟着改 |
| `off` 为什么放在 server 层处理 | 不在日志构建器里屏蔽 | 屏蔽 `info` 级会连带丢掉其他 `info` 记录（如观察命中）；放行是「按判定结果」区分的，只有 server 层知道本次结果 |
| `debug` 为什么要下探通道级别 | 在下探与「不改语义」之间选择下探 | 不下探则该配置是**静默失效**（用户以为开了、实际永远看不到）；下探只影响访问通道，系统日志通道不受影响 |
| 命令名沿用 `allow_level` 而非复用 `level` | 两个正交维度 | `level` 是「通道能写多细」，`allow_level` 是「放行这一类的开关」；混在一起会导致「想临时看放行就得把整个通道调成 debug」 |

#### 验证结果

**门禁**：`gofmt -l` 为空；`go build ./...` / `go vet ./...` 退出码 0；`go test ./... -count=1` 全绿；
`waf check-config` 对 `configs/waf.local.yaml` 与 `configs/waf.example.yaml` 均返回 0。

**新增测试**：

- `internal/config/access_log_test.go`：默认值回落 `info`、三个合法取值、非法取值报错文案包含 `logging.access.allow_level`；
- `internal/logging/allow_level_test.go`：级别下探矩阵（空串 / info / off 不改级别，debug 下探、已更细时不下探成更粗、大小写与空白容错、非法取值报错）；
- `test/contract/forwardauth_test.go`：放行默认写入访问日志（`action=allow` + `请求通过`）、`off` 时不写放行但拦截仍在（`action=block`）、`debug` 时放行记录可见且级别为 `DEBUG`。

#### 已知边界

| 边界 | 说明 | 处置 |
| --- | --- | --- |
| `allow_level` 只作用于访问日志 | 系统日志的级别仍由 `logging.system.level` 单独控制 | 这是有意为之：两类日志的服务对象不同，不能用同一个开关表达 |
| 放行记录会显著增加访问日志体积 | 高 QPS 下 file 轮转压力上升 | 用 `keep_days` / `max_total_bytes` / `rotate: both` 控制总量；或调 `debug`、`off` |
| 报表口径未变 | `waf report attack` / `report ban` 仍跳过 `allow` 记录（`default: continue`） | 属于预期：报表回答「被拦了什么」，流量构成请直接按 `action` 统计 |

---

### 10.14 已完成：无参数 / 无请求体请求不再被误判为异常（缺陷修复）

**触发原因（用户反馈）**：`ingress.body.mode: required` 下，任何未携带请求体的请求都会
产生一条 WARN 并累加 `waf_body_missing_total`——包括 GET / HEAD 这类**本来就不带请求体**的正常请求。
现象上表现为「日志里大量「请求体缺失」告警 + 指标持续上涨」，容易被误读成「WAF 判断失误」，
也让真正的部署问题（代理没有转发请求体）淹没在噪声里。

#### 根因

`internal/ingress/body` 的 `markMissingIfRequired` 只判断了 `mode == required`，
没有判断请求方法，而设计文档 §3.7 本来就限定为「POST/PUT/PATCH 且 Content-Length == 0」。
属于**实现与设计不一致**，不是行为取舍。

#### 本次改动（交付物）

| 能力 | 交付物 | 说明 |
| --- | --- | --- |
| **按方法判定缺失** | `ingress.body.missing_methods`（`internal/config/config.go`、`defaults.go`、`validate.go`） | 默认 `[POST, PUT, PATCH]`；只有这些方法缺少请求体才算缺失 |
| **方法随请求传入** | `body.Source.Method`、`Spool.method`、`Spool.expectsBody`（`internal/ingress/body/spool.go`） | 由 `internal/pipeline` 在创建缓冲器时填入原始请求方法；大小写不敏感 |
| **配置强校验** | `validateMissingMethods`（`internal/config/validate.go`） | 空项 / 含空白 / 重复声明报错；`mode = required` 且列表为空属于静默失效，直接拒绝启动 |

#### 关键设计取舍

| 决策点 | 结论 | 理由 |
| --- | --- | --- |
| 判定口径 | **按方法 + 是否真的有体**，而不是「无体即异常」 | 与设计文档 §3.7 对齐；GET / HEAD 无体是 HTTP 语义的正常形态，不该被当成配置错误 |
| 方法集合是否可配置 | 可配置（`missing_methods`） | 与项目「功能即开关、全部可配置」（R5 / R6）一致：某些团队会用 GET 承载 GraphQL 查询，或 DELETE 带体，硬编码会误伤 |
| 缺失是否参与拦截 | **不参与**，只告警 + 计数 | 缺失只能说明「接入链路可能没转发请求体」，不能说明「这个请求是攻击」。按需求 R22，拦截依据只能是命中规则 |
| 方法无法还原时怎么办 | 保守视为「非预期」，不计缺失 | 宁可漏报缺失，也不能因为「无法判断」就持续刷屏告警 |
| 参数类检测为什么不会因「无参数」命中 | 逐变量匹配语义：变量不存在时规则不命中 | CRS 中唯一按参数个数判定的是 920380（参数**过多**），不存在「参数个数为 0」的规则 |

#### 验证结果

**门禁**：`gofmt -l` 为空；`go build ./...` / `go vet ./...` 退出码 0；`go test ./... -count=1` 全绿；
`waf check-config` 对 `configs/waf.local.yaml` 与 `configs/waf.example.yaml` 均返回 0。

**新增 / 更新测试**：

- `internal/ingress/body/spool_test.go`：`TestFillMissingRequired` 改为按方法驱动（POST / PUT / 小写 post 均计入）；新增 `TestFillBodylessMethodsAreNotMissing` 覆盖 GET / HEAD / OPTIONS / DELETE / TRACE / 空方法；
- `internal/config/ingress_body_test.go`：默认值、自定义集合、`required` + 空列表、空项、含空白、重复声明六类；
- `test/contract/forwardauth_test.go`：`TestRequestWithoutParametersIsNotBlocked`（GET 无查询串 / 空查询串 / POST 无体 / 空 JSON / 无 Content-Type 全部放行）与 `TestBodyMissingMetricOnlyCountsBodyBearingMethods`（GET 不计缺失、POST 计 1 次且仍放行）。

#### 已知边界

| 边界 | 说明 | 处置 |
| --- | --- | --- |
| `missing_methods` 只支持配置文件 | 数组无法由环境变量 / CLI 机械表达 | 与 `ban.ban_keys`、`ban.escalate_steps` 保持同一取舍 |
| 只覆盖来自 `request-body` 通道的请求体 | `source != request-body` 时本就不读体，也不判缺失 | 与设计一致：`none` 表示链路不转发请求体 |
| 不改写 `mode: required` 的语义 | `required` 仍表示「本部署预期能拿到请求体」 | 它只是一个断言；是否算异常由 `missing_methods` 与方法共同决定 |
### 10.15 已完成：`Content-Length: 0` 不再被判定为「请求体缺失」（缺陷修复）

**触发原因（用户反馈）**：§10.14 修好了「GET 等无体方法 + 空体」被误判的问题，
但 `POST` 携带 `Content-Length: 0` 时仍会计入 `waf_body_missing_total` 并打 WARN 告警。
用户诉求：`Content-Length: 0` 是客户端主动声明「本次没有请求体」，
**取不到请求参数本来就属于正常现象**，不应被视为异常。

#### 根因

| 编号 | 根因 | 位置 |
| --- | --- | --- |
| ① | 缺失判定只消费了「方法维度」，没有消费设计文档 §3.7 早已写明的「声明长度维度」 | `internal/ingress/body/spool.go` 的 `markMissingIfRequired` |
| ② | `core.RawRequest.ContentLength` 直接取子请求的 `Content-Length`，而原生 Nginx `auth_request` 通道既不转发请求体也不转发 `Content-Length`，读到的 `0` 只代表「未知」 | `internal/ingress/forwardauth/extractor.go` 的 `Extract` |

②是关键：同一条链路里 `0` 有两种完全相反的语义（「客户端声明空体」与「通道没能力告诉我」）。
若不区分，要么掩盖真实故障（通道根本没有体检测能力），要么把正常空体误报成异常。

#### 本次改动（交付物）

| 能力 | 交付物 | 说明 |
| --- | --- | --- |
| **按接入通道还原声明长度** | `internal/ingress/forwardauth/extractor.go` 的 `pickContentLength` | `nginx-auth-only` 恒返回 `-1`（未知）；其余通道直接采用子请求 `ContentLength` |
| **声明长度参与缺失判定** | `internal/ingress/body/spool.go` 的 `markMissingIfRequired` 条件 3 | `declared == 0` 直接返回，不计缺失、不打告警 |
| **告警带上声明长度** | 同文件的缺失 WARN | 新增 `"declared", s.declared` 字段，便于区分「声明 0」与「未知」 |
| **启动能力清单自检** | `cmd/waf/cmd_run.go` 的 `reportIngressCapabilities` | 启动时打印 `ingress_type` / `body_detection` / `json_error_body` / `trusted_content_length` / `body_mode`；`nginx-auth-only` + `mode: required` 打 WARN |
| **通道能力边界落文档** | `deploy/forward-auth/nginx-auth-only.conf` | 补写「该通道会连带抹掉 `Content-Length`，WAF 统一视为未知」的说明 |

**「请求体缺失」的最终判定条件（三者必须同时满足）**：

1. **方法维度**：原始方法 ∈ `ingress.body.missing_methods`（默认 `[POST, PUT, PATCH]`）；
2. **声明维度**：`declared != 0`；
3. **通道维度**：`declared == -1`（未知）仍按方法维度计数——未知不等于空体。

`Declared` 取值语义：`0` = 明确声明空体（静默）；`-1` = 未知（chunked，或通道不转发 CL）；`>0` = 具体长度。

#### 关键设计取舍

| 取舍 | 结论 | 理由 |
| --- | --- | --- |
| `Content-Length: 0` 是否算缺失 | 不算 | 客户端已声明无体，无参数是预期结果；本项目的原则是「只对确实存在的内容做校验」 |
| 「未知」是否等同空体 | 不等同 | 否则 `nginx-auth-only` 通道下 `waf_body_missing_total` 永远为 0，A16 验收项形同失效，真实故障被静默掩盖 |
| 长度来源 | 子请求自身的 `Content-Length` | 已核对 Traefik v3 `forwardBody` 实现为 `forwardReq.ContentLength = req.ContentLength`；无需新增 `X-Forwarded-Content-Length`（会多一个没有消费方的静默失效配置） |
| 缺失是否拦截 | 不拦截 | 与 §10.14 一致，缺失只告警、只计指标 |
| 是否新增配置开关 | 不需要 | 「CL 为 0 是正常」是语义修正，不是策略选项 |

#### 验证结果

- 门禁四项：`gofmt -l .\cmd .\internal .\test` 输出为空、`go build ./...`、`go vet ./...`、`go test ./... -count=1` 全部通过（30 个包）；
- 新增/更新测试：
  - `internal/ingress/body/spool_test.go`：新增 `TestFillZeroContentLengthIsNotMissing`（POST/PUT/PATCH × 空体流/无体流，`Declared: 0` 不计缺失）；`TestFillMissingRequired` 改为覆盖 `128` / `-1` / 小写 `post` + `-1` 三种应计数场景；`TestFillBodylessMethodsAreNotMissing` 改用 `Declared: -1` 以隔离方法维度；
  - `internal/ingress/forwardauth/extractor_test.go`：新增 `TestExtractContentLengthPerIngressType`（`nginx-auth-only` 得 `-1`；Traefik + 128 得 128；Traefik + 0 得 0）；
  - `test/contract/forwardauth_test.go`：`TestBodyMissingMetricOnlyCountsBodyBearingMethods` 改为三条件矩阵（GET 无体得 0；POST + `CL:0` 得 0 且放行；POST + 未知长度得 1 且放行）；
- 真机冒烟（`bin\waf.exe run -c configs\waf.local.yaml`）：
  - Traefik 通道（`-ingress-type traefik-forwardauth`）下 `POST` 无体与 `Content-Length: 0` 均 200 放行，`waf_body_missing_total` 保持 0、无 WARN；
  - 切换 `-ingress-type nginx-auth-only` 后同样一条 `POST` 计 1 次并输出带 `"declared":-1` 的 WARN，请求依旧 200 放行；
  - 启动日志新增「接入通道能力清单」一行，`nginx-auth-only` 下同时提示 `mode: required` 无法观测缺失。
- 文档同步：`docs/configuration.md`（`ingress.body` 判定条件段）、`docs/forward-auth-design.md`（§3.6 声明长度行 / §3.7 启动能力清单）、`docs/dev-guide.md`（冒烟用例 13 / 14）。

#### 已知边界

| 边界 | 说明 | 处置 |
| --- | --- | --- |
| chunked 请求体记为「未知」 | 无 `Content-Length` 可读 | 属预期；仍按方法维度计数 |
| `nginx-auth-only` + `mode: required` | 该通道无体检测能力，`required` 无实际意义 | 启动 WARN 提示；应改用 `optional` / `disabled` |
| Traefik 关闭 `forwardBody` | 指标会归零，且不报错 | 属配置漂移，需靠巡检发现；`reportIngressCapabilities` 已在启动日志给出能力清单 |

---

### 10.16 已完成：文档一致性回补（历史差异收口）

**背景**：§10.14 / §10.15 的改动集中在 `internal/ingress/body`、`internal/ingress/forwardauth`、`internal/config`
与 `cmd/waf`，但更早几轮（M1.6 / M2 / M3）遗留的文档差异一直没有回补：表格断行、表格内未转义竖线、
断点地图的代码行号漂移、排错表缺项、文档索引重复行。本轮**只改文档**，不动任何运行期代码与配置。

| 差异 | 位置 | 处置 |
| --- | --- | --- |
| 表格单元格被折成两行，渲染后该行多出一列 | `docs/forward-auth-design.md` §7.5「封禁维度」行 | 合并为一行 |
| 单元格内的代码片段含未转义 `\|`，被解析成额外列 | `docs/development-roadmap.md` §10.12「计数键」行 | 转义为 `\|` |
| 断点地图行号漂移：`Fill` 已由 155 行移到 169 行 | `docs/debugging.md` §3「请求体缓冲」行 | 更正为 `spool.go:169` |
| 排错行与 `logging.access.allow_level` **默认 `info`（放行也留痕）**矛盾 | `docs/dev-guide.md` §8 | 改写为 `info` / `debug` / `off` 三态语义 |
| 排错表缺少近期行为的条目 | `docs/configuration.md` §5 | 新增 3 行：请求体缺失告警口径（§2.2）、`sites[].engine_mode` 已知限制（§2.5）、放行留痕开关（§2.10） |
| 文档索引里 `docs/dev-guide.md` 被重复列了 5 次 | `README.md` | 去重为 1 行 |

**校验方式（可复跑）**：

1. **表格结构检查**：按每个表格的分隔行推断列数，再逐行统计**未被转义**的 `|` 数量，数量不符即报错——
   本轮开始时命中 2 处（上表前两条），修复后为空。
2. **跨文档引用检查**：抽取全部 `docs/*.md §N.M` 形态的引用，逐个确认目标文件存在该小节——结果为空。

**门禁**：本轮为纯文档改动，代码门禁维持上一轮结论（`gofmt -l` 为空、`go build ./...` 与 `go vet ./...` 退出码 0、
`go test ./... -count=1` 全绿）。

#### 已知边界

| 边界 | 说明 | 处置 |
| --- | --- | --- |
| 表格检查只覆盖「列数不符」 | 无法发现文案层面的口径漂移（例如默认值写错） | 口径漂移仍靠功能改动时同步更新文档 + 人工评审 |
| 行号类引用天然易漂移 | 代码每次增删行都可能让断点地图失效 | 断点地图只保留「函数名 + 关键行」两段信息，函数名始终有效，行号漂移时以函数名为准 |
---

### 10.17 已完成：重建请求的消息框架头还原（`920180` 误报导致 POST 全 403，缺陷修复）

**触发原因（用户反馈）**：站点上「拿不到请求参数」的 POST 请求被返回 **403**，
用户认为「`Content-Length: 0` / 代理没有转发请求体时取不到参数是正常现象，不该触发错误」，
并追问此前是否未修改到位。

#### 复现与根因

实测（用户实例 `configs/waf.example.yaml` + 本机 :9080，以及自建 :9400 实例）：

| 形态 | 修复前 | 说明 |
| --- | --- | --- |
| `POST` + `Content-Length: 0` | `200` | §10.15 已修好，无告警、指标为 0 |
| `POST` + 真实长度与请求体 | `200` | 正常 |
| `GET` 无体 | `200` | 正常 |
| **`POST` 子请求既无 `Content-Length` 也无 `Transfer-Encoding`** | **`403` / `WAF_BLOCKED` / `X-WAF-Rule-Id: 920180`** | 本次修复的对象 |
| `POST` 分块（`Transfer-Encoding: chunked`） | **`403` / `920180`** | 同上 |

访问日志证据：`{"check":"threshold","rule_id":"920180","path":"/api/constant/selectAll.do","method":"POST"}`
（该实例在 14:39 / 14:59 / 17:06 多次出现），且 `waf_requests_total{verdict="block"}` 持续增长。

根因（三个事实叠加）：

1. 鉴权子请求是代理**合成**的报文，其框架头描述的是「代理 → WAF」这一段链路。
   代理没转发请求体时（原生 Nginx `auth_request` 的 `proxy_set_header Content-Length ""`、
   Traefik 未开 `forwardBody`、未做体捕获的 OpenResty 配置），两个框架头都不存在。
2. Go 的 `net/http` 会把 `Transfer-Encoding` 从 `Header` 中剥离（只留 `r.TransferEncoding`），
   并把这种形态的 `ContentLength` 记为 `0`。
3. CRS 的 **920180**（`POST without Content-Length or Transfer-Encoding headers`）恰好以
   「非 HTTP/2+ && POST && 两个框架头都不存在」为判定条件，严重级别 `WARNING`（5 分）
   **正好等于默认评分阈值** → `threshold` 直接 403。

也就是说：**「代理没把请求体送过来」被误判成了「客户端协议违规」**，与 §10.14 / §10.15
要表达的语义正好相反。

#### 本次改动（交付物）

| 能力 | 交付物 | 说明 |
| --- | --- | --- |
| **框架头还原** | `internal/ingress/forwardauth/extractor.go` 的 `restoreFramingHeaders` | 重建请求时补回消息框架头，判定顺序：① 代理已转发任一框架头 → 原样保留；② GET / HEAD / OPTIONS / TRACE → 不补；③ 子请求分块 → 补 `Transfer-Encoding: chunked`；④ 其余 → 补 `Content-Length: 0` |
| **方法判定辅助** | 同文件的 `methodMayCarryBody` | 只排除 RFC 9110 中以「无请求体为常态」的方法；方法无法还原时保守不补，避免编造框架信息 |
| **单元测试** | `internal/ingress/forwardauth/extractor_test.go` 的 `TestExtractRestoresFramingHeaders` | 6 种矩阵：无框架头 / 已声明空体 / 真实长度 / 分块 / GET 无框架头 / auth-only 通道；同时断言不会重复写头 |
| **契约测试** | `test/contract/forwardauth_test.go` 的 `TestPostWithoutFramingHeadersIsNotBlocked`（含裸 TCP 辅助 `doRaw` / `rawAuthRequest`） | 用裸 TCP 构造「无框架头」「分块」两种形态，断言 `200` + `X-WAF-Verdict: allow`；**该用例在修复前稳定复现 403 + `920180`**（已用临时短路反证） |
| **文档** | `docs/forward-auth-design.md` §3.6 / 新增 §3.8、`docs/configuration.md` §2.2 与 §5、`docs/dev-guide.md` 冒烟用例 15 | 说明还原规则、边界与手工验证方式 |

#### 关键设计取舍

| 取舍 | 结论 | 理由 |
| --- | --- | --- |
| 修在哪一层 | 接入还原层（`forwardauth.Extractor`），不在 CRS 侧豁免规则 | 框架头是「还原出的原始请求」的属性；在引擎侧豁免等于把一条真实的协议检查整体关掉，会影响 Traefik `forwardBody` / OpenResty 等能拿到真实框架头的通道 |
| 未知长度该补什么 | 补 `Content-Length: 0` | 对「WAF 实际收到的这条报文」而言它确实不带请求体；补 `Transfer-Encoding: chunked` 会在没有体时谎称分块，且可能干扰其它规则 |
| 无体方法是否补 | **不补** | GET / HEAD 缺框架头是合法形态；盲目补 `Transfer-Encoding` 反而会命中 CRS 920171（GET/HEAD 携带 TE），制造新的误报 |
| 是否影响「请求体缺失」告警 | **不影响** | 告警只看 `core.RawRequest.ContentLength`（§3.7），因此「代理没转发请求体」这个真实故障仍会被 `ingress.body.mode: required` 观测到 |
| 直通形态是否同样处理 | **不处理** | 直通（`direct`）下框架头是客户端原始报文，真实协议违规必须继续命中 |
| 是否新增配置开关 | 不需要 | 与 §10.15 同一取舍：这是「重建报文的语义修正」，不是策略选项 |

#### 验证结果

- **门禁**：`gofmt -l .\cmd .\internal .\test` 为空；`go build ./...` / `go vet ./...` 退出码 0；
  `go test ./... -count=1` 30 个包全绿。
- **真机冒烟**（`bin\waf.exe run -c configs\waf.local.yaml`，:9400/:9401）：
  - 裸 TCP「无框架头 POST」→ `200` + `X-Waf-Verdict: allow`（修复前 403 / 920180）；
  - 裸 TCP「分块 POST」→ `200`；
  - `Content-Length: 0` 的 POST → `200`；`waf_body_missing_total` 保持 **0**；
  - 回归：JSON 体里的 SQLi（`1' OR '1'='1`）→ `403` + `X-Waf-Rule-Id: 942100`，
    证明检测能力未被削弱。
- **文档一致性**：同时修掉 `docs/dev-guide.md` 中 8 处**多余的孤立代码围栏行**（渲染破损，
  属更早几轮插入代码块时遗留），并加了「围栏配对 + 表格列数」两项可复跑的文档结构检查（当前全绿）。

#### 已知边界

| 边界 | 说明 | 处置 |
| --- | --- | --- |
| 直通形态下真正的「无框架头 POST」不再被拦 | 该形态保留客户端原始头，920180 仍会命中，属于预期 | 无需处理 |
| 代理确实没转发请求体时，WAF 看不到请求体内容 | 这是接入形态的固有边界，不是本缺陷 | 由 §3.7 启动能力清单 + `ingress.body.mode` 告警暴露；需要体检测就必须用 Traefik `forwardBody` 或 OpenResty 体捕获通道（R4） |
| `Content-Length: 0` 在此处的含义是「WAF 收到的报文无体」 | 与「客户端声明空体」是两个概念 | 后者由 `Declared` 承载（§10.15），告警语义不受本次改动影响 |

### 10.18 已完成：M4 能力实现（多站点 / 本地情报 / 虚拟补丁 / API 契约 / 站点口令）

**目标**：在 forward-auth 形态不变的前提下，补齐多站点差异化、本地 GeoIP 与威胁情报、
CVE 虚拟补丁、OpenAPI 请求契约校验和本地站点口令保护。

#### 交付总览

| 能力 | 交付物 | 状态 |
| --- | --- | --- |
| P2-1 多站点差异化 | `config.pipelines[]`、`sites[].pipeline`、`sites[].allowlist/blocklist/access_action/access_score`、`internal/pipeline/router.go` | 已完成 |
| P2-1 站点级引擎模式 | `sites[].engine_mode` → Coraza 事务级 `ctl:ruleEngine`（规则 ID `901900+`） | 已完成 |
| P2-2 GeoIP | `internal/geoip`（Country/City MMDB）、`internal/check/geoip`（国家/洲 allow/block + 热更新） | 已完成（真实 MMDB 验收待补） |
| P2-3 本地威胁情报 | `internal/intel`（IP/CIDR、ASN、精确域名、`*.suffix`）、`internal/check/threatintel`（文件/目录 + 指纹热更新） | 已完成 |
| P2-4 虚拟补丁 | `internal/vpatch`：Log4Shell / Spring4Shell / Apache 路径穿越 / PAN-OS 命令注入模板 + 自定义 `.conf` | 已完成 |
| P2-5 站点口令 | `internal/check/challenge`：Basic、签名 Cookie、`basic_or_cookie`；常量时间口令比较 | 已完成基础版 |
| P2-6 API 契约 | `internal/apisec` + `internal/check/apisec`：OpenAPI 3.x、路径/查询/Header/Cookie 参数、JSON 请求体 | 已完成基础版 |

#### 关键设计取舍

| 决策点 | 结论 | 理由 |
| --- | --- | --- |
| 多站点链路选择 | 装配期构建默认链与具名链，请求期按 `rctx.Site.Name` O(1) 选择 | 不在每个请求上重新构造插件；站点名单命中先于校验链执行 |
| 站点级 `engine_mode` | 不重复编译规则集，用 phase 1 的 `ctl:ruleEngine` 按 Host 切换事务模式 | 同一份 CRS 同时服务 `on` / `detection_only` 站点，避免规则集复制 |
| 站点引擎规则 ID | 使用 `901900+` | 避开例外规则 `900300+`、内置 CRS `901001-901500` 与项目其它注入 ID |
| GeoIP 实现 | 自研本地 MMDB 读取与查询，不依赖 `coraza-geoip` | 保持 `CGO_ENABLED=0`，查询与热更新逻辑可控，失败时保留旧 reader |
| 威胁情报格式 | 文本 / CSV / YAML / JSON 统一加载，目录递归扫描 | 便于离线环境导入多家情报源，文件指纹只含路径/大小/修改时间 |
| 虚拟补丁位置 | CRS 规则之后、全局例外之前 | 补丁可独立命中，同时允许通过 `engine.exceptions` 做误报治理 |
| API 契约范围 | 只做请求侧 OpenAPI 3.x 与 JSON Schema 常用子集 | forward-auth 形态看不到业务响应体；先覆盖最常用的契约违规场景 |
| 本地挑战 | Basic + HMAC-SHA256 无状态 Cookie，不维护会话表 | 多实例无需共享会话；不使用弱口令明文落日志 |

#### 验证结果

- `go test ./... -count=1` 全部通过（含新增 router / 站点字段 / 配置校验 / 规则 ID 唯一性测试）。
- `go test ./internal/apisec ./internal/check/apisec ./internal/check/challenge ./internal/intel ./internal/vpatch -count=1` 通过。
- `waf check-config -c configs/waf.example.yaml` 通过。
- 规则 ID 冲突回归：站点 `engine_mode` 规则与作用域例外不再共用 `900300`。

#### 已知边界

| 边界 | 说明 |
| --- | --- |
| GeoIP 数据集 | 只支持本地 MaxMind MMDB；G4 需要部署方提供真实 GeoLite2 Country/City 与 ASN 数据 |
| ASN 情报刷新 | 情报文件按指纹轮询；ASN MMDB 自身更新需等待同一刷新周期触发 |
| `apisec` | 只做请求侧；只支持 OpenAPI 3.x、JSON 请求体和 `components.schemas` 的本地 `$ref`；不执行完整 `format` 语义，不校验 XML / multipart 结构 |
| `challenge` | 不是 CAPTCHA / JS 无感挑战；Nginx 原生 `auth_request` 默认不透传 `Set-Cookie`，Cookie 模式需 Traefik / OpenResty 配合 |
| 自定义虚拟补丁 | 按行拆分，不处理跨行 `chain` 续行；复杂规则建议写成单行或使用 `engine.inline_directives` |
