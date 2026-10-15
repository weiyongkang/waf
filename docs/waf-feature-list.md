# WAF 功能列表（Go + OWASP Coraza，离线环境）

> 调研时间：2026-10
> 目标：为「Go + Coraza 引擎 + 完全离线部署」的自研 WAF 界定功能范围与优先级
> 仓库内可复用资产：`reference/coraza-traefik-WAF`（Coraza forward-auth 参考实现）、`reference/honeypot`（限流 / IP 封禁 / 告警通知可复用组件）

---

## 1. 调研对象

### 1.1 开源引擎（技术同源，优先级最高）

| 项目 | 定位 | 与本方案的关系 |
| --- | --- | --- |
| OWASP Coraza v3 | Go 编写的企业级 WAF 引擎，支持 ModSecurity SecLang，100% 兼容 OWASP CRS v4 | 本方案的检测内核 |
| OWASP CRS v4（当前 4.29.x，另有 4.25.x LTS 线） | 通用攻击检测规则集，Apache-2.0 | 事实标准规则基线，直接复用 |
| OWASP ModSecurity v3 | Coraza 的规则语言来源，SecLang 事实规范 | 规则语法兼容目标（非运行时依赖） |
| SafeLine 雷池 | 自托管商业开源 WAF（Go），含 Web 控制台 | 功能与交互的主要对标对象 |
| RuiQi | 基于 HAProxy + Coraza SPOA 的 WAF 管理平台 | 架构与「引擎 + 管理面」分层的主要参考 |
| coraza-coreruleset / CRS Plugin Registry | CRS 的 Go 模块化封装与官方插件注册表 | 离线打包规则与扩展的事实通道 |

### 1.2 商业 / 云 WAF（功能完备性对标）

| 产品 | 代表性能力（与本方案相关的部分） |
| --- | --- |
| Cloudflare WAF | 托管规则集、自定义规则表达式、速率限制规则、WAF 攻击评分（ML）、Bot 评分、泄露凭据检测、AI 应用安全（提示注入 / PII）、Application Profiles（schema 基线）、攻击特征检测、日志模式 vs 生产模式、Skip 动作 |
| AWS WAF | 规则语句与 AND/OR/NOT 嵌套、scope-down 语句、标签（label）传递、托管规则组、Count/Block/Allow/CAPTCHA/Challenge 动作、IP Set、Regex Pattern Set、地理匹配、基于速率的规则、自定义响应、日志外送 |
| 阿里云 / 腾讯云 WAF | 域名接入、CC 防护与频次控制、Bot 管理、IP/地域封禁、Web 漏洞防护（虚拟补丁）、业务风控、报表与大屏 |
| F5 / Imperva / Wallarm 等 | 正向/负向安全模型、虚拟补丁、API 发现与保护、Bot 管理、DDoS 与 L7 联动 |

### 1.3 评估基线

- **OWASP Top 10**：CRS 的检测目标基线（SQLi、XSS、RCE、LFI、RFI、PHP/Java 注入、协议攻击、扫描器、会话固定、数据泄露等）。
- **PCI DSS v4.0 6.4.1 / 6.4.2**：面向公网的 Web 应用需被防护；可用自动化技术方案（即 WAF）作为持续防护手段。
- **WASC WAFEC**（Web Application Firewall Evaluation Criteria）：历史评估框架，可作为「功能完备性」的对照清单。

---

## 2. 市场功能全景

图例：`✅` Coraza 原生 / `🔌` 有现成插件或库 / `🛠` 需自研 / `⚠️` 离线环境下受限或需替代方案

### 2.1 检测与规则

| 功能域 | 市场常见做法（举例） | 本方案支撑 | 优先级 |
| --- | --- | --- | --- |
| 签名/正则规则引擎 | ModSecurity SecLang、自定义表达式语言 | ✅ SecLang（`SecRule`/`SecAction`/`Include`/`SecDefaultAction`） | P0 |
| 规则集基线 | 托管规则集（Cloudflare Managed / AWS Managed Rules） | ✅ OWASP CRS v4（离线随二进制分发） | P0 |
| 异常评分模型 | 入站/出站异常分数阈值 | ✅ CRS 评分机制（PL1–PL4、阈值可调） | P0 |
| 规则编排与流程控制 | 规则组、标签、scope-down、跳过 | ✅ `chain`、`skip`/`skipAfter`、`SecMarker`、`tag`、`ctl` | P0 |
| 规则热更新 | 控制台下发即时生效 | ✅ `fsnotify` 监听 + 原子替换引擎（参考 `reference/coraza-traefik-WAF`） | P0 |
| 规则灰度与回滚 | 规则集版本管理、按站点生效 | 🛠 规则包版本化 + 回滚 | P1 |
| 规则误报治理 | 误报上报、例外管理、按 tag/id/target 排除 | ✅ `SecRuleRemoveByID/Msg/Tag`、`SecRuleUpdateTargetByTag` | P0 |
| 规则命中统计 | 规则有效性评分 | 🛠 基于审计日志聚合 | P1 |
| 自定义检测算子 | 规则语言扩展 | ✅ 插件机制（Go 接口）+ 自定义 operator/action | P1 |
| 语义/ML 检测 | WAF 攻击评分（ML）、智能规则生成 | ⚠️ 云端模型不可用；可用本地 libinjection + 离线模型替代 | P2 |
### 2.2 协议与请求处理

| 功能域 | 市场常见做法 | 本方案支撑 | 优先级 |
| --- | --- | --- | --- |
| HTTP 协议合规 | 方法白名单、请求头校验、Host/Content-Length 校验 | ✅ CRS 920/921 系列 | P0 |
| 请求体解析 | JSON / 表单 / multipart / XML | ✅ `SecRequestBodyAccess`、JSON 深度限制、multipart 解析 | P0 |
| 请求体限额 | 内存/磁盘阈值与超限动作 | ✅ `SecRequestBodyLimit`、`SecRequestBodyInMemoryLimit`、`SecRequestBodyLimitAction` | P0 |
| 上传文件处理 | 上传目录、文件保留、外部检查 | ✅ `SecUploadDir`、`SecUploadKeepFiles`、`@inspectFile` | P1 |
| 响应体检查 | 泄露检测、敏感信息防外泄 | ✅ `SecResponseBodyAccess`、MIME 白名单、`SecResponseBodyLimit` | P1 |
| 请求规范化 | URL/Unicode/编码解码、路径归一 | ✅ 内置 transformations（`t:` 系列，含 base64/hex/htmlEntityDecode 等） | P0 |
| HTTP/2、gzip/brotli | 现代协议与压缩体检测 | ✅ 压缩体处理（另有 `body-decompress` 插件）；🔌 协议层由接入层负责 | P1 |
| WebSocket / SSE 透传 | 长连接不被误伤 | 🛠 接入层需跳过体检查（参考实现已有 `isWebSocketRequest` 判断） | P1 |
| 防盗链 / 静态资源豁免 | 排除图片、视频等二进制大流量 | 🛠 按 Content-Type / 路径跳过体检测 | P1 |

### 2.3 攻击类型覆盖（CRS 分类）

| 类别 | 覆盖内容 | 优先级 |
| --- | --- | --- |
| SQL 注入（SQLi） | 特征 + libinjection `@detectSQLi` + 指纹识别 | P0 |
| 跨站脚本（XSS） | 特征 + libinjection `@detectXSS` | P0 |
| 远程命令执行（RCE）/ 命令注入 | Unix/PowerShell 命令字典型检测 | P0 |
| 本地/远程文件包含（LFI/RFI） | 路径穿越、协议包装器 | P0 |
| PHP / Java 注入 | 函数名、变量、错误信息特征 | P0 |
| 协议攻击 | 请求走私、响应拆分、HTTP 参数污染（HPP） | P0 |
| 扫描器 / 爬虫识别 | 指纹库 + 行为特征 | P1 |
| 会话固定 / 会话劫持 | CRS 943 系列 | P2 |
| 数据泄露（响应侧） | SQL/Java/PHP/IIS 错误页、WebShell 回显 | P1 |
| 漏洞虚拟补丁 | 针对具体 CVE 的定向规则 | P1 |
| XXE / SSRF / SSTI / 反序列化 | 部分由 CRS 覆盖，其余需自定义规则 | P1 |
### 2.4 访问控制与反自动化

| 功能域 | 市场常见做法 | 本方案支撑 | 优先级 |
| --- | --- | --- | --- |
| IP 黑白名单 | IP / CIDR 集合、批量导入 | ✅ `@ipMatch` + 自研名单管理；🛠 持久化与导入 | P0 |
| 地域封禁 | GeoIP 定位、国家级拦截 | 🔌 `coraza-geoip` 插件（本地 MaxMind MMDB，完全离线可用）+ `@geoLookup` / `GEO` 变量 | P1 |
| IP 信誉库 | 云威胁情报 | ⚠️ 本地 IP/CIDR 情报库 + 内网 DNSBL（`@rbl` 走 DNS，离线必须指向内网服务或停用） | P1 |
| 速率限制 / CC 防护 | 按 IP/URL/Header 维度的频次与并发控制 | 🛠 复用 `reference/honeypot/internal/ratelimit`，扩展为多维度令牌桶 | P0 |
| 暴力破解防护 | 登录接口频次、失败计数、锁定 | 🛠 基于 `TX` 变量 + 本地计数（注意 Coraza `initcol` 为内存态） | P0 |
| 人机校验 / 反 Bot | CAPTCHA、JS 挑战、无感挑战 | ⚠️ 无云端 Bot 指纹库；🛠 本地挑战页 + UA/IP/行为启发式 | P2 |
| 访问认证挑战 | 站点级口令（预发/内网保护） | 🛠 Basic Auth / Cookie 挑战 | P2 |
| 封禁联动 | 自动封禁 IP、与防火墙联动 | 🛠 复用 `reference/honeypot/internal/firewall`（iptables / firewalld / ufw）+ 定时解封 | P0 |
| 限速与封禁的可观测 | 封禁列表、解封、误封申诉 | 🛠 管理面提供 | P1 |

### 2.5 响应侧与内容安全

| 功能域 | 市场常见做法 | 本方案支撑 | 优先级 |
| --- | --- | --- | --- |
| 自定义拦截页 | 403 页面 / 自定义响应体 | ✅ `deny,status:` / `redirect` / `block`；🛠 品牌化错误页 | P0 |
| 敏感信息脱敏 | 响应体过滤、掩码 | ✅ `SecResponseBodyAccess` + 自定义规则；🛠 脱敏算子 | P2 |
| 防爬虫动态防护 | HTML/JS 动态加密（SafeLine Dynamic Protection） | 🛠 需自研（离线可做，但成本高） | P2 |
| 恶意文件查杀 | 上传文件病毒扫描 | 🔌 CRS `antivirus` 插件（对接本地 ClamAV，离线可用） | P1 |
| 防篡改 / 网页水印 | 内容完整性校验 | 🛠 可选 | P2 |
### 2.6 日志、告警与运营

| 功能域 | 市场常见做法 | 本方案支撑 | 优先级 |
| --- | --- | --- | --- |
| 审计日志 | 完整事务记录、取证 | ✅ `SecAuditEngine` + `SecAuditLogParts`，格式支持 `Native`/`JSON`/`JsonLegacy`/`OCSF` | P0 |
| 结构化访问/安全日志 | JSON 行日志、按日轮转 | 🛠 复用 `reference/honeypot/internal/logger`（按日切分 JSON 日志） | P0 |
| 日志本地留存 | 保留周期、容量控制、清理 | 🛠 自研（离线无对象存储可依赖） | P0 |
| 指标监控 | QPS、拦截率、时延、规则命中 | ✅ Prometheus 指标（参考实现已具备 counters/histogram）；🛠 本地 Prometheus/VictoriaMetrics | P0 |
| 告警通知 | 邮件 / IM / Webhook | 🛠 复用 `reference/honeypot/internal/notify`（企业微信 / 通用 JSON / HFish / HoneyWire），扩展钉钉/飞书/SMTP | P0 |
| 告警降噪与聚合 | 批量推送、抑制窗口 | 🛠 复用 `PushIntervalSec` 批量间隔思路 | P1 |
| 攻击态势可视化 | 攻击地图、Top 攻击源、趋势 | 🛠 本地大屏（无云端） | P1 |
| 报表导出 | 日报/周报、合规报表 | 🛠 PDF/CSV 本地导出 | P2 |
| 溯源与取证包 | 一键导出请求全文 | 🛠 基于审计日志 | P1 |

### 2.7 平台、部署与运维

| 功能域 | 市场常见做法 | 本方案支撑 | 优先级 |
| --- | --- | --- | --- |
| 接入形态 | 反向代理 / 旁路 / 插件 | 🛠 反向代理（推荐）/ forward-auth / Go 中间件库 / HAProxy SPOE | P0 |
| 多站点 / 多域名 | 按域名绑定策略 | 🛠 站点级策略路由 | P1 |
| TLS 卸载与证书 | 证书管理、SNI | 🛠 支持 PEM 载入 + 内网 CA；⚠️ 无 ACME（离线） | P0 |
| 配置管理 | 控制台可视化配置 | 🛠 本地 Web UI + 配置文件双通道 | P0 |
| 配置热加载 | 改配置不重启 | ✅ 规则热加载；🛠 业务配置热加载 | P0 |
| 高可用 | 双机热备、集群 | 🛠 无状态化 + Keepalived/VIP 或前置 LB | P1 |
| 水平扩展 | 多实例共享策略 | 🛠 配置文件分发或只读共享存储 | P2 |
| 用户与权限 | RBAC、多租户 | 🛠 本地账号 + RBAC（可对接内网 LDAP/AD） | P1 |
| 操作审计 | 管理员操作留痕 | 🛠 自研 | P1 |
| 性能与容量 | 吞吐、并发、时延目标 | ✅ 引擎性能可参考 Coraza Benchmarks；🛠 需自建压测基线 | P0 |
| 版本升级 | 灰度、回滚 | 🛠 离线二进制替换 + 双版本共存 | P1 |
---

## 3. 离线环境带来的约束与对策

离线是**架构级约束**，会直接砍掉一批云 WAF 的核心卖点。以下为必须提前设计的能力：

| 约束 | 影响的能力 | 对策 |
| --- | --- | --- |
| 无法自动更新规则 | 托管规则集、虚拟补丁、0day 应急 | 规则包离线导入：`tar.gz` + SHA256/GPG 校验 + 版本号 + 一键回滚；CRS 用 Go 模块 `go:embed` / `coraza-coreruleset` 编入二进制 |
| 无法查询云端威胁情报 | IP 信誉、Bot 指纹、泄露凭据库 | 本地情报库（CIDR/ASN/域名 txt、CSV、MMDB）定期介质摆渡导入；`@rbl` 指向内网 DNSBL，或直接停用该算子 |
| 无云端 GeoIP API | 地域封禁、攻击地图 | `coraza-geoip` 插件 + 本地 MaxMind GeoLite2 `mmdb`（country/city 两种库） |
| 无云端 ML / 攻击评分 | WAF Attack Score、智能检测 | 用 `@detectSQLi`/`@detectXSS`（libinjection）+ CRS 异常评分替代；如确有需要，本地推理模型 |
| 无云端沙箱 / 威胁分析 | 恶意文件与 URL 分析 | 本地 ClamAV（unix socket）+ `@inspectFile`（CRS `antivirus` 插件） |
| 无公网证书签发 | TLS 证书 | 内网 CA 签发 + 证书过期告警；证书与 CRL/OCSP 全部本地 |
| 无外发遥测 | 使用统计、健康上报 | 全部指标/日志本地闭环；提供「是否外联」自检 |
| 依赖管理受限 | 构建、升级 | `go mod vendor` 或预置 module cache；离线镜像 `docker save/load`；优先纯 Go（`CGO_ENABLED=0`），需 CGO 的依赖提前固化 |
| 时间同步 | 证书校验、JWT、会话、日志时序 | 内网 NTP，并在无 NTP 时明确降级策略 |
| 许可与授权 | 商业组件激活 | 离线授权文件（含有效期/机器指纹），不联网校验 |
| 告警通道 | 短信/云 IM | 内网企业微信/钉钉/飞书机器人、内网 SMTP、Syslog |

---

## 4. 功能列表（按交付阶段）

### P0 — MVP（可用、能扛住真实流量、可运维）

1. **接入层**：HTTP/HTTPS 反向代理，支持 TLS（PEM/内网 CA）、Host/路径路由、WebSocket/SSE 透传、请求体限额与超时控制。
2. **检测引擎**：Coraza v3 + OWASP CRS v4，异常评分模式，Paranoia Level 可配（默认 PL1）。
3. **规则管理**：`Include` 目录化加载、确定性加载顺序、`SecRuleEngine On/DetectionOnly` 全局与站点级切换、规则热加载（`fsnotify` + 引擎原子替换，加载失败保留旧引擎）。
4. **旁路/观察模式**：先用 DetectionOnly 跑一段时间，输出「若拦截」清单，用于压误报。
5. **访问控制**：IP/CIDR 黑白名单（`@ipMatch`）、方法/路径白名单、UA 白名单。
6. **限速与 CC**：按 IP、按 IP+URL 的滑动窗口/令牌桶限速；登录接口失败计数与临时锁定。
7. **自动封禁**：超阈自动封禁（内存黑名单 + 可选下发 iptables/firewalld/ufw），带 TTL 自动解封与手工解封。
8. **审计日志**：Coraza 审计日志（JSON 格式）+ 自研结构化安全日志，按日轮转、保留周期与容量上限。
9. **日志脱敏**：默认不落完整 Cookie/Authorization/证件号等敏感字段。
10. **指标**：Prometheus 指标（QPS、拦截数、按规则 ID 命中、时延直方图、引擎重载次数）。
11. **告警**：内网 webhook（企业微信/通用 JSON）+ Syslog；告警聚合与抑制。
12. **配置**：YAML 配置文件 + 环境变量覆盖；配置校验、失败快速退出。
13. **运维**：健康检查端点、优雅关停、`/metrics`、日志级别动态调整。
14. **离线交付**：单二进制（`CGO_ENABLED=0`）+ 容器镜像 tar；CRS 规则 `go:embed` 或随包分发。

### P1 — 生产加固

15. **规则包离线升级**：签名校验、版本清单、灰度、一键回滚，支持按站点差异化。
16. **误报治理**：控制台例外管理（按 rule id / tag / target / URL），例外生效即时且可审计。
17. **GeoIP 地域控制**：`coraza-geoip` + 本地 MMDB，支持国家级/地区级放行与拦截。
18. **本地威胁情报**：CIDR / ASN / 域名情报导入，定时与引擎联动刷新。
19. **响应侧防护**：错误页信息泄露、WebShell 回显、敏感数据外泄检测。
20. **文件上传安全**：上传目录隔离、类型/大小限制、ClamAV 扫描。
21. **虚拟补丁**：已有 CVE 的定向规则模板与一键启用。
22. **多站点策略**：按域名/端口绑定规则集、限速策略、黑白名单。
23. **管理面（本地 Web UI）**：仪表盘、攻击日志检索、规则开关、名单管理、系统状态；本地账号 + RBAC。
24. **攻击态势可视化**：Top 攻击源 IP/国家、攻击类型分布、趋势图、原始请求取证包导出。
25. **高可用**：无状态化、配置外置、VIP/前置 LB 方案与切换演练。
26. **性能基线**：压测脚本与容量模型（目标 QPS / 并发 / P99 时延），确定规则规模上限。
27. **离线升级流程**：二进制/镜像替换、双版本共存、回滚预案。

### P2 — 增强（按需）

28. 本地人机校验（JS/无感挑战）与站点口令保护。
29. API 安全：OpenAPI/Schema 基线校验（`@validateSchema`、`@restpath`）、接口资产发现。
30. 会话安全：会话固定/劫持检测、Cookie 属性校验。
31. 敏感数据脱敏（响应侧掩码）。
32. 合规报表：PCI DSS 6.4.2 证据链、月度安全报表导出。
33. 动态防护（HTML/JS 加密）与防篡改。
34. 离线模型推理（异常行为、Bot 打分）。
35. 多租户与租户级配额。
---

## 5. Coraza 能力边界（据此判断「自研 or 复用」）

### 5.1 原生可直接用

- 规则语言：`SecRule`、`SecAction`、`SecDefaultAction`、`Include`（支持 glob 与 `@owasp_crs/` 别名）、`SecMarker`、`SecRuleEngine`。
- 动作：`allow` `block` `deny` `drop` `pass` `redirect` `status` `chain` `skip` `skipAfter` `ctl` `setvar` `setenv` `initcol` `expirevar` `capture` `t` `log` `nolog` `auditlog` `noauditlog` `logdata` `msg` `tag` `severity` `id` `rev` `ver` `maturity` `multimatch` `exec`。
- 算子：`@rx`（RE2）`@pm` `@contains` `@beginsWith` `@endsWith` `@streq` `@strmatch` `@within` `@eq/@ge/@gt/@le/@lt` `@ipMatch` `@detectSQLi` `@detectXSS` `@validateByteRange` `@validateUtf8Encoding` `@validateURLEncoding` `@validateNid` `@validateSchema` `@restpath` `@inspectFile` `@fuzzyHash` `@noMatch` `@unconditionalMatch` `@rbl`。
- 审计：`SecAuditEngine` / `SecAuditLogParts` / `SecAuditLogFormat`（Native、JSON、JsonLegacy、OCSF）/ 并发与串行模式。
- 请求与响应：体限额、内存限额、JSON 深度限制、multipart、上传目录、响应体 MIME 白名单。
- 运维友好：纯 Go、可 `CGO_ENABLED=0`；支持 FIPS 140-3 模式（此时 `t:md5`/`t:sha1` 受限）；官方集成 Caddy、proxy-wasm/Envoy、Traefik WASM、HAProxy SPOE、libcoraza(nginx)。

### 5.2 需要插件或自研

| 需求 | 结论 |
| --- | --- |
| GeoIP 地域判断 | 官方 `coraza-geoip` 插件 + 本地 MMDB（离线可用） |
| 病毒扫描 | CRS `antivirus` 插件（本地 ClamAV） |
| 请求体解压（多层） | CRS `body-decompress` 插件 |
| 多重编码绕过 | CRS `auto-decoding` 插件 |
| 框架误报例外 | CRS `wordpress/drupal/nextcloud/dokuwiki/cpanel/xenforo` rule-exclusions 插件 |
| 域名/账号相关检测 | CRS `google-oauth2`、`fake-bot` 插件 |
| 限速 / 并发控制 / 封禁 | 引擎外自研（复用 `reference/honeypot` 的 ratelimit + firewall） |
| HTTP 服务、TLS、路由、连接管理 | 自研接入层（`net/http` + `httputil.ReverseProxy` 或 fasthttp） |
| 管理面、配置持久化、RBAC、报表 | 自研 |
| 告警通道 | 自研（复用 `reference/honeypot/internal/notify`） |

### 5.3 已知缺口（不要踩坑）

- `FILES_TMP_CONTENT` 变量 Coraza **未实现**；上传内容检查走 `@inspectFile` / `FILES_TMPNAMES`。
- `GEO` 集合**必须**先有 `coraza-geoip` 插件与 `@geoLookup`，否则为空。
- `@rbl` 依赖 DNS 查询（含 500ms 超时），离线环境必须改指内网 DNSBL 或停用。
- `initcol`/`expirevar` 为**内存态**，不保证跨重启持久化，不能作为长期计数的唯一存储。
- 无内置 ML 攻击评分、无内置 Bot 指纹库、无内置 CAPTCHA、无内置会话保护。
- 引擎内**不含**反向代理、TLS、连接池、限速，这些都在引擎之外。

---

## 6. 建议的部署形态

| 形态 | 适用场景 | 能力差异 |
| --- | --- | --- |
| **反向代理（推荐）** | 独立 WAF 网关，多后端站点 | 可完整处理请求体 + 响应体；需自研 TLS/路由/连接管理 |
| **forward-auth** | 已有 Nginx/Traefik/APISIX，做前置校验 | 只能看 Header/URL，**看不到请求体**，无法做响应侧检测（参考实现即此形态） |
| **Go 中间件库** | 自有 Go 服务内嵌 WAF | 零额外跳数，但需改造业务代码，升级耦合 |
| **HAProxy SPOE** | 已有 HAProxy，流量大 | 请求/响应头可查，体处理能力受限；参考 RuiQi |

> 若必须覆盖「请求体 + 响应体 + 上传文件」，选反向代理形态。

---

## 7. 验收与测试

| 项目 | 方法 |
| --- | --- |
| 规则正确性 | `go-ftw` 跑 CRS 官方回归用例（离线，用例随模块分发） |
| 规则调试 | 自建 Coraza Playground 离线实例 |
| 防护有效性 | 离线靶场（DVWA / OWASP Juice Shop / vulhub）批量验证拦截率 |
| 误报评估 | DetectionOnly 阶段采集真实或回放流量，统计「若拦截」比例与规则分布，再定阈值/例外 |
| 绕过测试 | 编码/变形/分块/参数污染等规避手法回归 |
| 性能 | 压测工具（wrk/hey/k6 离线）测 QPS、并发、P99；锁定规则规模与 PL 等级 |
| 回归 | 规则包升级前后跑同一用例集，防止规则变更引入回归 |

**建议量化指标**：已知攻击拦截率、误报率（False Positive Rate）、P99 时延增量、单实例 QPS、规则加载耗时、引擎重载成功率。

---

## 8. 参考来源

- OWASP Coraza：<https://github.com/corazawaf/coraza> / <https://coraza.io/docs/>
- Coraza Seclang 指令、算子、动作、变量：<https://coraza.io/docs/seclang/>
- coraza-coreruleset（CRS Go 模块化封装）：<https://github.com/corazawaf/coraza-coreruleset>
- coraza-geoip 插件：<https://github.com/corazawaf/coraza-geoip>
- OWASP CRS：<https://coreruleset.org/> / <https://github.com/coreruleset/coreruleset>
- CRS 插件注册表：<https://github.com/coreruleset/plugin-registry>
- Cloudflare WAF 文档：<https://developers.cloudflare.com/waf/>
- AWS WAF 文档：<https://docs.aws.amazon.com/waf/>
- SafeLine 雷池：<https://github.com/chaitin/SafeLine>
- RuiQi WAF：<https://github.com/HUAHUAI23/RuiQi>
- 本仓库参考实现：`reference/coraza-traefik-WAF`、`reference/honeypot`