# WAF（forward-auth 前置校验 · Nginx + Traefik · 含请求体检测）

基于 **OWASP Coraza + CRS** 的可插拔 WAF，以 **forward-auth 前置校验**形态接入已有的
Nginx / Traefik 入口，**不承担反向代理职责**（不接管业务流量、不做 TLS 卸载与路由转发）。

- 纯 Go、`CGO_ENABLED=0` 静态单二进制，无动态加载，适配离线/内网环境
- 双代理支持：**Traefik >= v2.11**（`forwardBody`）与 **Nginx(OpenResty)**（`ngx.location.capture`）
- **请求体检测**为一等能力（按需读体 + 流式 + 全量限额可配置）
- 全部功能项与插件**配置化启停**，同类型可多实例**串联**执行
- 限速计数与内部封禁走**共享存储**（Redis），未启用则自动降级本地存储
- 封禁只在 WAF 内部生效，**不执行任何系统防火墙操作**
- 拦截统一返回 **JSON 错误体**（不提供拦截页面），通过**鉴权响应头 + 代理侧渲染**送达
- 日志分**系统日志 / 访问日志**两类，分级、JSON 格式

## 文档

| 文档 | 内容 |
| --- | --- |
| `docs/waf-feature-list.md` | 功能全景、市场对标、Coraza 能力边界、部署形态建议 |
| `docs/forward-auth-design.md` | 部署形态、双代理接入矩阵、请求体检测方案、抽象接口、配置启用方案、第一步详案与验收标准 |
| `docs/development-roadmap.md` | 开发优先级（P0/P1/P2/P3）、阶段划分（M0–M5）、逐文件交付清单、WBS 与关键路径、实施记录 |
| `docs/configuration.md` | 配置手册：三通道与优先级、**全量配置项**、插件 `settings` 参考、常见组合、排错速查 |
| `docs/operations.md` | 运维手册：上线前动作、告警接入与验证、误报压降流程、封禁运维、容量规划、巡检与应急预案 |
| `docs/dev-guide.md` | 开发手册：环境准备、构建、三种运行入口、冒烟验证清单、分层测试、打包与离线交付、CI 与排错 |
| `docs/debugging.md` | 调试手册：VS Code / Delve / GoLand 断点调试，以及「WAF 到底看到了什么参数」的断点地图 |

## 快速开始

```bash
# 查看版本
waf version

# 校验配置并输出「生效配置 + 逐项来源摘要」
waf check-config -c configs/waf.example.yaml

# 启动服务（生产基线配置；需要 Redis，见 docker-compose.yml）
waf run -c configs/waf.example.yaml

# 本地测试（无任何外部依赖：内存存储 + 内置嵌入 CRS）
waf check-config -c configs/waf.local.yaml
waf run         -c configs/waf.local.yaml

# 运维报表（读取访问日志，完全离线）与导出
waf report detection --since 24h
waf report attack --since 24h --top 20
waf report ban --since 24h --format xlsx --out ban.xlsx

# 规则包运维
waf rules list
waf rules verify --dir rules/crs
```

### 配置三通道与优先级

优先级由高到低：**CLI > 配置文件 > 环境变量 > 内置默认值**。
命名由配置路径机械推导，一一对应：

| 通道 | 形式 | 示例 |
| --- | --- | --- |
| CLI | `--路径（点转横线）` | `--ban-default-ttl=2h`、`--set server.listen=:9081` |
| 配置文件 | YAML，可多次 `-c`（后者覆盖前者） | `ban: { default_ttl: 2h }` |
| 环境变量 | `WAF_` + 路径大写（点转下划线） | `WAF_BAN_DEFAULT_TTL=2h` |

> 注意：本项目的优先级与 `reference/honeypot` **相反**（honeypot 是环境变量最高）。
> 照搬其运维经验会导致配置不生效。

结构化列表（`pipeline` / `stores` / `notifiers` / `sites`）只能写在配置文件里。

## 代理接入

| 代理 | 配置文件 | 能力 |
| --- | --- | --- |
| Traefik >= v2.11 / v3.x | `deploy/forward-auth/traefik-forwardauth.yml` | 原生体转发（`forwardBody`）；错误体经 `errors` 中间件回源 `/waf/deny` |
| Nginx(OpenResty) | `deploy/forward-auth/nginx-openresty.conf` + `waf_auth.lua` | 推荐形态：可回写 JSON 错误体，直接得到正确对外状态码 |
| Nginx(原生) | `deploy/forward-auth/nginx-auth-only.conf` | 仅作兜底：**无体检测、无 WAF 原生错误体**，状态码统一 403 |

WAF 对外契约：`200` 放行 / `403` 拦截（真实语义在 `X-WAF-Code`）/
`401` 认证 / `429` 限速 / `400` 请求不合规 / `503` 失败关闭，
并回传 `X-WAF-Request-Id`、`X-WAF-Verdict`、`X-WAF-Code`、`X-WAF-Rule-Id`。

## 构建与离线交付

```bash
# 本地构建（注入版本信息）
scripts/build.sh

# 离线打包：静态二进制 + 镜像 tar + module 缓存 + 校验和
scripts/build-offline.sh

# 容器编排（waf + redis）
cp configs/waf.example.yaml configs/waf.yaml
docker compose up -d
```

镜像采用多阶段构建 + distroless 非 root 运行，`HEALTHCHECK` 直接调用 `waf healthz`
（不依赖镜像内的 curl/wget）。

## 目录结构

```
cmd/waf/                    # 入口与子命令（run / check-config / version / healthz /
                            #   ban / rules / report）
internal/core/              # 领域模型与契约：Verdict / Result / Check / Registry / Store /
                            #   Decider / Notifier / AlertSink
internal/config/            # 三通道配置、优先级叠加、校验与来源摘要
internal/server/            # forward-auth HTTP 服务与路由
internal/responder/         # JSON 错误体与 /waf/deny 渲染端点
internal/logging/           # 系统日志与访问日志（slog JSON + 按天/按大小轮转）
internal/ingress/           # 双代理请求还原（forwardauth）与请求体缓冲 / 解压（body）
internal/pipeline/          # 串联执行器：按 phase + order 排序、短路、on_error、按需读体
internal/store/             # 共享存储抽象：memory / file / redis（standalone/sentinel/cluster）
internal/check/             # 插件实现：passthrough / ipaccess / banlist / ratelimit /
                            #   threshold / autoban / coraza / ...
internal/rules/             # CRS 离线包治理、目录指纹热加载、误报例外编译
internal/sites/             # 站点解析与站点级策略覆盖
internal/notify/            # 告警外送：扇出 / 抑制 / 重试 + webhook / wechat / syslog / smtp
internal/notifycfg/         # 「配置 → 告警管理器」映射（生产与契约测试共用）
internal/observe/           # Prometheus 指标与离线报表导出（report：CSV / xlsx）
internal/fsx/               # 受限额保护的流式文件读取原语
internal/version/           # 版本信息（ldflags 注入）
configs/waf.example.yaml    # 完整示例配置
deploy/forward-auth/        # Nginx / Traefik 接入配置
scripts/bench/             # 离线压测脚本（wrk / hey / k6 / .NET builtin）与容量模型
```

## 开发进度

按 `docs/development-roadmap.md` 推进，当前 **M0 – M3 全部完成**，门禁 **G0 / G1 / G2 / G3 全部通过**
（P0 与 P1 级需求已闭环，具备生产上线条件）：

- **M0 / M1（MVP 闭环）**：工程骨架与规范门禁、核心契约（`internal/core`）、三通道配置体系与来源摘要、
  `check-config` / `version` / `healthz` / `run` / `ban` 子命令、JSON 错误体与 `/waf/deny`、
  双类 JSON 日志（含轮转）、双代理接入配置、Docker/离线打包脚本、CI 与单元测试；
  接入适配器、请求体缓冲（含限额与超限策略）、串联执行器、共享存储与内置插件
  （`banlist` / `ipaccess` / `ratelimit` / `coraza` / `threshold` / `autoban`）、Prometheus 指标。
- **M2（检测引擎生产化）**：CRS 离线包治理（`waf rules manifest|verify|install|rollback`）、
  规则热加载与引擎原子替换、Paranoia Level + 评分阈值、误报例外（全局 / 作用域，可审计）、
  压缩体解压、DetectionOnly 试运行闭环（`waf report detection`）、`go-ftw` 兼容用例离线回归。
- **M3（运营与告警）**：告警外送（`webhook` / `wechat` / `syslog` / `smtp` 四通道并联扇出 +
  聚合抑制 + 重试，`notify` / `notifiers` 配置化）、封禁运维报表（`waf report ban`）、
  报表导出（`--format csv|xlsx --out`，Excel 可直接打开）、离线压测脚本与容量模型
  （`scripts/bench/*`），以及 `docs/operations.md` 运维手册。
- **未开始**：M4（多站点策略 / GeoIP / 本地情报）与 M5（管理面，已下调为 P3，不阻塞 M4）。

## 许可

见 `LICENSE`。