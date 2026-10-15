# WAF 运维手册（告警接入 · 误报压降 · 封禁运维 · 容量规划）

> 版本：v1.0（对应里程碑 M3 / 门禁 G3）
> 配套文档：`docs/configuration.md`（配置项逐项说明）、`docs/forward-auth-design.md`（架构与设计）、`docs/development-roadmap.md`（阶段与验收）
> 适用范围：forward-auth 前置校验形态（Nginx/OpenResty 与 Traefik ≥ v2.11）

本手册只回答一件事：**上线之后每天该做什么、出问题先看什么、什么时候该扩容**。
配置项的含义与取值一律以 `docs/configuration.md` 为准，本手册不重复列举。

---

## 1. 上线前的一次性动作

| 步骤 | 命令 / 动作 | 期望结果 |
| --- | --- | --- |
| 1 | `waf check-config -c /etc/waf/waf.yaml` | 退出码 0；输出末尾能看到「生效配置」，且未注册的 `type` 会在这一步暴露 |
| 2 | 用 `configs/ftw/*.yaml` 在测试环境跑一遍（`go test ./test/ftw/ -v`） | 10 个阶段全绿 |
| 3 | 以 `engine.mode: detection_only` 灰度上线 | 只记录 `would_block`，不真正拦截 |
| 4 | `waf report detection --since 24h`，连续观察 3–7 天 | 「若拦截」比例稳定且样例复核无大规模误报 |
| 5 | 切到 `engine.mode: on`，同时开启告警外送（第 2 节） | 拦截有日志、有指标、有告警 |

> **不要跳过第 3 步**。CRS 的误报率与业务形态强相关，
> 直接以 `on` 上线最常见的结果是「上线当天拦了正常用户」，
> 而 detection_only 的成本只是多等几天。

---

## 2. 告警接入

### 2.1 通道选型

| 通道 | `type` | 适用场景 | 注意 |
| --- | --- | --- | --- |
| 通用 HTTP | `webhook` | 自建告警网关、Alertmanager webhook、SIEM HTTP 收集口 | 只按状态码判定成功；对端返回 2xx 即认为送达 |
| 企业微信 | `wechat` | 安全值班群、即时可见 | 会额外判定响应体里的 `errcode`，HTTP 200 也可能是失败 |
| syslog | `syslog` | 已有集中日志平台（rsyslog / syslog-ng / SIEM） | **仅类 Unix 平台**；Windows 上启用会在启动阶段明确报错 |
| 邮件 | `smtp` | 值班邮箱、邮件组、工单系统 | 低时效、高留存，建议只承接 `error` 级 |

多个通道是**并联**关系：一条告警会送给全部 `enabled: true` 的通道，
任一通道失败不影响其它通道，也不影响请求判定结果。

### 2.2 最小可用配置

```yaml
notify:
  enabled: true          # 总开关；false 时完全不构造通道（零开销）
  min_level: warn        # 低于该级别不发（info / warn / error）
  suppress_window: 5m    # 同一「聚合键」的告警在窗口内只发一次
  queue_size: 1024
  workers: 2
  timeout: 5s
  max_attempts: 3
  retry_backoff: 2s
  max_tracked_keys: 10000

notifiers:
  - name: ops-wechat
    type: wechat
    enabled: true
    settings:
      url: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<KEY>"
      format: markdown
```

### 2.3 告警口径（决定「会不会被淹没」）

- **级别门槛**：`notify.min_level` 是全局门槛，`notifiers[].min_level` 可以按通道覆盖。
  典型用法是「群里只收 warn 及以上，邮箱只收 error」。
- **聚合键** = `级别 + 站点 + 标题 + 命中规则`。
  「同一站点反复被同一条规则拦下」在窗口内只产生一条告警。
- **抑制窗口** `notify.suppress_window`：设为 `0` 表示**完全不抑制**。
  需要「某个通道不抑制」时，把全局窗口设为 `0`，而不是在通道上写特殊值——
  这样「抑制到底开没开」只有一个权威来源。
- **队列满时丢告警不阻塞 WAF**：指标 `waf_alert_total{result="dropped"}` 增长，
  同时系统日志会有节流后的 WARN。处置方式是提高 `min_level` / 加大抑制窗口，
  而不是盲目加大队列（队列只是缓冲，不是解决办法）。

### 2.4 三步验证「告警真的通了」

```bash
# 1) 配置层：确认通道类型已注册、配置能通过校验
waf check-config -c /etc/waf/waf.yaml | tail -40
#    输出中「已注册的告警通道类型」应包含 webhook / wechat / syslog / smtp

# 2) 真机层：故意发一个会被拦截的请求
curl -i -X POST http://127.0.0.1:9080/waf/auth \
  -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-Host: app.example.com' \
  -H 'X-Forwarded-For: 203.0.113.10' -H 'X-Forwarded-Method: GET' \
  -H 'X-Forwarded-Uri: "/api/user?id=1%27%20OR%20%271%27%3D%271"'
#    期望：403 + X-WAF-Code: WAF_BLOCKED，同时告警通道收到消息

# 3) 观测层：确认指标计数
curl -s http://127.0.0.1:9090/metrics | grep waf_alert_total
#    result="sent" 增长 → 送达成功
#    result="failed" 增长 → 通道不可达或对端拒绝（看系统日志的「告警外送失败」）
#    result="suppressed" 增长 → 被抑制窗口拦下（正常）
#    result="dropped" 增长 → 队列已满（见 2.3）
```

### 2.5 告警排错速查

| 现象 | 优先检查 |
| --- | --- |
| 一条都没发出去 | `notify.enabled` 是否为 `true`；是否有通道 `enabled: true`（总开关关着时启动日志会 WARN） |
| 启动直接失败，报「通道类型未注册」 | `notifiers[].type` 拼写；用 `waf check-config` 看已注册类型 |
| 启动直接失败，报「当前操作系统不支持 syslog」 | 在 Windows 上用了 `type: syslog`，改用 webhook / wechat / smtp |
| 指标 `failed` 持续增长 | 系统日志 `告警外送失败` 里的 `error`；确认网络策略、对端地址、令牌是否过期 |
| 指标 `suppressed` 远大于 `sent` | 正常（说明抑制生效）；若希望每条都看到，把 `suppress_window` 设为 `0` |
| 企业微信返回 `errcode != 0` | 机器人 KEY 失效或频率超限；响应体里的 `errmsg` 会写进错误信息 |
| 收到的内容缺关键信息 | 用载荷里的 `request_id` 到访问日志中反查完整上下文（这是设计预期，不是缺陷） |

---

## 3. 误报压降流程（detection_only → on）

### 3.1 闭环步骤

```
detection_only 运行  →  waf report detection  →  人工复核样例  →  登记 engine.exceptions
        ↑                                                                    │
        └────────────  重新出报表，确认「若拦截」比例下降  ←───────────────────┘
```

```bash
# 出报表（默认取 logging.access.dir）
waf report detection --since 24h --top 20

# 直接导出给复核人（Excel 可打开，多张工作表：汇总 / Top 规则 / Top 路径 / Top 来源 / 样例）
waf report detection --since 7d --out /var/tmp/detection.xlsx

# 复核完成后，确认例外的生效情况（会同时给出「生效 / disabled / 已过期」三态）
waf rules list -c /etc/waf/waf.yaml
```

### 3.2 例外登记的硬性要求

- **必填 `reason`**：例外是「有意的安全放松」，没有理由的例外等于没有审计。
  请写清依据（工单号、复核人、业务说明），例如
  `业务参数里存在形如 ' OR '1'='1 的合法内容，经 XX 复核确认为误报（工单 #1234）`。
- **优先用作用域**：能用 `url_pattern` + `methods` 限定的，不要用全局例外。
  全局例外会被编译为 `SecRuleRemoveById`，影响所有站点。
- **优先带 `expires_at`**：临时放行（例如上线期）必须写失效时间，避免「临时」变永久。
- **用 `enabled: false` 先写好再逐条开启**：配置里可以预置一批待评审的例外，
  默认关闭不影响线上，评审通过后再改 `enabled: true`。

### 3.3 例外只作用于 Coraza

`engine.exceptions` 编译为 SecLang 指令，只影响 `type: coraza` 的实例。
限速（`ratelimit`）、IP 名单（`ipaccess`）、阈值（`threshold`）、自动封禁（`autoban`）
各有自己的 `settings`，不共用例外清单——
因为「放行某条检测规则」与「放行某个来源 IP」是完全不同的安全语义。

---

## 4. 封禁运维

### 4.1 关键约束（务必先读）

- **封禁只在 WAF 内部生效**，不会执行任何系统防火墙命令（需求 R18）。
  被封禁的来源依旧能连到代理，只是会被 WAF 判为「拦截」；
  因此**代理侧必须把鉴权结论真正落到拒绝动作上**，否则封禁形同虚设。
- **封禁维度**由 `ban.ban_key`（主维度）+ `ban.ban_keys`（运行期查询的全部维度）决定，
  可选 `client_ip` / `client_ip+site` / `client_ip+path` / `client_ip+method`。
  示例：`ban_keys: [client_ip, client_ip+path]` 表示「整段 IP 封禁」与「只封该 IP 对该路径」同时生效。
  维度越多，每个请求的名单查询次数越多（按声明顺序短路），因此只启用真正需要的维度。
  `waf ban list` 的表头会打印生效的查询维度，启动日志也会输出 `ban_keys`。
- **时长**：`ban.default_ttl` 默认 `30m`，`ban.max_ttl` 默认 `24h`。
  默认值是「足够劝退扫描器/爆破脚本」与「避免办公网 NAT 出口被整体误封」之间的平衡点。
  累进封禁（`ban.escalate` + `ban.escalate_steps`）默认关闭，
  在「同一来源反复命中」的场景下才建议开启。
- **封禁状态多实例共享**：由 `stores[].type: redis` 承载；
  Redis 未启用时回落到本地存储（此时各实例的封禁视图不共享，属于已知降级）。
- **本地存储的两种后端行为不同**，选型前必须区分：

  | 存储后端 | 封禁是否持久化 | 是否支持「CLI 封禁 → 运行中进程立即生效」 |
  | --- | --- | --- |
  | `memory` | 否（进程重启即清空） | 否（CLI 是独立进程，写不到服务进程的内存） |
  | `file` | 是（JSON Lines，启动时回放到内存） | **否**：只在**启动阶段回放**，运行期的外部写入不会被已启动的进程感知 |
  | `redis` | 视 Redis 持久化策略 | **是**：CLI 与服务读同一个存储；生效延迟受 `settings.local_cache_ttl` 约束（默认 `5s`，置 `0` 即每次请求都查 Redis，代价是多一次往返） |

  因此用 `file` 后端时，`waf ban add` 之后**必须重启进程**（或直接用 `redis`）才会生效；
  这一点在多实例部署下会更容易踩——不同实例的启动时间不同，会出现「有的实例已封、有的没封」。
  **多实例部署一律使用 `redis` 后端**，`file` 只用于单机持久化场景。

### 4.2 日常命令

```bash
waf ban list    -c /etc/waf/waf.yaml                  # 当前封禁清单（含全部维度）与剩余时长
waf ban add     -c /etc/waf/waf.yaml --ip 203.0.113.10 --ttl 2h --reason "手工封禁：爆破"
waf ban remove  -c /etc/waf/waf.yaml --ip 203.0.113.10
```

注意两点（都是「按维度封禁」带来的新语义）：

- `ban add` / `ban remove` 使用**主维度**（`ban.ban_key`）构造键；
  如果部署启用了 `client_ip+path` 等其他维度，`ban list` 里会出现形如
  `ip:203.0.113.10|path:/api/user` 的条目，它们无法用 `--ip` 参数解封——
  需要按 `ban list` 输出的原样键走运维流程删除（Redis：`DEL waf:ip:...|path:...`）。
- 多维度下的「同一来源」可能同时存在多条名单项（例如 IP 维度一条、路径维度一条），
  复盘时按 `report ban` 的 Top 来源聚合判断，不要按名单条数判断。

### 4.3 复盘命令

```bash
# 封禁命中报表：Top 来源 IP / 按小时时间线 / Top 站点 / Top 规则
waf report ban --since 24h --top 20
waf report ban --since 7d --out /var/tmp/ban.xlsx
```

时间线是判断处置方式的依据：

- **阶梯上升**：持续性扫描/爆破，考虑提高限速强度或直接扩大封禁时长；
- **孤立尖峰**：一次性事件（上新、被采集、爬虫误入），通常不需要长期封禁；
- **持续高位**：可能是正常业务被误伤（例如上游汇聚出口），
  此时应查 `report attack` 的 Top 规则与 Top 路径，而不是继续加长封禁。

访问日志默认 `logging.access.allow_level: info`，因此放行与拦截都会被记录，
每条记录带 `action` 字段（`allow` / `block` / `observe` / `error`），
可以用最轻量的方式核对「放行 vs 拦截」的构成（Windows 用 `Select-String ... ).Count`）：

```bash
grep -c '"action":"allow"' /var/log/waf/waf-access-*.log
grep -c '"action":"block"' /var/log/waf/waf-access-*.log
```

注意：`waf report attack` / `report ban` 的口径只统计拦截与「若拦截」，
新增的放行记录会被报表跳过，因此报表数字不会因为本次改动而变化。

### 4.4 解封判定

出现以下任一情况应主动解封并在例外中登记：

1. 被封 IP 属于自有资产或合作方（用 IP 归属信息确认，不要只看报表）；
2. 同一 IP 段的多个地址同时被封（典型的 NAT 出口或 CDN 回源地址）；
3. 封禁原因规则已被登记为误报例外（此时应同时评估是否需要写 IP 白名单）。

---

## 5. 容量规划

### 5.1 测量方法

使用 `scripts/bench/*`（离线脚本，用法见 `scripts/bench/README.md`）。
三条基线缺一不可：

| 基线 | 含义 | 用途 |
| --- | --- | --- |
| `framework-only`（pipeline 只留 `passthrough`） | 串联框架自身的固定成本 | 确定「无论如何都吃掉的」那部分开销 |
| `crs+clean`（完整 pipeline + 正常请求体） | 常规请求的检测开销 | 容量估算的基准档 |
| `crs+sqli` / `crs+xss`（完整 pipeline + 攻击载荷） | 规则命中路径的开销 | 评估被攻击时的余量 |

```bash
scripts/bench/run-bench.sh --label framework-only --out /var/tmp/bench.csv
scripts/bench/run-bench.sh --label crs+clean --body scripts/bench/payloads/clean.json --out /var/tmp/bench.csv
scripts/bench/run-bench.sh --label crs+sqli  --body scripts/bench/payloads/sqli.json  --out /var/tmp/bench.csv
```

### 5.2 容量模型

单实例可承载的稳态 QPS 用下面的模型估算（系数来自实测基线）：

```
可用 QPS ≈ min( CPU 核数 × 单核 QPS(规则规模) × 安全系数(0.6),
               共享存储可承载的写 QPS / 单请求平均存储写入次数 )
```

- **安全系数 0.6**：压测是理想条件（固定载荷、无 TLS 握手、本地回环）。
  接入真实代理后还需要叠加 TLS、连接复用、上游抖动带来的损耗。
- **P99 而不是平均延迟**：代理侧的 forward-auth 超时通常配在 1–3 秒，
  平均延迟没有意义，要看 P99 与「超过 100ms 的请求占比」。
- **共享存储往往是真正的瓶颈**：开启了 `ratelimit` + `autoban` 之后，
  每个请求至少产生一次 Redis 往返（限速计数），命中拦截时还会写封禁键。
  在压测里观察 `crs+sqli` 与 `crs+clean` 的 QPS 差值，就是这部分的开销。

### 5.3 档位建议

下表的 QPS 是**单实例**的规划参考值（`framework-only` 基线为空时按 1/3 比例折算）。
实际排期必须用自己机器上的实测值替换：

| 档位 | 规则规模 | 典型单实例 QPS（4 vCPU） | 加机器触发点 |
| --- | --- | --- | --- |
| 入门 | ≤ 100 条自定义规则 | 与 `framework-only` 的差距 < 15% | P99 > 50ms 或 CPU > 60% |
| 标准 | CRS PL1（约 500 条生效规则） | 约为 `framework-only` 的 55%–70% | P99 > 80ms 或 CPU > 65% |
| 增强 | CRS PL2 + 自定义规则 | 约为 `framework-only` 的 35%–50% | P99 > 120ms 或 CPU > 70% |

**扩容触发条件（任一满足即加实例）**：

1. 稳态 CPU 使用率连续 15 分钟 > 65%；
2. P99 延迟超过代理侧 forward-auth 超时预算的 1/3；
3. `waf_alert_total{result="dropped"}` 出现非零增长（说明本机处理能力已不足）；
4. `waf_store_errors_total` 增长伴随限速结论漂移（说明共享存储到达瓶颈，
   此时应先扩存储再做 WAF 的水平扩容）。

### 5.4 扩容优先顺序

1. **先横向扩 WAF 实例**：本服务无状态（状态在共享存储），加实例最直接；
2. **再扩共享存储**：Redis 成为瓶颈时，优先升配/加从库，而不是给 WAF 加机器；
3. **最后才考虑降规则规模**：这是把安全能力换成性能，必须经过安全评审。

---

## 6. 日常巡检清单

| 频率 | 检查项 | 命令 / 指标 | 异常判据 |
| --- | --- | --- | --- |
| 每日 | 存活与就绪 | `curl -s http://127.0.0.1:9080/healthz`、`/readyz` | 非 200 |
| 每日 | 拦截量与来源 | `waf report attack --since 24h --top 10` | 拦截量突增 3 倍以上 |
| 每日 | 放行 / 拦截留痕 | `Select-String -Path logs\waf-access-*.log -Pattern '"action":"allow"'` | 完全无放行记录（`logging.access.allow_level` 被调为 `off`，放行流量不可见） |
| 每日 | 封禁清单 | `waf ban list` | 出现自有/合作方网段 |
| 每日 | 告警送达 | `waf_alert_total{result="failed"}` | 非零增长 |
| 每日 | 共享存储 | `waf_store_errors_total` | 非零增长 |
| 每周 | 误报趋势 | `waf report detection --since 7d` | 「若拦截」比例上升 |
| 每周 | 规则完整性 | `waf rules verify -c /etc/waf/waf.yaml` | 退出码非 0 |
| 每月 | 容量基线 | `scripts/bench/run-bench.sh --label "月度基线"` | 同档位 QPS 下降 > 20% |

---

## 7. 应急预案

### 7.1 告警风暴（值班群被打爆）

1. 立刻提高门槛：`notify.min_level: error`（可通过环境变量或 CLI 覆盖，无需改文件）；
2. 加大抑制窗口：`notify.suppress_window: 30m`；
3. 定位来源：`waf report attack --since 1h --top 20`，判断是真实攻击还是单条规则误报；
4. 若为误报，按第 3 节登记例外；若为真实攻击，保留告警但把阈值调到「只报异常」。

### 7.2 共享存储故障

- `stores[].on_error: fallback_local` 时：降级为本地存储并打 WARN，
  限速与封禁**只在单实例内生效**——此时应尽快修复 Redis，并知会安全侧
  「多实例共享的封禁视图暂时不完整」。
- 安全优先的部署可把 `banlist` / `ratelimit` 的 `on_error` 设为 `block`：
  存储不可用时直接返回 503，避免「查询不到名单就一律放行」。
  这是一个明确的可用性 vs 安全性的取舍，必须在变更评审中记录。

### 7.3 疑似大规模误封

1. 停止扩大：先把 `autoban` 实例置为 `enabled: false`（或把 `action` 改为 `observe`）；
2. 用 `waf report ban --since 1h` 看时间线与 Top 规则，
   用 `waf report attack --since 1h --top 20` 看触发路径；
3. 清空误封：`waf ban remove --ip <IP>`（逐条）或用存储侧按前缀批量清理；
4. 登记例外并在下一个工作日完成复盘，补齐「为什么这条规则会误伤」。

---

## 8. 与其它文档的关系

| 想了解 | 看这里 |
| --- | --- |
| 每个配置项的含义与默认值 | `docs/configuration.md` |
| 为什么这样设计（架构、抽象接口、取舍） | `docs/forward-auth-design.md` |
| 阶段划分、交付物、验收项与实施记录 | `docs/development-roadmap.md` |
| 压测脚本怎么用、基线 CSV 怎么读 | `scripts/bench/README.md` |
| 代理侧怎么配（OpenResty / Traefik） | `deploy/forward-auth/` |