# WAF 配置手册（三通道配置 · 全量配置项 · 插件参数）

> 适用版本：配置格式 `version: 1`；对应 `docs/development-roadmap.md` 的 M3 阶段。
> 本文档是配置的**唯一权威说明**：示例见 `configs/waf.example.yaml`，校验逻辑见 `internal/config/validate.go`。

---

## 1. 三条配置通道与优先级

本项目同时支持 **CLI 参数**、**配置文件**、**环境变量** 三种配置方式（需求 R15）。

优先级（从高到低，高优先级覆盖低优先级）：

```
CLI 参数  >  配置文件  >  环境变量  >  内置默认值
```

**为什么 CLI 最高**：`waf run -c a.yaml` 这类运维方式里，命令行是「本次执行的临时修正」，
必须能压过被长期维护的配置文件；而环境变量最容易被容器编排平台批量注入，
若它压过配置文件，会让「配置文件里明明写对了却不生效」变得难以排查（需求 R16）。

### 1.1 合并规则（逐项）

| 数据类型 | 合并语义 |
| --- | --- |
| 标量（字符串 / 数字 / 布尔 / 时长） | 高优先级存在即覆盖 |
| 映射（map） | **递归合并**：只覆盖出现过的键，未出现的键保留低优先级的值 |
| 序列（数组） | **整体替换**：不合并元素（例如新的 `pipeline` 会完全替换旧 `pipeline`） |
| 未在任一通道出现的键 | 使用内置默认值（`internal/config/defaults.go`） |

> 序列做「整体替换」是刻意设计：若数组按元素合并，`pipeline` 的顺序与启停状态会变得不可预测，
> 而校验链的顺序直接决定检测语义（先封禁查询、再限速、后评分聚合）。

### 1.2 配置文件通道

```bash
# 单文件：可多次指定；后指定的覆盖先指定的（按优先级从低到高排列）
waf run -c /etc/waf/base.yaml -c /etc/waf/override.yaml

# 目录：按文件名字典序合并；目录与文件也可以混用
waf run -c /etc/waf/conf.d -c /etc/waf/override.yaml
```

- 支持 `.yaml` / `.yml` / `.json`（按扩展名或内容自动识别）。
- `-c` 可以指向**目录**：只读取该目录第一层的 `.yaml` / `.yml` / `.json`，按文件名字典序依次合并；
  子目录、隐藏文件（`.` 开头）、`#` 开头与 `~` 结尾的备份/临时文件会被跳过。
- 目录中没有任何可加载文件时直接报错，避免「以为加载了目录、实际却使用默认值」。
- 推荐使用数字前缀明确顺序：`10-server.yaml`、`20-ingress.yaml`、`30-responder.yaml`、`40-pipeline.yaml`。
- 多文件合并遵循 §1.1：映射递归合并，数组（`pipeline` / `sites` / `notifiers`）整体替换。
- 单文件读取上限由 `limits.max_config_file_bytes` 控制（默认 1 MiB），超出直接失败（需求 R13：禁止大体积读取）。
- 解码使用 **严格模式**：出现未知字段会报错并退出码 2，避免拼写错误被静默忽略。

### 1.3 环境变量通道

命名规则（由配置路径机械推导）：

```
WAF_ + <配置路径，全部大写，点号换成下划线>
```

示例：

| 配置路径 | 环境变量 |
| --- | --- |
| `server.listen` | `WAF_SERVER_LISTEN` |
| `engine.paranoia_level` | `WAF_ENGINE_PARANOIA_LEVEL` |
| `logging.access.level` | `WAF_LOGGING_ACCESS_LEVEL` |
| `ban.default_ttl` | `WAF_BAN_DEFAULT_TTL` |

**不参与推导的键**（只能写配置文件）：

- `responder.messages.*`（用户自定义的错误码 → 文案映射）；
- `pipeline`、`stores`、`sites`、`notifiers`（结构化数组，环境变量无法表达）。

> 前缀当前固定为 `WAF_`，不可配置：可配置前缀会让「同一份配置在不同环境读到不同变量」，
> 排障成本远高于收益。若需要隔离，请通过容器的环境变量作用域控制。

**实现方式说明**：环境变量是**按 schema 正查**（逐个配置路径推导变量名后再 `os.LookupEnv`），
而不是遍历 `os.Environ` 反查。正查可以精确识别配置路径，也不会误伤系统中其它 `WAF_` 前缀的变量。

### 1.4 CLI 参数通道

通用参数（由 `internal/config` 统一注册）：

| 参数 | 说明 |
| --- | --- |
| `-c, --config <path>` | 指定配置文件或目录，可重复（后者覆盖前者）；目录按文件名字典序加载 |
| `--set <路径>=<值>` | 按配置路径覆盖**任意标量**配置项，可重复，例如 `--set server.listen=:9081` |

此外，**每个标量配置项都会被机械注册为一个同名参数**，命名规则为
「配置路径中的 `.` 与 `_` 一律替换为 `-`」：

| 配置路径 | CLI 参数 |
| --- | --- |
| `server.listen` | `--server-listen` |
| `engine.paranoia_level` | `--engine-paranoia-level` |
| `ban.default_ttl` | `--ban-default-ttl` |
| `ingress.body.max_bytes` | `--ingress-body-max-bytes` |

> `--set` 与具名参数只支持**标量**；数组与映射只能写在配置文件里
>（`--set pipeline=...` 会直接报错 `该配置项不是标量（数组或映射只能写在配置文件中）`）。

子命令：

| 命令 | 用途 | 退出码 |
| --- | --- | --- |
| `waf run` | 启动 forward-auth 服务 | 0 正常退出；1 运行期错误；2 配置错误 |
| `waf check-config` | 校验配置并打印**生效值与来源摘要**（不启动服务） | 0 通过；2 校验失败 |
| `waf config print` | 输出默认值叠加环境变量/配置文件/CLI 后的配置；数据库已初始化时继续叠加数据库运营策略 | 0 |
| `waf healthz` | 探活（可指定 `--listen`） | 0 / 1 |
| `waf version` | 版本 / 提交号 / 构建时间 | 0 |
| `waf ban list\|add\|del\|flush` | 内部封禁名单运维 | 0 / 1 / 2 |
| `waf db status` | 查看 SQLite 路径、初始化状态、策略版本与运营数据量 | 0 / 1 / 2 |
| `waf db import-config [--force]` | 从当前配置导入数据库运营数据；`--force` 覆盖策略但保留封禁与审计 | 0 / 1 / 2 |
| `waf rules list` | 查看运行态会加载的规则集、引擎参数与**误报例外审计清单** | 0 / 1 / 2 |
| `waf rules verify --dir <目录>` | 按 `manifest.yaml` 校验规则包完整性（缺失 / 摘要不一致 / 多余文件） | 0 通过；2 缺失或摘要不一致；**3 文件齐全但有清单未声明的多余文件** |
| `waf rules manifest --dir <目录> --name <名> --package-version <版本>` | 为规则目录生成 `manifest.yaml` | 0 / 1 / 2 |
| `waf rules install --source <新目录> --target <在线目录>` | 原子替换规则目录（自动保留上一版本） | 0 / 1 / 2 |
| `waf rules rollback --target <在线目录>` | 回滚到上一版本 | 0 / 1 / 2 |
| `waf rules reload` | 触发运行中实例重新加载规则（更新 `engine.hot_reload.marker_file` 时间戳） | 0 / 1 / 2 |
| `waf report detection [--dir <日志目录>] [--since 24h] [--top 20]` | DetectionOnly 试运行报告：「本应拦截」占比 + Top 规则/路径/IP + 样例 + 处置建议 | 0 / 1 / 2 |
| `waf report attack [--dir <日志目录>] [--since 24h] [--top 20]` | 攻击态势报表：拦截数 / 观察数 + Top 规则/来源 IP/路径/校验单元 | 0 / 1 / 2 |
| `waf report ban [--dir <日志目录>] [--since 24h] [--top 20]` | 封禁运维报表：封禁命中 Top 来源 IP / 按小时时间线 / Top 站点 / Top 规则 | 0 / 1 / 2 |

> `waf rules ...` 与 `waf report ...` 的全部子命令都支持 `--json`（便于流水线消费）与
> `-c/--set` 等配置体系参数；除 `rules reload` 外都**只操作文件与只读校验**，
> 不连接运行中的服务（管理面已下调到 P3，这些能力不应依赖任何在线接口）。
>
> `waf report detection|attack|ban` 三个子命令额外支持**报表导出**（需求 P1-9）：
> `--format table|csv|xlsx`（默认 `table`，即终端文本表格）与 `--out <文件>`。
> 只给 `--out` 时按扩展名推断格式（`.csv` → csv，`.xlsx` → xlsx，其它扩展名直接报错，需显式 `--format`）；
> 只给 `--format` 而省略 `--out` 时，导出内容写到标准输出（便于 `> 文件` 或管道消费）。
> CSV 带 UTF-8 BOM，Excel 双击直接打开不乱码；xlsx 为**手写最小 OOXML**（无第三方依赖）。
> 导出的单元格内容会被裁剪到 `limits.max_scan_token_bytes`，避免单个超大字段撑爆表格；
> 导出行数沿用 `--top`（报表本身是 Top N 语义，导出更多行既无统计意义，也容易让 Excel 打不开）。
>
> 业务参数名不得与配置体系参数同名——`--version` 与配置项 `version` 冲突，
> 因此规则包版本参数命名为 `--package-version`；程序会在构造参数集合时做冲突检测并直接报错。

`check-config` 的输出分为三段，用于快速回答「这个值到底从哪来的」：

1. **已加载的配置文件**（按优先级从低到高）；
2. **配置项来源摘要**（每个被显式设置的键，标注来自 file / env / flag）；
3. **生效配置**（合并后的最终 YAML）。

### 1.5 配置目录与运行期热重载

当 `-c` 指向目录时，`waf run` 会自动监听该配置输入（轮询间隔 2s、去抖动 500ms）。检测到文件内容、
新增或删除后，会重新执行完整的配置加载流程：

```
内置默认值 -> 环境变量 -> 目录内配置文件（字典序）-> CLI
```

加载或校验失败时只写 ERROR 日志，正在服务的旧配置继续生效，不会出现「改错一个字段导致 WAF 失去防护」。
应用成功后会输出「配置热重载成功」，并带上文件数、校验链条目数、站点与封禁策略摘要。

可在运行期安全替换的配置段：

| 配置段 | 说明 |
| --- | --- |
| `pipeline` | 重建校验链 |
| `sites` | 重建站点匹配表 |
| `ban` | 重建封禁策略（复用现有共享存储） |
| `responder` | 重建 JSON 响应模板与文案 |
| `engine` | 校验链内重建 Coraza 引擎与规则参数 |

必须重启才能生效的配置段：`version`、`server`、`ingress`、`stores`、`database`、
`notify` / `notifiers`、`logging`、`metrics`、`limits`、`cache`。如果一次修改同时包含可热加载段与重启段，整次重载会被拒绝，
并在日志中列出 `restart_required`，避免只应用一半而形成不一致状态。

启用 `database` 后，运行实例还会按 `database.reload_interval` 轮询策略版本。数据库中的
`site_policies`、`ip_lists`、`policy_settings` 变化后会自动重建 `pipeline` / `sites` / `ban` /
`responder` / `engine` 快照；YAML 修改这些数据库拥有的字段不会覆盖数据库值。

`waf config print` 与 `waf run` 使用同一套三通道叠加逻辑，因此可以用它确认目录合并、环境变量与 CLI 的最终结果。
未显式传入 `-c` 时，`config print` 不自动读取 `/etc/waf/waf.yaml`，保持「内置默认值 + 环境变量 + CLI」的可复现语义：

```bash
WAF_ENGINE_MODE=detection_only waf config print -c /etc/waf/conf.d --ban-default-ttl 2h
```

> 注意：热重载只监听**显式传给 `-c` 的目录**；单文件模式保持原有启动语义，不做运行期监听。
> 修改响应模板文件（`responder.template_file`）本身不会触发目录监听，需再修改目录内任一配置文件，
> 或等待其它配置变更触发重载。

`waf config print` 的完整优先级为：

```
数据库运营策略（已初始化时） > CLI > 配置文件 > 环境变量 > 内置默认值
```

数据库文件不存在或尚未完成首次导入时，`config print` 不会隐式创建数据库，仍输出 YAML 配置结果。

---

## 2. 全量配置项

> 下表「默认值」一列与 `internal/config/defaults.go` 一一对应；标注 `-` 表示默认为空值。

### 2.1 `server` — HTTP 服务

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `server.listen` | string | `:9080` | 鉴权端点监听地址 |
| `server.metrics_listen` | string | `:9090` | `/metrics`、`/healthz`、`/readyz` 的独立监听地址（便于网络隔离） |
| `server.base_path` | string | `-` | 所有 WAF HTTP 端点的统一前缀（如 `/gateway`）；为空表示不加前缀 |
| `server.read_header_timeout` | duration | `3s` | 读取请求头超时，防慢速攻击 |
| `server.shutdown_timeout` | duration | `10s` | 优雅关停最长等待时间 |

> `server.base_path` 会同时作用于 `ingress.path`、`ingress.deny_path`、`/healthz`、`/readyz`、
> `/metrics` 与 `/version`。拼接是幂等的：旧配置里已经写成 `/gateway/waf/auth` 的路径不会重复加前缀。
> 启用前缀后，代理侧 `forwardAuth.address` / `auth_request` 与 `errors` 回源地址必须同步修改；
> 配置校验会比较**叠加前缀后的最终路径**，重复路径会在启动前直接报错。

### 2.2 `ingress` — 接入还原

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `ingress.type` | enum | `auto` | `auto` / `traefik-forwardauth` / `nginx-openresty` / `nginx-auth-only` |
| `ingress.path` | string | `/waf/auth` | 鉴权子请求路径（必须与代理侧配置一致） |
| `ingress.deny_path` | string | `/waf/deny` | JSON 错误体渲染端点（Traefik `errors` 中间件回源使用） |
| `ingress.headers.uri` | []string | `[X-Forwarded-Uri, X-Original-URI]` | 原始 URI 候选注入头，按序取首个存在者 |
| `ingress.headers.method` | []string | `[X-Forwarded-Method, X-Original-Method]` | 原始方法候选头 |
| `ingress.headers.host` | []string | `[X-Forwarded-Host]` | 原始 Host 候选头 |
| `ingress.headers.proto` | []string | `[X-Forwarded-Proto]` | 原始协议候选头 |
| `ingress.client_ip.order` | []string | `[X-Forwarded-For, X-Real-IP]` | 客户端 IP 候选头顺序 |
| `ingress.client_ip.trusted_proxies` | []string | 私网四段 | **可信代理网段**；只有直连来源落在其中才信任转发头 |

> **安全提示（验收项 A10）**：`trusted_proxies` 生产环境必须收敛为实际代理地址。
> 若把 `0.0.0.0/0` 写进去，任何客户端都可以伪造 `X-Forwarded-For` 绕过限速与封禁。

#### `ingress.body` — 请求体通道

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `mode` | enum | `required` | `required` 必须携带（缺失告警）/ `optional` 可有可无 / `disabled` 完全不读 |
| `source` | enum | `request-body` | 请求体来源通道 |
| `lazy` | bool | `true` | 无 `phase: body` 单元时不读取请求体（零开销） |
| `max_bytes` | int | `1048576` | 单次请求可读取的请求体上限 |
| `chunk_bytes` | int | `32768` | 流式读取单块大小（需求 R13：读取粒度也必须可配置） |
| `on_exceed` | enum | `truncate` | 超限策略：`truncate` 截断继续检测 / `reject` 直接 400 / `skip` 跳过体检测 |
| `spool` | enum | `auto` | `memory` / `disk` / `auto` |
| `memory_threshold` | int | `65536` | `auto` 策略下落盘阈值 |
| `spool_dir` | string | `-` | 落盘目录；空表示系统临时目录 |
| `read_timeout` | duration | `2s` | 请求体读取超时 |
| `missing_methods` | []string | `[POST, PUT, PATCH]` | 预期必须携带请求体的方法；只有这些方法**且未声明空体**时缺少请求体才算「缺失」 |
| `decompress` | object | 关闭 | 压缩请求体解压，见下 |

**「请求体缺失」的判定条件（三者必须同时满足）**

`mode: required` 只是「本部署应该能拿到请求体」这个断言，它本身**不构成**任何异常判定。
一次请求要被记为「请求体缺失」（系统日志告警 + `waf_body_missing_total` 计数），必须同时满足：

1. **方法维度**：原始请求方法属于 `missing_methods`（默认 POST / PUT / PATCH）。
   GET / HEAD / OPTIONS / DELETE 本来就不携带请求体，若把无体一律记为缺失，
   `waf_body_missing_total` 与系统日志会被正常流量刷屏，真正的问题（代理没转发请求体）反而被噪声掩盖。
2. **声明维度**：客户端**没有**明确声明空请求体，即 `Content-Length != 0`。
   `Content-Length: 0` 表示客户端主动声明「本次请求没有请求体」；没有请求体就没有请求参数，
   「拿不到请求参数」是正常现象，不告警、不计数，更不构成拦截理由。
3. **通道维度**：接入通道确实能带来原始 `Content-Length`。
   原生 Nginx 的 `auth_request` 通道既不转发请求体也不转发 `Content-Length`，
   此时读到的 `0` 只代表「未知」而不是「客户端声明空体」，因此该通道下仍按方法维度计数。

> **注意 `Declared` 的取值语义**：`0` = 客户端明确声明空体；`-1` = 未知（`Transfer-Encoding: chunked`，
> 或接入通道不转发 `Content-Length`）；`> 0` = 客户端声明了具体长度。**未知不等于空体**，
> 只要无法证明客户端声明了空体，就仍按方法维度计入缺失——否则「代理没转发请求体」这类真实故障会被静默掩盖。
>
> 实现位置：`internal/ingress/forwardauth/extractor.go` 的 `pickContentLength`（还原原始长度）与
> `internal/ingress/body/spool.go` 的 `markMissingIfRequired`（三条件判定）。

**「无参数 / 无请求体」不会被拦截**：参数类检测是逐变量匹配，变量不存在时规则不命中；
缺失请求体只产生一条告警与一次计数，判定结果仍是放行，可参考 `test/contract` 的
`TestRequestWithoutParametersIsNotBlocked` 与 `TestBodyMissingMetricOnlyCountsBodyBearingMethods`。
> **消息框架头会被还原（缺陷修复，见设计文档 §3.8）**：鉴权子请求的 `Content-Length` /
> `Transfer-Encoding` 由代理合成。代理没转发请求体时两者皆缺，重建请求时会按方法补回
> （POST 等补 `Content-Length: 0`；子请求分块时补 `Transfer-Encoding: chunked`；
> GET / HEAD 等无体方法不补），避免 CRS 920180 把「拿不到请求体」误判成「POST 缺少框架头」而 403。

#### `ingress.body.decompress` — 压缩请求体解压（P1-5）

代理会把 `Content-Encoding: gzip` 的请求体**原样**转交给 WAF。不解压就等于
「请求体内容对检测引擎完全不可见」——攻击者只要加一个压缩头就能绕过全部请求体检测（需求 R4）。
因此解压是「请求体检测能力」的组成部分，而不是可选优化。

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | 是否解压（需求 R5：全部功能配置启用；关闭时压缩体不参与检测，启动日志会提示） |
| `encodings` | []string | `[gzip, deflate]` | 允许解压的编码。`br` 需要第三方依赖，与「无额外依赖」的交付约束冲突，写进配置会在校验阶段**直接报错**（需求 R10 / R14） |
| `max_bytes` | int | `4194304`（4 MiB） | **解压后**请求体上限。必须单独设置：压缩比可以极大（zip bomb），只限制压缩体大小无法阻止解压阶段耗尽内存（需求 R13） |
| `unsupported_action` | enum | `block` | `block` 失败关闭，返回 400 / `pass` 放过但不检测（会打 WARN 级系统日志留痕） |

行为约定（逐条对应一类真实事故）：

- **多重编码一律按不支持处理**（fail closed）。`gzip, deflate` 这类取值不会「只解一层」，
  否则攻击者用多层压缩即可让内层载荷完全不可见。
- **解压结果超过 `max_bytes` 一律拒绝，不做截断。** 截断后得到的是「不完整明文」，
  用它做检测会产生「检测过了但没检出」的假安全感（注意这与 `ingress.body.on_exceed=truncate`
  的语义不同：后者是代理侧的硬边界，前者是我们主动设的防线）。
- **`deflate` 同时接受 zlib 头与裸 flate 流。** 历史上大量实现发送的是裸 deflate 流，
  只支持 zlib 会把它们的请求误判为「数据损坏」。
- 解压结果整体放在内存，但其规模已被 `max_bytes` 硬限制；解压后的请求体对所有
  `phase: body` 单元可重复读取（`Rewind` 后可再次读取）。

### 2.3 `responder` — 拦截响应

本项目**不提供拦截页面**，一律返回 JSON（需求 R20）。

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `responder.type` | string | `json` | 响应渲染实现类型 |
| `responder.include_details` | bool | `false` | 是否在错误体里暴露 `rule_id` / `check` / `score`；默认关闭，避免向攻击者泄露检测细节 |
| `responder.messages.<CODE>` | map | 中文文案 | 错误码 → 提示语，可自定义 |
| `responder.template` | string | `-` | 内联 JSON 响应模板（Go `text/template`）；与 `template_file` 二选一 |
| `responder.template_file` | string | `-` | 外部模板文件路径；与 `template` 二选一，文件上限 64 KiB |
| `responder.max_body_bytes` | int | `8192` | 模板渲染结果字节上限；`<=0` 时使用默认值 |

对外错误码：

| 错误码 | 含义 | 默认 HTTP 状态 |
| --- | --- | --- |
| `WAF_BLOCKED` | 被安全策略拦截 | 403（`nginx-auth-only` 通道下由响应头承载真实语义） |
| `WAF_RATE_LIMITED` | 触发限速 | 429 |
| `WAF_UNAUTHORIZED` | 需要身份认证 | 401 |
| `WAF_BAD_REQUEST` | 请求不符合安全要求 | 400 |
| `WAF_UNAVAILABLE` | 检测服务不可用（失败关闭） | 503 |
| `WAF_NOT_FOUND` | 请求的 WAF 端点不存在（包括前缀外的路径） | 404 |

#### `responder.template` — 自定义拦截 JSON

模板使用 Go 标准库 `text/template`（不是 `html/template`），启动阶段和 `waf check-config`
都会用样例数据渲染一次并校验输出必须是合法 JSON。模板可用字段：

| 字段 | 说明 |
| --- | --- |
| `.Code` / `.Status` | 对外错误码与本次响应的 HTTP 状态码 |
| `.Message` | 错误码对应的提示语（来自 `responder.messages`） |
| `.RequestID` / `.Timestamp` | 请求标识与响应时间 |
| `.Verdict` / `.Site` | 判定结论与命中的站点名 |
| `.Path` / `.ClientIP` | 原始请求路径与客户端 IP（404 渲染同样可用） |
| `.Check` / `.RuleID` / `.Score` | 产生结论的校验单元、命中规则与评分 |
| `.RetryAfter` | 限速场景的建议退避秒数 |
| `.HasDetails` / `.Details` | 是否输出检测细节；仅在 `include_details=true` 时为真 |
| `.Messages` | 完整的错误码到提示语映射 |

字符串字段必须通过 `json` 函数输出，否则引号 / 中文 / 特殊字符可能生成非法 JSON：

```yaml
responder:
  include_details: false
  template: |
    {
      "code": {{ .Code | json }},
      "message": {{ .Message | json }},
      "request_id": {{ .RequestID | json }},
      "timestamp": {{ .Timestamp | json }}
      {{- if .HasDetails }},
      "details": {
        "check": {{ .Check | json }},
        "rule_id": {{ .RuleID | json }},
        "score": {{ .Score }}
      }
      {{- end }}
    }
```

模板运行期渲染失败（例如超过 `max_body_bytes` 或输出不是合法 JSON）会记录 WARN 并回退到内置
`ErrorBody` 结构，保证错误响应本身不会失效。

**鉴权响应头送达方案（需求 R22）**：因为 forward-auth 下代理会丢弃鉴权响应体，
真实语义通过响应头回传，代理侧据此重写状态码：

| 响应头 | 含义 |
| --- | --- |
| `X-WAF-Code` | **核心**：对外错误码（`WAF_BLOCKED` / `WAF_RATE_LIMITED` / ...） |
| `X-WAF-Verdict` | 判定结论（`allow` / `block` / `ratelimit` / `bad_request` / `unauthorized` / `unavailable` / `honeypot`） |
| `X-WAF-Rule-Id` | 命中的规则标识（便于排障与误报申诉） |
| `X-WAF-Target` | 触发拦截 / 封禁的检测目标，例如 `ARGS:id`、`REQUEST_URI`、`client_ip+path` |
| `X-WAF-Ban-Scope` | 导致本次拦截的封禁维度；普通规则拦截时为空 |
| `X-WAF-Request-Id` | 请求标识，用于把代理侧渲染的错误关联到访问日志 |
| `X-WAF-Site` | 命中站点名 |
| `X-WAF-Version` | WAF 版本 |
| `Retry-After` | 仅限速场景：建议退避秒数 |

代理侧读取方式（Nginx）：

```nginx
auth_request_set $waf_code $upstream_http_x_waf_code;
```

> Nginx `auth_request` 只透传 `401` / `403`，其它状态码会被改写成 `500`；
> 因此 `nginx-auth-only` 通道下 WAF 对外统一返回 `403`，
> 由 `X-WAF-Code` 承载真实语义，代理侧再据此渲染对外响应（需求 R22）。

**`/waf/deny` 渲染端点**：Traefik `errors`、Nginx `error_page` 与 OpenResty
`/__waf_deny` 都回源调用该端点。它既接受错误码字面量（`?code=WAF_BLOCKED`），
也接受数字状态码（`{status}`）；对 `WAF_HONEYPOT`、403、418 或空 code 会按
`X-Forwarded-Uri` / `X-Forwarded-Method` 重新匹配蜜罐规则，命中时返回规则定义的
状态码、响应头与正文，未命中时返回「真实语义」的 JSON 错误体。
渲染端点也接受查询参数或同名请求头 `target` / `X-WAF-Target`、
`ban_scope` / `X-WAF-Ban-Scope`，并把它们写入最终响应头与响应模板；
`uri` 缺失时回退读取 `X-Forwarded-Uri` / `X-Original-URI`。

### 2.4 `engine` — 检测引擎（Coraza + CRS）

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `engine.enabled` | bool | `true` | `false` 时完全不加载规则，退化为纯前置访问控制；此时配置里的 `coraza` 实例会在启动阶段直接失败（fail fast） |
| `engine.mode` | enum | `on` | `on` 正常拦截 / `detection_only` 旁路观察 |
| `engine.paranoia_level` | int | `1` | CRS 偏执等级 1–4；等级 1 时不会注入覆盖动作（CRS 默认值） |
| `engine.anomaly_score_threshold` | int | `5` | 入站异常评分阈值（CRS 默认 5）；同一个数字用于三处，见下 |
| `engine.exceptions` | []object | `[]` | 误报例外清单，见下 |
| `engine.virtual_patches` | []string | `[]` | 启用的内置虚拟补丁模板 ID 或 CVE 编号 |
| `engine.virtual_patch_files` | []string | `[]` | 自定义 SecLang 虚拟补丁文件（`.conf`） |

**`engine.anomaly_score_threshold` 的三处用途**（把阈值提到 `engine` 段正是为了让三处永不脱节）：

1. 当取值 ≠ 5 时注入一条 `SecAction`（规则 ID `900110`，位于规则文件之前），
   覆盖 CRS 的 `tx.inbound_anomaly_score_threshold`，即规则集自身的阻断判定；
2. 作为 `pipeline` 中 `threshold` 单元未显式配置 `inbound_threshold` 时的缺省阈值
   （避免出现「引擎认为该拦、WAF 却不拦」的割裂）；
3. `detection_only` 模式下判定「本应拦截」的基准（`would_block`）。

#### `engine.exceptions` — 误报例外（P1-4）

在**不修改规则集**的前提下把已确认的误报放行；每条例外强制要求 `name` 与 `reason`，
以便审计复盘（需求 R6）。所有例外都会在启动时写系统日志，并通过
`waf rules list` 输出可审计清单。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `name` | string | 是 | 审计标识，全局唯一 |
| `enabled` | bool | — | **默认 `false`（例外默认不生效）**。例外等于关闭部分防护，必须显式打开 |
| `reason` | string | 是 | 例外原因，必填且建议带上工单号 |
| `rule_ids` | []string | 三选一 | 要放行的规则 ID，支持区间（`"941100-941199"`） |
| `tags` | []string | 三选一 | 要放行的规则标签 |
| `targets` | []string | — | 从检测目标中摘除的变量（如 `ARGS:password`）；**必须配合 `rule_ids`**，语义是「规则保留、只不再检查这些参数」 |
| `url_pattern` | string | — | 例外生效的 URL 正则（对 `REQUEST_URI` 求值，**含查询串**；不做自动锚定） |
| `methods` | []string | — | 例外生效的方法列表；为空表示不限方法 |
| `expires_at` | string | — | 失效时间（RFC3339），用于「临时放行」到期自动失效；留空表示永不过期 |

**两类例外的作用顺序完全相反**（这是本能力最容易出错的地方，编译顺序由程序保证）：

| 作用范围 | 判定条件 | 生成的指令 | 放置位置 | 为什么 |
| --- | --- | --- | --- | --- |
| 全局例外 | `url_pattern` 与 `methods` 均为空 | `SecRuleRemoveById` / `SecRuleRemoveByTag` / `SecRuleUpdateTargetById` | 规则文件**之后** | 这些是「配置期指令」，只对**已经解析出来的规则**生效；放在规则文件之前等于什么都没做 |
| 作用域例外 | 指定了 `url_pattern` 和/或 `methods` | `phase:1` 的 `ctl:ruleRemoveById` / `ctl:ruleRemoveByTag` / `ctl:ruleRemoveTargetById` | 规则文件**之前** | 同一 phase 内规则按出现顺序求值，`ctl` 必须先执行才能影响目标规则 |

作用域例外的条件组合方式（`url_pattern` + `methods` 同时存在时用 `chain`）：

```
SecRule REQUEST_METHOD "@rx ^(?i:POST)$" "id:900300,phase:1,pass,nolog,noauditlog,ctl:ruleRemoveById=942100,chain"
    SecRule REQUEST_URI "@rx ^/api/login$" "t:none"
```

其他约定：

- 作用域例外**每个动作独立成一条规则**（规则 ID 从 `900300` 起顺序分配）。
  这样某个 `ctl` 动作不被目标引擎支持时，影响面只收敛到那一条规则；
- 规则 ID 分配区间：`900000/900001` 属 CRS，`900100` 偏执等级覆盖，`900110` 阈值覆盖，
  `900200+` 请求体处理器路由，`900300+` 作用域例外；
- 例外状态有三态：`applied`（生效）/ `disabled`（被 `enabled=false` 关闭）/
  `expired`（已过期）。**过期判定优先于启用开关**，便于报表区分「到期自动失效」与「被人为关闭」。

#### `engine.rules`

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `dirs` | []string | `[]` | 主规则目录；**留空 = 使用编译期嵌入的 CRS**（单二进制交付，需求 R14） |
| `custom_dirs` | []string | `[]` | 追加的自定义规则目录，排在主规则集之后加载（可用 `SecRuleRemoveById` 等压误报） |
| `include` | []string | `["*.conf"]` | 目录内规则文件匹配模式 |
| `data_include` | []string | `["*.data"]` | **规则引用的数据文件**匹配模式（`@pmFromFile unix-shell.data` 依赖）；这些文件不是规则，不能按 `include` 载入 |
| `crs_setup` | string | `crs-setup.conf` | CRS 设置文件名（相对规则根） |

#### `engine.body`

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `access` | bool | `true` | 对应 `SecRequestBodyAccess` |
| `limit_bytes` | int | `13107200` | 对应 `SecRequestBodyLimit`；必须 ≥ `ingress.body.max_bytes` |
| `in_memory_limit_bytes` | int | `131072` | 超出部分落盘，对应 `SecRequestBodyInMemoryLimit` |
| `limit_action` | enum | `reject` | `reject` / `processPartial` |
| `json_depth_limit` | int | `4096` | JSON 嵌套深度上限；`0` 表示不检查 |
| `parse_multipart` | bool | `false` | 是否解析 `multipart/form-data` 请求体（关闭时不把该请求体交给引擎） |
| `processors` | []object | JSON + XML | **请求体处理器路由**，见下 |

#### `engine.body.processors` — 请求体处理器路由

引擎只按 `Content-Type` 自动识别 `application/x-www-form-urlencoded` 与 `multipart/form-data`；
**JSON 与 XML 必须显式指定处理器**，否则会被当作 URLENCODED 解析，请求体里的攻击载荷几乎无法被检出（需求 R4）。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `name` | string | 处理器名：`JSON` / `XML` / `MULTIPART` / `URLENCODED` |
| `content_types` | []string | 匹配 `Content-Type` 的正则列表（任一匹配即选用该处理器） |
| `enabled` | bool | 是否生效 |

每条启用项生成一条 phase 1 规则（规则 ID 从 `900200` 起顺序分配）：

```
SecRule REQUEST_HEADERS:Content-Type "@rx (?:^application/(?:[^;,\s]+\+)?json(?:\s*;.*)?$)" \
    "id:900200,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=JSON"
```

默认值：

```yaml
engine:
  body:
    processors:
      - name: JSON
        enabled: true
        content_types: ['^application/(?:[^;,\s]+\+)?json(?:\s*;.*)?$']
      - name: XML
        enabled: true
        content_types: ['^(?:application|text)/(?:[^;,\s]+\+)?xml(?:\s*;.*)?$']
```

> 显式写 `processors: []` 表示关闭全部路由（不做 JSON / XML 体解析）；
> 不写该键表示使用上面的内置默认值。二者语义不同，代码中按 `nil` / 非 `nil` 区分。

#### `engine.inline_directives`

追加的 SecLang 指令，位于「引擎基础设置」之后、「规则文件」之前。

> 顺序很关键：SecLang 是「后写覆盖先写」。写在这里的指令能压过 `crs-setup.conf` 与引擎基础设置，
> 但会被规则文件里的规则影响。典型的用途是补 `SecRuleRemoveById`、`SecRequestBodyLimit` 等。

#### `engine.virtual_patches` — 虚拟补丁

虚拟补丁在规则文件之后、全局例外之前加载，因此既能独立命中，也能继续被
`engine.exceptions` 治理。内置模板：

| 模板 | CVE | 检测内容 |
| --- | --- | --- |
| `cve-2021-44228` | CVE-2021-44228 | `${jndi:...}` Log4Shell 注入 |
| `cve-2022-22965` | CVE-2022-22965 | Spring4Shell `class.module.classLoader` 链 |
| `cve-2021-41773` | CVE-2021-41773 | Apache 路径穿越变体 |
| `cve-2024-3400` | CVE-2024-3400 | PAN-OS SESSID 命令注入 |

```yaml
engine:
  virtual_patches: ["cve-2021-44228", "cve-2022-22965"]
  virtual_patch_files: ["/etc/waf/vpatch/custom.conf"]
```

自定义文件每行一条 SecLang 指令，空行与 `#` 注释会被忽略；单文件大小受
`limits.max_rule_file_bytes` 限制。模板名写错会在 `waf check-config` 阶段直接报错。

#### `engine.hot_reload`

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | 规则目录变化时自动重载（CRS 与蜜罐共用；重载失败会保留旧规则继续服务） |
| `debounce` | duration | `1s` | 变化去抖时间：指纹变化后再等一个周期复核，避免编辑器/打包工具「边写边改」触发多次重载 |
| `poll_interval` | duration | `5s` | 规则目录指纹的扫描/轮询间隔（CRS 与蜜罐共用） |
| `marker_file` | string | `-` | 「手动触发重载」的标记文件路径；`waf rules reload` 会更新其时间戳，实例据此立即重载 |

**为什么用轮询指纹而不是 inotify / ReadDirectoryChangesW（设计取舍，已记录于 roadmap §10.9）**：

1. 交付物是 `CGO_ENABLED=0` 的静态单二进制，引入 `fsnotify` 会增加依赖面（需求 R10 / R14）；
2. 容器绑定挂载、overlayfs 与部分 NFS 场景下文件系统事件会丢失或行为不一致，轮询在这三种环境下表现完全相同；
3. 规则目录通常只有几十个文件，每轮只做 `stat`（**不读文件内容**，满足需求 R13），默认 5s 的代价可忽略。

指纹由「相对路径 + 大小 + 修改时间（纳秒）」排序后取 SHA-256。**必须包含修改时间**：
只比大小会漏掉「等长内容替换」（例如把规则里的评分阈值从 5 改成 8），而修改时间能捕捉到它。

监听范围：

- CRS：`engine.rules.dirs` + `engine.rules.custom_dirs`，按 `engine.rules.include` / `data_include` 匹配；
- 蜜罐：`pipeline[].settings.rules_dir`，递归监听所有子目录中的 `.yaml` / `.yml`；
- GeoIP / 威胁情报 / OpenAPI 契约：分别由插件的 `hot_reload` + `poll_interval` /
  `refresh_interval` 独立扫描，失败时保留旧快照。

两者都受 `engine.hot_reload` 控制，因此更新路径下的规则文件后无需重启；
`waf rules reload` 也会通过同一个 `marker_file` 同时触发两类规则重载。

### 2.5 `sites` — 站点策略

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `name` | string | 站点名，全局唯一 |
| `hosts` | []string | Host 模式：精确域名、`*.example.com` 通配、`"*"` 兜底 |
| `engine_mode` | enum | `inherit` 继承全局 / `on` / `detection_only`。运行期通过 phase 1 的 `ctl:ruleEngine` 事务级覆盖生效，同一份规则可同时服务不同站点 |
| `pipeline` | string | `default` 使用顶层 `pipeline`；其它值引用 `pipelines[]` 中的具名链 |
| `allowlist` | []string | 站点级 IP / CIDR 白名单；命中直接放行 |
| `blocklist` | []string | 站点级 IP / CIDR 黑名单；命中按 `access_action` 处理 |
| `access_action` | enum | 黑名单动作：`block`（默认）/ `observe` |
| `access_score` | int | 黑名单命中时累加的异常评分 |
| `params` | map | 站点级参数覆盖，键名为 `<插件类型>.<参数名>` |

**匹配优先级**：精确 Host > 最长通配后缀 > `"*"` 站点 > 内置默认站点。

**Host 规范化**：去端口、转小写、去结尾 `.`、去 IPv6 `[]`。

**约束（启动阶段 fail fast）**：站点名重复 / 无 `hosts` / 多个 `"*"` / `"*"` 与其它模式混用 /
通配形态非法 / 同一 Host 被多个站点声明。

当前已支持的 `params` 键：

```yaml
params:
  ratelimit.limit: "300"
  ratelimit.burst: "30"
  ratelimit.window: "60s"
  geoip.action: "observe"
  geoip.allow_countries: "CN,HK"
  geoip.block_countries: "KP"
  threatintel.action: "block"
  threatintel.score: "20"
  apisec.action: "observe"
  apisec.unknown_action: "off"
  challenge.mode: "basic"
  challenge.realm: "shop-admin"
```

站点级链路与 IP 名单：

```yaml
sites:
  - name: shop
    hosts: ["shop.example.com"]
    engine_mode: detection_only
    pipeline: shop-strict
    allowlist: ["203.0.113.10/32"]
    blocklist: ["198.51.100.0/24"]
    access_action: block
    access_score: 10
```

### 2.6 `pipeline` — 校验链

有序数组，**数组顺序即串联顺序**；每个元素的 `phase` + `order` 决定实际执行次序。

```yaml
pipeline:
  - name: crs-header      # 实例名，全局唯一
    type: coraza          # 已注册的校验单元类型
    enabled: true         # 可单独启停
    order: 30             # 同阶段内排序
    phase: request        # pre | request | body | post
    on_error: block       # 校验单元自身出错时的策略：pass | block | observe（留空用实现默认值）
    settings: {...}       # 插件私有配置，严格模式解码
```

阶段语义：

| 阶段 | 时机 | 典型用途 |
| --- | --- | --- |
| `pre` | 还原原始请求之后、读体之前 | 封禁名单查询、IP 黑白名单、限速 |
| `request` | 请求头可用后 | 检测引擎（头 / 查询串） |
| `body` | 请求体可读时（执行器统一 `Rewind()`） | 检测引擎（请求体）、上传检查 |
| `post` | 链收尾 | 评分聚合、自动封禁、告警 |

> `post` 阶段具有**收尾语义**：即使链在中途短路（已拦截），`post` 单元仍会全部执行，
> 否则「命中即拦截」无法触发自动封禁与告警。

### 2.6.1 `pipelines` — 具名校验链

顶层 `pipeline` 始终是默认链；`pipelines[]` 声明可被 `sites[].pipeline` 引用的独立链。
具名链在启动阶段分别构建，请求期只做一次 map 查找。

```yaml
pipelines:
  - name: shop-strict
    instances:
      - name: shop-challenge
        type: challenge
        enabled: true
        order: 10
        phase: request
        settings:
          mode: basic
          users: [{ username: shop, password_sha256: "..." }]
      - name: shop-apisec
        type: apisec
        enabled: true
        order: 20
        phase: body
        settings: { spec_file: /etc/waf/shop-openapi.yaml }
```

约束：链名唯一、不能使用保留名 `default`；所有链中的实例 `name` 必须全局唯一。

### 2.7 `stores` — 共享状态存储

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `name` | string | `default` | 实例名，被插件的 `settings.store` 引用 |
| `type` | string | `redis` | 实现类型（注册表键） |
| `enabled` | bool | `true` | 关闭时回落到本地实现（单机可用，多实例不共享） |
| `fallback` | string | `memory` | 构造失败时的降级实现 |
| `on_error` | enum | `fallback_local` | 运行期故障策略：`fail_open` / `fail_closed` / `fallback_local` |
| `settings` | map | 见下 | 实现私有配置 |

`settings` 常用键（需求 R25：支持 standalone / sentinel / cluster）：

| 键 | 说明 |
| --- | --- |
| `topology` | `standalone` / `sentinel` / `cluster` |
| `addrs` | 地址列表 |
| `master_name` | sentinel 主节点名 |
| `password` / `username` | 认证 |
| `sentinel_password` | sentinel 自身认证 |
| `db` | 库号（standalone / sentinel） |
| `pool_size` / `min_idle_conns` / `max_retries` | 连接池 |
| `dial_timeout` / `read_timeout` / `write_timeout` | 超时 |
| `prefix` | 键前缀 |
| `local_cache_ttl` / `local_cache_entries` | 本地缓存（降低 Redis 压力） |
| `tls.*` | `enabled` / `ca_file` / `cert_file` / `key_file` / `insecure_skip_verify` |

> **需求 R23**：Redis 共享必须显式启用（`enabled: true`）；未启用时降级为本地存储，
> 启动日志会输出 WARN 提示「多实例之间不会共享限速计数与封禁名单」。

### 2.7.1 `database` — 运行期 SQLite 持久化

数据库用于保存**运营数据**，不是部署配置的第二份副本。

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `database.enabled` | bool | `false` | 是否启用 SQLite；关闭时保持原有 stores / YAML 行为 |
| `database.path` | string | `data/waf.db` | SQLite 文件路径；父目录不存在时自动创建 |
| `database.busy_timeout` | duration | `5s` | 写锁等待时间 |
| `database.reload_interval` | duration | `10s` | 策略版本轮询间隔 |
| `database.audit.mode` | enum | `events` | `off` / `events` / `all` |
| `database.audit.retention` | duration | `720h` | 审计保留时长；`0` 表示不自动清理 |
| `database.audit.queue_size` | int | `4096` | 审计异步队列长度，满时丢弃且不阻塞请求 |
| `database.audit.batch_size` | int | `100` | 单事务最多写入条数 |
| `database.audit.flush_interval` | duration | `1s` | 队列空闲时的最大等待时间 |

**数据边界**：

| 保存到 SQLite | 始终以 YAML / 环境变量 / CLI 为准 |
| --- | --- |
| 封禁记录与封禁事件 | `server` / `ingress` / `stores` / `database.path` |
| 站点策略、站点 IP 名单 | Redis 连接、规则目录、MMDB 路径、模板文件路径 |
| `ipaccess` 名单（含 `blocklist_file` 首次导入） | 日志、指标、limits、cache、密钥 |
| `ban` / `engine` / `responder` 的关键标量策略 | 告警通道与部署监听地址 |
| 请求审计（可选） | 规则内容、OpenAPI 文件与蜜罐规则目录 |

**初始化与覆盖规则**：

1. 首次启用时从当前生效配置导入；`ipaccess.blocklist_file` 只在该次导入时读取。
2. 之后每次启动不再解析导入文件，也不再覆盖数据库中的运营数据。
3. 需要重新导入时执行 `waf db import-config --force`；封禁记录、封禁事件与审计记录始终保留。
4. 数据库中的策略变化通过 `policy_revision` 触发运行期热重载；修改数据库字段后应同步递增该版本，
   或使用 `waf db import-config --force`。
5. 封禁记录使用 Unix 毫秒保存首次封禁时间与到期时间；重复命中不会续期，到期后查询路径自动解封。

**为什么限速计数不落库**：限速与累进封禁计数是高频、短周期易失状态，写入 SQLite 会把每个请求
变成磁盘写热点；它们继续使用 `stores[]`（Redis / memory / file）。SQLite 只承接需要跨重启保留的
封禁事实与运营策略。

**结构化封禁 / 拒绝上下文**：`bans`、`ban_events` 与 `audit_requests` 会保存
`rule_id`、`check_name`、`target`、`ban_scope`、完整 `uri`、`query_text` 与 `params_json`。
参数快照只包含查询串以及已缓冲的 JSON / form 请求体，正文超过
`logging.access.max_body_snippet_bytes` 时标记截断；`password`、`token`、`secret`、
`authorization`、`cookie`、`session` 等敏感字段在落库与日志前统一替换为 `[REDACTED]`。
旧数据库启动时会自动补齐这些列，无需手工迁移。

### 2.8 `ban` — 内部封禁策略

**仅在本 WAF 内部生效，不执行任何系统防火墙操作**（需求 R18：代码中禁用 `os/exec`）。

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `ban.default_ttl` | duration | `30m` | 默认封禁时长（需求 R19 给定的「恰当值」） |
| `ban.max_ttl` | duration | `24h` | 封禁时长上限，任何来源的 TTL 都会被它截断 |
| `ban.ban_key` | enum | `client_ip` | **主封禁维度**（见下表）；决定 `waf ban add/remove` 写入时用哪个维度 |
| `ban.ban_keys` | []enum | `[ban_key]` | **运行期生效的封禁维度集合**（可多个，按声明顺序查询，命中任一维度即拦截） |
| `ban.escalate` | bool | `false` | 是否启用累进封禁 |
| `ban.escalate_steps` | []duration | `[30m, 2h, 24h]` | 累进阶梯 |
| `ban.escalate_window` | duration | `24h` | 累进统计窗口 |
| `ban.renew_on_repeat` | bool | `false` | 重复命中时是否刷新已有封禁的到期时间 |

> **封禁计时语义**：默认 `renew_on_repeat=false`。自动封禁在**首次写入时**确定
> `banned_at` / `expire_at`，封禁有效期内相同来源再次触发只记录日志，不刷新到期时间、
> 不新增名单记录；到期后自动解封，下一次封禁再从当前时刻重新计时。只有显式设置
> `renew_on_repeat=true` 才会恢复「每次命中都续期」的旧行为；手工 `waf ban add` 始终是强制覆盖/续期。

#### 封禁维度（`ban_key` / `ban_keys`）

| 维度 | 键格式 | 适用场景 |
| --- | --- | --- |
| `client_ip` | `ip:1.2.3.4` | 默认；最通用，误伤面也最大（NAT 出口） |
| `client_ip+site` | `ip:1.2.3.4\|site:shop` | 多站点共用同一批来源 IP 时按站点隔离 |
| `client_ip+path` | `ip:1.2.3.4\|path:/api/user` | 只封「这个人访问这个接口」，止损精准、误伤最小 |
| `client_ip+method` | `ip:1.2.3.4\|method:POST` | 只读站点上反复出现写方法探测 |

`ban_key`（主维度）与 `ban_keys`（查询维度集合）的分工：

- `ban_keys` 为空时等价于 `[ban_key]`，**旧配置零改动即可升级**；
- `banlist` 会按 `ban_keys` 的顺序逐个查询，命中即短路（名单查询在关键路径上）；
- `autoban` 声明的每个触发维度都必须出现在 `ban_keys` 中，否则启动阶段直接失败；
- `ban_keys` 必须包含 `ban_key`：运维命令按主维度写键，缺少该维度会出现
  「CLI 说封了、运行期查不到」。该约束由配置校验强制（`waf check-config` 会报错）。

> `ban_keys` 是数组，**只能通过配置文件设置**（数组无法由环境变量 / CLI 机械表达）。

> **混用不同维度时的解封**：`waf ban list` 会列出全部键（含路径等维度），
> 解封时用 `waf ban remove --ip ...` 只能解主维度的键；
> 其余维度请按 `ban list` 输出的原样键，通过运维流程直接删除（Redis: `DEL waf:<键>`），
> 或在 `configs` 中临时收窄 `ban_keys` 后重启（TTL 到期也会自动失效）。

**封禁键的唯一构造入口**：`ban.ClientIPScopeKey`（由 `ban.Manager.KeyFor` /
`ban.Manager.KeyForScope` / `waf ban ...` 复用）。「写进去却查不到」是多实例封禁最难排查的问题，
键的构造必须只有一处实现——这正是维度抽象（`ban.KeyScope`）存在的意义。

### 2.9 `notify` + `notifiers` — 告警外送

告警外送（需求 P1-7）分成**公共策略**（`notify`）与**通道声明**（`notifiers`）两段。
公共策略描述的是「外送这件事本身的行为」，因此不随通道重复配置。

#### 2.9.1 `notify` — 公共策略

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | 总开关。`false` 时**完全不构造任何通道**（零开销）；此时即使 `notifiers[].enabled=true` 也不生效，启动日志会给出 WARN |
| `queue_size` | int | `1024` | 告警队列长度。队列把「产生告警」与「送达告警」解耦，使请求判定路径永不等待外部系统；队列满时**丢弃并计数**（`waf_alert_total{result="dropped"}`），绝不阻塞 WAF |
| `workers` | int | `2` | 并发外送协程数。大于 1 时同一通道可能被并发调用，因此通道实现必须并发安全 |
| `timeout` | duration | `5s` | 单次送达超时（必须 > 0）。没有超时的外送会让协程永久卡在不可达的外部系统上 |
| `min_level` | enum | `warn` | 全局最低告警级别：`info` / `warn` / `error`。默认 `warn` 是因为 `info` 级（观察模式命中）在试运行阶段量级极大 |
| `suppress_window` | duration | `5m` | 聚合抑制窗口：同一「聚合键」的告警在窗口内只发一次。设为 `0` 表示**不抑制**（此时抑制表完全不参与工作） |
| `max_attempts` | int | `3` | 单条告警的最大外送尝试次数（含首次） |
| `retry_backoff` | duration | `2s` | 两次尝试之间的固定间隔 |
| `max_tracked_keys` | int | `10000` | **每个通道**抑制表的键上限（内存上限，需求 R13）。达到上限后按「最早写入」淘汰；设为 `0` 表示不设上限（改用周期性过期清理） |

**聚合键 = 级别 + 站点 + 标题 + 命中规则**（`Fields["rule_id"]`）。
这样「同一站点反复被同一条规则拦下」在窗口内只产生一条告警，
而「换了规则」或「换了站点」会被视为新事件。

**抑制表是按通道独立的**：A 通道发过并不会导致 B 通道不发——
通道之间是并联关系，共用一张表会与扇出语义矛盾。

#### 2.9.2 `notifiers[]` — 通道声明

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `name` | string | 实例名，必须唯一（用于日志与指标标签） |
| `type` | string | `webhook` / `wechat` / `syslog` / `smtp`；用 `waf check-config` 可列出全部已注册类型 |
| `enabled` | bool | 是否启用。**默认关闭**（需求 R5：功能即开关） |
| `min_level` | enum | 覆盖 `notify.min_level`；留空表示继承 |
| `suppress_window` | duration | 覆盖 `notify.suppress_window`；`0` 表示继承（需要「完全不抑制」时把全局设为 `0`，而不是在这里写哨兵值） |
| `settings` | map | 实现私有配置（严格模式：未知字段会直接报错） |

多个通道**并联扇出**：一条告警送给全部 `enabled: true` 的通道，
任一通道失败不影响其它通道，也不影响请求判定结果。

> **配置校验**：「声明了通道但一个都没启用」属于典型的**静默失效**配置（运维以为告警已接好，
> 实际一条都发不出去），因此 `notify.enabled: true` 且 `notifiers` 非空但无 `enabled: true` 时，
> **校验阶段直接报错**（`check-config` 退出码 2，`run` 拒绝启动）。
> 若 `notifiers` 本身为空，则视为「未接任何通道」这个合法状态；
> 启动时系统日志的「告警外送已装配」会打印 `enabled` 与 `channels`，可据此确认是否真的接上了。

#### 2.9.3 各通道的 `settings`

| 通道 | 字段 | 默认 | 说明 |
| --- | --- | --- | --- |
| `webhook` | `url` | — | **必填**，须为 `http://` 或 `https://` |
| | `method` | `POST` | 仅支持 `POST` / `PUT` |
| | `headers` | — | 附加请求头（可承载令牌，注意配置文件权限） |
| | `content_type` | `application/json` | 请求体类型 |
| | `insecure_tls` | `false` | 跳过 TLS 证书校验，仅自签名证书内网使用 |
| | `timeout` | 继承 `notify.timeout` | 单次送达超时 |
| | `max_response_bytes` | `65536` | 响应体读取上限（用于错误提示，防止对端返回超大响应体） |
| `wechat` | `url` | — | **必填**，企业微信机器人 webhook 地址 |
| | `format` | `markdown` | `markdown` / `text` |
| | `insecure_tls` / `timeout` / `max_response_bytes` | 同上 | |
| `syslog` | `network` | 空（本机套接字） | `udp` / `tcp` / `unixgram` / `unix`；留空使用 `/dev/log` |
| | `address` | — | `network` 非空时必填，例如 `10.0.0.20:514` |
| | `tag` | `waf` | 报文中的程序标识 |
| | `facility` | `local0` | `kern` / `user` / `mail` / `daemon` / `auth` / `syslog` / `lpr` / `news` / `uucp` / `cron` / `authpriv` / `ftp` / `local0`–`local7` |
| | `format` | `summary` | `summary`（一行摘要）/ `json`（完整结构化载荷，推荐给 SIEM） |
| | `timeout` | 继承 | 写入等待上限（log/syslog 自身不支持超时，本实现用协程 + `ctx` 兜底） |
| `smtp` | `host` | — | **必填**，同时作为 TLS `ServerName` 与认证域 |
| | `port` | `25` | 1–65535 |
| | `username` / `password` | — | 留空表示匿名提交。`tls: none` 时配置账号密码会在发送阶段被标准库拒绝（防止口令明文传输，属预期行为） |
| | `from` | — | **必填** |
| | `to` | — | **必填**，至少一个 |
| | `subject_prefix` | `[WAF]` | 主题前缀 |
| | `tls` | `starttls` | `none` / `starttls`（587 常用）/ `tls`（465 常用，建连即 TLS） |
| | `insecure_tls` | `false` | 跳过证书校验 |
| | `timeout` | 继承 | 建连与写入的整体上限 |

**平台约束**：`syslog` 依赖 Go 标准库 `log/syslog`，该包**仅提供类 Unix 实现**。
在 Windows 上启用 `type: syslog` 会在**启动阶段**直接报错（fail fast），
不会静默丢弃告警——请改用 `webhook` / `wechat` / `smtp`。

#### 2.9.4 安全约束

告警载荷（`internal/notify.Payload`）**不含原始请求体与请求头**，
只带 `request_id` 这类可用于在访问日志中反查的定位信息。
原因：告警会经由第三方系统（IM、邮件、SIEM）中转并在多个终端留存，
把业务数据放进去等于把敏感数据副本散播到不可控的位置。

运维流程（通道选型、告警接入验证、告警风暴处置）见 `docs/operations.md`。

### 2.10 `logging` — 日志

日志分两类（需求 R21），均为 JSON 格式、均可分级：

| 类别 | 记录内容 | 默认输出 |
| --- | --- | --- |
| `logging.system` | WAF 系统日志：启动 / 装配 / 配置 / 规则加载 / 内部错误 | stdout + file |
| `logging.access` | 请求访问与拦截日志：每次请求的判定结论、命中摘要、耗时 | file |

两类日志共用的字段：

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `enabled` | bool | system `true` / access `true` | 是否输出 |
| `level` | enum | system `info` / access `info` | `debug` / `info` / `warn` / `error` |
| `format` | string | `json` | 当前仅支持 `json` |
| `outputs` | []string | system `[stdout,file]` / access `[file]` | `stdout` / `file` |
| `dir` | string | `logs` | 日志目录 |
| `file` | string | `waf-system` / `waf-access` | 文件名前缀（不含时间戳与扩展名） |
| `rotate` | enum | `daily` | 轮转策略：`daily` 按天 / `size` 按大小 / `both` 两者同时 |
| `max_file_bytes` | int | `134217728` | 单文件上限（`rotate` 为 `size` / `both` 时必须大于 0） |
| `keep_days` | int | system `30` / access `90` | 保留天数 |
| `max_total_bytes` | int | `0` | 总容量上限；`0` 表示不限制 |
| `compress` | bool | `false` | 归档文件是否压缩 |

`logging.access` 专有：

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `allow_level` | enum | `info` | **放行请求**的记录策略：`info` 记录 / `debug` 仅 debug 级可见 / `off` 不记录 |
| `include_headers` | bool | `false` | 是否记录请求头 |
| `include_body` | bool | `false` | 是否记录请求体片段 |
| `max_body_snippet_bytes` | int | `4096` | 请求体片段上限（避免日志放大） |
| `mask_ip` | bool | `false` | 是否对 IP 脱敏 |
| `redact` | []string | 常见敏感头 | 需要脱敏的头部名列表 |

> **为什么 `allow_level` 默认是 `info`（放行也要留痕）**
>
> 鉴权请求无论「过」还是「不过」都应当留下可解释的记录。若只记录拦截，访问日志里会出现
> 「完全没有任何记录」的请求——排查「某接口为什么变慢」「放行流量有多大」时无从下手。
>
> - `info`（默认）：放行以 `info` 级写入，**默认可见**，即「过与不过都记录」；
> - `debug`：放行以 `debug` 级写入。此时构建器会把访问日志通道级别自动下探到 `debug`，
>   无需同时修改 `level`；把 `allow_level` 改回 `info` 或把 `level` 调粗即可恢复；
> - `off`：完全不记录放行，只保留拦截 / 观察 / 异常记录（仅适用于极端高频、日志体积优先的链路）。
>
> 每条访问日志都带 `action` 字段（`allow` / `block` / `observe` / `honeypot` / `error`），
> 便于直接 `grep` 或做聚合统计，不必再从 `msg` 文案反推判定类型。

### 2.11 `metrics` — 指标

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `metrics.enabled` | bool | `true` | 是否暴露 `/metrics` |
| `metrics.namespace` | string | `waf` | 指标名前缀（需匹配 `^[a-zA-Z_][a-zA-Z0-9_]*$`） |
| `metrics.path` | string | `/metrics` | 指标路径；不得与 `ingress.path` / `ingress.deny_path` / 内置端点冲突 |

暴露的指标：

| 指标 | 类型 | 标签 |
| --- | --- | --- |
| `waf_requests_total` | counter | `site`, `verdict` |
| `waf_check_duration_seconds` | histogram | `check` |
| `waf_check_errors_total` | counter | `check` |
| `waf_blocked_total` | counter | `check`, `rule_id` |
| `waf_body_bytes_total` | counter | `check` |
| `waf_body_truncated_total` | counter | - |
| `waf_body_skipped_total` | counter | - |
| `waf_body_missing_total` | counter | - |
| `waf_bans_total` | counter | `scope` |
| `waf_deny_render_total` | counter | - |
| `waf_store_errors_total` | counter | `store` |
| `waf_build_info` | gauge | `version`, `commit` |

### 2.12 `limits` — 资源与容量限额

需求 R13：所有体积 / 数量限额必须来自配置，禁止硬编码。

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `limits.max_rule_file_bytes` | int | `2097152`（2 MiB） | 单个规则文件读取上限 |
| `limits.max_rules_total_bytes` | int | `67108864`（64 MiB） | 全部规则文件总量上限 |
| `limits.max_scan_token_bytes` | int | `1048576`（1 MiB） | 单个待检测 token 上限（JSON 深度扫描也复用它） |
| `limits.max_intel_file_bytes` | int | `67108864` | 情报文件上限 |
| `limits.max_mmdb_bytes` | int | `268435456` | GeoIP 库上限 |
| `limits.max_config_file_bytes` | int | `1048576` | 单个配置文件上限 |
| `limits.max_header_bytes` | int | `1048576` | 请求头总量上限 |

### 2.13 `cache` — 本地缓存

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `cache.enabled` | bool | `true` | 是否启用本地缓存 |
| `cache.rule_cache_entries` | int | `10000` | 规则相关缓存条目上限 |
| `cache.ban_cache_entries` | int | `100000` | 封禁查询缓存条目上限 |
| `cache.max_bytes` | int | `33554432`（32 MiB） | 缓存总字节上限 |
| `cache.ttl` | duration | `5m` | 默认条目存活时间 |

---

## 3. 插件 `settings` 参考

`settings` 采用 **严格模式** 解码：出现未定义字段会直接报错，避免「配置写了但拼错了」。

### 3.1 `passthrough`

| 键 | 类型 | 说明 |
| --- | --- | --- |
| `log` | bool | `true` 时每个请求写一条 debug 系统日志，用于确认串联顺序 |

### 3.2 `banlist`（PhasePre）

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `action` | enum | `block` | `block` / `observe` |
| `score` | int | `0` | 命中时累加的异常评分 |
| `store_timeout` | duration | `200ms` | 单次存储查询超时 |

### 3.3 `ipaccess`（PhasePre）

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `allowlist` | []string | `[]` | 白名单（IP 或 CIDR） |
| `blocklist` | []string | `[]` | 黑名单（IP 或 CIDR） |
| `blocklist_file` | string | `-` | 黑名单文件（一行一条） |
| `action` | enum | `block` | 命中黑名单后的动作 |
| `score` | int | `0` | 命中时累加的异常评分 |

### 3.4 `ratelimit`（PhasePre）

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `dimensions` | []enum | 必填 | 计数维度：`ip` / `path` / `host` / `site` / `ua` |
| `path_match` | []string | `[]` | 路径正则列表；空表示全部路径 |
| `window` | duration | 必填 | 固定窗口长度 |
| `limit` | int | 必填 | 窗口内基础放行次数（必须 > 0） |
| `burst` | int | `0` | 额外突发额度；实际阈值 = `limit + burst` |
| `action` | enum | `ratelimit` | `ratelimit`（429）/ `block` / `observe` |
| `score` | int | `0` | 触发时累加的异常评分 |
| `store` | string | 默认存储 | 计数使用的存储实例名 |
| `store_timeout` | duration | `200ms` | 单次计数访问超时 |
| `key_prefix` | string | `-` | 计数键额外前缀（同一存储被多条规则共用时区分） |
| `ban` | bool | `false` | 触发时是否同时请求内部封禁 |
| `ban_ttl` | duration | `0`（用 `ban.default_ttl`） | 封禁时长 |
| `ban_reason` | string | 自动生成 | 封禁原因 |

计数键格式：`[key_prefix]rl:<维度>=<值>|<维度>=<值>:<窗口秒>`

### 3.5 `threshold`（PhasePost）

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `score_key` | string | `anomaly_score` | 评分所在状态键 |
| `inbound_threshold` | int | 继承 `engine.anomaly_score_threshold` | 入站评分拦截阈值（必须 > 0）；留空时继承引擎阈值，保证与 CRS 的阻断判定同源 |
| `action` | enum | `block` | `block` / `observe` |
| `score` | int | `0` | 超阈值时额外累加的评分 |
| `rule_id` | string | 内置标识 | 命中明细使用的规则标识 |
| `min_severity` | enum | `-` | 拦截门槛：要求至少存在一条该级别及以上的命中 |

### 3.6 `autoban`（PhasePost）

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `trigger_on` | []string | `[block, honeypot]` | 计入触发条件的判定结论；`any` 表示任何终态。蜜罐命中默认参与窗口计数 |
| `min_severity` | enum | `-`（不设门槛） | 最低命中严重度：`info` / `low` / `medium` / `high` / `critical`；只有存在该级别及以上的命中才计入 |
| `dimensions` | []object | 单个 `client_ip` | **触发维度列表**（见下）；为空等价于单一的 `client_ip` 维度 |
| `dimensions[].scope` | enum | `client_ip` | 维度：`client_ip` / `client_ip+site` / `client_ip+path` / `client_ip+method`；**必须已在 `ban.ban_keys` 中启用** |
| `dimensions[].threshold` | int | 继承 `threshold` | 该维度的命中次数阈值 |
| `dimensions[].window` | duration | 继承 `window` | 该维度的统计窗口 |
| `dimensions[].ttl` | duration | 继承 `ttl` | 该维度的封禁时长 |
| `threshold` | int | `3` | 各维度的默认阈值 |
| `window` | duration | `5m` | 各维度的默认统计窗口 |
| `ttl` | duration | `0`（用 `ban.default_ttl`） | 各维度的默认封禁时长（受 `ban.max_ttl` 限制） |
| `skip_when_banned` | bool | `true` | 来源已在名单中时是否跳过计数（避免「命中次数虚高」与「名单被反复续期」） |
| `action` | enum | `ban` | `ban` / `observe` |
| `reason` | string | 自动生成 | 封禁原因 |
| `score` | int | `0` | 触发时累加的额外评分 |
| `alert` | bool | `false` | 是否产生告警事件 |
| `store` | string | 默认存储 | 命中计数使用的存储实例 |
| `store_timeout` | duration | `200ms` | 单次计数访问超时 |

计数键格式：`ab:<维度>|<封禁键>|<窗口>`（维度与窗口都编进键名：不同维度的计数互不污染，
调整窗口后也不会沿用旧计数）。

蜜罐命中与 `block` / `ratelimit` 等触发结论在同一维度、同一窗口下统一累计，
因此 `threshold` 与 `window` 同时约束所有列入 `trigger_on` 的结论。

> `skip_when_banned` 的「已封禁」判定读取的是 `settings.store` 指定的存储。
> 若它与封禁写入使用的存储不是同一个实例，最坏结果只是退化为「每次都重新计数」，
> **不影响封禁本身的正确性**——名单由 `banlist` 在 pre 阶段统一拦截。

#### 为什么要「维度」而不是只按 IP

只按 IP 统计时，两类完全不同的风险无法区分：

- 「单一来源集中打某一个接口」（遍历、撞库、注入探测）——希望**快速、精准**地止损；
- 「办公网 NAT 出口里某个用户触发规则」——希望**尽量不封**，或只封到路径粒度。

把维度做成可配置项之后，可以两者兼顾：

```yaml
settings:
  min_severity: medium
  dimensions:
    - scope: client_ip          # 维度一：整段 IP（阈值高一些，避免误伤 NAT 出口）
      threshold: 3
      window: 5m
    - scope: client_ip+path     # 维度二：只封「这个人访问这个接口」
      threshold: 5
      window: 10m
      ttl: 30m
```

语义：**每个维度独立计数、独立判定**；同一请求可以让多个维度同时达标，
此时会一并产出多条封禁动作（由 `internal/ban` 逐条落地），即「可配置多个、多个则串联」。

> 维度必须同时出现在 `configs` 的 `ban.ban_keys` 中，否则「封禁写进去也没有请求会去查它」。
> 该约束在 `waf check-config` 与启动装配阶段都会强制校验。

### 3.7 `coraza`（PhaseRequest / PhaseBody）

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `process_body` | bool | `false` | 是否检测请求体；**必须与实例所在阶段一致**（`body` 阶段必须为 `true`，反之必须为 `false`），否则启动失败 |
| `score_key` | string | `inbound_anomaly_score` | 异常评分写入 `RequestContext` 状态使用的键 |
| `max_findings` | int | `16` | 单次请求最多记录的命中明细条数（防日志放大） |
| `mode` | enum | 继承 `engine.mode` | 实例级模式覆盖 |
| `paranoia_level` | int | 继承 | 实例级偏执等级覆盖（1–4） |
| `rule_dirs` | []string | 继承 | 实例级规则目录覆盖；`[]` 表示使用内置 CRS |
| `custom_rule_dirs` | []string | 继承 | 实例级自定义规则目录覆盖 |
| `body_processors` | []object | 继承 | 实例级请求体处理器路由覆盖；`[]` 表示关闭全部路由 |
| `inline_directives` | []string | 继承 | 实例级追加 SecLang 指令 |
| `body_access` | bool | 继承 | 实例级 `SecRequestBodyAccess` 覆盖 |
| `body_limit_bytes` | int | 继承 | 实例级请求体上限覆盖 |
| `body_in_memory_limit_bytes` | int | 继承 | 实例级内存上限覆盖 |
| `parse_multipart` | bool | 继承 | 实例级 multipart 解析覆盖 |

> **为什么拆成两个实例**（示例配置中的 `crs-header` / `crs-body`）：
> 按需读体是硬约束（需求 R13）——只有链中确实存在 `body` 阶段单元时才会读取请求体。
> 拆成两个实例后，运维可以选择只启用头实例（此时一个字节的请求体都不会被读）。
>
> **注意**：两个实例都会执行 Coraza 的 phase 2（请求体阶段）求值——
> 这是 CRS 攻击规则（941xxx / 942xxx 等）与查询串参数（`ARGS`）的检测位置；
> 头实例不写入任何请求体字节，只触发求值，因此不违背按需读体约束。

### 3.8 `honeypot`（PhasePre）

把诱饵端点集中到 WAF 内：规则命中后按规则自己的状态码、响应头与正文响应，
不再走统一 JSON 拦截模板。匹配与返回语义参考 `reference/honeypot` 的 baitroute：
**规则按声明顺序匹配、首个命中短路、未命中继续执行后续校验单元**。

响应分两步完成，以便 Traefik、Nginx 原生与 OpenResty 共用同一套实现：

1. `/waf/auth` 命中后只返回 `403` 与 `X-WAF-Code: WAF_HONEYPOT` 等元数据，不携带正文；
2. 代理侧调用 `/waf/deny?code=WAF_HONEYPOT`（Traefik 传 `code=403`），
   WAF 按 `X-Forwarded-Uri` / `X-Forwarded-Method` 重新匹配规则，返回最终状态码、响应头与正文。

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `rules` | []object | `[]` | 内联规则列表，顺序即匹配顺序 |
| `rules_dir` | string | `-` | 规则目录，递归读取 `.yaml` / `.yml`；按文件路径字典序加载，排在内联规则之后。配置后由 `engine.hot_reload` 自动监听目录变化（递归，包含子目录），加载失败保留旧规则 |
| `score` | int | `0` | 命中时累加的异常评分（可供 `threshold` / `autoban` 使用） |
| `alert` | bool | `true` | 是否产生告警事件（经 `notify` 通道外送） |

单条规则字段：

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `name` | string | 自动生成 | 规则名；为空时内联规则为 `rule-N`，目录规则为 `相对路径#N` |
| `method` | string | 任意 | 单个请求方法；为空且 `methods` 也为空时匹配任意方法 |
| `methods` | []string | `[]` | 多个请求方法，与 `method` 合并 |
| `path` | string | 必填 | 匹配表达式 |
| `match` | enum | `exact` | `exact` / `prefix` / `glob` / `regex`；`glob` 使用 `path.Match`，`regex` 不做自动锚定 |
| `target` | enum | `path` | `path`（不含查询串）/ `uri`（含查询串）；exact 模式的 `path` 含 `?` 时自动使用 `uri` |
| `status` | int | `200` | 返回状态码，必须为 200–599 |
| `content_type` | string | `text/plain; charset=utf-8` | 返回的 Content-Type；兼容参考规则的 `content-type` 写法 |
| `headers` | map | `{}` | 附加响应头；禁止 `Content-Length` / `Transfer-Encoding` 等逐跳头 |
| `body` | string | `""` | 响应正文原文；`204` / `304` 不允许携带正文 |

示例：

```yaml
pipeline:
  - name: honeypot
    type: honeypot
    enabled: true
    order: 1
    phase: pre
    on_error: pass
    settings:
      score: 10
      alert: true
      rules:
        - name: phpinfo
          method: GET
          path: /phpinfo.php
          status: 200
          content_type: text/html
          headers:
            Server: Apache/2.4.59
            X-Powered-By: PHP/8.2.17
          body: |
            <!DOCTYPE html><html><body><h1>PHP Version 8.2.17</h1></body></html>
```

也可以直接复用参考规则目录：

```yaml
settings:
  rules_dir: /etc/waf/honeypot-rules   # 递归读取 .yaml / .yml
```

命中时结论为 `honeypot`，响应头携带 `X-WAF-Code: WAF_HONEYPOT` 与
`X-WAF-Verdict: honeypot`；访问日志 `action=honeypot`，不会计入
`waf_blocked_total`。蜜罐命中默认会由 `autoban` 按维度写入窗口计数
（`trigger_on` 默认包含 `honeypot`），达到 `threshold` 后按 `ttl` 封禁。
若显式配置了 `trigger_on`，必须把 `honeypot` 列入（或使用 `any`），例如：

```yaml
trigger_on: [block, ratelimit, honeypot]
threshold: 3
window: 5m
ttl: 30m
```

> **代理通道（三通道统一）**
>
> - OpenResty：`waf_auth.lua` 识别 `WAF_HONEYPOT` 后回源 `/__waf_deny`，
>   由 `/waf/deny` 返回最终页面；
> - Traefik：`errors` 中间件捕获 403 后回源 `/waf/deny?code=403`；
>   `errors` 无法读取鉴权响应头，因此 WAF 对 403 执行一次蜜罐重匹配；
> - Nginx 原生 `auth_request`：`auth_request` 丢弃鉴权响应体，但
>   `error_page ... = @waf_render` 回源 `/waf/deny?code=$waf_code` 后返回最终页面。
>
> 三个通道都支持 `status: 200` 的伪造页面。代理必须传递原始请求信息：
> `X-Forwarded-Uri`、`X-Forwarded-Method`、`X-Forwarded-Host`、`X-Real-IP`
> （或对应的 `X-Original-*` 候选头）。渲染端点只重新匹配蜜罐规则，
> 不重复执行限速、封禁或 CRS 检测。

### 3.9 `geoip`（PhaseRequest）

只读取本地 MaxMind MMDB（GeoLite2 Country / City），不访问任何云端 GeoIP API。
白名单优先于黑名单；命中黑名单后按 `action` 拦截或观察。

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `database` | string | 必填 | 本地 `GeoLite2-Country.mmdb` / `GeoLite2-City.mmdb` |
| `action` | enum | `block` | `block` / `observe` |
| `score` | int | `0` | 命中时累加的异常评分 |
| `rule_id` | string | `geoip_country_block` | 命中明细规则标识 |
| `allow_countries` | []string | `[]` | 放行国家代码（ISO 两位） |
| `block_countries` | []string | `[]` | 拦截国家代码 |
| `allow_continents` | []string | `[]` | 放行洲代码（例如 `AS` / `EU`） |
| `block_continents` | []string | `[]` | 拦截洲代码 |
| `hot_reload` | bool | `true` | 是否轮询 MMDB 文件变化 |
| `poll_interval` | duration | `5s` | 文件指纹扫描间隔 |

至少配置一个 allow/block 名单；空名单会让实例静默失效，因此启动阶段直接报错。
私有地址、回环地址与未指定地址不参与地域判定。

### 3.10 `threatintel`（PhasePre / PhaseRequest）

本地威胁情报匹配，不访问云端服务。支持 IP / CIDR、ASN、精确域名与
`*.example.com` 通配后缀；ASN 需要额外的 `GeoLite2-ASN.mmdb`。

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `files` | []string | `[]` | 显式情报文件列表 |
| `dirs` | []string | `[]` | 递归扫描目录（`.txt` / `.list` / `.csv` / `.yaml` / `.yml` / `.json`） |
| `asn_database` | string | `-` | ASN 条目存在时必填 |
| `action` | enum | `block` | `block` / `observe` |
| `score` | int | `0` | 命中时累加的异常评分 |
| `rule_id` | string | `threat_intel_match` | 命中明细规则标识 |
| `max_total_bytes` | int | 单文件上限 × 16 | 情报文件总量上限 |
| `hot_reload` | bool | `true` | 是否轮询文件变化 |
| `refresh_interval` | duration | `5m` | 文件扫描间隔 |

文件格式：

```text
# txt / list：一行一条，支持 type value、type:value 或自动识别
1.2.3.0/24
AS13335
evil.example.com
*.bad.example
```

```csv
type,value
ip,9.9.9.9
asn,64512
domain,phish.example
```

```yaml
- type: ip
  value: 203.0.113.0/24
- type: domain
  value: "*.malware.example"
```

匹配顺序：先客户端 IP/CIDR，再 ASN，最后 Host / Referer / Origin 域名。

### 3.11 `apisec`（PhaseBody）

基于本地 OpenAPI 3.x 文件校验请求契约。支持 path / query / header / cookie 参数，
以及 `application/json`（含 `+json`）请求体；JSON Schema 覆盖
`type` / `required` / `properties` / `additionalProperties` / `items` /
`enum` / `pattern` / 长度与数值范围 / `allOf` / `anyOf` / `oneOf` / `nullable`，
并支持 `#/components/schemas/...` 本地 `$ref`。

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `spec_file` | string | 必填 | 本地 OpenAPI 3.x YAML / JSON |
| `action` | enum | `block` | 违规时的动作：`block` / `observe` |
| `score` | int | `0` | 命中违规时累加的异常评分 |
| `rule_id` | string | `apisec_contract_violation` | 命中明细规则标识 |
| `unknown_action` | enum | `off` | spec 未声明接口的动作：`off` / `block` / `observe` |
| `check_parameters` | bool | `true` | 是否校验参数 |
| `check_body` | bool | `true` | 是否校验 JSON 请求体；启用时实例必须是 `phase: body` |
| `max_violations` | int | `8` | 单次请求最多上报的违规数 |
| `max_body_bytes` | int | `limits.max_scan_token_bytes` | 参与契约校验的请求体上限 |
| `hot_reload` | bool | `true` | 是否轮询 spec 文件变化 |
| `poll_interval` | duration | `5s` | spec 文件扫描间隔 |

行为约定：

- 同时匹配多个模板路径时，字面段更多的路径优先（`/users/me` 优先于 `/users/{id}`）；
- 参数按 schema 类型转换后再校验；数组参数支持重复键与逗号分隔；
- 请求体只在 `check_body=true` 且运行期确实缓冲了请求体时校验；
- 当前版本只做结构校验，不执行 `format`（email / uuid 等）语义校验；
- 未在 spec 中出现的接口默认放行，避免增量接入时误伤存量接口。

### 3.12 `challenge`（PhaseRequest）

不依赖外部服务的本地身份校验，适合后台、管理面与需要额外口令保护的站点。

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `mode` | enum | `basic` | `basic` / `cookie` / `basic_or_cookie` |
| `realm` | string | `waf` | Basic 认证提示域 |
| `users` | []object | 必填 | 本地账号列表 |
| `users[].username` | string | 必填 | 用户名，列表内唯一 |
| `users[].password` | string | 二选一 | 明文口令 |
| `users[].password_sha256` | string | 二选一 | 口令的 SHA-256 十六进制摘要（优先） |
| `cookie_name` | string | `waf_auth` | 签名 Cookie 名 |
| `cookie_path` | string | `/` | Cookie 作用路径 |
| `cookie_secure` | bool | `true` | 是否添加 `Secure` |
| `secret` | string | Cookie 模式必填 | HMAC 密钥，至少 16 字节 |
| `secret_file` | string | 二选一 | 从文件读取密钥（自动去首尾空白） |
| `ttl` | duration | `1h` | 签名 Cookie 有效期 |
| `rule_id` | string | `challenge_required` | 未认证命中的规则标识 |

认证流程：

1. `basic`：校验 `Authorization: Basic`，失败返回 401 + `WWW-Authenticate`；
2. `cookie`：校验 HMAC-SHA256 签名 Cookie；同时接受 Basic 凭据并下发 Cookie，
   便于首次认证与后续免密；
3. `basic_or_cookie`：两者任一通过即可。

Cookie 是无状态令牌，不在 WAF 内存中维护会话表，因此适合多实例部署。
`Set-Cookie` 能否透传取决于代理：Traefik 需把该头加入 `authResponseHeaders`；
Nginx `auth_request` 默认不透传鉴权子请求的 `Set-Cookie`，此时请使用 `basic` 模式，
或由 OpenResty / Traefik 显式转发该响应头。

---

## 4. 常见配置组合

### 4.1 本地最小可跑（默认纯放行）

```yaml
version: 1
server: { listen: ":9080", metrics_listen: ":9090" }
pipeline: []
```

### 4.2 双代理前置校验 + 体检测（推荐起点）

见 `configs/waf.example.yaml`：`banlist` → `ratelimit` → `coraza(request)` → `coraza(body)` → `threshold` → `autoban`。

### 4.3 只观察不拦截（上线前试运行）

`detection_only` 下 CRS 的 `deny` 动作被引擎抑制，但**异常评分照常累计**。
因此「评分越过 `engine.anomaly_score_threshold`」就等于「开着拦截就会被拦」，
该结论会以 `would_block: true` + `would_block_reason` 写入访问日志（日志级别升为 `warn`），
并累加指标 `waf_would_block_total{check,rule_id}`。闭环流程：

```bash
waf run -c /etc/waf/waf.yaml            # mode: detection_only 先跑一个窗口（建议 ≥ 24h）
waf report detection --since 24h --top 20   # 看「若拦截」占比 / Top 规则 / 样例或建议
# 对确认的误报登记 engine.exceptions（必须填 reason），再复跑报表确认占比下降
waf report detection --since 1h         # 占比降到可接受范围后再切 mode: on
```

```yaml
engine:
  mode: detection_only
  anomaly_score_threshold: 5   # 同时也是「本应拦截」的判定基准
pipeline:
  - name: crs-header
    type: coraza
    enabled: true
    phase: request
    settings: { process_body: false }
  - name: crs-body
    type: coraza
    enabled: true
    phase: body
    settings: { process_body: true }
  - name: threshold
    type: threshold
    enabled: true
    phase: post
    settings: { action: observe, inbound_threshold: 5 }
```

### 4.4 多实例共享（Redis）

```yaml
stores:
  - name: shared
    type: redis
    enabled: true
    on_error: fallback_local
    settings:
      topology: standalone
      addrs: ["redis:6379"]
      prefix: "waf:"
pipeline:
  - name: rl-ip
    type: ratelimit
    enabled: true
    phase: pre
    settings: { dimensions: [ip], window: 60s, limit: 600, store: shared }
```

---

## 5. 配置排错速查

| 现象 | 排查方向 |
| --- | --- |
| 启动报「类型未注册」 | 该 `type` 未在 `cmd/waf/plugins.go` 空白导入 |
| 启动报 `engine.enabled=false 与 coraza 实例冲突` | `engine.enabled` 置 `true`，或关闭 `coraza` 实例 |
| 启动报 `process_body 与阶段不一致` | `body` 阶段实例必须 `process_body: true` |
| 启动报「站点 ... 重复 / 无 hosts」 | 见 §2.5 约束清单 |
| `check-config` 报未知字段 | 拿 §2 的表逐项比对；严格模式会指出完整路径 |
| 配置改了但不生效 | `waf check-config` 看「配置项来源摘要」，确认是不是被 CLI / 环境变量覆盖 |
| `-c 目录` 改了配置但没生效 | 确认目录内文件扩展名是 `.yaml/.yml/.json`、文件名不是隐藏/备份文件；启动日志应出现「配置目录监听已启用」 |
| 热重载日志报 `restart_required=...` | 修改了必须重启的配置段；按日志列出的段重启进程，或只保留可热加载段（见 §1.5） |
| 空配置目录启动失败 | 目录必须至少包含一个可加载配置文件；如需纯默认值运行，不要传该目录 |
| 站点 `engine_mode` 配了不生效 | 确认 `Host` 是否命中该站点；覆盖由 phase 1 的 `ctl:ruleEngine` 实现，`inherit` 不会生成覆盖规则。全局灰度仍可用 `engine.mode: detection_only` |
| `apisec` 启动报「必须使用 phase: body」 | 关闭 `check_body`，或把实例改为 `phase: body`；只有 body 阶段才会缓冲请求体 |
| GeoIP 启动报数据库不可访问 | `geoip.database` 必须是本地 `GeoLite2-Country.mmdb` / `GeoLite2-City.mmdb` 文件；同时检查 `limits.max_mmdb_bytes` |
| 威胁情报启动报 ASN 缺少数据库 | 情报文件中存在 ASN 条目时必须配置 `threatintel.asn_database`（GeoLite2-ASN MMDB） |
| 挑战 Cookie 不生效 | Nginx 原生 `auth_request` 默认不透传鉴权子请求的 `Set-Cookie`；改用 `mode: basic`，或由 Traefik / OpenResty 显式转发 |
| 放行请求在访问日志里查不到 | `logging.access.allow_level` 被改成了 `debug` / `off`（默认 `info` 表示放行与拦截都留痕，见 §2.10） |
| JSON 请求体检测不生效 | 检查 `engine.body.processors` 是否覆盖了该 `Content-Type` |
| 请求体没读 | 检查 `ingress.body.lazy` 与链中是否存在 `phase: body` 单元 |
| 站点 POST 全部 403 且 `X-WAF-Rule-Id: 920180` | 该规则判的是「POST 缺少 `Content-Length` / `Transfer-Encoding`」。子请求的框架头由代理合成，代理没转发请求体时两者皆缺，当前版本已在接入还原层补回（设计文档 §3.8）；若仍命中，检查是否替换了规则包或加了例外覆盖 |
| 日志里刷出大量「请求体缺失」告警 / `waf_body_missing_total` 持续增长 | 先按 §2.2 的三个条件对齐语义：GET / HEAD 等无体方法不计、客户端声明 `Content-Length: 0` 不计、接入通道不转发长度（`nginx-auth-only`）会计数。若方法本该带体却仍在告警，多半是代理没把请求体转发过来（Traefik 需 `forwardBody: true`） |
| `Content-Encoding: gzip` 的请求体检测不到 | `ingress.body.decompress.enabled` 默认关闭；开启后 gzip/deflate 体才会参与检测 |
| 启动报「编码不受支持」 | `encodings` 只接受 `gzip` / `deflate`（`br` 需要第三方依赖，本项目不支持） |
| 例外明明配了却不生效 | 检查 `enabled`（**默认 false**）；再看作用范围：全局例外必须由程序放在规则文件之后、作用域例外放在之前（自动保证，勿手工写进 `inline_directives`） |
| 例外里的 `url_pattern` 匹配不上 | 该正则对 `REQUEST_URI` 求值且**含查询串**，也不做自动锚定；精确匹配请自己写 `^...$` |
| 改 CRS / 蜜罐规则文件后没生效 | 看 `engine.hot_reload`：`enabled` 是否为 `true`、`poll_interval` 是否已到；蜜罐还需配置 `settings.rules_dir`；也可 `waf rules reload` 立即触发 |
| `waf rules reload` 报缺少 marker_file | 在配置里设置 `engine.hot_reload.marker_file` 后重试 |
| `waf rules verify` 退出码是 3 | 文件齐全，但目录里有 `manifest.yaml` 未声明的文件（升级残留）；确认后清理，不要直接投入使用 |
| 告警一条都发不出 | ① `notify.enabled` 是否为 `true`；② `notifiers[]` 里是否有 `enabled: true` 的通道（声明的通道一个都没启用会在校验阶段直接报错）；③ 启动日志「告警外送已装配」的 `channels` 是否为空；④ `notifiers[].min_level` / `notify.min_level` 是否把该级别过滤掉了 |
| 启动报「当前操作系统不支持 syslog」 | Windows / Plan9 上没有 `log/syslog`；该通道改用 `webhook` / `wechat` / `smtp`，或换成 `network: tcp` 指向远端 syslog 服务 |
| 告警没发出来但日志里也没有失败记录 | 大概率是**预期内丢弃**：级别门槛（`notify.min_level` / `notifiers[].min_level`）或抑制窗口 `suppress_window` 命中了；指标 `waf_alert_total{result="suppressed"}` 会同步增长 |
| 指标 `waf_alert_total{result="failed"}` 持续增长 | 看系统日志里同一时间的「告警外送失败」，`error` 字段会带上 HTTP 状态码、业务错误码或连接错误 |
| 指标 `waf_alert_total{result="dropped"}` 出现 | 队列 `notify.queue_size` 已满。调大队列、增加 `notify.workers`，或把接收端变快（`dropped` 表示告警被主动丢弃，不是发送失败） |
| 告警里看不到请求体 / 请求头 | **设计如此**：告警载荷只带规则、站点、路径、客户端 IP 等元数据，不含 `body` / `headers` / `raw_request`，避免把敏感数据外送到第三方通道 |
| 报表导出后中文乱码 | CSV 已带 UTF-8 BOM、xlsx 为标准 OOXML，用 Excel 直接打开即可；不要用记事本「另存为 ANSI」，也不要把 `.csv` 改名成 `.xls` |
| `report --out` 报「无法从扩展名推断格式」 | 只识别 `.csv` / `.xlsx`；其它后缀需显式 `--format csv` 或 `--format xlsx` |
| 导出表格里字段被截断 | 单元格上限为 `limits.max_scan_token_bytes`（与请求体检测的单 token 上限同一个值）；导出行数沿用 `--top` |
