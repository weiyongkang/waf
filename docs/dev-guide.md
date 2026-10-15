# WAF 开发、运行、测试与打包手册

> 适用版本：M3（配套 `docs/development-roadmap.md` v0.9）。
> 定位：**动手手册**——只回答「怎么把它跑起来、怎么验证它对、怎么打成可交付的包」。
> 配置项含义见 `docs/configuration.md`；线上运维流程见 `docs/operations.md`；设计与分层见 `docs/forward-auth-design.md`。

---

## 1. 环境要求与一次性准备

| 项 | 要求 | 说明 |
| --- | --- | --- |
| Go | ≥ 1.21（`go.mod` 声明），CI 使用 `go-version-file: go.mod` 自动取值 | 本项目无 CGO 依赖，跨平台构建一致 |
| CGO | **一律 `CGO_ENABLED=0`** | 需求 R14：静态单二进制，才能跑在 distroless / scratch 上 |
| Docker | 仅打包与容器运行需要（≥ 20.10 支持 `HEALTHCHECK` 的写法即可） | 离线环境需提前同步基础镜像 |
| 代理 | Traefik ≥ v2.11 或 Nginx(OpenResty) | 只做**真实接入验证**时需要；本地功能验证用 curl 模拟注入头即可 |
| 端口 | `9080`（鉴权）/ `9090`（指标与探针） | 两者不能相同；被占用时用 `--server-listen` / `--server-metrics-listen` 覆盖 |
| Delve | 仅**断点调试**需要：`go install github.com/go-delve/delve/cmd/dlv@latest` | VS Code 的 Go 扩展底层也用它；不调试可以不装 |

仓库不含 `reference/`、`.tmp/`、`bin/`、`logs/`、`dist/`（见 `.gitignore`），它们都是本地产物，不入交付。

### 1.1 离线环境准备（内网无外网时）

```bash
# 在有网机器上执行 scripts/build-offline.sh 产出 dist/waf-module-cache.tar.gz，
# 拷进内网后解到任意目录，然后：
tar -xzf waf-module-cache.tar.gz -C /data/gomodcache
export GOMODCACHE=/data/gomodcache/pkg/mod
export GOPROXY=off          # 强制只用本地缓存，任何缺失都会立刻报错而不是偷偷联网
export GOFLAGS=-mod=mod
```

`GOPROXY=off` 是刻意的：让「依赖没带全」在构建期立刻暴露，而不是在压测/上线时才炸。

---

## 2. 构建

### 2.1 本地构建（推荐脚本）

```bash
sh scripts/build.sh                  # 产出 bin/waf，版本信息取自 git
VERSION=v0.9.0 sh scripts/build.sh   # 显式指定版本
```

脚本做的事：`CGO_ENABLED=0` + `-trimpath`（去构建路径，可复现）+ `-ldflags="-s -w"`（去符号表减体积）+ 通过 `-X` 注入 `internal/version` 的三个变量。

> 脚本是 POSIX `sh`：Windows 上用 Git Bash / WSL 执行；纯 PowerShell 环境请用下面的等价命令。

### 2.2 本地构建（PowerShell 等价命令）

```powershell
cd E:\work\project\waf
New-Item -ItemType Directory -Force -Path bin | Out-Null
$env:CGO_ENABLED = "0"
go build -trimpath `
  -ldflags "-s -w -X github.com/weiyongkang/waf/internal/version.Version=v0.9.0 -X github.com/weiyongkang/waf/internal/version.Commit=local -X github.com/weiyongkang/waf/internal/version.BuildTime=2026-10-15T00:00:00Z" `
  -o bin/waf.exe ./cmd/waf
.\bin\waf.exe version        # 应打印 v0.9.0 / local / 构建时间
```

### 2.3 日常快速编译（不关心版本信息）

```bash
go build ./...                       # 只编译全部包，不产出文件（最快的语法/类型检查）
go build -o bin/waf ./cmd/waf        # 产出可执行文件
go install ./cmd/waf                 # 装到 $GOBIN，方便直接敲 waf
```

### 2.4 跨平台构建

```bash
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o bin/waf-linux-amd64   ./cmd/waf
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o bin/waf-linux-arm64   ./cmd/waf
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/waf.exe           ./cmd/waf
```

生产目标只有 Linux；Windows 构建通常只用于本地开发与自测。

---

## 3. 运行

三个入口，按「依赖从少到多」排列：本地无依赖配置 → 生产基线配置 → Docker Compose。

### 3.1 入口一：本地无依赖运行（功能验证首选）

`configs/waf.local.yaml` 与生产基线 `configs/waf.example.yaml` 的唯一差异是
`stores[0].type` 由 `redis` 改为 `memory`，因此**不需要任何外部组件**即可跑通全链路
（内置嵌入的 CRS 规则集已编译进二进制）。

```powershell
.\bin\waf.exe check-config -c configs\waf.local.yaml    # 先看生效值与来源，退出码 0
.\bin\waf.exe run          -c configs\waf.local.yaml    # 前台运行；Ctrl+C 优雅关停
```

启动日志里这几行是「配置真的生效了」的证据，建议每次启动都扫一眼：

- `WAF 启动`：`listen` / `ingress_type` / `pipeline_entries`（链上单元与顺序）/ `stores`（含降级说明）/ `sites`；
- `检测引擎实例装配完成`：规则来源、文件数、`paranoia_level`、`process_body`；
- `告警外送已装配`：`enabled` 与 `channels`（空列表即「一条都不会发」）。

### 3.2 入口二：生产基线配置（需要 Redis）

```bash
cp configs/waf.example.yaml configs/waf.yaml
# 编辑 configs/waf.yaml：把 stores[0].settings.addrs 指向真实 Redis
waf check-config -c /etc/waf/waf.yaml
waf run          -c /etc/waf/waf.yaml
```

`waf` 未指定 `-c` 时，若 `/etc/waf/waf.yaml` 存在会自动加载（见 `waf help`）。

### 3.3 入口三：Docker Compose（waf + redis）

```bash
cp configs/waf.example.yaml configs/waf.yaml
docker compose up -d
docker compose logs -f waf         # 跟随日志
docker compose ps                  # 容器状态（healthcheck 结果）
```

`docker-compose.yml` 的既定约定：容器以 `65532:65532` 非 root 运行、根文件系统只读、
只挂载 `./configs`（只读）/ `./logs`（可写）/ `/tmp`（tmpfs，请求体落盘用），
健康检查直接调用镜像内的 `/waf healthz`。

### 3.4 关停

```bash
Ctrl+C            # 前台运行：优雅关停（刷日志、关闭存储、按超时 flush 告警队列）
docker compose down
```

关停顺序有讲究：日志与存储的 `Close` 会先于告警管理器 flush 完成，
所以**不要用 `kill -9`**——那样会丢掉尚未落盘的访问日志，也就拿不到 `waf report` 的数据。

### 3.5 三通道配置的临时覆盖（调试利器）

优先级：**CLI > 配置文件 > 环境变量 > 内置默认值**。改端口、调日志级别、临时打开某个开关都不需要动配置文件（DetectionOnly 灰度是例外，它必须同时改数组里的 `threshold` 设置，见 §3.6）：

```bash
waf run -c configs/waf.local.yaml --server-listen :9180 --server-metrics-listen :9190
waf run -c configs/waf.local.yaml --set logging.access.level=debug # 记录放行请求
waf run -c configs/waf.local.yaml --set logging.system.dir=.tmp/logs
waf run -c configs/waf.local.yaml --engine-mode detection_only     # 只关「检测引擎」的拦截，见 3.6

WAF_SERVER_LISTEN=:9180 waf run -c configs/waf.local.yaml          # 环境变量通道
```

> 结构化列表（`pipeline` / `stores` / `notifiers` / `sites`）**只能写在配置文件里**；
> `--set` 与具名参数只接受标量。用 `-c a.yaml -c b.yaml` 合并多个文件表达差异（后者覆盖前者）。

### 3.6 DetectionOnly 灰度：怎么真正「只观察不拦截」

这条流程很容易配错，务必按下面的组合来（**只改 `engine.mode` 是不够的**）：

| 单元 | 配置项 | 灰分值 | 说明 |
| --- | --- | --- | --- |
| 检测引擎 | `engine.mode` | `detection_only` | 命中降级为 `observe`，并把「本应拦截」计入 `waf_would_block_total` |
| 评分聚合 | `pipeline[type=threshold].settings.action` | `observe` | **必须一起改**：否则引擎虽降级，评分达标后 `threshold` 仍会按 `block` 拦截 |
| 限速 | `pipeline[type=ratelimit].settings.action` | 按需 | 需要连限速一起观察时再改 |
| 封禁名单 | `pipeline[type=banlist].settings.action` | 保持 `block` | 已经封禁的来源应当继续被拦，否则灰度期间等于放开攻击者 |

```bash
waf run -c configs/waf.local.yaml --engine-mode detection_only
# 同时需要把配置文件里的 pipeline[type=threshold].settings.action 改为 observe
```

验证方式：构造一次 SQLi，期望 **200 + `X-WAF-Verdict: observe`**，
且 `GET /metrics` 能看到 `waf_would_block_total` 增长；随后 `waf report detection` 就能出「若拦截」清单。

> ⚠️ **已知问题**：`sites[].engine_mode`（站点级引擎模式覆盖）目前**会被解析与校验，但运行期未生效**——
> 站点上写 `engine_mode: detection_only` 依然会按全局 `engine.mode` 拦截。
> 需要按站点灰度时，请用「单独起一套实例 + 代理侧按 Host 分流」的方式代替。

---

## 4. 冒烟验证（不接代理，直接打鉴权端点）

`ingress.type: auto` 会按注入头自动判定通道，因此用 curl 就能模拟两个代理的流量。
下面每条都对应一个**明确的期望结果**，逐条过一遍即为「服务可用」。

| # | 场景 | 期望 |
| --- | --- | --- |
| 1 | `GET /healthz`、`GET /readyz` | 均 200 |
| 2 | 放行（无异常注入头） | 200，**无响应体**，`X-WAF-Code: WAF_ALLOW` |
| 3 | 查询串 SQLi | 403，`X-WAF-Code: WAF_BLOCKED`，`X-WAF-Rule-Id: 920100`，`X-WAF-Verdict: block` |
| 4 | `POST` JSON 体内的 XSS | 403，`X-WAF-Rule-Id: 941100`，`check: crs-body` |
| 5 | `GET /waf/deny?code=429` | 429 + `{"code":"WAF_RATE_LIMITED",...}` |
| 6 | `GET /waf/deny?code=WAF_RATE_LIMITED` | 429（字面量错误码同样可用） |
| 7 | `GET /waf/unknown` | 404 + `{"code":"WAF_NOT_FOUND",...}` |
| 8 | `GET /metrics`（9090 端口） | Prometheus 文本，含 `waf_requests_total{...}` |
| 9 | 同一 IP 连打 3 次查询串 SQLi（`configs/waf.local.yaml`：`client_ip` 阈值 3） | 系统日志出现 `触发自动封禁`（`ban_scope=client_ip`）；`waf_bans_total{scope="client_ip"} 1`；第 4 次起由 `ban-list` 拦截（`rule_id=internal_banlist`） |
| 10 | 同一 IP 再打 2 次（累计 5 次，`client_ip+path` 阈值 5） | 系统日志出现 `ban_scope=client_ip+path`、`ban_key=ip:203.0.113.10\|path:/api/user`；`waf_bans_total{scope="client_ip+path"} 1`；第 4/6 次**不再**重复写名单（`skip_when_banned`） |
| 11 | 任意放行请求（用例 2）后查看访问日志 | 访问日志出现 `"action":"allow"` 与 `请求通过`（默认 `allow_level: info`，**放行与拦截都留痕**）；同一文件里拦截请求为 `"action":"block"` |
| 12 | `GET /api/user`（无查询串、无请求体） | 200 放行；`waf_body_missing_total` **不增长**（GET 无体是正常现象，不是「判断失误」） |
| 13 | `POST /api/user` 且不带请求体（`Content-Length: 0`） | 仍然 200 放行；**不告警、`waf_body_missing_total` 不增长**（客户端明确声明空体，没有参数是正常现象） |
| 14 | `POST /api/user` 且声明长度**未知**（把 `ingress.type` 改成 `nginx-auth-only`，或改用 `Transfer-Encoding: chunked`） | 仍然 200 放行；系统日志出现一条告警、`waf_body_missing_total` +1（缺失只是可观测信号，不参与拦截） |
| 15 | 裸 TCP 构造的 `POST`：子请求**既没有** `Content-Length` 也**没有** `Transfer-Encoding`（模拟「代理完全没转发请求体」的接入形态） | 200 放行（`X-WAF-Verdict: allow`），**不出现** `920180`。修复前该形态会被 CRS 920180 判成协议违规（WARNING=5 分=默认阈值）→ 403 |

```bash
# 2) 放行
curl -i -H 'X-Forwarded-Proto: http' -H 'X-Forwarded-Host: shop.example.com' \
  -H 'X-Forwarded-Method: GET' -H 'X-Forwarded-Uri: /api/user' -H 'X-Real-IP: 203.0.113.10' \
  http://127.0.0.1:9080/waf/auth

# 3) 查询串 SQLi
curl -i -H 'X-Forwarded-Proto: http' -H 'X-Forwarded-Host: shop.example.com' \
  -H 'X-Forwarded-Method: GET' -H "X-Forwarded-Uri: /api/user?id=1' OR '1'='1" \
  -H 'X-Real-IP: 203.0.113.10' http://127.0.0.1:9080/waf/auth

# 4) 请求体 XSS
curl -i -X POST -H 'Content-Type: application/json' -H 'X-Forwarded-Proto: http' \
  -H 'X-Forwarded-Host: shop.example.com' -H 'X-Forwarded-Method: POST' \
  -H 'X-Forwarded-Uri: /api/comment' -H 'X-Real-IP: 203.0.113.10' \
  -d '{"comment":"<script>alert(1)</script>"}' http://127.0.0.1:9080/waf/auth

# 5) 渲染端点 6) 7) 404 8) 指标
curl -i 'http://127.0.0.1:9080/waf/deny?code=429'
curl -i http://127.0.0.1:9080/waf/unknown
curl -s http://127.0.0.1:9090/metrics | grep '^waf_'
```

PowerShell 用户注意两点：

- 读**错误响应的响应头**必须加 `-SkipHttpErrorCheck`（PS 7+）；
  用 `$_.Exception.Response.Headers` 会拿到空值，容易误判成「`X-WAF-Code` 没设」。
- 查询串里的 `'` 会被 PS 当成字符串边界，务必用**双引号**包整条 URL。

```powershell
$h = @{ "X-Forwarded-Proto"="http"; "X-Forwarded-Host"="shop.example.com"
        "X-Forwarded-Method"="GET"; "X-Forwarded-Uri"="/api/user?id=1' OR '1'='1"
        "X-Real-IP"="203.0.113.10" }
$r = Invoke-WebRequest http://127.0.0.1:9080/waf/auth -Headers $h -SkipHttpErrorCheck
$r.StatusCode ; $r.Headers["X-Waf-Code"] ; $r.Headers["X-Waf-Rule-Id"]
```

验证自动封禁（用例 9 / 10）时把同一条请求连打 5 次，然后看两侧证据：

```powershell
$h = @{ "X-Forwarded-Proto"="http"; "X-Forwarded-Host"="shop.example.com"
        "X-Forwarded-Method"="GET"; "X-Forwarded-Uri"="/api/user?id=1' OR '1'='1"
        "X-Real-IP"="203.0.113.10" }
1..5 | ForEach-Object { (Invoke-WebRequest http://127.0.0.1:9080/waf/auth -Headers $h -SkipHttpErrorCheck).StatusCode }

# 证据 1：系统日志（logs/waf-system-*.log）
Select-String -Path logs\waf-system-*.log -Pattern "触发自动封禁" | Select-Object -Last 5

# 证据 2：指标（按封禁维度分组）
(Invoke-WebRequest http://127.0.0.1:9090/metrics -UseBasicParsing).Content -split "`n" |
  Select-String "waf_bans_total"
```

**无参数请求不会被拦截**（用例 12 / 13 / 14）：参数类检测是逐变量匹配，变量不存在时规则不命中；
唯一与「缺失」有关的信号是 `waf_body_missing_total`，而且必须**同时**满足三个条件才会计数：
方法属于 `ingress.body.missing_methods`（默认 POST / PUT / PATCH）、客户端**没有**声明空体
（`Content-Length != 0`）、接入通道确实能带来原始 `Content-Length`。缺失**不影响放行判定**。

```powershell
# 用例 13：POST 但 Content-Length: 0 —— 客户端明确声明空体，指标不应增长
$h0 = @{ "X-Forwarded-Proto"="http"; "X-Forwarded-Host"="shop.example.com"
         "X-Forwarded-Method"="POST"; "X-Forwarded-Uri"="/api/user"
         "X-Real-IP"="203.0.113.10"; "Content-Length"="0" }
(Invoke-WebRequest http://127.0.0.1:9080/waf/auth -Method POST -Headers $h0 -SkipHttpErrorCheck).StatusCode

# 用例 14：改用原生 Nginx 通道后，同样一条 POST 会因为「长度未知」而被计入缺失
#（需在配置里把 ingress.type 改成 nginx-auth-only 后重启服务）
```

```powershell
# 用例 15：裸 TCP 直接写报文（http.Client 对 POST 一定会补 Content-Length: 0，构造不出这个形态）
$c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 9080)
$s = $c.GetStream()
$req = "POST /waf/auth HTTP/1.1`r`nHost: waf.internal`r`n" +
       "X-Forwarded-Uri: /api/constant/selectAll.do`r`nX-Forwarded-Method: POST`r`n" +
       "X-Forwarded-Host: app.example.com`r`nX-Forwarded-Proto: http`r`n" +
       "X-Forwarded-For: 203.0.113.10`r`nConnection: close`r`n`r`n"
$b = [Text.Encoding]::ASCII.GetBytes($req); $s.Write($b, 0, $b.Length); $s.Flush()
(New-Object System.IO.StreamReader($s)).ReadToEnd() -split "`r?`n" | Select-String '^HTTP/|^X-Waf-'
$c.Close()
# 期望：HTTP/1.1 200 OK 且 X-Waf-Verdict: allow
```

```powershell
(Invoke-WebRequest http://127.0.0.1:9090/metrics -UseBasicParsing).Content -split "`n" |
  Select-String "waf_body_missing_total"
```

访问日志（用例 11）默认「放行与拦截都记录」，因此可以据此核对流量构成；
若只关心拦截，把 `logging.access.allow_level` 调为 `debug` 或 `off`（见 `docs/configuration.md` §2.10）：

```powershell
# 放行与拦截都在同一个访问日志文件里（logs/waf-access-*.log）
Select-String -Path logs\waf-access-*.log -Pattern '"action":"allow"|"action":"block"' |
  Select-Object -Last 10

# 只数放行 / 拦截的条数（快速判断流量构成）
(Select-String -Path logs\waf-access-*.log -Pattern '"action":"allow"').Count
(Select-String -Path logs\waf-access-*.log -Pattern '"action":"block"').Count
```

### 4.1 接真实代理的验证要点

- **Traefik（≥ v2.11）**：动态配置用 `deploy/forward-auth/traefik-forwardauth.yml`；
  中间件顺序必须是 `[waf-errors, waf-auth]`（`errors` 在外层才能接管 403/429 并回源 `/waf/deny`），
  `forwardBody: true` 是体检测的前提。
- **Nginx(OpenResty)**：`deploy/forward-auth/nginx-openresty.conf` + `waf_auth.lua`；
  原始请求信息必须由 Lua 在父请求上用 `ngx.req.set_header` 注入（子请求里的 `$request_uri` 是内部路径）。
- **原生 Nginx**：`nginx-auth-only.conf` 仅作兜底——**无体检测、无 JSON 错误体**，状态码统一 403。
- 验收动作：故意构造一次拦截，断言响应体以 `{"code":"WAF_BLOCKED"` 开头（不是 HTML 错误页）。

---

## 5. 测试

分层执行，从「快且只覆盖改动点」到「全量回归」：

### 5.1 全量门禁（每次改动后都跑）

```bash
gofmt -w ./cmd ./internal ./test     # 先格式化
gofmt -l ./cmd ./internal ./test     # 必须为空输出（有输出即未格式化）
go build ./...
go vet ./...
go test ./... -count=1
```

CI 还额外跑 `go test ./... -race -count=1` 与 `golangci-lint`（见 `.github/workflows/ci.yml`）。
本地若无 C 工具链，`-race` 在部分平台不可用；Windows 上用 Git Bash 安装 mingw 后可正常使用。

### 5.2 只跑相关测试（迭代期用）

```bash
go test ./internal/notify/... -count=1 -v                 # 某个包
go test ./test/contract -count=1 -v                       # 双代理契约 + 告警契约
go test ./test/contract -run 'TestAlert|TestNotify' -v    # 按用例名过滤
go test ./cmd/waf/ -run 'TestReport' -v                   # 报表子命令
go test ./... -count=1 -cover                             # 带覆盖率
```

### 5.3 各测试层的职责与位置

| 层 | 位置 | 覆盖内容 |
| --- | --- | --- |
| 单元测试 | `internal/**/*_test.go` | 配置三通道与优先级、串联语义与短路、体限额与超限策略、存储、日志、请求还原、各插件、报表导出 |
| 契约测试 | `test/contract/` | **按真实装配路径**起服务（`config.Load` → `logging.Build` → … → `server.New` → `httptest`）：Traefik / OpenResty 两种流量、JSON 送达、双实例共享与「不共享」反例、指标与探针、访问日志结构、告警送达/扇出/抑制/计数 |
| go-ftw 兼容用例 | `configs/ftw/*.yaml` + `test/ftw/` | CRS 规则命中的**离线执行器**（进程内驱动真实校验链，10 个阶段），不需要下载 go-ftw 二进制 |
| 压测 | `scripts/bench/` | 性能基线与容量模型，见该目录 `README.md` |

> 契约测试的插件注册清单（`test/contract/plugins_test.go`）与生产（`cmd/waf/plugins.go`）**刻意保持空白导入一致**；
> 新增插件时两处都要加，否则会出现「测试通过、线上类型未注册」。

### 5.4 配置校验与离线报表的验证

```bash
waf check-config -c configs/waf.example.yaml   # 退出码 0；失败为 2，并指出完整路径
waf check-config -c configs/waf.local.yaml
waf report detection --dir logs --since 24h            # 需要先有拦截/观察记录
waf report attack    --dir logs --since 24h --top 10
waf report ban       --dir logs --since 24h --out /tmp/ban.xlsx
```

`report` 读取 `--dir` 下的 `waf-access-*.log`（JSON Lines），**完全离线、可重复执行**；
日志目录里没有匹配文件时会明确报错，而不是给出空报表。

### 5.5 压测

```bash
# Linux / macOS / WSL
scripts/bench/run-bench.sh --tool auto --out bench.csv
# Windows（无 wrk/hey/k6 时用纯 .NET 的 builtin 模式兜底）
scripts/bench/run-bench.ps1 -Tool builtin -Out bench.csv
```

三条硬约束（细节见 `scripts/bench/README.md`）：不下载任何工具、必须带 `X-Forwarded-*` 注入头、
压测期间不改配置（要对比就起两套实例）。

### 5.6 退出码约定（写脚本/做 CI 判据时用）

| 码 | 含义 |
| --- | --- |
| `0` | 成功 |
| `1` | 运行期错误（探活失败、读取日志失败等） |
| `2` | 配置错误（校验失败、参数非法、未知子命令） |
| `3` | 仅 `waf rules verify`：文件齐全，但目录里有 `manifest.yaml` 未声明的多余文件 |

---

## 6. 打包

### 6.1 本地二进制包

版本信息来自 `git describe`（无 tag 时为 `dev`），提交号与构建时间一并通过 ldflags 注入：

```bash
VERSION=v0.9.0 sh scripts/build.sh      # 产出 bin/waf
./bin/waf version                       # 自检：确认三个字段都注入成功
```

### 6.2 容器镜像

```bash
docker build \
  --build-arg VERSION=v0.9.0 \
  --build-arg COMMIT="$(git rev-parse --short HEAD)" \
  --build-arg BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t waf:v0.9.0 .

docker run -d --name waf -p 9080:9080 -p 127.0.0.1:9090:9090 \
  -v "$PWD/configs:/etc/waf:ro" -v "$PWD/logs:/var/log/waf" \
  --read-only --tmpfs /tmp:size=64m,mode=1777 \
  waf:v0.9.0
docker exec waf /waf healthz          # 健康检查
```

镜像要点（`Dockerfile`）：多阶段构建 → `gcr.io/distroless/static:nonroot`（非 root、无 shell）；
`ENTRYPOINT ["/waf"]` + `CMD ["run","--config","/etc/waf/waf.yaml"]`；
`HEALTHCHECK` 直接调用 `/waf healthz`（distroless 里没有 curl/wget）。

### 6.3 离线交付包（内网搬运）

```bash
sh scripts/build-offline.sh
```

产出在 `dist/`：

| 工件 | 用途 |
| --- | --- |
| `waf-linux-amd64` | 静态单二进制，可直接放到裸机 / 容器里运行 |
| `waf-image.tar` | `docker save` 的镜像归档，内网 `docker load -i waf-image.tar` |
| `waf-module-cache.tar.gz` | 完整 Go module 缓存，供内网离线构建使用 |
| `SHA256SUMS` | 全部工件的校验和，落地前先校验 |

内网落地步骤：

```bash
sha256sum -c SHA256SUMS                        # 1) 校验完整性
docker load -i waf-image.tar                   # 2) 载入镜像
tar -xzf waf-module-cache.tar.gz -C /data      # 3) 解出 module 缓存（仅需要二次构建时）
export GOMODCACHE=/data/pkg/mod GOPROXY=off     # 4) 离线构建环境变量
install -m 0755 waf-linux-amd64 /usr/local/bin/waf && waf version   # 5) 裸机安装并自检
```

> `scripts/build-offline.sh` 依赖 `docker` 与 `sha256sum`（POSIX 环境）；Windows 上请用 WSL / Git Bash。
> 离线环境还需把基础镜像 `golang:1.24-alpine` 与 `gcr.io/distroless/static:nonroot` 同步进内网镜像仓库，
> 否则 `docker build` 仍会失败。

### 6.4 交付物清单（打包时一并带上）

| 类别 | 文件 |
| --- | --- |
| 二进制 / 镜像 | `bin/waf`、`dist/waf-image.tar` |
| 配置 | `configs/waf.example.yaml`（生产基线）、`configs/waf.local.yaml`（本地测试） |
| 代理接入 | `deploy/forward-auth/`（Traefik / OpenResty / 原生 Nginx 兜底） |
| 编排 | `Dockerfile`、`docker-compose.yml` |
| 脚本 | `scripts/build.sh`、`scripts/build-offline.sh`、`scripts/bench/*` |
| 文档 | `docs/` 全部（配置手册、运维手册、设计文档、路线图、本手册） |

---

## 7. CI

`.github/workflows/ci.yml` 两个 Job：

1. `build-test`：`go mod tidy` 整洁性校验 → `CGO_ENABLED=0 go build ./...` → `go vet ./...`
   → `go test ./... -race` → **`os/exec` 文本级禁用检查**（需求 R18 的双重保障之一）→ `golangci-lint`；
2. `docker-build`：构建镜像 → 起容器 → 轮询 `docker exec waf-ci /waf healthz` 验证健康检查。

迁到内网 GitLab CI / Jenkins 时，**必须保留 `os/exec` 静态拦截这一步**，它是需求 R18 的强制手段。

---

## 8. 排错速查（开发视角）

| 现象 | 排查方向 |
| --- | --- |
| `go build` 报找不到模块 | 离线环境漏了 `GOPROXY=off` + `GOMODCACHE`；或缓存不完整，重新解 `waf-module-cache.tar.gz` |
| 端口被占用 | `--server-listen` / `--server-metrics-listen` 覆盖；Windows 查占用：`Get-NetTCPConnection -LocalPort 9080 -State Listen` |
| 改了配置但不生效 | 用 `waf check-config` 看「配置项来源摘要」，确认是不是被 CLI / 环境变量覆盖（优先级 CLI 最高） |
| 打 `/waf/auth` 返回 400 | 没带 `X-Forwarded-*` 注入头；WAF 校验的是**还原后的原始请求**，缺头即无法还原 |
| 封禁/限速在本地不生效 | `memory` 存储只在进程内，`waf ban add` 是独立进程写不进去；换 `file`（跨进程、需重启进程）或 `redis`（多实例共享） |
| 访问日志里只有拦截没有放行 | 看 `logging.access.allow_level`：默认 `info` 表示**放行与拦截都留痕**，`debug` 仅 debug 级可见，`off` 完全不记录；被改成 `debug` / `off` 后放行流量就查不到了（见 `docs/configuration.md` §2.10） |
| 日志文件不存在 | 按需创建：没有任何达到级别的记录时不会建文件；也可能是 `outputs` 没写 `file` |
| 进程被强杀后报表数据不全 | 日志靠 `Close` 落盘，务必优雅关停（`Ctrl+C` / `docker stop`），不要 `kill -9` |
| `waf rules verify` 退出码 3 | 文件齐全但有清单未声明的多余文件（升级残留），确认后清理，不要直接投用 |
| 想知道「WAF 把这次请求当成了什么参数」 | 断在 `internal/server/server.go:332`，看 `rctx.Raw`（Method/URI/Path/RawQuery/Host/ClientIP）；完整方法见 `docs/debugging.md` |
| `dlv` 找不到 / 断点不停 | 未安装或不在 PATH：`go install github.com/go-delve/delve/cmd/dlv@latest` 后重开终端；断点停在优化后的代码上要带 `-gcflags="all=-N -l"` |

---

## 9. 与其它文档的关系

| 文档 | 回答的问题 |
| --- | --- |
| **本手册** | 怎么构建、怎么跑起来、怎么测、怎么打包 |
| `docs/debugging.md` | 怎么打断点单步调试、怎么看清「WAF 看到了什么参数」 |
| `docs/configuration.md` | 每个配置项是什么、默认值多少、从哪个通道来 |
| `docs/operations.md` | 上线前做什么、告警怎么接、封禁怎么运维、容量怎么规划 |
| `docs/forward-auth-design.md` | 为什么是这个架构：部署形态、抽象接口、双代理差异 |
| `docs/development-roadmap.md` | 优先级、阶段划分、交付清单、实施记录与门禁结果 |
| `docs/waf-feature-list.md` | 功能全景、市场对标、能力边界 |
