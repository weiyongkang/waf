# 调试手册：断点、单步与「看参数」

面向场景：想确认「WAF 到底把这次请求当成了什么」——方法、URI、路径、查询串、请求体、
命中规则与最终判定。本文所有命令都在 Windows + PowerShell 7 + Go 1.26 + Delve 1.27.2 上实测通过。

---

## 1. 前置条件

| 依赖 | 检查命令 | 说明 |
| --- | --- | --- |
| Go 工具链 | `go version` | 与 `go.mod` 的 `go` 指令兼容即可 |
| Delve | `dlv version` | 断点调试引擎；VS Code 的 Go 扩展底层也用它 |
| VS Code + Go 扩展 | `gopls` 能解析工程 | 只用命令行调试可以不装 |

安装 Delve：

```powershell
go install github.com/go-delve/delve/cmd/dlv@latest
dlv version   # 期望：Delve Debugger / Version: 1.27.2
```

内网离线环境：把 `GOPROXY` 指向内网模块代理，或预置 `GOMODCACHE` 后再执行；
Delve 装不上并不影响「用 VS Code 附加到已编译二进制」这条路径（见 §2.2 的 `dlv exec`）。

---

## 2. 三种调试入口

### 2.1 VS Code（推荐）

本仓库的 `.gitignore` 忽略了 `/.vscode`，所以 `launch.json` 属于**本地便利配置**，不会进版本库。
仓库里已放好一份可直接使用的 `.vscode/launch.json`，包含 5 个配置：

| 配置名 | 用途 |
| --- | --- |
| 调试 WAF（local 配置 :9080/:9090） | 日常首选，本地无依赖（memory 存储，日志写 `logs/`） |
| 调试 WAF（换端口 :9300/:9301） | 已有实例占用 9080/9090 时用 |
| 调试 waf 子命令（check-config） | 调试配置加载与校验逻辑 |
| 调试当前包测试 | 打开某个 `*_test.go` 后直接 F5 |
| 调试指定测试函数 | 启动时弹框输入函数名，只跑 `-test.run` 命中的用例 |

核心内容（可直接复制重建）：

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "调试 WAF（local 配置 :9080/:9090）",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/cmd/waf",
      "args": ["run", "-c", "configs/waf.local.yaml"],
      "cwd": "${workspaceFolder}",
      "env": { "CGO_ENABLED": "0" }
    },
    {
      "name": "调试 WAF（换端口 :9300/:9301）",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/cmd/waf",
      "args": [
        "run", "-c", "configs/waf.local.yaml",
        "--server-listen", ":9300",
        "--server-metrics-listen", ":9301"
      ],
      "cwd": "${workspaceFolder}",
      "env": { "CGO_ENABLED": "0" }
    },
    {
      "name": "调试当前包测试",
      "type": "go",
      "request": "launch",
      "mode": "test",
      "program": "${fileDirname}",
      "cwd": "${workspaceFolder}",
      "env": { "CGO_ENABLED": "0" }
    }
  ]
}
```

使用步骤：

1. 打开目标文件，在行号左侧点出红点；
2. F5（或「运行和调试」面板）选择配置；
3. 面板含义：VARIABLES（当前帧变量）/ WATCH（自定义表达式）/ CALL STACK（调用栈）/
   DEBUG CONSOLE（可直接敲表达式求值）。

两个高频技巧：

- **条件断点**：右键断点 → 「编辑断点」→ 条件填 `rctx.Raw.RawQuery != ""`，只在带查询串时停下；
- **日志点（Logpoint）**：右键 → 「添加日志点」，填 `uri={rctx.Raw.URI} ip={rctx.Raw.ClientIP}`，
  **不暂停**只打印，适合看全量流量而不打断请求。

### 2.2 Delve 命令行（无 IDE / 远程服务器）

```powershell
# 在仓库根执行；「--」之后的参数原样传给 waf 子命令
dlv debug ./cmd/waf -- run -c configs/waf.local.yaml
```

进入 `(dlv)` 提示符后的典型会话（已实测，完整输出见 §5）：

```text
(dlv) break github.com/weiyongkang/waf/internal/server.(*Server).handleAuth
Breakpoint 1 set at 0x... for ...(*Server).handleAuth() E:/work/project/waf/internal/server/server.go:291
(dlv) continue
```

`continue` 之后服务开始监听，此时在**另一个终端**发请求；断点命中后回到 `(dlv)` 即可求值。

调试远程 / 容器里的进程（headless 模式）：

```powershell
# 目标机器上
dlv debug ./cmd/waf --headless --listen=:2345 --api-version=2 --accept-multiclient -- run -c configs/waf.local.yaml
# 本地
dlv connect <目标机器>:2345
```

调试**已经编译好的二进制**（未带调试信息时断点会不准，建议先
`go build -gcflags="all=-N -l" -o bin/waf.exe ./cmd/waf` 重新构建）：

```powershell
dlv exec ./bin/waf.exe -- run -c configs/waf.local.yaml
```

### 2.3 GoLand

Run → Edit Configurations → **Go Build**：

- Run kind：`Package`
- Package path：`github.com/weiyongkang/waf/cmd/waf`
- Program arguments：`run -c configs/waf.local.yaml`
- Working directory：仓库根

---

## 3. 「看参数」断点地图

每一层都有明确的「该看哪个变量」。断点按数据流顺序排列：

| 层次 | 位置 | 关键变量 | 能回答的问题 |
| --- | --- | --- | --- |
| HTTP 入口 | `internal/server/server.go:291` `handleAuth` | `r`（`*http.Request`）、`r.Header` | 代理**到底发了什么**注入头？ |
| 原始请求还原 | `internal/server/server.go:332` `rctx.Raw = raw` | `raw` / `rctx.Raw` | WAF 认为的「原始请求」：`Method` / `URI` / `Path` / `RawQuery` / `Host` / `ClientIP` / `Header` |
| 站点解析 | `internal/server/server.go:335` | `rctx.Site` | 命中哪个站点策略 |
| 请求体缓冲 | `internal/ingress/body/spool.go:169` `Fill` | `src`（`body.Source`）、`spool.Meta()` | 请求体有没有到、多大、是否截断 / 落盘 / 缺失 |
| 校验链 | `internal/pipeline/pipeline.go` `Decide` | `rctx`、`result`、`result.Findings` | 每个单元的结论、命中规则、评分 |
| 检测引擎 | `internal/check/coraza/coraza.go` `evaluateBody` | `tx`（Coraza 事务） | 引擎侧变量（`ARGS` 等）与异常分 |
| 最终留痕 | `internal/server/server.go` `recordAccess` | `result`、`attributes` | 最终判定与写入日志的字段 |

**只看参数，最短路径**：断在 `server.go:332`，然后求值：

```text
print rctx.Raw.Method
print rctx.Raw.Path
print rctx.Raw.RawQuery
print rctx.Raw.Header
```

---

## 4. 表达式速查（dlv 与 VS Code 调试控制台通用）

| 目的 | 表达式 / 命令 |
| --- | --- |
| 看单个字段 | `print rctx.Raw.RawQuery`（可简写 `p`） |
| 看请求头 | `print rctx.Raw.Header.Get("Content-Type")` |
| 当前帧全部变量 | `locals`；函数入参用 `args` |
| 看类型 | `whatis rctx.Raw` |
| 看调用栈 | `stack`（VS Code 直接看 CALL STACK 面板），切换帧用 `frame N` / `up` / `down` |
| 条件断点（命令行） | `break internal/server/server.go:332 rctx.Raw.RawQuery != ""` |
| 命中次数 | 断点命中时 dlv 会打印 `hits goroutine(x):N total:M` |
| 临时改值再走一遍 | `set rctx.Raw.Method = "POST"`（仅在当前调试会话生效，不改源码） |
| 列出 / 清除断点 | `breakpoints` / `clearall` |

---

## 5. 实战：一次 SQLi 请求的全链路

准备终端 A（调试器）与终端 B（发请求）。

**终端 A**

```powershell
dlv debug ./cmd/waf -- run -c configs/waf.local.yaml --server-listen :9300 --server-metrics-listen :9301
```

```text
(dlv) break github.com/weiyongkang/waf/internal/server.(*Server).handleAuth
Breakpoint 1 set at 0x7ff67386bc56 for ...(*Server).handleAuth() E:/work/project/waf/internal/server/server.go:291
(dlv) break internal/server/server.go:335
Breakpoint 2 set at 0x7ff67386c608 for ...(*Server).handleAuth() E:/work/project/waf/internal/server/server.go:335
(dlv) continue
```

**终端 B**（读错误响应必须加 `-SkipHttpErrorCheck`；查询串里的 `'` 要用双引号包住 URL）

```powershell
$h = @{ "X-Forwarded-Proto"="http"; "X-Forwarded-Host"="shop.example.com"
        "X-Forwarded-Method"="GET"; "X-Forwarded-Uri"="/api/user?id=1' OR '1'='1"
        "X-Real-IP"="198.51.100.231" }
Invoke-WebRequest http://127.0.0.1:9300/waf/auth -Headers $h -SkipHttpErrorCheck
```

**回到终端 A**：请求会停在 `server.go:335`（还原已完成）。实测输出：

```text
> [Breakpoint 2] ... server.go:335 (hits goroutine(86):1 total:1)
=> 335:         rctx.Site = s.resolveSite(raw.Host)
(dlv) print raw.Method
"GET"
(dlv) print raw.URI
"/api/user?id=1' OR '1'='1"
(dlv) print raw.Path
"/api/user"
(dlv) print raw.RawQuery
"id=1' OR '1'='1"
(dlv) print raw.Host
"shop.example.com"
(dlv) print raw.ClientIP
"198.51.100.231"
(dlv) print raw.PeerTrusted
true
(dlv) print len(raw.Header)
2
(dlv) print raw.Header
net/http.Header [
	"User-Agent": ["Mozilla/5.0 (Windows NT 10.0; ...)"],
	"Accept-Encoding": ["gzip, deflate, br"],
]
```

`print len(raw.Header)` 是排查「注入头被误当业务头」的快捷手段：接入适配器会把
`X-Forwarded-*` 等注入头从 `Header` 中剔除，因此这里通常只剩业务自己的头。

`continue` 放行后，终端 B 会拿到结果：

```text
(dlv) continue
# 终端 B：status=403 code=WAF_BLOCKED rule=920100
```

---

## 6. 注意事项（都是踩过的坑）

| 现象 | 原因与处置 |
| --- | --- |
| 请求一直挂着，最后客户端超时 | 断点停住时进程不再处理该请求（实测客户端 30s 超时）。调试期把客户端超时调大，或先 `clearall` 再发请求 |
| 断点位置飘、变量显示 `<optimized out>` | 编译优化。`dlv debug` 会自动加 `-gcflags="all=-N -l"`；自己 `go build` 时必须手动加 |
| 端口被占用 | 换端口配置（`:9300/:9301`）；Windows 查占用：`Get-NetTCPConnection -LocalPort 9080 -State Listen` |
| 调试结束后日志文件为空 | 日志靠 `Close` 落盘，必须优雅关停（`Ctrl+C`），不要 `kill -9` |
| `dlv` 提示找不到命令 | `go install` 后重开终端；确认 `C:\Users\<你>\go\bin` 在 PATH 上 |
| headless 监听被防火墙拦 | Windows 首次监听 `:2345` 会弹防火墙确认，允许即可；跨机调试请只监听内网地址 |
| 长时间停在断点上，共享存储 / Redis 报错 | 停顿时真实业务时钟仍在走，连接可能超时。排查存储逻辑时优先用 `file` / `memory` 存储 |

---

## 7. 与其它文档的关系

| 文档 | 回答的问题 |
| --- | --- |
| **本手册** | 怎么打断点、单步、看变量（尤其是「WAF 看到了什么参数」） |
| `docs/dev-guide.md` | 怎么构建、怎么跑起来、怎么测、怎么打包 |
| `docs/configuration.md` | 每个配置项是什么、默认值多少、从哪个通道来 |
| `docs/forward-auth-design.md` | 为什么是这个架构：部署形态、抽象接口、双代理差异 |
| `docs/operations.md` | 上线前做什么、告警怎么接、封禁怎么运维 |
