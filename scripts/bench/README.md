# 性能基线与容量压测（P1-10）

本目录提供 forward-auth 前置校验的**离线压测脚本**。目标不是"跑一个好看的 QPS"，
而是产出一条可复现、可归档、可横向对比的基线，用来回答两个运维问题：

1. **当前规则规模下，本机的 QPS 与 P99 是多少？** —— 决定单实例能承接多少流量；
2. **每增加 N 条规则，QPS 掉多少？** —— 决定扩容触发点与规则治理的紧迫度。

> 容量模型与档位建议见 `docs/operations.md` 的「容量规划」章节。

---

## 1. 文件一览

| 文件 | 用途 |
| --- | --- |
| `run-bench.sh` | 主脚本（Linux / macOS / WSL / Git Bash）：选择工具、发压、采集、写入基线 CSV |
| `run-bench.ps1` | 同参数的 PowerShell 版本；额外提供无外部工具时的 `builtin` 模式 |
| `auth-request.lua` | wrk 脚本：构造 forward-auth 注入头与请求体 |
| `k6-auth-request.js` | k6 脚本：多 VU、每 VU 独立来源 IP，`handleSummary` 直接产出 CSV |
| `payloads/clean.json` | 正常业务请求体 |
| `payloads/sqli.json` | SQL 注入载荷（测规则命中路径） |
| `payloads/xss.json` | XSS 载荷（测请求体解析 + 规则命中路径） |

---

## 2. 三条硬约束（与全局需求一致）

1. **不下载任何工具**。脚本只使用机器上已安装的 `wrk` / `hey` / `k6`；
   一个都没有时明确报错退出（`run-bench.ps1` 会退化为 `builtin`），
   不会去执行 `curl | sh` 之类的在线安装——内网环境通常也不允许。
2. **必须带 forward-auth 注入头**。WAF 校验的对象是**注入头还原出的原始请求**，
   直接压 `/waf/auth` 而不带 `X-Forwarded-*` 只会得到 400，
   测到的是错误处理路径的性能（脚本已经内置这些头）。
3. **压测期间不改配置**。基线只有在"配置固定"时才可复现；
   需要对比不同 pipeline 时，请分别启动两套实例（或用两个端口），
   而不是在压测过程中 reload。

---

## 3. 前置准备

```bash
# 1) 启动被测实例（示例配置见 configs/waf.example.yaml）
go build -o /tmp/waf ./cmd/waf
/tmp/waf run -c configs/waf.example.yaml

# 2) 确认注入头链路可用（应当返回 200 并带 X-WAF-Verdict 头）
curl -i -X POST http://127.0.0.1:19185/waf/auth \
  -H 'Content-Type: application/json' \
  -H 'X-Forwarded-Proto: https' \
  -H 'X-Forwarded-Host: bench.example.com' \
  -H 'X-Forwarded-For: 203.0.113.10' \
  -H 'X-Forwarded-Method: POST' \
  -H 'X-Forwarded-Uri: /api/v1/orders?page=1' \
  -d '{"order_id":10086}'
```

> 注意：`X-Forwarded-For` 必须落在配置的 `ingress.client_ip.trusted_proxies` 之内，
> 否则 WAF 不会信任该头（这是防伪造的设计，不是 bug）。压测建议在本机直连，
> 并把 `127.0.0.1/32` 保留在可信网段里。

---

## 4. 怎么跑

### 4.1 基线（零检测开销）

把 pipeline 置空或只留 `passthrough`，测出**框架自身的固定成本**：

```yaml
pipeline:
  - name: baseline
    type: passthrough
    enabled: true
    phase: pre
    order: 10
```

```bash
scripts/bench/run-bench.sh --label "framework-only" --out bench-baseline.csv
```

### 4.2 真实链路

恢复生产 pipeline（`banlist` / `ipaccess` / `ratelimit` / `coraza` / `threshold` / `autoban`），
分别用三种载荷各跑一次：

```bash
scripts/bench/run-bench.sh --label "crs+clean" --body scripts/bench/payloads/clean.json  --out bench-baseline.csv
scripts/bench/run-bench.sh --label "crs+sqli"  --body scripts/bench/payloads/sqli.json   --out bench-baseline.csv
scripts/bench/run-bench.sh --label "crs+xss"   --body scripts/bench/payloads/xss.json    --out bench-baseline.csv
```

**读数方式**（这三行构成一条完整的容量结论）：

- `crs+clean` 与 `framework-only` 的差值 = **常规请求的检测开销**；
- `crs+sqli` 与 `crs+clean` 的差值 = **规则命中路径的额外开销**（异常评分、告警、封禁写入）；
- 若 `sqli` 行的 `errors` 有增长，说明触发了 `autoban`/`ratelimit` 的存储写入，
  这正是最需要关注的那部分开销（共享存储的 QPS 上限往往就是 WAF 的上限）。

### 4.3 规则规模曲线

每增加一批规则就重跑一次基线，把 `label` 写成 `crs-<规则数>-<载荷>`，
即可在 CSV 里画出"规则数 → QPS / P99"的曲线：

```bash
scripts/bench/run-bench.sh --label "crs-100-sqli" --body scripts/bench/payloads/sqli.json --out bench-baseline.csv
scripts/bench/run-bench.sh --label "crs-300-sqli" --body scripts/bench/payloads/sqli.json --out bench-baseline.csv
```

### 4.4 Windows

```powershell
pwsh scripts/bench/run-bench.ps1 -Label "framework-only" -Out bench-baseline.csv
pwsh scripts/bench/run-bench.ps1 -Tool builtin -Duration 10 -Label "smoke" -Out bench-baseline.csv
```

`-Tool builtin` 使用 PowerShell 作业发压，**只用于冒烟与相对对比**，不要把它当作容量数字。

---

## 5. 基线 CSV 格式

`run-bench.sh` / `run-bench.ps1` 与 k6 脚本写出的表头是统一的（可直接 `cat` 拼在一起）：

```csv
label,tool,requests,rps,p50_ms,p90_ms,p99_ms,errors
framework-only,wrk,1520431,50681.03,1.132,2.457,5.881,0
crs+clean,wrk,842113,28070.43,2.014,4.882,12.337,0
crs+sqli,wrk,733905,24463.50,2.401,5.774,15.028,2
```

---

## 6. 没有压测工具时的替代命令

以下命令无需额外二进制，可在任意环境复现**同一请求路径**（数值不具容量意义）：

```bash
# 单请求延迟（curl 自带计时）
for i in $(seq 1 200); do
  curl -s -o /dev/null -w '%{time_total}\n' -X POST http://127.0.0.1:19185/waf/auth \
    -H 'Content-Type: application/json' -H 'X-Forwarded-Proto: https' \
    -H 'X-Forwarded-Host: bench.example.com' -H 'X-Forwarded-For: 203.0.113.10' \
    -H 'X-Forwarded-Method: POST' -H 'X-Forwarded-Uri: /api/v1/orders?page=1' \
    -d '{"order_id":10086}'
done | sort -n | awk '{a[NR]=$1} END {printf "p50=%.4fs p90=%.4fs p99=%.4fs\n", a[int(NR*0.5)], a[int(NR*0.9)], a[int(NR*0.99)]}'
```

```powershell
# Windows 等价写法（PowerShell 5.1 及以上）
$headers = @{
  'Content-Type'='application/json'; 'X-Forwarded-Proto'='https'
  'X-Forwarded-Host'='bench.example.com'; 'X-Forwarded-For'='203.0.113.10'
  'X-Forwarded-Method'='POST'; 'X-Forwarded-Uri'='/api/v1/orders?page=1'
}
$samples = 1..200 | ForEach-Object {
  (Measure-Command {
    Invoke-WebRequest -Method Post -Uri http://127.0.0.1:19185/waf/auth -Headers $headers -Body '{"order_id":10086}' -UseBasicParsing | Out-Null
  }).TotalMilliseconds
}
($samples | Sort-Object)[[int]($samples.Count * 0.99)]
```

---

## 7. 关于 `--bench`

WAF 二进制**没有** `--bench` 开关，也不应该有：压测是"外部对服务发压"，
把压测逻辑编进被测进程会污染结果（自测自）。
这里的 `scripts/bench/*` 就是上一节说的"`--bench` 说明"的实体交付物——
即"用哪个脚本、带哪些头、对比哪两行"的完整操作手册。