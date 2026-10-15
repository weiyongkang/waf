<#
.SYNOPSIS
    forward-auth 性能基线压测脚本（Windows / PowerShell 版本，需求 P1-10）。

.DESCRIPTION
    与 run-bench.sh 保持同一套参数与同一份 CSV 表头，便于把 Linux 与 Windows
    上采集到的基线汇总到同一张表里对比。

    设计取向同样是「离线优先」：
      * 不下载任何工具；
      * 优先复用已安装的 wrk / hey / k6；
      * 一个都没有时退化为 builtin 模式——用 .NET HttpClient 直接发压。
        builtin 模式的意义是「在没有专用压测工具的机器上也能做冒烟与相对对比」，
        它的并发模型基于 PowerShell 作业，绝对数值不可用于容量承诺，
        这一点在输出里会明确提示。

.EXAMPLE
    pwsh scripts/bench/run-bench.ps1 -Target http://127.0.0.1:19185 -Tool auto -Label "crs" -Out bench-baseline.csv

.EXAMPLE
    pwsh scripts/bench/run-bench.ps1 -Body scripts/bench/payloads/sqli.json -Label "sqli-body"
#>
[CmdletBinding()]
param(
    # 被测服务地址。
    [string]$Target = "http://127.0.0.1:19185",
    # 鉴权子请求路径。
    [string]$Path = "/waf/auth",
    # 压测工具：auto / wrk / hey / k6 / builtin。
    [ValidateSet("auto", "wrk", "hey", "k6", "builtin")]
    [string]$Tool = "auto",
    # 压测时长（秒）。
    [int]$Duration = 30,
    # 并发连接数 / 虚拟用户数。
    [int]$Connections = 64,
    # 本次基线的标签。
    [string]$Label = "default",
    # 原始请求 URI。
    [string]$Uri = "/api/v1/orders?page=1",
    # 原始请求体文件路径。
    [string]$Body = "",
    # 原始请求方法。
    [string]$Method = "POST",
    # 原始站点 Host。
    [string]$HostName = "bench.example.com",
    # 基线 CSV 输出路径（追加写入）。
    [string]$Out = ""
)

$ErrorActionPreference = "Stop"

# 请求体：未指定文件时使用内置的正常业务体。
$bodyText = '{"order_id":10086,"remark":"bench"}'
$bodyFromFile = $false
if ($Body -ne "" -and (Test-Path -LiteralPath $Body)) {
    $bodyText = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Body).Path)
    $bodyFromFile = $true
}

$url = $Target + $Path

# 探测可用的外部压测工具。
function Resolve-Tool {
    param([string]$Requested)
    if ($Requested -ne "auto") { return $Requested }
    foreach ($candidate in @("wrk", "hey", "k6")) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) { return $candidate }
    }
    return "builtin"
}

$Tool = Resolve-Tool -Requested $Tool

Write-Host "压测配置：工具=$Tool 目标=$url 并发=$Connections 时长=${Duration}s 标签=$Label"
if ($bodyFromFile) { Write-Host "请求体：$Body" } else { Write-Host "请求体：内置" }

# 构造 forward-auth 注入头：不带这些头测到的是「无法还原原始请求」的 400 路径。
$headers = @{
    "Content-Type"        = "application/json"
    "X-Forwarded-Proto"   = "https"
    "X-Forwarded-Host"    = $HostName
    "X-Forwarded-For"     = "203.0.113.10"
    "X-Forwarded-Method"  = $Method
    "X-Forwarded-Uri"     = $Uri
}

$requests = 0
$errors = 0
$rps = 0.0
$p50 = 0.0
$p90 = 0.0
$p99 = 0.0

switch ($Tool) {
    "wrk" {
        $env:BENCH_HOST = $HostName
        $env:BENCH_URI = $Uri
        $env:BENCH_METHOD = $Method
        if ($bodyFromFile) { $env:BENCH_BODY = (Resolve-Path -LiteralPath $Body).Path }
        $lua = Join-Path $PSScriptRoot "auth-request.lua"
        $output = & wrk -t2 -c$Connections -d"${Duration}s" --latency -s $lua $Target 2>&1 | Out-String
        Write-Host $output
        $rps = [double]([regex]::Match($output, "Requests/sec:\s+([\d\.]+)").Groups[1].Value)
        $p50 = [double]([regex]::Match($output, "50%\s+([\d\.]+)").Groups[1].Value)
        $p90 = [double]([regex]::Match($output, "90%\s+([\d\.]+)").Groups[1].Value)
        $p99 = [double]([regex]::Match($output, "99%\s+([\d\.]+)").Groups[1].Value)
        $requests = [int]([regex]::Match($output, "(\d+)\s+requests in").Groups[1].Value)
    }
    "hey" {
        $args = @("-z", "${Duration}s", "-c", "$Connections", "-m", "POST")
        foreach ($key in $headers.Keys) { $args += @("-H", "$key`: $($headers[$key])") }
        if ($bodyFromFile) { $args += @("-D", (Resolve-Path -LiteralPath $Body).Path) } else { $args += @("-d", $bodyText) }
        $args += $url
        $output = & hey @args 2>&1 | Out-String
        Write-Host $output
        $rps = [double]([regex]::Match($output, "Requests/sec:\s+([\d\.]+)").Groups[1].Value)
        $p50 = [double]([regex]::Match($output, "50%\s+in\s+([\d\.]+)").Groups[1].Value) * 1000
        $p90 = [double]([regex]::Match($output, "90%\s+in\s+([\d\.]+)").Groups[1].Value) * 1000
        $p99 = [double]([regex]::Match($output, "99%\s+in\s+([\d\.]+)").Groups[1].Value) * 1000
        $requests = [int]([regex]::Match($output, "Total:\s+([\d\.]+)").Groups[1].Value)
    }
    "k6" {
        $env:WAF_TARGET = $Target
        $env:WAF_AUTH_PATH = $Path
        $env:WAF_BENCH_URI = $Uri
        $env:WAF_BENCH_BODY = $bodyText
        $env:WAF_BENCH_VUS = "$Connections"
        $env:WAF_BENCH_DURATION = "${Duration}s"
        $csv = Join-Path ([System.IO.Path]::GetTempPath()) "waf-bench-k6.csv"
        $env:WAF_BENCH_CSV = $csv
        $output = & k6 run (Join-Path $PSScriptRoot "k6-auth-request.js") 2>&1 | Out-String
        Write-Host $output
        if (Test-Path -LiteralPath $csv) {
            $row = (Get-Content -LiteralPath $csv -Tail 1) -split ","
            $requests = [int]$row[1]
            $rps = [double]$row[2]
            $p50 = [double]$row[3]
            $p90 = [double]$row[4]
            $p99 = [double]$row[5]
        }
    }
    default {
        # builtin：用 .NET HttpClient 发压；PowerShell 7 起可用 -Parallel 获得真实并发。
        Write-Host "提示：builtin 模式使用 PowerShell 作业发压，数值仅用于冒烟与相对对比，不可作为容量承诺。" -ForegroundColor Yellow
        $latencies = [System.Collections.Concurrent.ConcurrentBag[double]]::new()
        $statusBag = [System.Collections.Concurrent.ConcurrentBag[int]]::new()

        $worker = {
            param($Target, $Path, $Headers, $Body, $Deadline, $Latencies, $Statuses)
            $client = [System.Net.Http.HttpClient]::new()
            $client.Timeout = [TimeSpan]::FromSeconds(10)
            try {
                while ([DateTime]::UtcNow -lt $Deadline) {
                    $content = [System.Net.Http.StringContent]::new($Body, [System.Text.Encoding]::UTF8, "application/json")
                    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, ($Target + $Path))
                    $request.Content = $content
                    foreach ($key in $Headers.Keys) {
                        # 内容头由 StringContent 负责，其余头加入请求头集合。
                        if ($key -eq "Content-Type") { continue }
                        [void]$request.Headers.TryAddWithoutValidation($key, $Headers[$key])
                    }
                    $watch = [System.Diagnostics.Stopwatch]::StartNew()
                    try {
                        $response = $client.SendAsync($request).GetAwaiter().GetResult()
                        $watch.Stop()
                        $Latencies.Add($watch.Elapsed.TotalMilliseconds)
                        $Statuses.Add([int]$response.StatusCode)
                        $response.Dispose()
                    } catch {
                        $watch.Stop()
                        $Statuses.Add(0)
                    } finally {
                        $request.Dispose()
                    }
                }
            } finally {
                $client.Dispose()
            }
        }

        $deadline = [DateTime]::UtcNow.AddSeconds($Duration)
        $watchTotal = [System.Diagnostics.Stopwatch]::StartNew()
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            1..$Connections | ForEach-Object -Parallel {
                & $using:worker -Target $using:Target -Path $using:Path -Headers $using:headers -Body $using:bodyText -Deadline $using:deadline -Latencies $using:latencies -Statuses $using:statusBag
            } | Out-Null
        } else {
            1..$Connections | ForEach-Object {
                & $worker -Target $Target -Path $Path -Headers $headers -Body $bodyText -Deadline $deadline -Latencies $latencies -Statuses $statusBag
            }
        }
        $watchTotal.Stop()

        $samples = @($latencies) | Sort-Object
        $requests = $samples.Count
        foreach ($status in $statusBag) { if ($status -eq 0 -or $status -ge 500) { $errors++ } }
        $rps = if ($watchTotal.Elapsed.TotalSeconds -gt 0) { $requests / $watchTotal.Elapsed.TotalSeconds } else { 0 }
        if ($requests -gt 0) {
            $p50 = $samples[[int][Math]::Floor($requests * 0.50)]
            $p90 = $samples[[int][Math]::Min($requests - 1, [Math]::Floor($requests * 0.90))]
            $p99 = $samples[[int][Math]::Min($requests - 1, [Math]::Floor($requests * 0.99))]
        }
    }
}

$result = "{0},{1},{2},{3:N2},{4:N3},{5:N3},{6:N3},{7}" -f $Label, $Tool, $requests, $rps, $p50, $p90, $p99, $errors
if ($Out -ne "") {
    if (-not (Test-Path -LiteralPath $Out)) {
        [System.IO.File]::WriteAllText($Out, "label,tool,requests,rps,p50_ms,p90_ms,p99_ms,errors`n")
    }
    [System.IO.File]::AppendAllText($Out, $result + "`n")
    Write-Host "已追加基线：$Out"
} else {
    Write-Host "基线结果（未指定 -Out，仅打印）："
    Write-Host $result
}