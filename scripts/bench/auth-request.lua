-- forward-auth 鉴权子请求压测脚本（wrk 用）。
--
-- 用法：
--   wrk -t2 -c64 -d30s --latency -s scripts/bench/auth-request.lua http://127.0.0.1:19185
--
-- 为什么必须用脚本而不是直接压路径：forward-auth 的校验对象是**注入头还原出来
-- 的原始请求**，而不是鉴权子请求本身的 URL。不带这些头，WAF 会按
-- "无法还原原始请求" 直接返回 400，测出来的是错误路径的性能。
--
-- 变量说明（可用环境变量覆盖，便于压测不同场景）：
--   BENCH_HOST   原始站点 Host
--   BENCH_URI    原始请求 URI（含查询串，可放入攻击载荷）
--   BENCH_METHOD 原始请求方法
--   BENCH_IP     伪造的客户端 IP（压测环境使用文档专用网段 203.0.113.0/24）
--   BENCH_BODY   请求体文件路径（缺省时使用内置的正常 JSON 体）

local host = os.getenv("BENCH_HOST") or "bench.example.com"
local uri = os.getenv("BENCH_URI") or "/api/v1/orders?page=1"
local method = os.getenv("BENCH_METHOD") or "POST"
local client_ip = os.getenv("BENCH_IP") or "203.0.113.10"
local body_path = os.getenv("BENCH_BODY")

local function read_body(path)
  local handle = io.open(path, "rb")
  if not handle then
    return "{}"
  end
  local content = handle:read("*a")
  handle:close()
  return content
end

local body = body_path and read_body(body_path) or '{"order_id":10086,"remark":"bench"}'

wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.headers["X-Forwarded-Proto"] = "https"
wrk.headers["X-Forwarded-Host"] = host
wrk.headers["X-Forwarded-For"] = client_ip
wrk.headers["X-Forwarded-Method"] = method
wrk.headers["X-Forwarded-Uri"] = uri
wrk.body = body

-- 自定义汇总：把关键指标打成一行，便于脚本抓取后写入基线 CSV。
done = function(summary, latency, requests)
  io.write("--- bench-summary ---\n")
  io.write(string.format("requests=%d\n", summary.requests))
  io.write(string.format("errors=%d\n", summary.errors.status + summary.errors.connect + summary.errors.read + summary.errors.write))
  io.write(string.format("rps=%.2f\n", summary.requests / (summary.duration / 1000000)))
  io.write(string.format("p50_ms=%.2f\n", latency:percentile(50) / 1000))
  io.write(string.format("p90_ms=%.2f\n", latency:percentile(90) / 1000))
  io.write(string.format("p99_ms=%.2f\n", latency:percentile(99) / 1000))
end