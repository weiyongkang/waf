// forward-auth 鉴权子请求压测脚本（k6 用）。
//
// 用法：
//   WAF_TARGET=http://127.0.0.1:19185 k6 run scripts/bench/k6-auth-request.js
//
// 与 wrk 脚本的差异：k6 的 VU（虚拟用户）是长期存活的对象，
// 因此这里用 __VU 派生客户端 IP，让限速与封禁类插件看到「多个来源」，
// 避免所有流量都来自同一个 IP 而被限速插件提前拦下，导致测出来的其实是限速路径。
//
// 环境变量：
//   WAF_TARGET        被测服务基础地址（默认 http://127.0.0.1:19185）
//   WAF_AUTH_PATH     鉴权子请求路径（默认 /waf/auth）
//   WAF_BENCH_URI     原始请求 URI（可放入攻击载荷）
//   WAF_BENCH_BODY    请求体 JSON 字符串
//   WAF_BENCH_VUS     并发 VU 数（默认 50）
//   WAF_BENCH_DURATION 压测时长（默认 30s）
//   WAF_BENCH_CSV     基线 CSV 输出路径（默认 bench-k6.csv）

import http from 'k6/http';
import { check } from 'k6';

const target = __ENV.WAF_TARGET || 'http://127.0.0.1:19185';
const authPath = __ENV.WAF_AUTH_PATH || '/waf/auth';
const requestUri = __ENV.WAF_BENCH_URI || '/api/v1/orders?page=1';
const requestBody = __ENV.WAF_BENCH_BODY || '{"order_id":10086,"remark":"bench"}';
const csvPath = __ENV.WAF_BENCH_CSV || 'bench-k6.csv';

export const options = {
  vus: Number(__ENV.WAF_BENCH_VUS || 50),
  duration: __ENV.WAF_BENCH_DURATION || '30s',
  summaryTrendStats: ['avg', 'p(50)', 'p(90)', 'p(99)', 'max'],
};

export default function () {
  // 每个 VU 使用不同来源 IP：这样限速/封禁插件不会把压测流量当成单一攻击源。
  const clientIp = `203.0.113.${(__VU % 200) + 10}`;
  const response = http.post(target + authPath, requestBody, {
    headers: {
      'Content-Type': 'application/json',
      'X-Forwarded-Proto': 'https',
      'X-Forwarded-Host': 'bench.example.com',
      'X-Forwarded-For': clientIp,
      'X-Forwarded-Method': 'POST',
      'X-Forwarded-Uri': requestUri,
    },
  });

  // 200 表示放行，403/401 表示拦截——两者都是「正常判定」，
  // 只有 5xx 与网络错误才算压测失败（因此这里只断言状态码 < 500）。
  check(response, { '不是服务端错误': (r) => r.status < 500 });
}

// handleSummary 直接把基线写入 CSV，避免依赖 jq 之类的额外二进制（离线环境要求）。
export function handleSummary(data) {
  const metric = (name, key) => {
    const m = data.metrics[name];
    if (!m || !m.values || m.values[key] === undefined) {
      return '';
    }
    return m.values[key];
  };

  const requests = metric('http_reqs', 'count');
  const rps = metric('http_reqs', 'rate');
  const p50 = metric('http_req_duration', 'p(50)');
  const p90 = metric('http_req_duration', 'p(90)');
  const p99 = metric('http_req_duration', 'p(99)');
  const failed = metric('http_req_failed', 'rate');

  const header = 'tool,requests,rps,p50_ms,p90_ms,p99_ms,failure_rate\n';
  const row = `k6,${requests},${Number(rps).toFixed(2)},${Number(p50).toFixed(3)},${Number(p90).toFixed(3)},${Number(p99).toFixed(3)},${Number(failed).toFixed(6)}\n`;

  const summary = header + row;
  const output = {};
  output[csvPath] = summary;
  output['stdout'] = `--- bench-summary ---\n${row}`;
  return output;
}