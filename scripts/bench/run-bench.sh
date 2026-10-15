#!/usr/bin/env bash
#
# forward-auth 性能基线压测脚本（需求 P1-10）。
#
# 设计目标（离线优先）：
#   1. **不下载任何东西**：只使用机器上已经装好的 wrk / hey / k6，一个都没有时直接报错退出，
#      不会悄悄去 curl 一个安装脚本（内网环境通常也不允许）；
#   2. **产出可归档的基线**：每次运行都把一行 CSV 追加到 --out 指定的文件，
#      便于把「规则规模 -> QPS / P99」的曲线画出来（见 docs/operations.md 容量章节）；
#   3. **区分"检测开销"与"框架开销"**：通过 --profile 选择不同的 pipeline，
#      用 passthrough 基线减去真实链路的差值，就是检测本身的代价。
#
# 用法示例：
#   scripts/bench/run-bench.sh --target http://127.0.0.1:19185 --tool auto \
#       --duration 30s --connections 64 --label "crs+ratelimit" --out bench-baseline.csv
#
# 注意：本脚本只负责"发压 + 采集"，不含任何 WAF 侧配置切换。
# 切换 pipeline（基线与真实链路）请修改配置文件后重启 waf，
# 原因见 docs/operations.md：压测期间改配置会让基线不可复现。

set -euo pipefail

TARGET="http://127.0.0.1:19185"
AUTH_PATH="/waf/auth"
TOOL="auto"
DURATION="30s"
CONNECTIONS="64"
THREADS="2"
LABEL="default"
OUT=""
URI="/api/v1/orders?page=1"
BODY_FILE=""
METHOD="POST"
HOST="bench.example.com"

usage() {
  cat <<'EOF'
usage: run-bench.sh [options]

  --target <url>        被测服务地址（默认 http://127.0.0.1:19185）
  --path <path>         鉴权子请求路径（默认 /waf/auth）
  --tool <auto|wrk|hey|k6>
  --duration <30s>      压测时长（k6 支持 30s，wrk 支持 30s，hey 支持 30s）
  --connections <64>    并发连接 / VU 数
  --threads <2>         wrk 线程数（仅 wrk 生效）
  --label <name>        本次基线的标签，写入 CSV 第一列
  --uri <uri>           原始请求 URI（可携带攻击载荷）
  --body <file>         原始请求体文件（--body scripts/bench/payloads/sqli.json）
  --method <METHOD>     原始请求方法（默认 POST）
  --host <host>         原始站点 Host
  --out <file.csv>      基线输出文件（追加写入）；省略时只打印
  -h, --help            显示本帮助

预置载荷（scripts/bench/payloads/）：
  clean.json  正常业务请求体（测框架与常规检测开销）
  sqli.json   SQL 注入载荷（测规则命中路径）
  xss.json    XSS 载荷（测请求体解析 + 规则命中路径）
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --path) AUTH_PATH="$2"; shift 2 ;;
    --tool) TOOL="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --connections) CONNECTIONS="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --uri) URI="$2"; shift 2 ;;
    --body) BODY_FILE="$2"; shift 2 ;;
    --method) METHOD="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数：$1" >&2; usage; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL="${TARGET}${AUTH_PATH}"

have() { command -v "$1" >/dev/null 2>&1; }

if [[ "${TOOL}" == "auto" ]]; then
  if have wrk; then TOOL="wrk"
  elif have hey; then TOOL="hey"
  elif have k6; then TOOL="k6"
  else
    echo "未找到任何压测工具（wrk / hey / k6）。" >&2
    echo "本脚本不会自动下载工具；请先在内网镜像源安装其中一个，或参考 docs/operations.md 的替代命令。" >&2
    exit 3
  fi
fi

# 秒数解析：把 30s / 1m 统一转成秒，喂给 hey 的 -z 与 k6 的 duration 参数。
duration_seconds() {
  local value="$1"
  case "${value}" in
    *s) echo "${value%s}" ;;
    *m) echo $(( ${value%m} * 60 )) ;;
    *) echo "${value}" ;;
  esac
}

SECONDS_VALUE="$(duration_seconds "${DURATION}")"
RESULT=""

echo "压测配置：工具=${TOOL} 目标=${URL} 并发=${CONNECTIONS} 时长=${DURATION} 标签=${LABEL}"
if [[ -n "${BODY_FILE}" ]]; then
  echo "请求体：${BODY_FILE}"
else
  echo "请求体：内置（可用 --body 指定）"
fi

case "${TOOL}" in
  wrk)
    BENCH_HOST="${HOST}" BENCH_URI="${URI}" BENCH_METHOD="${METHOD}" \
    BENCH_BODY="${BODY_FILE}" \
      wrk -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}" --latency \
        -s "${SCRIPT_DIR}/auth-request.lua" "${TARGET}" | tee /tmp/waf-bench-wrk.txt
    RPS="$(grep -E '^rps=' /tmp/waf-bench-wrk.txt | cut -d= -f2 | tail -1)"
    P50="$(grep -E '^p50_ms=' /tmp/waf-bench-wrk.txt | cut -d= -f2 | tail -1)"
    P90="$(grep -E '^p90_ms=' /tmp/waf-bench-wrk.txt | cut -d= -f2 | tail -1)"
    P99="$(grep -E '^p99_ms=' /tmp/waf-bench-wrk.txt | cut -d= -f2 | tail -1)"
    REQUESTS="$(grep -E '^requests=' /tmp/waf-bench-wrk.txt | cut -d= -f2 | tail -1)"
    ERRORS="$(grep -E '^errors=' /tmp/waf-bench-wrk.txt | cut -d= -f2 | tail -1)"
    RESULT="${LABEL},wrk,${REQUESTS},${RPS},${P50},${P90},${P99},${ERRORS}"
    ;;
  hey)
    HEY_ARGS=(-z "${SECONDS_VALUE}s" -c "${CONNECTIONS}" -m POST
      -H "Content-Type: application/json"
      -H "X-Forwarded-Proto: https"
      -H "X-Forwarded-Host: ${HOST}"
      -H "X-Forwarded-For: 203.0.113.10"
      -H "X-Forwarded-Method: ${METHOD}"
      -H "X-Forwarded-Uri: ${URI}")
    if [[ -n "${BODY_FILE}" ]]; then
      HEY_ARGS+=(-D "${BODY_FILE}")
    else
      HEY_ARGS+=(-d '{"order_id":10086,"remark":"bench"}')
    fi
    hey "${HEY_ARGS[@]}" "${URL}" | tee /tmp/waf-bench-hey.txt
    RPS="$(awk '/Requests\/sec:/ {print $2}' /tmp/waf-bench-hey.txt | head -1)"
    P50="$(awk '/50%% in/ {print $3}' /tmp/waf-bench-hey.txt | head -1)"
    P90="$(awk '/90%% in/ {print $3}' /tmp/waf-bench-hey.txt | head -1)"
    P99="$(awk '/99%% in/ {print $3}' /tmp/waf-bench-hey.txt | head -1)"
    RESULT="${LABEL},hey,,${RPS},${P50},${P90},${P99},"
    ;;
  k6)
    WAF_TARGET="${TARGET}" WAF_AUTH_PATH="${AUTH_PATH}" WAF_BENCH_URI="${URI}" \
    WAF_BENCH_VUS="${CONNECTIONS}" WAF_BENCH_DURATION="${DURATION}" \
    WAF_BENCH_CSV="/tmp/waf-bench-k6.csv" \
      k6 run "${SCRIPT_DIR}/k6-auth-request.js" | tee /tmp/waf-bench-k6.txt
    if [[ -f /tmp/waf-bench-k6.csv ]]; then
      RESULT="${LABEL},$(tail -1 /tmp/waf-bench-k6.csv)"
    fi
    ;;
  *)
    echo "不支持的压测工具：${TOOL}" >&2
    exit 2
    ;;
esac

if [[ -z "${RESULT}" ]]; then
  echo "未能解析压测结果，请检查上面的原始输出。" >&2
  exit 4
fi

if [[ -n "${OUT}" ]]; then
  if [[ ! -f "${OUT}" ]]; then
    echo "label,tool,requests,rps,p50_ms,p90_ms,p99_ms,errors" > "${OUT}"
  fi
  echo "${RESULT}" >> "${OUT}"
  echo "已追加基线：${OUT}"
else
  echo "基线结果（未指定 --out，仅打印）："
  echo "${RESULT}"
fi