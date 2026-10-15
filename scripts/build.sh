#!/bin/sh
# =============================================================================
# WAF 本地构建脚本（需求 R14）
#
# 用法：
#   scripts/build.sh                # 使用当前 git 信息注入版本
#   VERSION=v1.0.0 scripts/build.sh # 显式指定版本
#
# 产出：
#   bin/waf（静态编译的单二进制，CGO_ENABLED=0）
# =============================================================================
set -eu

# 脚本所在目录与仓库根目录。
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# 版本信息：优先取环境变量，其次从 git 推导，最后回退为占位值。
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo none)}"
BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

# 静态编译：
#   -trimpath 去除构建路径信息（可复现构建）；
#   -s -w     去除符号表与调试信息（减小体积）。
LDFLAGS="-s -w"
LDFLAGS="${LDFLAGS} -X github.com/weiyongkang/waf/internal/version.Version=${VERSION}"
LDFLAGS="${LDFLAGS} -X github.com/weiyongkang/waf/internal/version.Commit=${COMMIT}"
LDFLAGS="${LDFLAGS} -X github.com/weiyongkang/waf/internal/version.BuildTime=${BUILD_TIME}"

mkdir -p bin

echo "构建 WAF：VERSION=${VERSION} COMMIT=${COMMIT} BUILD_TIME=${BUILD_TIME}"
CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o bin/waf ./cmd/waf

echo "构建完成：bin/waf"