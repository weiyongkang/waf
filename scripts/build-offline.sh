#!/bin/sh
# =============================================================================
# WAF 离线打包脚本（需求 R14：离线交付）
#
# 用途：在可联网的构建机上完成依赖下载与镜像构建，产出可搬运到内网的全部工件。
#
# 用法：
#   scripts/build-offline.sh
#
# 产出（dist/ 目录）：
#   waf-linux-amd64          静态单二进制
#   waf-image.tar            docker save 的镜像归档
#   waf-module-cache.tar.gz  完整 Go module 缓存（供内网离线构建使用）
#   SHA256SUMS               全部工件的校验和
# =============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

DIST_DIR="dist"
IMAGE_TAG="${IMAGE_TAG:-waf:offline}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo none)}"
BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

# ---------------------------------------------------------------------------
# 1) 静态二进制（Linux amd64）
# ---------------------------------------------------------------------------
echo "==> 构建 Linux/amd64 静态二进制"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath \
  -ldflags="-s -w \
    -X github.com/weiyongkang/waf/internal/version.Version=${VERSION} \
    -X github.com/weiyongkang/waf/internal/version.Commit=${COMMIT} \
    -X github.com/weiyongkang/waf/internal/version.BuildTime=${BUILD_TIME}" \
  -o "${DIST_DIR}/waf-linux-amd64" ./cmd/waf

# ---------------------------------------------------------------------------
# 2) 容器镜像归档
# ---------------------------------------------------------------------------
echo "==> 构建并导出容器镜像 ${IMAGE_TAG}"
docker build \
  --build-arg VERSION="${VERSION}" \
  --build-arg COMMIT="${COMMIT}" \
  --build-arg BUILD_TIME="${BUILD_TIME}" \
  -t "${IMAGE_TAG}" .
docker save "${IMAGE_TAG}" -o "${DIST_DIR}/waf-image.tar"

# ---------------------------------------------------------------------------
# 3) Go module 缓存（供内网离线构建）
# ---------------------------------------------------------------------------
echo "==> 导出 Go module 缓存"
# 先确保依赖完整下载，再打包缓存目录。
go mod download all
MODCACHE="$(go env GOMODCACHE)"
tar -czf "${DIST_DIR}/waf-module-cache.tar.gz" -C "$(dirname "${MODCACHE}")" "$(basename "${MODCACHE}")"

# ---------------------------------------------------------------------------
# 4) 校验和
# ---------------------------------------------------------------------------
echo "==> 生成校验和"
# shellcheck disable=SC2164
cd "${DIST_DIR}"
sha256sum waf-linux-amd64 waf-image.tar waf-module-cache.tar.gz > SHA256SUMS

echo "离线打包完成，工件位于 ${DIST_DIR}/："
ls -lh