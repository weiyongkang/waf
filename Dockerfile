# =============================================================================
# WAF 镜像构建（常用 Go Docker 模式，需求 R14）
#   - 多阶段构建：builder 含工具链，runtime 最小化；
#   - 静态单二进制：CGO_ENABLED=0，可运行于 distroless / scratch；
#   - 非 root 运行：distroless 的 nonroot 用户（UID 65532）；
#   - 版本注入：通过 ldflags 写入 internal/version 的三个变量；
#   - 体积优化：-trimpath -ldflags="-s -w"，先下载依赖再拷贝源码以复用构建缓存。
# =============================================================================

# ---------------------------- 构建阶段 ----------------------------
FROM golang:1.24-alpine AS builder

WORKDIR /src

# 先拷贝依赖描述文件，最大化利用构建缓存（依赖不变时无需重新下载）。
COPY go.mod go.sum ./
RUN go mod download

# 再拷贝源码。
COPY . .

# 版本信息由构建命令注入，未传入时使用占位值。
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown

# 静态编译：
#   CGO_ENABLED=0 保证无动态库依赖；
#   GOOS=linux    保证跨平台构建（在 Windows/macOS 上也能产出 Linux 镜像）。
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w \
        -X github.com/weiyongkang/waf/internal/version.Version=${VERSION} \
        -X github.com/weiyongkang/waf/internal/version.Commit=${COMMIT} \
        -X github.com/weiyongkang/waf/internal/version.BuildTime=${BUILD_TIME}" \
      -o /out/waf ./cmd/waf

# ---------------------------- 运行阶段 ----------------------------
# distroless/static 不含 shell 与包管理器，攻击面最小；
# 离线环境需提前将该基础镜像同步到内网镜像仓库。
FROM gcr.io/distroless/static:nonroot

# 二进制与示例配置。注意：示例配置仅作参考，生产配置通过卷挂载下发。
COPY --from=builder /out/waf /waf
COPY --from=builder /src/configs/waf.example.yaml /etc/waf/waf.example.yaml

# 非 root 运行（UID 65532）。
USER nonroot:nonroot

# 9080 为鉴权端点，9090 为指标与探针端点。
EXPOSE 9080 9090

# 健康检查直接调用自身子命令，不依赖镜像内的 curl / wget
# （distroless 镜像中不存在这些工具）。
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/waf", "healthz"]

ENTRYPOINT ["/waf"]
CMD ["run", "--config", "/etc/waf/waf.yaml"]