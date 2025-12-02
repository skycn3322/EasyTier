# 阶段 1: 基础镜像 (运行时)
FROM alpine:latest AS base

# 阶段 2: Builder 阶段 - 用于从 CI 下载的 Artifact 中复制文件
# 注意：我们不再依赖 ARG TARGETPLATFORM 来选择文件，因为 CI 已经为特定平台下载了特定 Artifact
FROM base AS builder

ARG TARGETPLATFORM
ARG RELEASE_TAG # 从 CI 传入版本信息

# 假设：在 CI 中，我们下载了名为 'easytier-linux-x86_64' 的压缩包，解压后所有文件都在 /tmp/artifacts/ 下
COPY /tmp/artifacts /tmp/output

WORKDIR /tmp/output

# 检查并复制正确的二进制文件（仅处理核心和 CLI）
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
        echo "Copying x86_64 binaries..."; \
        cp easytier-core ./easytier-core; \
        cp easytier-cli ./easytier-cli; \
    elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
        echo "Copying aarch64 binaries..."; \
        cp easytier-core ./easytier-core; \
        cp easytier-cli ./easytier-cli; \
    else \
        echo "Unsupported platform for Docker build: $TARGETPLATFORM"; \
        exit 1; \
    fi;

# 阶段 3: 最终运行镜像

FROM base

RUN apk add --no-cache tzdata tini
WORKDIR /app
COPY --from=builder --chmod=755 /tmp/output/* /usr/local/bin

# users can use "-e TZ=xxx" to adjust it
ENV TZ=Asia/Shanghai

# tcp
EXPOSE 11010/tcp
# udp
EXPOSE 11010/udp
# wg
EXPOSE 11011/udp
# ws
EXPOSE 11011/tcp
# wss
EXPOSE 11012/tcp

ENTRYPOINT ["/sbin/tini", "--", "easytier-core"]
