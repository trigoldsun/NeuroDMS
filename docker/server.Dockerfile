# 构建阶段：工具链版本与 versions.lock 一致（Go 1.27.3）
FROM golang:1.27.3-alpine AS build

WORKDIR /src

# 模块代理：官方 proxy.golang.org 在本网络返回 502，默认走镜像。
# 用 ARG 暴露出来，CI 或客户环境可覆盖为自己的代理：
#   docker build --build-arg GOPROXY_URL=https://proxy.golang.org,direct ...
ARG GOPROXY_URL=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY_URL}

# 先复制依赖清单，利用层缓存
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# CGO 关闭以获得静态二进制；trimpath 去掉本机路径，保证可复现
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/docvault-server ./cmd/server

# ---------------------------------------------------------------------------
# ffmpeg 阶段：从官方源码自行构建，**刻意禁用 GPL**
#
# 为什么不用 apk 的 ffmpeg：Alpine 的 ffmpeg 配置里带 --enable-gpl --enable-libx264，
# 随商业产品分发会带来 GPL 传染与专利风险（见 docs/versions.lock.md §5）。
# 这里用 --disable-gpl --disable-nonfree，H.264 编码改由 openh264（BSD-2）承担。
#
# 代价：没有 libx264，CPU 转码压缩效率略低。但源片已达标时走 remux（不重编码），
# 绝大多数真实场景不受影响。
# ---------------------------------------------------------------------------
FROM alpine:3.24 AS ffmpeg

ARG FFMPEG_VERSION=8.1.3

# ca-certificates 必须显式装：缺少它时 curl 报 exit 35（TLS 握手失败），
# 看起来像"源码站挂了"，实际是本机信任链缺失。
RUN apk add --no-cache build-base nasm pkgconf openssl-dev openh264-dev xz curl ca-certificates

RUN set -eux; \
    cd /tmp; \
    # 源码站偶发 TLS 抖动，重试 6 次；仍失败则换同样的官方发布路径（www 前缀）
    if ! curl -fsSL --retry 6 --retry-delay 3 --retry-all-errors \
         -o ffmpeg.tar.xz "https://ffmpeg.org/releases/ffmpeg-${FFMPEG_VERSION}.tar.xz"; then \
      curl -fsSL --retry 3 --retry-delay 3 --retry-all-errors \
        -o ffmpeg.tar.xz "https://www.ffmpeg.org/releases/ffmpeg-${FFMPEG_VERSION}.tar.xz"; \
    fi; \
    tar xf ffmpeg.tar.xz; \
    cd "ffmpeg-${FFMPEG_VERSION}"; \
    ./configure \
      --prefix=/usr \
      --disable-gpl \
      --disable-nonfree \
      --disable-doc \
      --disable-debug \
      --disable-static \
      --enable-shared \
      --enable-libopenh264 \
      --enable-openssl; \
    make -j"$(nproc)"; \
    make install DESTDIR=/out

# ---------------------------------------------------------------------------
# 运行阶段：API + 前端 + 预览/转码能力，非 root 运行
# Alpine 3.24 为当前稳定分支（2026-06-09，EOS 2028-06-01）
# ---------------------------------------------------------------------------
FROM alpine:3.24

# LibreOffice 用于 Office → PDF 预览（MPL-2.0，无 GNU 传染问题）。
# 字体必须与 Office 度量兼容，否则预览排版会与本地打开不一致：
#   - font-noto-cjk：中文
#   - font-liberation：Arial/Times/Courier 的度量兼容替代
# libraw-tools 提供 dcraw_emu，用于相机 RAW（CR2/NEF/ARW/DNG）解码。
# 只装工具不装开发包：解码在子进程里做，API 进程不需要链接 libraw。
RUN apk add --no-cache \
      ca-certificates tzdata \
      libreoffice-writer libreoffice-calc libreoffice-impress \
      font-noto-cjk font-dejavu font-liberation \
      libraw-tools \
      openh264 libstdc++ libgcc

# ffmpeg 只带走可执行文件与共享库，不带构建工具链。
# musl 的默认搜索路径是 /lib:/usr/lib，所以库放 /usr/lib。
COPY --from=ffmpeg /out/usr/bin/ffmpeg /usr/local/bin/ffmpeg
COPY --from=ffmpeg /out/usr/bin/ffprobe /usr/local/bin/ffprobe
COPY --from=ffmpeg /out/usr/lib/ /usr/lib/

# 构建期硬断言：交付镜像里不允许出现 GPL 构建，且两个外部程序都必须能跑
RUN set -eux; \
    if ! ffmpeg -version >/dev/null 2>&1; then echo "ffmpeg 无法运行"; exit 1; fi; \
    if ffmpeg -version | head -3 | grep -q -- '--enable-gpl'; then \
      echo "检测到 GPL 构建的 ffmpeg，禁止交付"; exit 1; \
    fi; \
    if ! soffice --version >/dev/null 2>&1; then echo "soffice 无法运行"; exit 1; fi; \
    echo "ffmpeg 与 LibreOffice 校验通过"

RUN addgroup -S docvault \
 && adduser -S -G docvault -H -s /sbin/nologin docvault \
 && mkdir -p /data/blob /data/preview /data/media /app/web \
 && chown -R docvault:docvault /data

COPY --from=build /out/docvault-server /usr/local/bin/docvault-server

# 前端产物随镜像分发：单镜像即可提供 API + 界面
COPY --from=build /src/web/dist /app/web/dist
# 水印用中文字体（OFL 许可，随镜像分发；OFL.txt 必须一起带上以满足许可要求）
COPY --from=build /src/assets/fonts /app/assets/fonts

ENV LD_LIBRARY_PATH=/usr/lib

USER docvault
EXPOSE 8080

# 存活探针只证明进程能响应，不代表依赖就绪（就绪看 /readyz）
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/docvault-server"]
