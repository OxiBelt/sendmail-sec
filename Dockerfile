# syntax=docker/dockerfile:1.7

ARG RUST_BUILDER_IMAGE=rust:1.94-alpine
ARG ALPINE_VERSION=3.22

FROM --platform=$TARGETPLATFORM ${RUST_BUILDER_IMAGE} AS builder

WORKDIR /app

ARG TARGETARCH

RUN if command -v apk >/dev/null 2>&1; then \
      apk add --no-cache build-base cmake musl-dev perl pkgconfig; \
    else \
      apt-get update && \
      apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        musl-tools \
        perl \
        pkg-config && \
      rm -rf /var/lib/apt/lists/*; \
    fi

# The Cargo config uses canonical musl linker names. In this builder each stage
# runs on TARGETPLATFORM, so the native musl compiler is already the right linker.
RUN case "${TARGETARCH}" in \
      amd64) \
        echo "x86_64-unknown-linux-musl" > /tmp/rust-target; \
        musl_linker=x86_64-linux-musl-gcc ;; \
      arm64) \
        echo "aarch64-unknown-linux-musl" > /tmp/rust-target; \
        musl_linker=aarch64-linux-musl-gcc ;; \
      riscv64) \
        echo "riscv64gc-unknown-linux-musl" > /tmp/rust-target; \
        musl_linker=riscv64-linux-musl-gcc ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    if command -v apk >/dev/null 2>&1; then \
      ln -sf /usr/bin/gcc "/usr/local/bin/${musl_linker}"; \
    elif command -v musl-gcc >/dev/null 2>&1; then \
      ln -sf "$(command -v musl-gcc)" "/usr/local/bin/${musl_linker}"; \
    fi

RUN rustup target add "$(cat /tmp/rust-target)"

COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY sources ./sources

RUN RUST_TARGET="$(cat /tmp/rust-target)" && \
    cargo build --locked --release --target "${RUST_TARGET}" && \
    install -Dm755 "target/${RUST_TARGET}/release/sendmail-sec" /out/sendmail-sec

FROM --platform=$TARGETPLATFORM alpine:${ALPINE_VERSION}

ARG OCI_SOURCE=""

LABEL org.opencontainers.image.source="${OCI_SOURCE}"

WORKDIR /app

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /out/sendmail-sec /usr/local/bin/sendmail-sec

USER app:app

ENTRYPOINT ["/usr/local/bin/sendmail-sec"]
CMD ["--config", "/config/sendmail-sec.yaml"]
