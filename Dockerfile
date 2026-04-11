# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.94
ARG ALPINE_VERSION=3.22

FROM --platform=$TARGETPLATFORM rust:${RUST_VERSION}-alpine AS builder

WORKDIR /app

ARG TARGETARCH

RUN apk add --no-cache build-base cmake musl-dev perl pkgconfig

RUN case "${TARGETARCH}" in \
      amd64) echo "x86_64-unknown-linux-musl" > /tmp/rust-target ;; \
      arm64) echo "aarch64-unknown-linux-musl" > /tmp/rust-target ;; \
      riscv64) echo "riscv64gc-unknown-linux-musl" > /tmp/rust-target ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac

RUN rustup target add "$(cat /tmp/rust-target)"

COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY sources ./sources

RUN RUST_TARGET="$(cat /tmp/rust-target)" && \
    cargo build --locked --release --target "${RUST_TARGET}" && \
    install -Dm755 "target/${RUST_TARGET}/release/sendmail-sec" /out/sendmail-sec

FROM --platform=$TARGETPLATFORM alpine:${ALPINE_VERSION}

WORKDIR /app

RUN addgroup -S app && adduser -S -G app app

COPY --from=builder /out/sendmail-sec /usr/local/bin/sendmail-sec

USER app:app

ENTRYPOINT ["/usr/local/bin/sendmail-sec"]
CMD ["--config", "/config/sendmail-sec.yaml"]
