# syntax=docker/dockerfile:1.25.0@sha256:0adf442eae370b6087e08edc7c50b552d80ddf261576f4ebd6421006b2461f12

ARG NATIVE_RUST_BUILDER_IMAGE=rust:1.97-alpine3.24@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900
ARG RISCV_RUST_BUILDER_IMAGE=rust:1.97-trixie@sha256:1bcff4befb740599103a2c7cb51058e14479b2e35e3a34a3f0dc4ede09927488
ARG CARGO_ZIGBUILD_IMAGE=ghcr.io/rust-cross/cargo-zigbuild:0.23.0@sha256:b8364c2c60cdcc9b95c402d17654bff517410926a35678bd89dd924b8158d6ae
ARG ALPINE_IMAGE=alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
ARG SENDMAIL_SEC_VERSION=dev
ARG SENDMAIL_SEC_REVISION=unknown
ARG SENDMAIL_SEC_CREATED=1970-01-01T00:00:00Z
ARG SENDMAIL_SEC_SOURCE=https://github.com/OxiBelt/sendmail-sec
ARG SENDMAIL_SEC_REF_NAME=dev

FROM ${NATIVE_RUST_BUILDER_IMAGE} AS native-builder

WORKDIR /app

ARG TARGETARCH

RUN apk add --no-cache build-base cmake musl-dev perl pkgconfig

# The Cargo config uses canonical musl linker names. This stage runs on
# TARGETPLATFORM, so the native musl compiler is already the right linker.
RUN case "${TARGETARCH}" in \
      amd64) \
        echo "x86_64-unknown-linux-musl" > /tmp/rust-target; \
        musl_linker=x86_64-linux-musl-gcc ;; \
      arm64) \
        echo "aarch64-unknown-linux-musl" > /tmp/rust-target; \
        musl_linker=aarch64-linux-musl-gcc ;; \
      *) echo "unsupported TARGETARCH for native builder: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    ln -sf /usr/bin/gcc "/usr/local/bin/${musl_linker}"

RUN rustup target add "$(cat /tmp/rust-target)"

COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo

RUN cargo fetch --locked --target "$(cat /tmp/rust-target)"

COPY sources ./sources

RUN --network=none RUST_TARGET="$(cat /tmp/rust-target)" && \
    cargo build --locked --offline --release --target "${RUST_TARGET}" && \
    install -Dm755 "target/${RUST_TARGET}/release/sendmail-sec" /out/sendmail-sec

FROM --platform=$BUILDPLATFORM ${CARGO_ZIGBUILD_IMAGE} AS cargo-zigbuild-tools

RUN set -eux; \
    zig_directory="$(dirname "$(readlink -f /usr/local/bin/zig)")"; \
    install -Dm755 /usr/local/cargo/bin/cargo-zigbuild /out/cargo-zigbuild; \
    mkdir -p /out/zig; \
    cp -a "${zig_directory}/." /out/zig/; \
    test "$(/out/zig/zig version)" = "0.16.0"

FROM --platform=$BUILDPLATFORM ${RISCV_RUST_BUILDER_IMAGE} AS riscv64-builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      cmake \
      perl \
      pkg-config && \
    rm -rf /var/lib/apt/lists/*

COPY --from=cargo-zigbuild-tools /out/cargo-zigbuild /usr/local/cargo/bin/cargo-zigbuild
COPY --from=cargo-zigbuild-tools /out/zig /opt/zig

ENV CARGO_ZIGBUILD_ZIG_PATH=/opt/zig/zig

RUN test "$("${CARGO_ZIGBUILD_ZIG_PATH}" version)" = "0.16.0" && \
    rustup target add riscv64gc-unknown-linux-musl

COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo

# cargo-zigbuild uses a generated target specification. Fetch the complete
# locked graph so target-conditional crates are available to the offline build.
RUN cargo fetch --locked

COPY sources ./sources

RUN --network=none cargo zigbuild \
      --locked \
      --offline \
      --release \
      --target riscv64gc-unknown-linux-musl && \
    install -Dm755 \
      target/riscv64gc-unknown-linux-musl/release/sendmail-sec \
      /out/sendmail-sec

FROM native-builder AS build-amd64
FROM native-builder AS build-arm64
FROM riscv64-builder AS build-riscv64
FROM build-${TARGETARCH} AS builder

FROM --platform=$BUILDPLATFORM ${ALPINE_IMAGE} AS runtime-accounts

RUN addgroup -S app && adduser -S -G app app

FROM ${ALPINE_IMAGE}

ARG SENDMAIL_SEC_VERSION
ARG SENDMAIL_SEC_REVISION
ARG SENDMAIL_SEC_CREATED
ARG SENDMAIL_SEC_SOURCE
ARG SENDMAIL_SEC_REF_NAME

LABEL org.opencontainers.image.title="sendmail-sec" \
      org.opencontainers.image.description="Authenticated local SMTP OpenPGP encryption relay" \
      org.opencontainers.image.source="${SENDMAIL_SEC_SOURCE}" \
      org.opencontainers.image.url="${SENDMAIL_SEC_SOURCE}" \
      org.opencontainers.image.version="${SENDMAIL_SEC_VERSION}" \
      org.opencontainers.image.ref.name="${SENDMAIL_SEC_REF_NAME}" \
      org.opencontainers.image.revision="${SENDMAIL_SEC_REVISION}" \
      org.opencontainers.image.created="${SENDMAIL_SEC_CREATED}" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY --from=runtime-accounts /etc/passwd /etc/passwd
COPY --from=runtime-accounts /etc/group /etc/group
COPY --from=runtime-accounts /etc/shadow /etc/shadow
COPY --from=runtime-accounts --chown=app:app --chmod=2755 /home/app /home/app
COPY --from=builder /out/sendmail-sec /usr/local/bin/sendmail-sec

USER app:app

ENTRYPOINT ["/usr/local/bin/sendmail-sec"]
CMD ["--config", "/config/sendmail-sec.yaml"]
