# === Tier 1: Dependency Preparation ===

# Stage 1: chef — Alpine (musl) base image with cargo-chef
# The digest is the digest of the image index (linux/amd64 and linux/arm64) of
# cargo-chef 0.1.78 with Rust 1.97.1. Change the tag and the digest together.
FROM lukemathwalker/cargo-chef:latest-rust-1.97-alpine3.24@sha256:980619ec8e88608ad967ee0fb697ed3b3e4368acdbac71e5e85ae61f9e2f1a2a AS chef
WORKDIR /app

# Write the musl target of the image platform to /rust-target. BuildKit sets
# TARGETARCH. The legacy builder does not set it, thus the apk architecture of
# the builder is the fallback.
ARG TARGETARCH
RUN arch="${TARGETARCH:-$(apk --print-arch)}" && \
    case "$arch" in \
        amd64|x86_64) echo x86_64-unknown-linux-musl ;; \
        arm64|aarch64) echo aarch64-unknown-linux-musl ;; \
        *) echo "no musl target for architecture: $arch" >&2; exit 1 ;; \
    esac > /rust-target

# .cargo/config.toml sets target-cpu=native in build.rustflags. Cargo uses the
# target.<triple>.rustflags values in place of build.rustflags. Thus cargo chef
# cook and each cargo build use the baseline CPU of the platform.
# rustc has no static PIE for aarch64-unknown-linux-musl. Thus the arm64
# binaries link musl dynamically, and the kernel loads them at a random address.
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-cpu=x86-64" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-cpu=generic -C target-feature=-crt-static"

# Stage 2: planner — generate dependency recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: cook — compile dependencies (cached until Cargo.toml/Cargo.lock change)
FROM chef AS cook

# The chef image has gcc and musl-dev. protoc compiles the signer protobuf files.
RUN apk add --no-cache protoc

# Set release profile overrides for smaller binaries
ENV CARGO_PROFILE_RELEASE_STRIP=true
ENV CARGO_PROFILE_RELEASE_LTO=true

# Cook dependencies from recipe (cached until Cargo.toml/Cargo.lock change)
COPY --from=planner /app/recipe.json recipe.json
RUN rust_target="$(cat /rust-target)" && \
    cargo chef cook --release --target "$rust_target" --recipe-path recipe.json

# === Tier 2: Source Compilation ===

# Stage 4: builder — compile all binaries
FROM cook AS builder
COPY . .
# Features are package-specific and allow-listed by
# scripts/docker-cargo-features.sh. A build-arg cannot enable test-utils.
#   rvc-bin: gcp-trace, gcp-secret
#   rvc-signer-bin: dvt
#   rvc-keygen: (none)
ARG RVC_FEATURES=""
ARG SIGNER_FEATURES=""
RUN rust_target="$(cat /rust-target)" && \
    rvc_feats="$(sh scripts/docker-cargo-features.sh rvc "$RVC_FEATURES")" && \
    signer_feats="$(sh scripts/docker-cargo-features.sh signer "$SIGNER_FEATURES")" && \
    cargo build --release --target "$rust_target" -p rvc-bin --bin rvc \
        ${rvc_feats:+--features "$rvc_feats"} && \
    cargo build --release --target "$rust_target" -p rvc-signer-bin --bin rvc-signer \
        ${signer_feats:+--features "$signer_feats"} && \
    cargo build --release --target "$rust_target" -p rvc-keygen --bin rvc-keygen && \
    mkdir -p /app/dist && \
    cp "target/$rust_target/release/rvc" "target/$rust_target/release/rvc-signer" \
        "target/$rust_target/release/rvc-keygen" /app/dist/

# === Tier 3: Runtime Images ===

# Stage 5: rvc — validator client runtime
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS rvc

LABEL org.opencontainers.image.title="rvc" \
      org.opencontainers.image.description="Rust Ethereum Validator Client" \
      org.opencontainers.image.url="https://github.com/rootwarp/rvc" \
      org.opencontainers.image.source="https://github.com/rootwarp/rvc" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

ARG VERSION=""
ARG GIT_SHA=""
ARG BUILD_DATE=""
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# The arm64 binaries link musl dynamically. They need libgcc_s from libgcc.
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates && \
    if [ "$(apk --print-arch)" = aarch64 ]; then apk add --no-cache libgcc; fi

RUN addgroup -g 10001 rvc && \
    adduser -u 10001 -G rvc -s /sbin/nologin -D rvc

RUN mkdir -p /data/keystores /config /certs && \
    chown -R rvc:rvc /data /config /certs

COPY --from=builder /app/dist/rvc /usr/local/bin/rvc

VOLUME ["/data", "/config"]

EXPOSE 8080 5062

# `rvc health` probes /livez one time (3 s limit). The image has no curl.
# /livez answers only after the beacon connect and the keystore decrypt, so the
# start period is long. See docs/running-guide.md "Container health check".
HEALTHCHECK --interval=30s --timeout=5s --start-period=300s --retries=3 \
    CMD ["rvc", "health", "--url", "http://127.0.0.1:8080/livez"]

USER rvc

ENTRYPOINT ["/usr/local/bin/rvc"]

# Stage 6: rvc-signer — remote signer runtime
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS rvc-signer

LABEL org.opencontainers.image.title="rvc-signer" \
      org.opencontainers.image.description="Rust Ethereum Validator Remote Signer" \
      org.opencontainers.image.url="https://github.com/rootwarp/rvc" \
      org.opencontainers.image.source="https://github.com/rootwarp/rvc" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

ARG VERSION=""
ARG GIT_SHA=""
ARG BUILD_DATE=""
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# The arm64 binaries link musl dynamically. They need libgcc_s from libgcc.
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates && \
    if [ "$(apk --print-arch)" = aarch64 ]; then apk add --no-cache libgcc; fi

RUN addgroup -g 10001 rvc && \
    adduser -u 10001 -G rvc -s /sbin/nologin -D rvc

RUN mkdir -p /data /config /certs && \
    chown -R rvc:rvc /data /config /certs

COPY --from=builder /app/dist/rvc-signer /usr/local/bin/rvc-signer

VOLUME ["/data", "/config", "/certs"]

EXPOSE 50051 9101

# `rvc-signer health` probes /metrics one time (3 s limit). The image has no curl.
# The metrics listener starts only after the keystores are decrypted.
HEALTHCHECK --interval=30s --timeout=5s --start-period=300s --retries=3 \
    CMD ["rvc-signer", "health", "--url", "http://127.0.0.1:9101/metrics"]

USER rvc

ENTRYPOINT ["/usr/local/bin/rvc-signer"]

# Stage 7: rvc-keygen — key generation CLI
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS rvc-keygen

LABEL org.opencontainers.image.title="rvc-keygen" \
      org.opencontainers.image.description="Rust Ethereum Validator Key Generator" \
      org.opencontainers.image.url="https://github.com/rootwarp/rvc" \
      org.opencontainers.image.source="https://github.com/rootwarp/rvc" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

ARG VERSION=""
ARG GIT_SHA=""
ARG BUILD_DATE=""
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# The arm64 binaries link musl dynamically. They need libgcc_s from libgcc.
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates && \
    if [ "$(apk --print-arch)" = aarch64 ]; then apk add --no-cache libgcc; fi

RUN addgroup -g 10001 rvc && \
    adduser -u 10001 -G rvc -s /sbin/nologin -D rvc

RUN mkdir -p /data/keystores && \
    chown -R rvc:rvc /data

COPY --from=builder /app/dist/rvc-keygen /usr/local/bin/rvc-keygen

VOLUME ["/data"]

USER rvc

ENTRYPOINT ["/usr/local/bin/rvc-keygen"]
