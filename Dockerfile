# === Tier 1: Dependency Preparation ===

# Stage 1: chef — base image with cargo-chef
ARG RUST_VERSION=1.97
FROM lukemathwalker/cargo-chef:latest-rust-${RUST_VERSION}-bookworm AS chef
WORKDIR /app

# Stage 2: planner — generate dependency recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: cook — compile dependencies (cached until Cargo.toml/Cargo.lock change)
FROM chef AS cook

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    gcc \
    make \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set release profile overrides for smaller binaries
ENV CARGO_PROFILE_RELEASE_STRIP=true
ENV CARGO_PROFILE_RELEASE_LTO=true

# Cook dependencies from recipe (cached until Cargo.toml/Cargo.lock change)
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# === Tier 2: Source Compilation ===

# Stage 4: builder — compile all binaries
FROM cook AS builder
COPY . .
# Features are package-specific:
#   rvc-bin: gcp-trace, gcp-secret
#   rvc-signer-bin: dvt
#   rvc-keygen: (none)
ARG RVC_FEATURES=""
ARG SIGNER_FEATURES=""
RUN cargo build --release -p rvc-bin --bin rvc \
        ${RVC_FEATURES:+--features "$RVC_FEATURES"} && \
    cargo build --release -p rvc-signer-bin --bin rvc-signer \
        ${SIGNER_FEATURES:+--features "$SIGNER_FEATURES"} && \
    cargo build --release -p rvc-keygen --bin rvc-keygen

# === Tier 3: Runtime Images ===

# Stage 5: rvc — validator client runtime
FROM debian:bookworm-slim AS rvc

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

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libgcc-s1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 rvc && \
    useradd --uid 10001 --gid rvc --shell /usr/sbin/nologin --create-home rvc

RUN mkdir -p /data/keystores /config /certs && \
    chown -R rvc:rvc /data /config /certs

COPY --from=builder /app/target/release/rvc /usr/local/bin/rvc

VOLUME ["/data", "/config"]

EXPOSE 8080 5062

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "-f", "http://localhost:8080/healthz"]

USER rvc

ENTRYPOINT ["/usr/local/bin/rvc"]

# Stage 6: rvc-signer — remote signer runtime
FROM debian:bookworm-slim AS rvc-signer

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

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libgcc-s1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 rvc && \
    useradd --uid 10001 --gid rvc --shell /usr/sbin/nologin --create-home rvc

RUN mkdir -p /data /config /certs && \
    chown -R rvc:rvc /data /config /certs

COPY --from=builder /app/target/release/rvc-signer /usr/local/bin/rvc-signer

VOLUME ["/data", "/config", "/certs"]

EXPOSE 50051 9101

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "-f", "http://localhost:9101/healthz"]

USER rvc

ENTRYPOINT ["/usr/local/bin/rvc-signer"]

# Stage 7: rvc-keygen — key generation CLI
FROM debian:bookworm-slim AS rvc-keygen

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

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 rvc && \
    useradd --uid 10001 --gid rvc --shell /usr/sbin/nologin --create-home rvc

RUN mkdir -p /data/keystores && \
    chown -R rvc:rvc /data

COPY --from=builder /app/target/release/rvc-keygen /usr/local/bin/rvc-keygen

VOLUME ["/data"]

USER rvc

ENTRYPOINT ["/usr/local/bin/rvc-keygen"]
