# Multi-stage build — Rust compiler only in builder stage
# Final image is ~50 MB (debian:bookworm-slim)

# ---------------------------------------------------------------------------
# Stage 1: builder
# ---------------------------------------------------------------------------
FROM rust:1.88-slim AS builder

WORKDIR /app

# System build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy all source files
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src

# Build with all optimizations
RUN cargo build --release

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/cosmicsec-ingest /app/cosmicsec-ingest

# Create non-root user
RUN useradd --system --no-create-home --shell /usr/sbin/nologin ingest
USER ingest

EXPOSE 8099 50051

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:8099/health > /dev/null || exit 1

CMD ["/app/cosmicsec-ingest"]
