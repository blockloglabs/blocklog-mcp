# Stage 1: Build binary
FROM rust:1.88-bookworm AS builder

WORKDIR /usr/src/blocklog-mcp

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release || true
RUN rm -rf src

# Copy real sources and compile
COPY src ./src
COPY tests ./tests
RUN cargo build --release --locked

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root user
RUN groupadd -g 10001 blocklog && \
    useradd -u 10001 -g blocklog -m -s /bin/bash blocklog

WORKDIR /home/blocklog
COPY --from=builder /usr/src/blocklog-mcp/target/release/blocklog-mcp /usr/local/bin/blocklog-mcp

USER blocklog

ENV BLOCKLOG_MCP_TRANSPORT=http
ENV BLOCKLOG_HTTP_BIND=0.0.0.0:8080
ENV BLOCKLOG_LOG_FORMAT=json

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/blocklog-mcp"]
