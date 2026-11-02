FROM rust:1.99-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/nxsd --create-home nxsd

COPY --from=builder /build/target/release/nxsd /usr/local/bin/nxsd

ENV NXSD_LISTEN=0.0.0.0:8080
ENV NXSD_PUBLIC_ORIGIN=https://localhost
ENV NXSD_DATABASE_PATH=/var/lib/nxsd/nxsd.db
ENV NXSD_LOG=nxsd=info

USER nxsd
VOLUME ["/var/lib/nxsd"]
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/nxsd"]
