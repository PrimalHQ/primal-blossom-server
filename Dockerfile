FROM rust:1-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY .sqlx ./.sqlx

ENV SQLX_OFFLINE=true
RUN cargo build --locked --release --no-default-features

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        ffmpeg \
        file \
        libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 blossom \
    && mkdir -p /data/cache /data/media \
    && chown -R blossom:blossom /data

COPY --from=builder /app/target/release/primal_blossom_server /usr/local/bin/primal-blossom-server

USER blossom

EXPOSE 8181

ENTRYPOINT ["primal-blossom-server"]
CMD ["--config-file", "/etc/primal-blossom/config.json", "serve"]
