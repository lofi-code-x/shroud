# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder
WORKDIR /usr/src/shroud

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p shroud-server

FROM debian:bookworm-slim AS runtime
WORKDIR /app

COPY --from=builder /usr/src/shroud/target/release/shroud-server /usr/local/bin/shroud-server
COPY configs/server.yaml ./configs/server.yaml
COPY web ./web

EXPOSE 8443

ENTRYPOINT ["shroud-server"]
CMD ["configs/server.yaml"]
