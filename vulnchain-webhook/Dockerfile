FROM rust:1.88-slim AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/vulnchain-webhook /usr/local/bin/vulnchain-webhook

EXPOSE 8080
CMD ["vulnchain-webhook"]
