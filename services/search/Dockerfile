FROM rust:1.78-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY services/search/Cargo.toml services/search/Cargo.lock* ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs && cargo build --release && rm src/main.rs

COPY services/search/src ./src
RUN touch src/main.rs && cargo build --release

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/nids-search /usr/local/bin/nids-search

RUN useradd -r -s /bin/false nids
USER nids

EXPOSE 8080
ENTRYPOINT ["nids-search"]
