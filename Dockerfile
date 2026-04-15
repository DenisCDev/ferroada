# Stage 1: Build
FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y curl build-essential pkg-config libssl-dev cmake && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /app
COPY Cargo.toml ./
COPY Cargo.lock* ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs && cargo build --release && rm -rf src
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# Stage 2: Runtime
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/ferroada /
EXPOSE 3000 3443 9000
ENTRYPOINT ["/ferroada"]
