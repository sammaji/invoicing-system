# Multi-stage, two targets (`api` and `mock-psp`) out of one build.
#
# The workspace is compiled once in the builder stage and each runtime stage
# copies out the binary it needs, so `docker compose build` does not compile
# the same dependency tree twice.

FROM rust:1.91-slim-bookworm AS builder

WORKDIR /build

# Dependency-only pre-build: with just the manifests and stub sources present,
# this layer is cached and only invalidated when a Cargo.toml changes. Editing
# application code then rebuilds in seconds instead of re-fetching and
# recompiling the whole dependency graph.
COPY Cargo.toml Cargo.lock ./
COPY crates/api/Cargo.toml crates/api/
COPY crates/mock-psp/Cargo.toml crates/mock-psp/
RUN mkdir -p crates/api/src crates/mock-psp/src \
    && echo 'fn main() {}' > crates/api/src/main.rs \
    && echo '' > crates/api/src/lib.rs \
    && echo 'fn main() {}' > crates/mock-psp/src/main.rs \
    && cargo build --release \
    && rm -rf crates/api/src crates/mock-psp/src

COPY migrations migrations
COPY crates crates

# Touch the real entrypoints so cargo does not reuse the stub artefacts above.
RUN touch crates/api/src/main.rs crates/api/src/lib.rs crates/mock-psp/src/main.rs \
    && cargo build --release --locked

# --------------------------------------------------------------------------

FROM debian:bookworm-slim AS runtime

# ca-certificates is needed for outbound TLS - webhook endpoints and, in a real
# deployment, the payment providers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged: nothing here needs root, and a payment service is a bad place
# to leave that lying around.
RUN useradd --system --create-home --uid 10001 app
USER app

# --------------------------------------------------------------------------

FROM runtime AS api
COPY --from=builder /build/target/release/api /usr/local/bin/api
EXPOSE 8080
# Exec form, so the binary is PID 1 and receives SIGTERM directly - which is
# what makes the graceful shutdown in main.rs actually run.
ENTRYPOINT ["/usr/local/bin/api"]

# --------------------------------------------------------------------------

FROM runtime AS mock-psp
COPY --from=builder /build/target/release/mock-psp /usr/local/bin/mock-psp
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/mock-psp"]
