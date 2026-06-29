# syntax=docker/dockerfile:1
#
# Multi-stage build for authzen-sidecar (DESIGN.md §11).
# Build on glibc (Debian) and run on distroless/cc (glibc + libgcc, nonroot).
# No native TLS / aws-sdk deps, so the image stays small.
#
# Build for the target Fargate architecture, e.g.:
#   docker buildx build --platform linux/amd64 -t <ecr>/authzen-sidecar:0.1.0 --push .

# ---- builder ----
FROM rust:1-bookworm AS builder
WORKDIR /build

# Pre-build dependencies first for better layer caching.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

# Build the real binary.
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ---- runtime ----
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /build/target/release/authzen-sidecar /usr/local/bin/authzen-sidecar

# Policies + schema are supplied at runtime via the S3 Files mount (/mnt/s3files).
# Bind defaults to 127.0.0.1:9000 (localhost-only; reached by Keycloak over the
# shared awsvpc network namespace — DESIGN.md §9).
ENTRYPOINT ["/usr/local/bin/authzen-sidecar"]
