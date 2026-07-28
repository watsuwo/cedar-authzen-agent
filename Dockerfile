# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.97.1
ARG DEBIAN_RELEASE=bookworm
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot

# cargo-chefを利用する
FROM lukemathwalker/cargo-chef:latest-rust-${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS chef
WORKDIR /build

# cargo-chef用のrecipe.jsonを作成
FROM chef AS planner
RUN --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=bind,source=src,target=src \
    cargo chef prepare --recipe-path /recipe.json

# 依存関係のビルド
FROM chef AS builder
COPY --from=planner /recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo chef cook --release --locked --recipe-path recipe.json

# アプリケーションのビルド
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=bind,source=src,target=src \
    cargo build --release --locked --bin authzen-pdp \
    && install -D target/release/authzen-pdp /out/authzen-pdp

# ユニットテスト
FROM builder AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=bind,source=src,target=src \
    cargo test --release --locked

# 起動
FROM ${RUNTIME_IMAGE} AS runtime
COPY --from=builder /out/authzen-pdp /usr/local/bin/authzen-pdp
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/authzen-pdp"]
