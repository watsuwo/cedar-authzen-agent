#!/bin/sh
et -eu

cd "$(dirname "$0")/.." || exit 1
START_TIME=$(date +%s)
SKIPPED=""

step() {
    echo ""
    echo ">>>> $*"
}

step "cargo fmt --all --check"
cargo fmt --all --check

# -D warnings is passed to clippy directly rather than via RUSTFLAGS so that the
# build cache is shared with the test step below.
step "cargo clippy --all-targets --locked"
cargo clippy --all-targets --locked -- -D warnings

step "cargo test --locked"
cargo test --locked

if command -v cargo-audit >/dev/null 2>&1; then
    step "cargo audit --deny warnings"
    cargo audit --deny warnings
else
    SKIPPED="$SKIPPED cargo-audit"
    echo ""
    echo "[SKIP] cargo audit — install with: cargo install cargo-audit"
fi

if command -v cargo-deny >/dev/null 2>&1; then
    step "cargo deny check"
    cargo deny check
else
    SKIPPED="$SKIPPED cargo-deny"
    echo ""
    echo "[SKIP] cargo deny — install with: cargo install cargo-deny"
fi

END_TIME=$(date +%s)
echo ""
echo "All checks passed in $((END_TIME - START_TIME)) seconds"
if [ -n "$SKIPPED" ]; then
    echo "Skipped (not installed):$SKIPPED"
fi
