#!/bin/bash

cd "$(dirname "$0")/.."

if [[ "$1" == "--fix" ]]; then
  cargo fix --allow-dirty
  cargo clippy --fix --allow-dirty
  cargo fmt
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --workspace
else
  cargo check --all-targets --all-features
  cargo fmt --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --workspace
fi
