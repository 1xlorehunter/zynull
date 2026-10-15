#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export ZYNULL_VK_MODE=production-candidate
export ZYNULL_NORMAL_VK_PATH="$(pwd)/public-parameters/normal-vk.json"
export ZYNULL_NORMAL_VK_SHA256=1ab39ab86cf3522fbc9e9fb885b247430d0e6b8aa2682c06b368857516db1fdd
export ZYNULL_EXIT_VK_PATH="$(pwd)/public-parameters/exit-vk.json"
export ZYNULL_EXIT_VK_SHA256=8be9e693ff1f8ec2e9e76c0c5a751646e30998ec597d777ced40b14b7e365f15
export CARGO_TARGET_DIR="$(pwd)/build/cargo-target"
export CARGO_PROFILE_RELEASE_OPT_LEVEL=z
cargo build-sbf --manifest-path program/Cargo.toml -- --locked --no-default-features --features canonical-fr,custom-panic,compact-system,compact-token,close-empty-state,compact-state
cp "$CARGO_TARGET_DIR/deploy/privacy_size_experiment.so" build/zynull.so
sha256sum build/zynull.so
