#!/usr/bin/env bash
# Invoked in a fresh, pinned builder container by the reusable workflow.
set -euo pipefail
release_target=$1
release_mode=${2:-build}
git config --global --add safe.directory "$PWD"
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
export BATHYSIGN_SOURCE_REVISION="$(git rev-parse HEAD)"
export TZ=UTC LC_ALL=C CARGO_INCREMENTAL=0
git config --global --add safe.directory "$PWD"
if [[ "$release_mode" == prepare ]]; then rustup component add clippy; fi
export RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$CARGO_HOME=/cargo"
if [[ "$release_mode" == prepare ]]; then cargo fetch --locked --target "$release_target"; fi
if [[ "$release_target" == x86_64-unknown-hermit ]]; then
  if [[ "$release_mode" == prepare ]]; then
    git clone https://github.com/hermit-os/loader.git dist/loader-source
    release_loader=$(python3 -c 'import json; print(json.load(open("config/release-build.json"))["loader_source"])')
    git -C dist/loader-source checkout --detach "$release_loader"
  fi
  (cd dist/loader-source; cargo xtask build --target x86_64-multiboot --release)
  cp dist/loader-source/target/release/hermit-loader-x86_64-multiboot dist/rebuilt-loader
  python3 scripts/build-hermit.py
else
  cargo build --frozen --release --target "$release_target" --features admin,collector --bin bathysign-admin --bin bathysign-collector
  cargo test --frozen --all-features
  cargo clippy --frozen --all-features --all-targets -- -D warnings
fi
if [[ "$release_mode" == prepare ]]; then
  cargo clean
  if [[ "$release_target" == x86_64-unknown-hermit ]]; then (cd dist/loader-source; cargo clean); fi
  exit 0
fi
if [[ "$release_target" == x86_64-unknown-hermit ]]; then cp dist/rebuilt-loader dist/hermit-loader; fi
python3 scripts/release.py package "$release_target" --out release
