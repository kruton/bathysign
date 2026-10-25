#!/usr/bin/env bash
# Verify ALL parts with GitHub attestations before invoking this script.
set -euo pipefail
bundle=$(realpath "$1")
work=$(realpath "$2")
target=$3
mkdir -p "$work"
cat "$bundle"/builder.tar.part-* | docker image load
cat "$bundle"/inputs.tar.gz.part-* | tar -xz -C "$work"
docker run --rm --network none -e CARGO_NET_OFFLINE=true -e BATHYSIGN_OFFLINE_BUILD=1 -v "$work/src:/src" -v "$work/usr/local/cargo:/usr/local/cargo" -v "$work/usr/local/rustup:/usr/local/rustup" -w /src bathysign-builder bash scripts/release-build.sh "$target"
