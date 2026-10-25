#!/usr/bin/env bash
# Preserve first builder's complete fetched environment for offline consumers.
set -euo pipefail
mkdir -p offline-output
# Docker image archive includes the digest-pinned OS/compiler and snapshot packages.
docker image save bathysign-builder | split -b 1800M -d - offline-output/builder.tar.part-
docker run --rm --network none -v "$PWD:/src:ro" -v release-cargo:/usr/local/cargo:ro -v release-rustup:/usr/local/rustup:ro bathysign-builder tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --exclude=target --exclude=release --exclude=offline-output --exclude=.local -czf - /src /usr/local/cargo /usr/local/rustup | split -b 1800M -d - offline-output/inputs.tar.gz.part-
