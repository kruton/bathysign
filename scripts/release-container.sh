#!/usr/bin/env bash
# Build each runnable OCI object twice; attestations are published separately.
set -euo pipefail
release_arch=$1
release_archive=$2
mkdir -p container-context container-output
python3 - "$release_archive" <<'PY'
import pathlib, sys, tarfile
with tarfile.open(sys.argv[1]) as source:
    member = source.getmember('bin/bathysign-collector')
    pathlib.Path('container-context/bathysign-collector').write_bytes(source.extractfile(member).read())
PY
cp deploy/collector/Dockerfile container-context/Dockerfile
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
for copy in first second; do
  docker buildx create --name "reproduce-$copy" --driver docker-container --driver-opt image=moby/buildkit:v0.28.0@sha256:37539dd4d60fc70968d164d3850d903a2c56f6402214a1953fbf9fcb81ada731 --use
  docker buildx build --no-cache --platform "linux/$release_arch" --provenance=false --sbom=false --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" --output "type=oci,dest=$copy.tar,rewrite-timestamp=true" container-context
  mkdir "$copy"
  tar -xf "$copy.tar" -C "$copy"
done
python3 scripts/release.py compare first second --report container-output/reproducibility.json
cp first.tar container-output/collector.oci.tar
# Hashes cover OCI config, manifest, and compressed layer blobs, not only a rootfs.
docker run --rm --network none -v "$PWD:/scan:ro" anchore/syft:v1.38.0@sha256:825cad3a952c87676a6d07e9a3bb05ac9c401d598360070e970aa46d54c1727e oci-archive:/scan/first.tar -o spdx-json > container-output/sbom.spdx.json
