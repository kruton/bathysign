#!/usr/bin/env bash
# Copyright 2026 Kenny Root
# Shared by the composite action and CI: never resolve source-build dependencies.
set -euo pipefail
venv_path="$1"
scripts_path="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python3 -m venv --clear "$venv_path"
for requirements in pip-requirements.txt trust-requirements.txt; do
  "$venv_path/bin/python" -m pip --isolated install \
    --disable-pip-version-check --timeout 30 --retries 3 \
    --index-url https://pypi.org/simple --only-binary=:all: --no-deps \
    --require-hashes -r "$scripts_path/$requirements"
done
"$venv_path/bin/python" -m pip --isolated check
