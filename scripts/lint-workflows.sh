#!/usr/bin/env bash
# actionlint 1.7.12 predates Ubuntu 26.04, same-revision self references and job workflow metadata.
# Contract tests separately bind these exact expressions and reject caller overrides.
# Ubuntu 26.04 is a supported GitHub-hosted label in actions/runner-images.
set -euo pipefail
if [ "$#" -eq 0 ]; then
  set -- .github/workflows/sonar.yml .github/workflows/coverage.yml .github/workflows/release.yml .github/workflows/release-build.yml .github/workflows/release-container.yml .github/workflows/bathysign-ci.yml .github/workflows/bathysign-attest.yml .github/workflows/bathysign-finalize.yml .github/workflows/bathysign-publish.yml
fi
exec go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 \
  -ignore 'label "ubuntu-26\.04" is unknown' \
  -ignore 'specifying action "\$/bathysign(/runtime)?" in invalid format because ref is missing' \
  -ignore 'property "workflow_(ref|sha)" is not defined in object type' "$@"
