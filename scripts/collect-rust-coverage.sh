#!/usr/bin/env bash
# Fail the job if tool setup, reference checks, or coverage export fails.
set -euo pipefail
java_home=${1:?JDK home required}
android_sdk=${2:?Android SDK required}
export PATH="$java_home/bin:$PATH"
mkdir -p coverage
rustup component add llvm-tools-preview
cargo llvm-cov clean --workspace
coverage_environment=$(cargo llvm-cov show-env --export-prefix)
eval "$coverage_environment"
python3 scripts/test-android.py --java-home "$java_home" --android-sdk "$android_sdk"
# Feature selection belongs to cargo test above; report only exports collected data.
cargo llvm-cov report --include-build-script --lcov --output-path coverage/rust.lcov
