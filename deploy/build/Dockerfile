FROM rust:1.99.0-trixie@sha256:81015672d6939b0265f09adf96d5de125482bb1330106076956b0518e74edc90
RUN rustup component add clippy
# Freeze package resolution for build and verification prerequisites.
RUN rm -f /etc/apt/sources.list.d/debian.sources && printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261020T000000Z trixie main' > /etc/apt/sources.list && apt-get update && apt-get install -y --no-install-recommends python3 clang lld cmake pkg-config openjdk-21-jdk-headless && rm -rf /var/lib/apt/lists/*
