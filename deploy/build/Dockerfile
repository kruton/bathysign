FROM rust:1.99.1-trixie@sha256:09027f873d45b8ecd1dc86f1fa13b7a62b875c961f017a0e331267b350430137
RUN rustup component add clippy
# Freeze package resolution for build and verification prerequisites.
RUN rm -f /etc/apt/sources.list.d/debian.sources && printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261020T000000Z trixie main' > /etc/apt/sources.list && apt-get update && apt-get install -y --no-install-recommends python3 clang lld cmake pkg-config openjdk-21-jdk-headless && rm -rf /var/lib/apt/lists/*
# Hermit's kernel build clears CARGO_HOME and RUSTUP_HOME. Its default paths must
# resolve to the same persistent caches used by preparation and offline rebuilds.
RUN ln -s /usr/local/cargo /root/.cargo && ln -s /usr/local/rustup /root/.rustup && env -u CARGO_HOME -u RUSTUP_HOME -u RUSTUP_TOOLCHAIN rustup run "$RUST_VERSION" cargo --version
