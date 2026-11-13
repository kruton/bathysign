FROM rust:1.100.0-trixie@sha256:e19840879045c951c905d0eaa9887f3439c62000e429963371b376bac8d38c31
RUN rustup component add clippy
# Freeze package resolution for build and verification prerequisites.
RUN rm -f /etc/apt/sources.list.d/debian.sources && printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261020T000000Z trixie main' > /etc/apt/sources.list && apt-get update && apt-get install -y --no-install-recommends python3 clang lld cmake pkg-config openjdk-21-jdk-headless && rm -rf /var/lib/apt/lists/*
# Hermit's kernel build clears CARGO_HOME and RUSTUP_HOME. Its default paths must
# resolve to the same persistent caches used by preparation and offline rebuilds.
RUN ln -s /usr/local/cargo /root/.cargo && ln -s /usr/local/rustup /root/.rustup && env -u CARGO_HOME -u RUSTUP_HOME -u RUSTUP_TOOLCHAIN rustup run "$RUST_VERSION" cargo --version
