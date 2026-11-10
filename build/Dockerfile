# Build image for ferritewrt: OpenWrt (kernel + C daemons + image packaging) and the
# Rust workspace, on any host with Docker (Windows hosts included).
#   docker build -t ferritewrt-build:1 -f build/Dockerfile build/
# Normally invoked through build/run-in-docker.sh.
FROM ubuntu:26.04

ARG DEBIAN_FRONTEND=noninteractive
# Host UID/GID that owns bind-mounted files (run-in-docker.sh passes the caller's on Linux).
ARG BUILDER_UID=1000
ARG BUILDER_GID=1000
# cargo-deny gates the dependency graph (deny.toml). Pinned for reproducibility.
ARG CARGO_DENY_VERSION=0.18.3

# OpenWrt build prerequisites for an x86_64 host and an aarch64 target (no multilib
# needed), plus what the in-tree U-Boot / ARM TF-A builds use (pyelftools, swig,
# python3-dev, gnutls, uuid, libelf). ca-certificates/curl for rustup and downloads.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bc bison build-essential bzip2 ca-certificates clang curl diffutils file flex g++ \
      gawk gettext git libelf-dev libgnutls28-dev libncurses-dev libssl-dev patch perl \
      pkg-config python3 python3-dev python3-pyelftools python3-setuptools rsync swig \
      time unzip uuid-dev wget xz-utils zlib1g-dev zstd \
 && rm -rf /var/lib/apt/lists/* \
 && git config --system --add safe.directory '*'

# Ubuntu 24.04 ships a user "ubuntu" with UID/GID 1000: remove it so builder can own that id.
RUN (userdel -r ubuntu 2>/dev/null || true) \
 && (getent group "${BUILDER_GID}" >/dev/null || groupadd -g "${BUILDER_GID}" builder) \
 && useradd -m -u "${BUILDER_UID}" -g "${BUILDER_GID}" -s /bin/bash builder

# Rust toolchain lives in the image (/opt); the cargo registry is a runtime volume
# (CARGO_HOME=/work/cargo-home) so downloads survive container removal.
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain stable \
          -t aarch64-unknown-linux-musl -c clippy -c rustfmt \
 && cargo install cargo-deny --locked --version "${CARGO_DENY_VERSION}" --root /opt/cargo \
 && rm -rf /opt/cargo/registry /opt/cargo/git \
 && chmod -R a+rX /opt/rustup /opt/cargo

# /work/ferritewrt = bind-mounted repo; the others are named volumes. Created here so a
# fresh named volume inherits builder ownership.
RUN mkdir -p /work/ferritewrt /work/openwrt /work/cargo-home /work/cargo-target \
 && chown -R builder:"$(id -gn builder)" /work

ENV LANG=C.UTF-8 \
    CARGO_HOME=/work/cargo-home \
    CARGO_TARGET_DIR=/work/cargo-target

USER builder
WORKDIR /work/ferritewrt
VOLUME ["/work/openwrt", "/work/cargo-home", "/work/cargo-target"]
# Run through bash: executable bits are not reliable on Windows bind mounts.
ENTRYPOINT ["bash", "/work/ferritewrt/build/build-image.sh"]
