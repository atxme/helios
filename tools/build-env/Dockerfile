# Conteneur de build de la chaîne de livraison Helios.
#
# Seul chemin de livraison des binaires : `cargo xtask bundle` et `cargo xtask app`
# compilent ici, sauf avec `--native`. Étiquette d'image :
# `helios-build:<12 premiers hex du SHA-256 de ce fichier>`.
#
# Monter de version : changer les ARG ci-dessous (DEBIAN_DIGEST, SNAPSHOT,
# RUSTUP_VERSION, RUSTUP_INIT_SHA256, RUST_VERSION, NODE_VERSION, NODE_SHA256). Les versions
# de Rust et de Node sont ensuite alignées dans le dépôt : `python3
# scripts/toolchain_pins.py` dit ce qui reste à changer. Les paquets apt sont
# figés par l'horodatage SNAPSHOT : les changer évolue avec lui.
#
# Valeurs courantes : DEBIAN_DIGEST = index multi-architectures de
# debian:trixie-slim (`docker buildx imagetools inspect debian:trixie-slim`) ;
# RUSTUP_INIT_SHA256 = static.rust-lang.org/rustup/archive/<RUSTUP_VERSION>/x86_64-unknown-linux-gnu/rustup-init.sha256
# (version figée : le chemin dist/ sert le dernier rustup, qui casse le SHA-256 à chaque sortie) ;
# NODE_SHA256 = nodejs.org/dist/v<NODE_VERSION>/SHASUMS256.txt, ligne linux-x64.tar.xz.

ARG DEBIAN_DIGEST=a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG SNAPSHOT=20261120T000000Z
ARG RUSTUP_VERSION=1.29.3
ARG RUSTUP_INIT_SHA256=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55
ARG RUST_VERSION=1.100.0
ARG NODE_VERSION=26.13.1
ARG NODE_SHA256=5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864

FROM debian:trixie-slim@sha256:${DEBIAN_DIGEST}

ARG SNAPSHOT
ARG RUSTUP_VERSION
ARG RUSTUP_INIT_SHA256
ARG RUST_VERSION
ARG NODE_VERSION
ARG NODE_SHA256

# Paquets apt figés sur l'instantané Debian : même liste et mêmes dépôts à chaque build.
# Check-Valid-Until est désactivé car un instantané ancien a des index expirés.
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian/${SNAPSHOT}" \
      'Suites: trixie trixie-updates' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' \
      '' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}" \
      'Suites: trixie-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' \
      > /etc/apt/sources.list.d/snapshot.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      clang \
      curl \
      git \
      libclang-dev \
      libmnl-dev \
      libnftnl-dev \
      libtss2-dev \
      libudev-dev \
      pkg-config \
      xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Rust : rustup-init vérifié par SHA-256, toolchain épinglée. Les binaires
# (proxies rustup) vivent dans /usr/local/cargo/bin ; CARGO_HOME passe sur le
# volume helios-build-cargo à l'exécution.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo
RUN curl --proto '=https' --tlsv1.2 -sSfL \
      https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init \
      -o /tmp/rustup-init \
 && echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c - \
 && chmod +x /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal \
      --default-toolchain "${RUST_VERSION}" -c clippy -c rustfmt \
 && rm /tmp/rustup-init
ENV PATH=/usr/local/cargo/bin:/usr/local/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Node : archive officielle vérifiée par SHA-256, dans /usr/local/node.
RUN curl --proto '=https' --tlsv1.2 -sSfL \
      "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      -o /tmp/node.tar.xz \
 && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
 && mkdir -p /usr/local/node \
 && tar -xJf /tmp/node.tar.xz -C /usr/local/node --strip-components=1 \
 && rm /tmp/node.tar.xz

# Répertoires de travail à l'exécution. Un volume nommé neuf hérite du contenu
# et des modes du point de montage : 1777 permet à l'UID de l'appelant d'écrire.
ENV CARGO_HOME=/helios/cargo \
    HOME=/tmp
RUN mkdir -p /helios/cargo /helios/target \
 && chmod 1777 /helios/cargo /helios/target
WORKDIR /helios/src
