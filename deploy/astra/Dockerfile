# Astra — coordinateur d'autorité (ADR-008), conteneur co-implanté.
#
# Ce qu'Astra ne monte JAMAIS, et que rien ici n'introduit : le socket Docker,
# `network.toml`, les coffres de `heliosd`, le plan de données WireGuard, les
# secrets TPM. Un seul volume, son répertoire d'état — voir compose.yaml.
#
# `-p astra` et non `cargo build` : le second tirerait `astra-signer`, donc la
# pile CTAP2 et `libudev`, dans une image qui n'a aucune clé de sécurité à
# brancher. Le compagnon vit sur le poste opérateur, jamais ici.

FROM rust:1.92-bookworm AS build

# aws-lc-rs non-FIPS se compile en statique avec `cc` et des bindings
# pré-générés : ni CMake, ni Go, ni Ninja, ni bindgen.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cargo build --release -p astra

FROM debian:bookworm-slim

# UID fixe : le volume d'état lui appartient, et un UID attribué à la volée
# rendrait un volume restauré illisible après reconstruction de l'image.
RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin astra \
 && mkdir -p /var/lib/astra \
 && chown astra:astra /var/lib/astra \
 && chmod 0700 /var/lib/astra

COPY --from=build /src/target/release/astra /usr/local/bin/astra

USER astra:astra
ENV ASTRA_STATE_DIR=/var/lib/astra
VOLUME ["/var/lib/astra"]

# 0.0.0.0 dans le conteneur, pas sur l'hôte : la publication du port est la
# décision de compose, et le terminateur TLS se met devant. `astra run` sert du
# HTTP clair délibérément — ce n'est pas son certificat de transport qui
# l'authentifie, c'est sa clé de service ML-DSA-87 épinglée (§9.6).
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/astra"]
CMD ["run", "--bind", "0.0.0.0:8443"]
