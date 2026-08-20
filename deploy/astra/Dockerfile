# Astra — coordinateur d'autorité (ADR-008), conteneur co-implanté.
#
# Ce qu'Astra ne monte JAMAIS, et que rien ici n'introduit : le socket Docker,
# `network.toml`, les coffres de `heliosd`, le plan de données WireGuard, les
# secrets TPM. Un seul volume, son répertoire d'état — voir compose.yaml.
#
# `-p astra` et non `cargo build` : le second tirerait `astra-signer`, donc la
# pile CTAP2 et `libudev`, dans une image qui n'a aucune clé de sécurité à
# brancher. Le compagnon vit sur le poste opérateur, jamais ici.
#
# Le graphe d'`astra` lui-même en est libre, et cela se maintient : il ne lie
# pas `helios-fido`. Les trois valeurs du coffre qu'il nomme — longueur de sel,
# borne d'identifiant de credential, `SlotSecret` — sont des propriétés de la
# clé, donc définies dans `aether`. Rajouter ici une dépendance vers
# `helios-fido` rendrait `libudev-dev` obligatoire à la construction et
# `libudev1` à l'exécution, pour un conteneur sans port USB. Astra transporte
# et sauvegarde le coffre ; il ne l'ouvre pas.

FROM rust:1.92-bookworm AS build

# aws-lc-rs non-FIPS se compile en statique avec `cc` et des bindings
# pré-générés : ni CMake, ni Go, ni Ninja, ni bindgen.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# `aether/build.rs` refuse le trousseau éditeur de développement dans toute
# compilation `--release` (ADR-002), et une image de production compile en
# release. Le trousseau **public** est donc déposé dans le contexte par
# `scripts/deploy.sh`, à côté des sources. Il ne contient que des clés
# publiques : rien de secret n'entre dans l'image, et rien n'y reste — cette
# étape est jetée avec l'étage de construction.
ENV HELIOS_PUBLISHER_KEYRING_PATH=/src/publisher-keyring.json
RUN test -f "$HELIOS_PUBLISHER_KEYRING_PATH" || { \
        echo "publisher-keyring.json absent du contexte de construction :" >&2; \
        echo "  il est déposé par scripts/deploy.sh depuis \$HELIOS_PUBLISHER_EPOCH" >&2; \
        exit 1; \
    }
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
