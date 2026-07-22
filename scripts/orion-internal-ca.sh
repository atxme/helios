#!/usr/bin/env bash
# Crée une petite autorité interne et un certificat Authenticode Orion.
#
# Ce script manipule uniquement X.509. Les clés hybrides ADR-002 appartiennent
# à helios-publisher et ne doivent jamais être placées dans le répertoire donné
# ici, ni importées dans le magasin de certificats Windows.
set -euo pipefail

usage() {
    echo "Usage: $0 /chemin/hors-depot/autorite-orion" >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
command -v openssl >/dev/null 2>&1 || {
    echo "openssl est requis" >&2
    exit 1
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
WORKSPACE=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
OUTPUT_REQUESTED=$1
mkdir -p -- "$OUTPUT_REQUESTED"
OUTPUT=$(CDPATH= cd -- "$OUTPUT_REQUESTED" && pwd -P)

case "$OUTPUT/" in
    "$WORKSPACE/"*)
        echo "Le répertoire de l'autorité doit rester hors du dépôt : $WORKSPACE" >&2
        exit 1
        ;;
esac
if [ -n "$(find "$OUTPUT" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    echo "Le répertoire de sortie doit être vide : $OUTPUT" >&2
    exit 1
fi

umask 077
AUTHORITY_DIR=$OUTPUT/authority-offline
SIGNING_DIR=$OUTPUT/signing-station
mkdir -p -- "$AUTHORITY_DIR" "$SIGNING_DIR"

ROOT_KEY=$AUTHORITY_DIR/orion-root-ca.key
ROOT_PEM=$AUTHORITY_DIR/orion-root-ca.pem
ROOT_CER=$AUTHORITY_DIR/orion-root-ca.cer
SIGNING_KEY=$SIGNING_DIR/orion-code-signing.key
SIGNING_CSR=$SIGNING_DIR/orion-code-signing.csr
SIGNING_PEM=$SIGNING_DIR/orion-code-signing.pem
SIGNING_CER=$SIGNING_DIR/orion-code-signing.cer
SIGNING_PFX=$SIGNING_DIR/orion-code-signing.pfx
SIGNING_EXT=$SIGNING_DIR/code-signing.ext

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$ROOT_KEY"
openssl req -x509 -new -sha256 -days 3650 \
    -key "$ROOT_KEY" \
    -subj "/CN=Helios Orion Internal Root/O=Helios/OU=Internal Distribution" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$ROOT_PEM"
openssl x509 -in "$ROOT_PEM" -outform DER -out "$ROOT_CER"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$SIGNING_KEY"
openssl req -new -sha256 \
    -key "$SIGNING_KEY" \
    -subj "/CN=Helios Orion Code Signing/O=Helios/OU=Internal Distribution" \
    -out "$SIGNING_CSR"

{
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    echo "extendedKeyUsage=critical,codeSigning"
    echo "subjectKeyIdentifier=hash"
    echo "authorityKeyIdentifier=keyid,issuer"
} > "$SIGNING_EXT"

openssl x509 -req -sha256 -days 825 \
    -in "$SIGNING_CSR" \
    -CA "$ROOT_PEM" \
    -CAkey "$ROOT_KEY" \
    -CAcreateserial \
    -extfile "$SIGNING_EXT" \
    -out "$SIGNING_PEM"
openssl x509 -in "$SIGNING_PEM" -outform DER -out "$SIGNING_CER"

echo "OpenSSL demande maintenant le mot de passe d'export du PFX de signature."
openssl pkcs12 -export \
    -inkey "$SIGNING_KEY" \
    -in "$SIGNING_PEM" \
    -certfile "$ROOT_PEM" \
    -name "Helios Orion Code Signing" \
    -out "$SIGNING_PFX"

chmod 600 "$ROOT_KEY" "$SIGNING_KEY" "$SIGNING_PFX"
chmod 644 "$ROOT_PEM" "$ROOT_CER" "$SIGNING_PEM" "$SIGNING_CER"

echo
echo "Autorité créée dans $OUTPUT"
echo "  Racine à provisionner hors bande : $ROOT_CER"
echo "  PFX à transférer au poste de signature : $SIGNING_PFX"
echo "  Empreinte du certificat de signature :"
openssl x509 -in "$SIGNING_PEM" -noout -fingerprint -sha1
echo
echo "Conserver authority-offline hors ligne. Ne transférer ni sa clé privée,"
echo "ni aucune clé ADR-002 vers le poste client ou la gateway."
