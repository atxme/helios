#!/usr/bin/env python3
"""Campagne HTTP du flux de mise à jour applicative signé.

Le script ne construit ni ne signe : il reçoit l’artefact exact produit par
`helios-publisher`, altère d’abord une copie du manifeste pour prouver le refus,
puis transfère le manifeste et le binaire valides par fragments JSON.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import pathlib
import urllib.error
import urllib.request


def post(url: str, path: str, payload: object, expected: int = 200) -> dict:
    request = urllib.request.Request(
        f"{url.rstrip('/')}{path}",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != expected:
                raise RuntimeError(f"{path}: HTTP {response.status}, {expected} attendu")
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        body = error.read().decode(errors="replace")
        if error.code == expected:
            return {"error": body}
        raise RuntimeError(f"{path}: HTTP {error.code} — {body}") from error


def get(url: str, path: str) -> dict:
    with urllib.request.urlopen(f"{url.rstrip('/')}{path}", timeout=30) as response:
        return json.load(response)


def run(url: str, manifest_path: pathlib.Path, binary_path: pathlib.Path, activate: bool) -> None:
    manifest = json.loads(manifest_path.read_text())
    sequence = manifest["payload"]["release_sequence"]

    altered = copy.deepcopy(manifest)
    signature = altered["signatures"][0]["sig"]
    altered["signatures"][0]["sig"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    post(url, "/api/update/stage", {"manifest": altered}, expected=422)
    print("  ✓ manifeste dont la signature est altérée refusé")

    staged = post(url, "/api/update/stage", {"manifest": manifest})
    if staged["release"]["release_sequence"] != sequence:
        raise RuntimeError("la séquence stagée diffère du manifeste")
    print(f"  ✓ manifeste hybride accepté, séquence {sequence}")

    post(
        url,
        "/api/update/chunk",
        {"release_sequence": sequence, "offset": 1, "data": base64.b64encode(b"x").decode()},
        expected=422,
    )
    print("  ✓ fragment désordonné refusé")

    size = binary_path.stat().st_size
    offset = 0
    with binary_path.open("rb") as binary:
        while chunk := binary.read(512 * 1024):
            response = post(
                url,
                "/api/update/chunk",
                {
                    "release_sequence": sequence,
                    "offset": offset,
                    "data": base64.b64encode(chunk).decode(),
                },
            )
            offset = response["next_offset"]
    if offset != size:
        raise RuntimeError(f"{offset} octets acquittés sur {size}")
    finalized = post(url, "/api/update/finalize", {"release_sequence": sequence})
    if finalized["release"]["sha256"] != manifest["payload"]["sha256"]:
        raise RuntimeError("le SHA-256 finalisé diffère du manifeste")
    print(f"  ✓ {size} octets transférés et SHA-256 vérifié")

    post(
        url,
        "/api/update/activate",
        {"release_sequence": sequence, "confirmation": f"INSTALLER {sequence + 1}"},
        expected=422,
    )
    print("  ✓ confirmation incorrecte refusée")

    if activate:
        post(
            url,
            "/api/update/activate",
            {"release_sequence": sequence, "confirmation": f"INSTALLER {sequence}"},
            expected=202,
        )
        status = get(url, "/api/update")
        if status["activation_pending"] != sequence:
            raise RuntimeError("l’activation acceptée n’apparaît pas dans le statut")
        print("  ✓ activation authentifiée enregistrée")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--activate", action="store_true")
    args = parser.parse_args()
    run(args.url, args.manifest, args.binary, args.activate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
