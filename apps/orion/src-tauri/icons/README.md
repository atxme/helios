# Icônes Orion

Sources vectorielles et rendus. Les PNG et l'`.ico` sont **générés** : les
modifier à la main serait perdu au prochain rendu.

## Les variantes, et pourquoi il y en a plusieurs

| Fichier | Rôle |
|---|---|
| `icon.svg` | marque complète — anneau de confinement, trajectoire elliptique, ceinture d'Orion et ses deux étoiles extérieures |
| `icon-small.svg` | même figure, réduite à ce qui survit sous 48 px |
| `profile.svg` | icône des documents `.orion` — la marque sur une feuille à coin plié |
| `profile-small.svg` | même feuille, sous 48 px : feuille plus claire, moins de traits |

L'anneau, les lignes de constellation et les étoiles extérieures passent sous le
pixel à 16 px et s'y transforment en bouillie grise. La variante réduite ne garde
que la trajectoire et la ceinture, tracées plus épais. Un `.ico` est un
**ensemble d'images**, pas une image redimensionnée : c'est précisément ce que le
format permet, et l'utiliser évite le compromis d'un dessin unique illisible à
une extrémité et grossier à l'autre.

La grammaire est celle de `apps/orion/src/components/OrionMark.tsx` — mêmes
coordonnées sur la grille de 48 unités — de sorte que l'icône système et la
marque affichée dans l'application soient la même chose.

## L'icône de document

`orion-profile.ico` habille les fichiers `.orion`. Elle **ressemble** à l'icône
de l'application sans être la même, et c'est le point : dans un dossier, un
profil et le client qui l'ouvre ne doivent pas se confondre. La distinction est
portée par la silhouette — une feuille à coin plié plutôt qu'une tuile — parce
que c'est la seule chose qui survive à 16 px. La marque à l'intérieur est celle
de la variante réduite : sous cette taille, l'anneau et les étoiles extérieures
ne passent pas.

Sa feuille est plus claire sous 48 px. Le bleu nuit de la grande taille se fond
dans le fond sombre de l'Explorateur en thème sombre, où il ne resterait alors
qu'un trait vert flottant.

L'icône est livrée en ressource, à côté de `orion.exe`, et désignée par
`windows/orion-profile-icon.wxs` — voir
[`ORION-DISTRIBUTION.md`](../../../../docs/security/ORION-DISTRIBUTION.md).

## Regénérer

```sh
cd apps/orion/src-tauri/icons
for s in 512 256 128 64; do inkscape icon.svg -w $s -h $s -o /tmp/orion-$s.png; done
for s in 48 32 24 16; do inkscape icon-small.svg -w $s -h $s -o /tmp/small-$s.png; done
cp /tmp/orion-512.png icon.png
cp /tmp/orion-128.png 128x128.png
cp /tmp/small-32.png 32x32.png
python3 - <<'PY'
from PIL import Image
plan = [(256,'orion'),(128,'orion'),(64,'orion'),
        (48,'small'),(32,'small'),(24,'small'),(16,'small')]
frames = [Image.open(f"/tmp/{v}-{s}.png").convert('RGBA') for s, v in plan]
frames[0].save('icon.ico', format='ICO',
               sizes=[f.size for f in frames], append_images=frames[1:])
PY
```

Puis l'icône de document :

```sh
for s in 256 128 64; do inkscape profile.svg -w $s -h $s -o /tmp/full-$s.png; done
for s in 48 32 24 16; do inkscape profile-small.svg -w $s -h $s -o /tmp/petit-$s.png; done
python3 - <<'ICO'
from PIL import Image
plan = [(256,'full'),(128,'full'),(64,'full'),
        (48,'petit'),(32,'petit'),(24,'petit'),(16,'petit')]
frames = [Image.open(f"/tmp/{v}-{s}.png").convert('RGBA') for s, v in plan]
frames[0].save('orion-profile.ico', format='ICO',
               sizes=[f.size for f in frames], append_images=frames[1:])
ICO
```

The largest frame is intentionally first. Tauri decodes the first ICO entry
for the default window icon; starting with the 16×16 frame makes Windows scale
that small bitmap for the title bar, taskbar and other shell surfaces.
