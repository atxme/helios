# Icônes Orion

Sources vectorielles et rendus. Les PNG et l'`.ico` sont **générés** : les
modifier à la main serait perdu au prochain rendu.

## Les deux variantes, et pourquoi il y en a deux

| Fichier | Rôle |
|---|---|
| `icon.svg` | marque complète — anneau de confinement, trajectoire elliptique, ceinture d'Orion et ses deux étoiles extérieures |
| `icon-small.svg` | même figure, réduite à ce qui survit sous 48 px |

L'anneau, les lignes de constellation et les étoiles extérieures passent sous le
pixel à 16 px et s'y transforment en bouillie grise. La variante réduite ne garde
que la trajectoire et la ceinture, tracées plus épais. Un `.ico` est un
**ensemble d'images**, pas une image redimensionnée : c'est précisément ce que le
format permet, et l'utiliser évite le compromis d'un dessin unique illisible à
une extrémité et grossier à l'autre.

La grammaire est celle de `apps/orion/src/components/OrionMark.tsx` — mêmes
coordonnées sur la grille de 48 unités — de sorte que l'icône système et la
marque affichée dans l'application soient la même chose.

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

The largest frame is intentionally first. Tauri decodes the first ICO entry
for the default window icon; starting with the 16×16 frame makes Windows scale
that small bitmap for the title bar, taskbar and other shell surfaces.
