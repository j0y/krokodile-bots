# Nav Mesh Parser & Room Clustering

## parse_nav.py

Parses Source Engine `.nav` files (version 16, subversion 4) as shipped with Insurgency 2014.

```bash
python3 parse_nav.py <path_to.nav> [--dump] [--stats] [--json out.json]
```

## cluster_nav.py

Clusters nav mesh areas into room-like regions using BSP wall geometry. The tactical brain loads these as zones for the strategist.

### Algorithm

1. Load BSP mesh (`.glb`), extract wall outlines via cross-sections at multiple Z levels
2. Rasterize wall segments onto a 2D grid (16u cells)
3. For each adjacent nav area pair, check if the line between centers crosses a wall cell (Bresenham)
4. Union-find: merge areas NOT separated by walls
5. Merge tiny fragments (<5 areas) into nearest large cluster
6. Directional split: rooms with doorway connections on opposing sides are split into east/west or north/south halves
7. Compute room adjacency from nav mesh connections that cross cluster boundaries

### Usage

Single map:
```bash
python3 cluster_nav.py <map>.nav --glb <map>.glb -o <map>_clusters.json
```

All coop maps (batch):
```bash
python3 cluster_nav.py --batch \
    --nav-dir ../insurgency-server/server-files/insurgency/maps \
    --data-dir ../data
```

Batch mode processes every `*_coop.nav` that has a matching `.glb` in `--data-dir`.

### Output

`*_clusters.json` — one entry per room:
```json
{
  "room_0_south": {
    "centroid": [x, y, z],
    "radius": 919,
    "adjacent": ["room_1_north", "room_8_west"],
    "nav_area_ids": [101, 102, ...],
    "nav_area_count": 176
  }
}
```

### Prerequisites

Requires `.glb` mesh files in `data/` (from `bspMeshExporter mesh`) and `.nav` files in the server maps directory.

```bash
pip3 install numpy trimesh
```
