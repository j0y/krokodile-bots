# Nav Mesh Parser & Room Clustering

## parse_nav.py

Parses Source Engine `.nav` files (version 16, subversion 4) as shipped with Insurgency 2014.

```bash
python3 parse_nav.py <path_to.nav> [--dump] [--stats] [--json out.json]
```

## cluster_nav.py

Segments nav mesh areas into tactical regions using agglomerative merging. The tactical brain loads these as zones for the strategist.

### Algorithm

1. Compute connection width (shared-edge overlap) for each pair of adjacent nav areas
2. Agglomerative merge: repeatedly merge the two adjacent clusters with the widest total boundary (sum of shared-edge widths across all connections)
3. Stop when remaining boundaries are narrow (doorways/chokepoints, < 120u aggregate)
4. Merge tiny fragments (< 5 areas) into the segment they share the most nav connections with
5. Order segments by Dijkstra distance from enemy spawn

### Usage

Single map:
```bash
python3 cluster_nav.py <map>.nav --objectives <map>_objectives.json -o <map>_clusters.json
```

All coop maps (batch):
```bash
python3 cluster_nav.py --batch \
    --nav-dir ../insurgency-server/server-files/insurgency/maps \
    --data-dir ../data
```

Batch mode processes every `*_coop.nav` that has a matching `*_objectives.json` in `--data-dir`.

### Output

`*_clusters.json` — one entry per segment:
```json
{
  "seg_0": {
    "centroid": [x, y, z],
    "radius": 919,
    "adjacent": ["seg_1", "seg_8"],
    "nav_area_ids": [101, 102, ...],
    "nav_area_count": 176
  }
}
```

### Prerequisites

Requires `*_objectives.json` files in `data/` (from `bspMeshExporter objectives`) and `.nav` files in the server maps directory.
