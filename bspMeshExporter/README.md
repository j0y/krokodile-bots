# BSP Mesh Exporter

Extract world geometry from Source Engine BSP files and precompute nav area visibility using Embree raycasting.

## Setup

```
cd bspMeshExporter
uv sync
```

## Usage

Two subcommands: `extract` (stable, run once) and `visibility` (tweak and re-run).

### extract — BSP to GLB mesh

Single map:
```
uv run python -m bsp_mesh_exporter extract ministry_coop \
    --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
    --output-dir ../data/
```

All maps:
```
uv run python -m bsp_mesh_exporter extract --batch \
    --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
    --output-dir ../data/
```

### visibility — GLB + NAV to visibility NPZ

Single map:
```
uv run python -m bsp_mesh_exporter visibility ministry_coop \
    --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
    --mesh-dir ../data/ \
    --output-dir ../data/
```

All maps:
```
uv run python -m bsp_mesh_exporter visibility --batch \
    --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
    --mesh-dir ../data/ \
    --output-dir ../data/
```

Options:
- `--max-distance` — max visibility range in units (default 3000)
- `--eye-height` — height above nav area center for ray origin (default 64)

## Output

- `{map}.glb` — world geometry mesh (viewable in Blender/MeshLab)
- `{map}_visibility.npz` — precomputed visibility loaded by tactical-brain at runtime
