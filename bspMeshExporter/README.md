# BSP Mesh Exporter

Extract world geometry from Source Engine BSP files and precompute spatial data (visibility, clearance, vismatrix, influence) using Embree raycasting.

## Setup

```
cd bspMeshExporter
uv sync
```

## Usage

Five subcommands, run in order: `extract` → `visibility` / `clearance` / `vismatrix` → `influence`.

### extract — BSP to GLB mesh

```bash
uv run python -m bsp_mesh_exporter extract ministry_coop \
    --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
    --output-dir ../data/

# All maps:
uv run python -m bsp_mesh_exporter extract --batch \
    --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
    --output-dir ../data/
```

### visibility — GLB + NAV to area-pair visibility NPZ

```bash
uv run python -m bsp_mesh_exporter visibility ministry_coop \
    --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
    --mesh-dir ../data/ \
    --output-dir ../data/
```

Options: `--max-distance` (default 3000), `--eye-height` (default 64)

### clearance — GLB + NAV to radial clearance NPZ

```bash
uv run python -m bsp_mesh_exporter clearance ministry_coop \
    --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
    --mesh-dir ../data/ \
    --output-dir ../data/
```

Options: `--grid-spacing` (default 20), `--max-range` (default 500), `--eye-height` (default 64)

### vismatrix — GLB + NAV to point-to-point visibility matrix NPZ

```bash
uv run python -m bsp_mesh_exporter vismatrix ministry_coop \
    --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
    --mesh-dir ../data/ \
    --output-dir ../data/
```

Options: `--grid-spacing` (default 32), `--max-distance` (default 2000), `--eye-height` (default 64)

### influence — vismatrix to influence/cover NPZ

```bash
uv run python -m bsp_mesh_exporter influence ministry_coop \
    --vismatrix-dir ../data/ \
    --output-dir ../data/
```

All subcommands support `--batch` to process all maps at once.

## Output

| File | Description |
|------|-------------|
| `{map}.glb` | World geometry mesh (viewable in Blender/MeshLab) |
| `{map}_visibility.npz` | Pairwise nav area visibility |
| `{map}_clearance.npz` | 72-azimuth radial clearance per grid sample |
| `{map}_vismatrix.npz` | Point-to-point visibility on grid |
| `{map}_influence.npz` | Precomputed cover + sightline influence layers |
