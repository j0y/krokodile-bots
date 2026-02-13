"""Cluster nav mesh areas into room-like regions using BSP wall geometry.

Algorithm:
1. Parse .nav file, build adjacency graph from nav area connections
2. Load BSP mesh (.glb), extract wall outlines via cross-sections at multiple Z levels
3. Rasterize wall segments onto a 2D grid (16u cells)
4. For each adjacent nav area pair, check if line between centers crosses wall cells
5. Union-find: merge areas NOT separated by walls
6. Merge tiny fragments (<5 areas) into nearest large cluster
7. Directional split: rooms with connections on opposing sides are split (east/west or north/south)
8. Output clusters JSON compatible with tactical-brain's AreaMap

Usage:
    python cluster_nav.py <map.nav> --glb map.glb [-o output.json] [--min-size 5]
    python cluster_nav.py --batch --nav-dir DIR --data-dir DIR
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from parse_nav import NavArea, NavMesh, parse_nav

# ── Constants ──────────────────────────────────────────────────────

CELL = 16          # wall grid resolution (units per cell)
Z_MIN = -200       # lowest cross-section height
Z_MAX = 600        # highest cross-section height
Z_STEP = 30        # step between cross-sections
MIN_FRAG = 5       # merge fragments smaller than this
SPLIT_MIN = 10     # only split rooms with >= this many areas


# ── Union-Find ──────────────────────────────────────────────────────

class UnionFind:
    def __init__(self, elements: list[int]) -> None:
        self.parent = {e: e for e in elements}
        self.rank = {e: 0 for e in elements}

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1

    def components(self) -> dict[int, list[int]]:
        groups: dict[int, list[int]] = defaultdict(list)
        for e in self.parent:
            groups[self.find(e)].append(e)
        return dict(groups)


# ── Wall grid ──────────────────────────────────────────────────────

def _rasterize_line(x0: int, y0: int, x1: int, y1: int) -> list[tuple[int, int]]:
    """Bresenham's line algorithm — returns all cells along the line."""
    cells = []
    dx = abs(x1 - x0)
    dy = abs(y1 - y0)
    sx = 1 if x0 < x1 else -1
    sy = 1 if y0 < y1 else -1
    err = dx - dy
    while True:
        cells.append((x0, y0))
        if x0 == x1 and y0 == y1:
            break
        e2 = 2 * err
        if e2 > -dy:
            err -= dy
            x0 += sx
        if e2 < dx:
            err += dx
            y0 += sy
    return cells


def build_wall_grid(
    glb_path: str | Path,
) -> tuple[np.ndarray, float, float, float, float]:
    """Load BSP mesh and build a 2D wall occupancy grid.

    Returns (grid, xmin, ymin, xmax, ymax) where grid[gy, gx] is True for wall cells.
    """
    import trimesh

    mesh = trimesh.load(str(glb_path), force="mesh")

    # Extract wall segments from cross-sections at multiple Z levels
    segments: list[tuple[float, float, float, float]] = []
    for z in range(Z_MIN, Z_MAX, Z_STEP):
        try:
            sl = mesh.section(plane_origin=[0, 0, z], plane_normal=[0, 0, 1])
            if sl is None:
                continue
            for entity in sl.entities:
                pts = sl.vertices[entity.points][:, :2]
                for i in range(len(pts) - 1):
                    segments.append((pts[i, 0], pts[i, 1], pts[i + 1, 0], pts[i + 1, 1]))
        except Exception:
            pass

    if not segments:
        raise RuntimeError(f"No wall segments extracted from {glb_path}")

    segs = np.array(segments)
    xmin = float(segs[:, [0, 2]].min())
    xmax = float(segs[:, [0, 2]].max())
    ymin = float(segs[:, [1, 3]].min())
    ymax = float(segs[:, [1, 3]].max())

    nx = int((xmax - xmin) / CELL) + 2
    ny = int((ymax - ymin) / CELL) + 2
    grid = np.zeros((ny, nx), dtype=bool)

    for x0, y0, x1, y1 in segments:
        gx0 = int((x0 - xmin) / CELL)
        gy0 = int((y0 - ymin) / CELL)
        gx1 = int((x1 - xmin) / CELL)
        gy1 = int((y1 - ymin) / CELL)
        for gx, gy in _rasterize_line(gx0, gy0, gx1, gy1):
            if 0 <= gy < ny and 0 <= gx < nx:
                grid[gy, gx] = True

    return grid, xmin, ymin, xmax, ymax


def line_crosses_wall(
    x1: float, y1: float, x2: float, y2: float,
    grid: np.ndarray, xmin: float, ymin: float,
) -> bool:
    """Check if the line between two points crosses any wall cells.

    Skips the first and last cells (the endpoints themselves may sit on walls).
    """
    gx1 = int((x1 - xmin) / CELL)
    gy1 = int((y1 - ymin) / CELL)
    gx2 = int((x2 - xmin) / CELL)
    gy2 = int((y2 - ymin) / CELL)

    cells = _rasterize_line(gx1, gy1, gx2, gy2)
    ny, nx = grid.shape

    # Check interior cells (skip first and last)
    for gx, gy in cells[1:-1]:
        if 0 <= gy < ny and 0 <= gx < nx and grid[gy, gx]:
            return True
    return False


# ── Clustering ──────────────────────────────────────────────────────

@dataclass
class Cluster:
    id: int
    area_ids: list[int]
    centroid: tuple[float, float, float]
    name: str = ""


def cluster_by_walls(
    mesh: NavMesh,
    grid: np.ndarray,
    xmin: float,
    ymin: float,
    min_frag: int = MIN_FRAG,
) -> list[Cluster]:
    """Cluster nav areas: merge adjacent pairs not separated by walls."""
    area_ids = list(mesh.areas.keys())
    if not area_ids:
        return []

    uf = UnionFind(area_ids)

    # For each adjacent pair, check wall line-of-sight
    seen: set[tuple[int, int]] = set()
    for aid, area in mesh.areas.items():
        ac = area.center()
        for nid in area.neighbor_ids():
            if nid not in mesh.areas:
                continue
            key = (min(aid, nid), max(aid, nid))
            if key in seen:
                continue
            seen.add(key)

            nc = mesh.areas[nid].center()
            if not line_crosses_wall(ac.x, ac.y, nc.x, nc.y, grid, xmin, ymin):
                uf.union(aid, nid)

    components = uf.components()
    sorted_comps = sorted(components.values(), key=len, reverse=True)

    # Separate large and small
    large: list[list[int]] = []
    small: list[list[int]] = []
    for comp in sorted_comps:
        if len(comp) >= min_frag:
            large.append(comp)
        else:
            small.append(comp)

    # Merge small fragments into nearest large cluster
    if large and small:
        large_centroids: list[tuple[float, float]] = []
        for comp in large:
            cx = sum(mesh.areas[a].center().x for a in comp) / len(comp)
            cy = sum(mesh.areas[a].center().y for a in comp) / len(comp)
            large_centroids.append((cx, cy))

        for frag in small:
            fx = sum(mesh.areas[a].center().x for a in frag) / len(frag)
            fy = sum(mesh.areas[a].center().y for a in frag) / len(frag)
            best_idx = 0
            best_dist = float("inf")
            for i, (cx, cy) in enumerate(large_centroids):
                d = (fx - cx) ** 2 + (fy - cy) ** 2
                if d < best_dist:
                    best_dist = d
                    best_idx = i
            large[best_idx].extend(frag)

    # Build Cluster objects
    clusters: list[Cluster] = []
    for i, comp in enumerate(large):
        cx = sum(mesh.areas[a].center().x for a in comp) / len(comp)
        cy = sum(mesh.areas[a].center().y for a in comp) / len(comp)
        cz = sum(mesh.areas[a].center().z for a in comp) / len(comp)
        clusters.append(Cluster(
            id=i,
            area_ids=sorted(comp),
            centroid=(round(cx, 1), round(cy, 1), round(cz, 1)),
        ))

    return clusters


# ── Directional splitting ──────────────────────────────────────────

def _direction_of(from_xy: tuple[float, float], to_xy: tuple[float, float]) -> str:
    """Classify direction from one point to another as N/E/S/W."""
    dx = to_xy[0] - from_xy[0]
    dy = to_xy[1] - from_xy[1]
    if abs(dx) > abs(dy):
        return "east" if dx > 0 else "west"
    else:
        return "north" if dy > 0 else "south"


def directional_split(
    clusters: list[Cluster],
    mesh: NavMesh,
    grid: np.ndarray,
    xmin: float,
    ymin: float,
    min_size: int = SPLIT_MIN,
) -> list[Cluster]:
    """Split rooms that have connections on opposing sides.

    For rooms connected east+west, split into east/west halves.
    For rooms connected north+south, split into north/south halves.
    If both, split on the longer axis (more spread).
    """
    # Build area_id → cluster_id
    area_to_cluster: dict[int, int] = {}
    for cl in clusters:
        for aid in cl.area_ids:
            area_to_cluster[aid] = cl.id

    # Find doorway edges (wall-blocked connections between different clusters)
    doorway_edges: dict[int, list[tuple[int, int]]] = defaultdict(list)  # cluster_id → [(aid, nid)]
    seen: set[tuple[int, int]] = set()
    for aid, area in mesh.areas.items():
        cid = area_to_cluster.get(aid)
        if cid is None:
            continue
        for nid in area.neighbor_ids():
            if nid not in mesh.areas:
                continue
            nid_cid = area_to_cluster.get(nid)
            if nid_cid is None or nid_cid == cid:
                continue
            key = (min(aid, nid), max(aid, nid))
            if key in seen:
                continue
            seen.add(key)
            doorway_edges[cid].append((aid, nid))
            doorway_edges[nid_cid].append((nid, aid))

    result: list[Cluster] = []
    next_id = 0

    for cl in clusters:
        if len(cl.area_ids) < min_size or cl.id not in doorway_edges:
            cl.id = next_id
            next_id += 1
            result.append(cl)
            continue

        cx, cy = cl.centroid[0], cl.centroid[1]
        center = (cx, cy)

        # Classify doorway directions
        dirs: set[str] = set()
        for aid, nid in doorway_edges[cl.id]:
            nc = mesh.areas[nid].center()
            dirs.add(_direction_of(center, (nc.x, nc.y)))

        has_ew = "east" in dirs and "west" in dirs
        has_ns = "north" in dirs and "south" in dirs

        if not has_ew and not has_ns:
            cl.id = next_id
            next_id += 1
            result.append(cl)
            continue

        # Decide split axis
        if has_ew and has_ns:
            # Split on the longer axis (more spread)
            xs = [mesh.areas[a].center().x for a in cl.area_ids]
            ys = [mesh.areas[a].center().y for a in cl.area_ids]
            x_spread = max(xs) - min(xs)
            y_spread = max(ys) - min(ys)
            split_ew = x_spread >= y_spread
        else:
            split_ew = has_ew

        # Partition area IDs
        half_a: list[int] = []
        half_b: list[int] = []
        for aid in cl.area_ids:
            c = mesh.areas[aid].center()
            if split_ew:
                if c.x <= cx:
                    half_a.append(aid)
                else:
                    half_b.append(aid)
            else:
                if c.y <= cy:
                    half_a.append(aid)
                else:
                    half_b.append(aid)

        # Don't produce empty halves
        if not half_a or not half_b:
            cl.id = next_id
            next_id += 1
            result.append(cl)
            continue

        # Build two clusters
        for half, suffix in [(half_a, "west" if split_ew else "south"),
                             (half_b, "east" if split_ew else "north")]:
            hcx = sum(mesh.areas[a].center().x for a in half) / len(half)
            hcy = sum(mesh.areas[a].center().y for a in half) / len(half)
            hcz = sum(mesh.areas[a].center().z for a in half) / len(half)
            result.append(Cluster(
                id=next_id,
                area_ids=sorted(half),
                centroid=(round(hcx, 1), round(hcy, 1), round(hcz, 1)),
                name=suffix,  # temporary suffix, used during naming
            ))
            next_id += 1

    return result


# ── Naming ──────────────────────────────────────────────────────────

def name_clusters(clusters: list[Cluster]) -> None:
    """Assign numeric names with directional suffixes.

    Clusters from directional splitting already have a suffix (east/west/north/south).
    Base rooms just get a number.
    """
    for cl in clusters:
        if cl.name:
            # Has directional suffix from split — prepend room number
            cl.name = f"room_{cl.id}_{cl.name}"
        else:
            cl.name = f"room_{cl.id}"


# ── Output ──────────────────────────────────────────────────────────

def compute_adjacency(
    clusters: list[Cluster], mesh: NavMesh,
) -> dict[str, list[str]]:
    """Compute which clusters share doorway edges (nav connections across boundaries)."""
    area_to_name: dict[int, str] = {}
    for cl in clusters:
        for aid in cl.area_ids:
            area_to_name[aid] = cl.name

    adj: dict[str, set[str]] = {cl.name: set() for cl in clusters}
    for aid, area in mesh.areas.items():
        cname = area_to_name.get(aid)
        if cname is None:
            continue
        for nid in area.neighbor_ids():
            nname = area_to_name.get(nid)
            if nname is not None and nname != cname:
                adj[cname].add(nname)
                adj[nname].add(cname)

    return {name: sorted(neighbors) for name, neighbors in adj.items()}


def clusters_to_json(
    clusters: list[Cluster], mesh: NavMesh, adjacency: dict[str, list[str]],
) -> dict:
    """Convert clusters to JSON format compatible with AreaMap zones."""
    result = {}
    for cl in clusters:
        max_dist = 0.0
        for aid in cl.area_ids:
            area = mesh.areas[aid]
            c = area.center()
            d = ((c.x - cl.centroid[0]) ** 2 + (c.y - cl.centroid[1]) ** 2) ** 0.5
            if d > max_dist:
                max_dist = d

        result[cl.name] = {
            "centroid": [round(cl.centroid[0]), round(cl.centroid[1]), round(cl.centroid[2])],
            "radius": round(max_dist),
            "adjacent": adjacency.get(cl.name, []),
            "nav_area_ids": cl.area_ids,
            "nav_area_count": len(cl.area_ids),
        }

    return result


# ── CLI ─────────────────────────────────────────────────────────────

def process_map(
    nav_path: Path,
    glb_path: Path,
    output_path: Path,
    min_frag: int = MIN_FRAG,
    split_min: int = SPLIT_MIN,
) -> None:
    """Process a single map: build wall grid, cluster, split, write JSON."""
    mesh = parse_nav(str(nav_path))
    print(f"  Parsed {len(mesh.areas)} nav areas")

    print(f"  Building wall grid from {glb_path.name}...")
    grid, gxmin, gymin, gxmax, gymax = build_wall_grid(glb_path)
    wall_cells = int(grid.sum())
    print(f"  Wall grid: {grid.shape[1]}x{grid.shape[0]} cells, {wall_cells} wall cells")

    clusters = cluster_by_walls(mesh, grid, gxmin, gymin, min_frag=min_frag)
    print(f"  Found {len(clusters)} rooms")

    clusters = directional_split(clusters, mesh, grid, gxmin, gymin, min_size=split_min)
    print(f"  After directional split: {len(clusters)} zones")

    name_clusters(clusters)

    # Ensure unique names (shouldn't happen but safety)
    seen_names: dict[str, int] = {}
    for cl in clusters:
        if cl.name in seen_names:
            seen_names[cl.name] += 1
            cl.name = f"{cl.name}_{seen_names[cl.name]}"
        else:
            seen_names[cl.name] = 0

    adjacency = compute_adjacency(clusters, mesh)
    result = clusters_to_json(clusters, mesh, adjacency)
    output_path.write_text(json.dumps(result, indent=2) + "\n")
    print(f"  Wrote {output_path} ({len(result)} zones)")

    # Summary of largest zones
    by_size = sorted(clusters, key=lambda c: len(c.area_ids), reverse=True)
    for cl in by_size[:10]:
        print(f"    {cl.name:30s} ({len(cl.area_ids):4d} areas)")
    if len(clusters) > 10:
        print(f"    ... and {len(clusters) - 10} more")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cluster nav mesh into room-like regions using BSP wall geometry"
    )
    parser.add_argument("nav_file", nargs="?", help="Path to .nav file")
    parser.add_argument("--glb", help="Path to BSP .glb mesh file")
    parser.add_argument("-o", "--output", help="Output JSON path")
    parser.add_argument("--min-frag", type=int, default=MIN_FRAG,
                        help=f"Merge fragments smaller than this (default: {MIN_FRAG})")
    parser.add_argument("--split-min", type=int, default=SPLIT_MIN,
                        help=f"Only split rooms with >= this many areas (default: {SPLIT_MIN})")
    parser.add_argument("--batch", action="store_true",
                        help="Process all maps found in --nav-dir")
    parser.add_argument("--nav-dir", help="Directory containing .nav files")
    parser.add_argument("--data-dir", help="Directory containing .glb meshes + output")
    args = parser.parse_args()

    if args.batch:
        if not args.nav_dir or not args.data_dir:
            parser.error("--batch requires --nav-dir and --data-dir")
        nav_dir = Path(args.nav_dir)
        data_dir = Path(args.data_dir)

        for nav_path in sorted(nav_dir.glob("*_coop.nav")):
            map_name = nav_path.stem
            glb_path = data_dir / f"{map_name}.glb"
            output_path = data_dir / f"{map_name}_clusters.json"

            print(f"\n=== {map_name} ===")
            if not glb_path.exists():
                print(f"  Skipping: no GLB mesh file")
                continue

            process_map(nav_path, glb_path, output_path,
                        min_frag=args.min_frag, split_min=args.split_min)
    else:
        if not args.nav_file:
            parser.error("nav_file is required (or use --batch)")
        nav_path = Path(args.nav_file)
        if not args.glb:
            parser.error("--glb is required for single-map mode")
        glb_path = Path(args.glb)
        output_path = Path(args.output) if args.output else nav_path.with_suffix(".clusters.json")

        print(f"Processing {nav_path.name}")
        process_map(nav_path, glb_path, output_path,
                    min_frag=args.min_frag, split_min=args.split_min)


if __name__ == "__main__":
    main()
