"""Point-to-point visibility matrix on a 32u grid across nav areas.

Generates a sparse adjacency-list encoding of which grid points can see
which other grid points, using batched bidirectional Embree raycasts.

Output arrays:
    point_positions: float32[N, 3]  — grid point XYZ (foot level)
    adj_index:       int32[N, 2]    — (start, count) per point into adj_list
    adj_list:        int32[M]       — concatenated visible point indices
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import trimesh
from scipy.spatial import KDTree

from bsp_mesh_exporter.nav_parser import NavArea, NavMesh

log = logging.getLogger(__name__)

DEFAULT_GRID_SPACING = 32.0
DEFAULT_MAX_DISTANCE = 2000.0
DEFAULT_EYE_HEIGHT = 64.0
HULL_INSET = 16.0
RAYCAST_CHUNK = 500_000
SOURCE_BATCH = 1000


@dataclass
class VisMatrixResult:
    """Sparse adjacency-list visibility matrix."""

    point_positions: np.ndarray  # float32[N, 3]
    adj_index: np.ndarray        # int32[N, 2]  (start, count)
    adj_list: np.ndarray         # int32[M]
    max_distance: float
    eye_height: float
    grid_spacing: float

    def save(self, path: str | Path) -> None:
        np.savez_compressed(
            str(path),
            point_positions=self.point_positions,
            adj_index=self.adj_index,
            adj_list=self.adj_list,
            max_distance=np.float32(self.max_distance),
            eye_height=np.float32(self.eye_height),
            grid_spacing=np.float32(self.grid_spacing),
        )
        size = Path(path).stat().st_size
        log.info(
            "Saved vismatrix: %d points, %d edges, %.1f MB -> %s",
            len(self.point_positions), len(self.adj_list), size / 1e6, path,
        )

    @staticmethod
    def load(path: str | Path) -> VisMatrixResult:
        data = np.load(str(path))
        return VisMatrixResult(
            point_positions=data["point_positions"],
            adj_index=data["adj_index"],
            adj_list=data["adj_list"],
            max_distance=float(data["max_distance"]),
            eye_height=float(data["eye_height"]),
            grid_spacing=float(data["grid_spacing"]),
        )


def generate_grid_points(nav: NavMesh, grid_spacing: float = DEFAULT_GRID_SPACING) -> np.ndarray:
    """Generate deduplicated grid points at grid_spacing across all nav areas.

    Returns float32[N, 3] at foot level.
    """
    all_points: list[tuple[float, float, float]] = []

    for area in nav.areas.values():
        min_x = min(area.nw.x, area.se.x) + HULL_INSET
        max_x = max(area.nw.x, area.se.x) - HULL_INSET
        min_y = min(area.nw.y, area.se.y) + HULL_INSET
        max_y = max(area.nw.y, area.se.y) - HULL_INSET

        c = area.center()
        foot_z = c.z

        if max_x <= min_x or max_y <= min_y:
            all_points.append((c.x, c.y, foot_z))
            continue

        nx = max(1, int((max_x - min_x) / grid_spacing) + 1)
        ny = max(1, int((max_y - min_y) / grid_spacing) + 1)

        for ix in range(nx):
            x = min_x if nx == 1 else min_x + ix * (max_x - min_x) / (nx - 1)
            for iy in range(ny):
                y = min_y if ny == 1 else min_y + iy * (max_y - min_y) / (ny - 1)
                all_points.append((x, y, foot_z))

    points = np.array(all_points, dtype=np.float32)

    # Deduplicate by rounding to grid resolution
    rounded = np.round(points[:, :2] / grid_spacing) * grid_spacing
    _, unique_idx = np.unique(rounded, axis=0, return_index=True)
    unique_idx.sort()
    points = points[unique_idx]

    log.info("Grid points: %d (after dedup from %d)", len(points), len(all_points))
    return points


def compute_vismatrix(
    mesh: trimesh.Trimesh,
    points: np.ndarray,
    *,
    max_distance: float = DEFAULT_MAX_DISTANCE,
    eye_height: float = DEFAULT_EYE_HEIGHT,
    grid_spacing: float = DEFAULT_GRID_SPACING,
) -> VisMatrixResult:
    """Compute point-to-point visibility via batched Embree raycasts.

    Processes source points in batches to keep memory bounded.
    Uses KDTree for efficient neighbor lookup within max_distance.
    Bidirectional raycasts at eye_height to handle one-way occlusion.
    """
    n = len(points)
    log.info(
        "Computing vismatrix: %d points (max_dist=%.0f, eye_height=%.0f)",
        n, max_distance, eye_height,
    )

    tree = KDTree(points)

    # Per-point adjacency lists, built incrementally
    adj_lists: list[list[int]] = [[] for _ in range(n)]

    # Process in batches of source points
    total_pairs = 0
    total_visible = 0

    for batch_start in range(0, n, SOURCE_BATCH):
        batch_end = min(batch_start + SOURCE_BATCH, n)
        batch_points = points[batch_start:batch_end]

        # Find neighbors within max_distance for the batch
        neighbors = tree.query_ball_point(batch_points, max_distance)

        # Build ray pairs (only i < j to avoid duplicates)
        src_indices: list[int] = []
        dst_indices: list[int] = []

        for local_i, neigh_list in enumerate(neighbors):
            global_i = batch_start + local_i
            for j in neigh_list:
                if j > global_i:
                    src_indices.append(global_i)
                    dst_indices.append(j)

        if not src_indices:
            log.info("  batch %d-%d: 0 pairs", batch_start, batch_end)
            continue

        src_arr = np.array(src_indices, dtype=np.int32)
        dst_arr = np.array(dst_indices, dtype=np.int32)
        num_pairs = len(src_arr)
        total_pairs += num_pairs

        # Source and destination positions at eye height
        origins_src = points[src_arr].copy()
        origins_src[:, 2] += eye_height
        origins_dst = points[dst_arr].copy()
        origins_dst[:, 2] += eye_height

        # Pair distances
        diff = origins_dst - origins_src
        pair_dists = np.linalg.norm(diff, axis=1).astype(np.float32)

        # Directions A->B
        dirs_ab = diff / np.maximum(pair_dists[:, np.newaxis], 1e-8)

        # Directions B->A
        dirs_ba = -dirs_ab

        visible_mask = np.ones(num_pairs, dtype=bool)

        # Raycast in chunks
        for chunk_start in range(0, num_pairs, RAYCAST_CHUNK):
            chunk_end = min(chunk_start + RAYCAST_CHUNK, num_pairs)
            c_dists = pair_dists[chunk_start:chunk_end]

            # A -> B
            hit_locs_ab, idx_ray_ab, _ = mesh.ray.intersects_location(
                origins_src[chunk_start:chunk_end],
                dirs_ab[chunk_start:chunk_end],
                multiple_hits=False,
            )
            if len(hit_locs_ab) > 0:
                hit_offsets = hit_locs_ab - origins_src[chunk_start:chunk_end][idx_ray_ab]
                hit_dists = np.linalg.norm(hit_offsets, axis=1)
                blocked = np.zeros(chunk_end - chunk_start, dtype=bool)
                blocked[idx_ray_ab] = hit_dists < (c_dists[idx_ray_ab] - 1.0)
                visible_mask[chunk_start:chunk_end] &= ~blocked

            # B -> A
            hit_locs_ba, idx_ray_ba, _ = mesh.ray.intersects_location(
                origins_dst[chunk_start:chunk_end],
                dirs_ba[chunk_start:chunk_end],
                multiple_hits=False,
            )
            if len(hit_locs_ba) > 0:
                hit_offsets = hit_locs_ba - origins_dst[chunk_start:chunk_end][idx_ray_ba]
                hit_dists = np.linalg.norm(hit_offsets, axis=1)
                blocked = np.zeros(chunk_end - chunk_start, dtype=bool)
                blocked[idx_ray_ba] = hit_dists < (c_dists[idx_ray_ba] - 1.0)
                visible_mask[chunk_start:chunk_end] &= ~blocked

        # Record visible pairs (bidirectional adjacency)
        vis_src = src_arr[visible_mask]
        vis_dst = dst_arr[visible_mask]
        batch_visible = int(visible_mask.sum())
        total_visible += batch_visible

        for i, j in zip(vis_src, vis_dst):
            adj_lists[i].append(int(j))
            adj_lists[j].append(int(i))

        log.info(
            "  batch %d-%d: %d pairs, %d visible (%.1f%%)",
            batch_start, batch_end, num_pairs, batch_visible,
            100.0 * batch_visible / max(num_pairs, 1),
        )

    # Pack into adjacency list arrays
    adj_index = np.empty((n, 2), dtype=np.int32)
    all_adj: list[int] = []
    for i in range(n):
        adj_index[i, 0] = len(all_adj)
        adj_index[i, 1] = len(adj_lists[i])
        all_adj.extend(adj_lists[i])

    adj_list = np.array(all_adj, dtype=np.int32) if all_adj else np.empty(0, dtype=np.int32)

    log.info(
        "Vismatrix complete: %d points, %d total pairs tested, %d visible edges, "
        "avg %.1f visible per point",
        n, total_pairs, total_visible,
        len(adj_list) / max(n, 1),
    )

    return VisMatrixResult(
        point_positions=points,
        adj_index=adj_index,
        adj_list=adj_list,
        max_distance=max_distance,
        eye_height=eye_height,
        grid_spacing=grid_spacing,
    )
