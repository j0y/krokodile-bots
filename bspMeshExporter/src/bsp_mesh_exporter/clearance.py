"""Precompute radial clearance from BSP mesh for each nav area.

For each nav area, generates an adaptive grid of sample points (20u spacing),
then casts horizontal rays from 3 body heights (foot=8u, knee=32u, eye=64u)
at 72 azimuth angles (5 degree steps).  Hit distances are stored as float16.

Result is saved as a compressed .npz for runtime use by the AI brain.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import trimesh

from bsp_mesh_exporter.nav_parser import NavArea, NavMesh

log = logging.getLogger(__name__)

# Defaults
DEFAULT_GRID_SPACING = 20.0
DEFAULT_MAX_RANGE = 500.0
DEFAULT_RAY_HEIGHTS = (8.0, 32.0, 64.0)  # foot, knee, eye
NUM_AZIMUTHS = 72
HULL_INSET = 16.0  # inset samples from area edges (half hull width)
RAYCAST_CHUNK = 500_000


@dataclass
class ClearanceResult:
    """Holds the full clearance computation result for saving."""

    area_ids: np.ndarray          # int32[N]
    centers: np.ndarray           # float32[N, 3]
    sample_positions: np.ndarray  # float32[T, 3]
    sample_index: np.ndarray      # int32[N, 2] — (start, count)
    clearance: np.ndarray         # float16[T, H, A]
    ray_heights: np.ndarray       # float32[H]
    ray_azimuths: np.ndarray      # float32[A]
    max_range: float

    def save(self, path: str | Path) -> None:
        np.savez_compressed(
            str(path),
            area_ids=self.area_ids,
            centers=self.centers,
            sample_positions=self.sample_positions,
            sample_index=self.sample_index,
            clearance=self.clearance,
            ray_heights=self.ray_heights,
            ray_azimuths=self.ray_azimuths,
            max_range=np.float32(self.max_range),
        )
        size = Path(path).stat().st_size
        log.info(
            "Saved clearance: %d areas, %d samples, %.1f MB -> %s",
            len(self.area_ids), len(self.sample_positions), size / 1e6, path,
        )


def _area_samples(
    area: NavArea, grid_spacing: float,
) -> list[tuple[float, float, float]]:
    """Generate adaptive grid sample positions for an area.

    Grid spacing = grid_spacing, inset HULL_INSET from edges.
    Minimum 1 sample (center) per area.
    """
    min_x = min(area.nw.x, area.se.x) + HULL_INSET
    max_x = max(area.nw.x, area.se.x) - HULL_INSET
    min_y = min(area.nw.y, area.se.y) + HULL_INSET
    max_y = max(area.nw.y, area.se.y) - HULL_INSET

    c = area.center()
    foot_z = c.z

    # If area is too small for even one inset grid point, use center
    if max_x <= min_x or max_y <= min_y:
        return [(c.x, c.y, foot_z)]

    # Generate grid
    nx = max(1, int((max_x - min_x) / grid_spacing) + 1)
    ny = max(1, int((max_y - min_y) / grid_spacing) + 1)

    samples: list[tuple[float, float, float]] = []
    for ix in range(nx):
        x = min_x if nx == 1 else min_x + ix * (max_x - min_x) / (nx - 1)
        for iy in range(ny):
            y = min_y if ny == 1 else min_y + iy * (max_y - min_y) / (ny - 1)
            samples.append((x, y, foot_z))

    return samples


def compute_clearance(
    mesh: trimesh.Trimesh,
    nav: NavMesh,
    *,
    grid_spacing: float = DEFAULT_GRID_SPACING,
    max_range: float = DEFAULT_MAX_RANGE,
    ray_heights: tuple[float, ...] = DEFAULT_RAY_HEIGHTS,
) -> ClearanceResult:
    """Compute radial clearance for all nav areas.

    Args:
        mesh: World geometry (BSP mesh loaded as trimesh).
        nav: Parsed nav mesh with areas.
        grid_spacing: Distance between sample grid points within each area.
        max_range: Maximum ray distance (cap).
        ray_heights: Z offsets above foot level for each ring.

    Returns:
        ClearanceResult ready for .save().
    """
    n = len(nav.areas)
    log.info(
        "Computing clearance for %d areas (grid=%.0f, range=%.0f, heights=%s, azimuths=%d)",
        n, grid_spacing, max_range, ray_heights, NUM_AZIMUTHS,
    )

    azimuths = np.linspace(0.0, 2.0 * np.pi, NUM_AZIMUTHS, endpoint=False, dtype=np.float32)
    heights = np.array(ray_heights, dtype=np.float32)
    num_h = len(heights)
    num_a = len(azimuths)

    # Pre-compute azimuth direction vectors (horizontal, Z=0)
    dir_x = np.cos(azimuths)  # [A]
    dir_y = np.sin(azimuths)  # [A]

    # Collect all samples per area
    area_ids_list: list[int] = []
    centers_list: list[tuple[float, float, float]] = []
    all_samples: list[tuple[float, float, float]] = []
    index_list: list[tuple[int, int]] = []  # (start, count) per area

    for area in nav.areas.values():
        c = area.center()
        area_ids_list.append(area.id)
        centers_list.append((c.x, c.y, c.z))

        samples = _area_samples(area, grid_spacing)
        start = len(all_samples)
        all_samples.extend(samples)
        index_list.append((start, len(samples)))

    total_samples = len(all_samples)
    total_rays = total_samples * num_h * num_a
    log.info("Total samples: %d, total rays: %d", total_samples, total_rays)

    area_ids = np.array(area_ids_list, dtype=np.int32)
    centers = np.array(centers_list, dtype=np.float32)
    sample_positions = np.array(all_samples, dtype=np.float32)  # [T, 3]
    sample_index = np.array(index_list, dtype=np.int32)  # [N, 2]

    # Build all ray origins and directions
    # For each sample t, height h, azimuth a: origin = (sx, sy, sz + h), dir = (dx_a, dy_a, 0)
    # Shape: [T, H, A] flattened to [T*H*A, 3]

    # Expand sample positions: [T, 1, 1, 3]
    sp = sample_positions[:, np.newaxis, np.newaxis, :]  # [T, 1, 1, 3]

    # Height offsets: [1, H, 1]
    h_offsets = heights[np.newaxis, :, np.newaxis]  # [1, H, 1]

    # Origins: [T, H, A, 3]
    origins = np.broadcast_to(sp, (total_samples, num_h, num_a, 3)).copy()
    # Add height offset to Z
    origins[:, :, :, 2] += h_offsets

    # Directions: [1, 1, A, 3]
    dirs = np.zeros((1, 1, num_a, 3), dtype=np.float32)
    dirs[0, 0, :, 0] = dir_x
    dirs[0, 0, :, 1] = dir_y
    dirs_broadcast = np.broadcast_to(dirs, (total_samples, num_h, num_a, 3)).copy()

    # Flatten for raycast
    origins_flat = origins.reshape(-1, 3)
    dirs_flat = dirs_broadcast.reshape(-1, 3)

    # Batch raycast via Embree (trimesh)
    hit_distances = np.full(total_rays, max_range, dtype=np.float32)

    for start in range(0, total_rays, RAYCAST_CHUNK):
        end = min(start + RAYCAST_CHUNK, total_rays)
        chunk_origins = origins_flat[start:end]
        chunk_dirs = dirs_flat[start:end]

        hit_locs, idx_ray, _idx_tri = mesh.ray.intersects_location(
            chunk_origins, chunk_dirs, multiple_hits=False,
        )

        if len(hit_locs) > 0:
            # Compute distances from origin to hit
            offsets = hit_locs - chunk_origins[idx_ray]
            dists = np.linalg.norm(offsets, axis=1).astype(np.float32)
            # Cap at max_range
            dists = np.minimum(dists, max_range)
            hit_distances[start + idx_ray] = dists

        done = min(end, total_rays)
        log.info("  raycast progress: %d / %d rays", done, total_rays)

    # Reshape to [T, H, A] and pack as float16
    clearance = hit_distances.reshape(total_samples, num_h, num_a).astype(np.float16)

    log.info(
        "Clearance complete: %d areas, %d samples, min=%.0f median=%.0f max=%.0f",
        n, total_samples,
        float(np.min(clearance)), float(np.median(clearance)), float(np.max(clearance)),
    )

    return ClearanceResult(
        area_ids=area_ids,
        centers=centers,
        sample_positions=sample_positions,
        sample_index=sample_index,
        clearance=clearance,
        ray_heights=heights,
        ray_azimuths=azimuths,
        max_range=max_range,
    )
