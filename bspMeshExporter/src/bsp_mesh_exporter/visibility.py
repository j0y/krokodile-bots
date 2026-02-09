"""Batch raycast visibility between nav areas and save/load results."""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import trimesh

log = logging.getLogger(__name__)


class VisibilityMap:
    """Area-to-area visibility lookup table.

    Stores visible pairs as (area_a, area_b) with a < b for canonical ordering.
    """

    def __init__(
        self,
        area_ids: np.ndarray,
        positions: np.ndarray,
        visible_pairs: np.ndarray,
        max_distance: float,
    ) -> None:
        self.area_ids = area_ids
        self.positions = positions
        self.visible_pairs = visible_pairs
        self.max_distance = max_distance
        self._visible: set[tuple[int, int]] = {
            (int(r[0]), int(r[1])) for r in visible_pairs
        }

    def can_see(self, area_a: int, area_b: int) -> bool:
        """Check if two areas have line-of-sight visibility."""
        a, b = min(area_a, area_b), max(area_a, area_b)
        return (a, b) in self._visible

    def save(self, path: str | Path) -> None:
        """Save visibility map to .npz file."""
        np.savez_compressed(
            str(path),
            area_ids=self.area_ids,
            positions=self.positions,
            visible_pairs=self.visible_pairs,
            max_distance=np.float32(self.max_distance),
        )
        size = Path(path).stat().st_size
        log.info(
            "Saved visibility: %d areas, %d visible pairs, %.1f KB -> %s",
            len(self.area_ids), len(self.visible_pairs), size / 1024, path,
        )

    @staticmethod
    def load(path: str | Path) -> VisibilityMap:
        """Load visibility map from .npz file."""
        data = np.load(str(path))
        return VisibilityMap(
            area_ids=data["area_ids"],
            positions=data["positions"],
            visible_pairs=data["visible_pairs"],
            max_distance=float(data["max_distance"]),
        )


def compute_visibility(
    mesh: trimesh.Trimesh,
    area_ids: np.ndarray,
    positions: np.ndarray,
    max_distance: float = 3000.0,
) -> VisibilityMap:
    """Compute pairwise line-of-sight visibility between nav area positions.

    Args:
        mesh: World geometry for occlusion testing.
        area_ids: (N,) int32 array of area IDs.
        positions: (N, 3) float32 array of eye-height positions.
        max_distance: Maximum distance to consider for visibility.

    Returns:
        VisibilityMap with all visible pairs.
    """
    n = len(area_ids)
    log.info("Computing visibility for %d areas (max_distance=%.0f)", n, max_distance)

    # Build candidate pairs within max_distance
    # Use vectorized pairwise distance computation
    # For ~3000 areas this is ~4.5M pairs before distance filter, manageable
    idx_i, idx_j = np.triu_indices(n, k=1)

    dx = positions[idx_j, 0] - positions[idx_i, 0]
    dy = positions[idx_j, 1] - positions[idx_i, 1]
    dz = positions[idx_j, 2] - positions[idx_i, 2]
    dists = np.sqrt(dx * dx + dy * dy + dz * dz)

    mask = dists <= max_distance
    idx_i = idx_i[mask]
    idx_j = idx_j[mask]
    pair_dists = dists[mask]

    num_pairs = len(idx_i)
    log.info("Candidate pairs within range: %d / %d", num_pairs, len(mask))

    if num_pairs == 0:
        return VisibilityMap(area_ids, positions, np.empty((0, 2), dtype=np.int32), max_distance)

    # Prepare rays: A->B
    origins_ab = positions[idx_i]
    dirs_ab = positions[idx_j] - origins_ab
    norms_ab = np.linalg.norm(dirs_ab, axis=1, keepdims=True)
    norms_ab = np.maximum(norms_ab, 1e-8)
    dirs_ab = dirs_ab / norms_ab

    # Prepare rays: B->A
    origins_ba = positions[idx_j]
    dirs_ba = positions[idx_i] - origins_ba
    norms_ba = np.linalg.norm(dirs_ba, axis=1, keepdims=True)
    norms_ba = np.maximum(norms_ba, 1e-8)
    dirs_ba = dirs_ba / norms_ba

    # Batch raycast using Embree (via trimesh)
    # Process in chunks to manage memory
    chunk_size = 500_000
    visible_mask = np.ones(num_pairs, dtype=bool)

    for start in range(0, num_pairs, chunk_size):
        end = min(start + chunk_size, num_pairs)
        chunk_dists = pair_dists[start:end]

        # A -> B direction
        hit_locs_ab, _idx_ray_ab, _idx_tri_ab = mesh.ray.intersects_location(
            origins_ab[start:end], dirs_ab[start:end], multiple_hits=False,
        )

        if len(hit_locs_ab) > 0:
            # Compute hit distances from origins
            hit_offsets_ab = hit_locs_ab - origins_ab[start:end][_idx_ray_ab]
            hit_dists_ab = np.linalg.norm(hit_offsets_ab, axis=1)
            # Mark as blocked if hit is closer than pair distance (with 1u tolerance)
            blocked_ab = np.zeros(end - start, dtype=bool)
            blocked_ab[_idx_ray_ab] = hit_dists_ab < (chunk_dists[_idx_ray_ab] - 1.0)
            visible_mask[start:end] &= ~blocked_ab

        # B -> A direction
        hit_locs_ba, _idx_ray_ba, _idx_tri_ba = mesh.ray.intersects_location(
            origins_ba[start:end], dirs_ba[start:end], multiple_hits=False,
        )

        if len(hit_locs_ba) > 0:
            hit_offsets_ba = hit_locs_ba - origins_ba[start:end][_idx_ray_ba]
            hit_dists_ba = np.linalg.norm(hit_offsets_ba, axis=1)
            blocked_ba = np.zeros(end - start, dtype=bool)
            blocked_ba[_idx_ray_ba] = hit_dists_ba < (chunk_dists[_idx_ray_ba] - 1.0)
            visible_mask[start:end] &= ~blocked_ba

        done = min(end, num_pairs)
        log.info("  raycast progress: %d / %d pairs", done, num_pairs)

    # Build result: visible pairs as (area_id_a, area_id_b) with a < b
    vis_idx_i = idx_i[visible_mask]
    vis_idx_j = idx_j[visible_mask]
    vis_pairs = np.stack([area_ids[vis_idx_i], area_ids[vis_idx_j]], axis=1).astype(np.int32)

    num_visible = len(vis_pairs)
    log.info(
        "Visibility complete: %d / %d pairs visible (%.1f%%)",
        num_visible, num_pairs, 100.0 * num_visible / max(num_pairs, 1),
    )

    return VisibilityMap(area_ids, positions, vis_pairs, max_distance)
