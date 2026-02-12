"""3D occupancy grid built from recorded hull traces.

Provides trace() as a drop-in replacement for NavGraph.trace_nav(),
using real collision data instead of nav-mesh area bounds.
"""

from __future__ import annotations

import logging
import math
from pathlib import Path

import numpy as np

log = logging.getLogger(__name__)

VOXEL_EMPTY: np.uint8 = np.uint8(1)
VOXEL_SOLID: np.uint8 = np.uint8(2)

# Trace heights — must match SM plugin g_fTraceHeights
_FOOT_HEIGHT = 8.0
_WAIST_HEIGHT = 32.0


class CollisionMap:
    """3D occupancy grid loaded from a {map}_collision.npz file."""

    def __init__(self, path: Path) -> None:
        data = np.load(path)
        self.grid: np.ndarray = data["grid"]  # uint8 3D array
        self.origin: np.ndarray = data["origin"]  # (min_x, min_y, min_z)
        self.voxel_size: float = float(data["voxel_size"])
        self._inv_voxel = 1.0 / self.voxel_size

        solid = int(np.sum(self.grid == VOXEL_SOLID))
        empty = int(np.sum(self.grid == 1))
        log.info(
            "CollisionMap loaded: shape=%s origin=(%.0f,%.0f,%.0f) voxel=%.0f solid=%d empty=%d",
            self.grid.shape,
            self.origin[0], self.origin[1], self.origin[2],
            self.voxel_size, solid, empty,
        )

    def _to_grid(self, x: float, y: float, z: float) -> tuple[int, int, int]:
        """Convert world coordinates to grid indices (may be out of bounds)."""
        return (
            int((x - self.origin[0]) * self._inv_voxel),
            int((y - self.origin[1]) * self._inv_voxel),
            int((z - self.origin[2]) * self._inv_voxel),
        )

    def _in_bounds(self, ix: int, iy: int, iz: int) -> bool:
        s = self.grid.shape
        return 0 <= ix < s[0] and 0 <= iy < s[1] and 0 <= iz < s[2]

    def is_solid(self, x: float, y: float, z: float) -> bool:
        """Check if a world point is in a solid voxel."""
        ix, iy, iz = self._to_grid(x, y, z)
        if not self._in_bounds(ix, iy, iz):
            return False  # unknown = not solid
        return self.grid[ix, iy, iz] == VOXEL_SOLID

    def trace(
        self,
        start: tuple[float, float],
        end: tuple[float, float],
        z: float = 0.0,
    ) -> float:
        """2D line trace through the voxel grid.

        Returns fraction [0..1] where the first solid voxel is hit.
        Drop-in replacement for NavGraph.trace_nav().

        Uses step-based ray marching at half-voxel resolution.

        Blocking rules per voxel column:
        - Waist SOLID → blocked (wall)
        - Foot SOLID + waist not EMPTY → blocked (unverified obstacle)
        - Foot SOLID + waist EMPTY → walkable surface (stairs/ramp), pass through
        """
        dx = end[0] - start[0]
        dy = end[1] - start[1]
        ray_len = math.sqrt(dx * dx + dy * dy)
        if ray_len < 0.001:
            return 1.0

        step_size = self.voxel_size * 0.5
        num_steps = int(ray_len / step_size) + 1
        inv_len = 1.0 / ray_len
        dir_x = dx * inv_len
        dir_y = dy * inv_len

        # Pre-compute Z grid indices for foot and waist
        iz_foot = int((z + _FOOT_HEIGHT - self.origin[2]) * self._inv_voxel)
        iz_waist = int((z + _WAIST_HEIGHT - self.origin[2]) * self._inv_voxel)
        sz = self.grid.shape[2]
        has_foot = 0 <= iz_foot < sz
        has_waist = 0 <= iz_waist < sz

        if not has_foot and not has_waist:
            return 1.0

        for i in range(1, num_steps + 1):
            d = i * step_size
            if d > ray_len:
                d = ray_len
            px = start[0] + d * dir_x
            py = start[1] + d * dir_y

            ix = int((px - self.origin[0]) * self._inv_voxel)
            iy = int((py - self.origin[1]) * self._inv_voxel)
            if ix < 0 or iy < 0 or ix >= self.grid.shape[0] or iy >= self.grid.shape[1]:
                continue

            # Waist solid → wall, always blocked
            if has_waist and self.grid[ix, iy, iz_waist] == VOXEL_SOLID:
                return d / ray_len

            # Foot solid → only blocked if waist is NOT proven empty
            if has_foot and self.grid[ix, iy, iz_foot] == VOXEL_SOLID:
                if not has_waist or self.grid[ix, iy, iz_waist] != VOXEL_EMPTY:
                    return d / ray_len

        return 1.0
