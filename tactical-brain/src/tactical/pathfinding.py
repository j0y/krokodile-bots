"""Runtime path-based look direction using precomputed coarse routing.

Loads a walkgraph.npz and uses two-level routing:
  1. Coarse: O(1) next-hop lookup from precomputed all-pairs table
  2. Fine: string-pull along cell centroids using vismatrix visibility

Look targets are cell centroids (room/corridor centers), not cell-boundary
door points.  Centroids correspond to where threats actually are ("inside
the next room"), and the string-pull naturally skips open-space transitions
because the bot can see through to distant centroids.

Corner watching: the bot looks at the visible grid point closest to the
next hidden centroid — the wall corner where an enemy would first appear.
As the bot rounds the corner, the hidden centroid becomes visible and the
string-pull advances naturally.
"""

from __future__ import annotations

import logging
import math
from typing import Callable

import numpy as np
from scipy.spatial import KDTree

log = logging.getLogger(__name__)


class PathFinder:
    """Precomputed coarse routing + runtime string-pulling for look direction."""

    # Distance at which the bot begins sweeping from the visible centroid
    # toward the hidden one.  At 220 u/s walk speed ≈ 2.3 s of sweep.
    SWEEP_DIST = 500.0

    # Degrees to rotate look toward the open side of a corner ("pie slicing").
    PEEK_OFFSET_DEG = 20.0

    # Only consider this many hops ahead for look direction.
    # Limits sensitivity to routing mismatches with the engine's pathfinder.
    MAX_LOOKAHEAD = 8

    def __init__(
        self,
        walkgraph_path: str,
        points: np.ndarray,
        vis_adj_index: np.ndarray,
        vis_adj_list: np.ndarray,
        tree: KDTree | None = None,
    ) -> None:
        wg = np.load(walkgraph_path)
        self.fine_to_coarse: np.ndarray = wg["fine_to_coarse"]       # uint16[N]
        self.coarse_next_hop: np.ndarray = wg["coarse_next_hop"]     # int16[C, C]
        self.coarse_centroids: np.ndarray = wg["coarse_centroids"]   # float32[C, 3]

        self.points = points
        self.vis_adj_index = vis_adj_index
        self.vis_adj_list = vis_adj_list

        # Map each cell centroid to its nearest grid point for vis checks
        if tree is None:
            tree = KDTree(points)
        _, self.centroid_grid_idx = tree.query(self.coarse_centroids)

        num_cells = len(self.coarse_centroids)
        log.info("PathFinder loaded: %d fine points, %d coarse cells", len(points), num_cells)

    def _visible_from(self, idx: int) -> np.ndarray:
        """All grid point indices visible from *idx*."""
        start, count = self.vis_adj_index[idx]
        if count <= 0:
            return np.empty(0, dtype=np.int32)
        return self.vis_adj_list[start:start + count]

    def _find_corner_point(
        self, bot_idx: int, target_pos: np.ndarray,
    ) -> tuple[float, float, float] | None:
        """Find the visible grid point closest to *target_pos*.

        This is the wall corner — the last visible point before the
        hidden area.  Always returns a point the bot can actually see.
        """
        visible = self._visible_from(bot_idx)
        if len(visible) == 0:
            return None
        vis_pts = self.points[visible]
        target_2d = np.array([float(target_pos[0]), float(target_pos[1])], dtype=np.float32)
        dists = np.linalg.norm(vis_pts[:, :2] - target_2d, axis=1)
        best = visible[int(np.argmin(dists))]
        p = self.points[best]
        return (float(p[0]), float(p[1]), float(p[2]))

    def _is_visible(self, idx_a: int, idx_b: int) -> bool:
        """Check if two grid points can see each other (vismatrix lookup)."""
        start, count = self.vis_adj_index[idx_a]
        if count == 0:
            return False
        visible = self.vis_adj_list[start:start + count]
        return int(idx_b) in visible

    def coarse_neighbors(self, cell: int) -> list[int]:
        """Directly adjacent coarse cells (next_hop[cell, j] == j)."""
        row = self.coarse_next_hop[cell]
        return [int(j) for j in range(len(row)) if row[j] == j and j != cell]

    def _coarse_path(self, src_cell: int, dst_cell: int) -> list[int] | None:
        """Walk the coarse path from src to dst using the next-hop table."""
        if src_cell == dst_cell:
            return [src_cell]

        path = [src_cell]
        current = src_cell
        max_hops = len(self.coarse_centroids)

        for _ in range(max_hops):
            nh = int(self.coarse_next_hop[current, dst_cell])
            if nh < 0:
                return None  # unreachable
            path.append(nh)
            if nh == dst_cell:
                return path
            current = nh

        return None  # loop safety

    def hop_count(
        self,
        src_pos: tuple[float, float, float],
        dst_pos: tuple[float, float, float],
        nearest_point_fn: Callable[[tuple[float, float, float]], int],
    ) -> int:
        """Number of coarse cell hops between two world positions.

        Returns a large value (999) if unreachable.
        """
        src_cell = int(self.fine_to_coarse[nearest_point_fn(src_pos)])
        dst_cell = int(self.fine_to_coarse[nearest_point_fn(dst_pos)])
        if src_cell == dst_cell:
            return 0
        path = self._coarse_path(src_cell, dst_cell)
        if path is None:
            return 999
        return len(path) - 1

    def find_look_target(
        self,
        bot_pos: tuple[float, float, float],
        goal_pos: tuple[float, float, float],
        nearest_point_fn: Callable[[tuple[float, float, float]], int],
    ) -> tuple[float, float, float] | None:
        """Determine where a walking bot should look.

        Uses cell centroids as waypoints (room/corridor centers).
        String-pull finds the farthest visible centroid, then sweeps
        toward the next hidden one as the bot approaches.

        Returns a world position, or None if the bot has direct line of
        sight to the goal (last leg — caller uses arrival look).
        """
        bot_idx = nearest_point_fn(bot_pos)
        goal_idx = nearest_point_fn(goal_pos)

        # Direct visibility → last leg, caller uses arrival look
        if self._is_visible(bot_idx, goal_idx):
            return None

        bot_cell = int(self.fine_to_coarse[bot_idx])
        goal_cell = int(self.fine_to_coarse[goal_idx])

        # Same coarse cell → very close, no routing needed
        if bot_cell == goal_cell:
            return None

        # Walk coarse path
        path = self._coarse_path(bot_cell, goal_cell)
        if not path or len(path) < 2:
            return None

        # Cell centroids as waypoints, skipping bot's own cell,
        # limited to MAX_LOOKAHEAD to stay near the actual engine path
        waypoints: list[tuple[int, int]] = []   # (grid_idx, cell_id)
        for cell_id in path[1 : 1 + self.MAX_LOOKAHEAD]:
            waypoints.append((int(self.centroid_grid_idx[cell_id]), cell_id))

        if not waypoints:
            return None

        # String-pull: find farthest visible centroid
        last_visible = -1
        for i, (gidx, _) in enumerate(waypoints):
            if self._is_visible(bot_idx, gidx):
                last_visible = i

        if last_visible < 0:
            # Can't see any centroid — find the corner toward the first one
            c = self.coarse_centroids[waypoints[0][1]]
            corner = self._find_corner_point(bot_idx, c)
            return corner if corner else (float(c[0]), float(c[1]), float(c[2]))

        if last_visible + 1 >= len(waypoints):
            # Can see all waypoints in lookahead — last leg
            return None

        # ── Corner watching ───────────────────────────────────────────
        #
        # vis_c   = farthest visible centroid (room the weapon covers)
        # invis_c = first hidden centroid     (room beyond the next corner)
        #
        # Instead of blending toward invis_c (which is behind a wall),
        # find the visible grid point closest to invis_c.  That point
        # IS the corner — the wall edge where an enemy would first appear.
        #
        # As the bot approaches and rounds the corner, invis_c becomes
        # visible and the string-pull advances naturally.

        vis_c = self.coarse_centroids[waypoints[last_visible][1]]
        invis_c = self.coarse_centroids[waypoints[last_visible + 1][1]]

        corner = self._find_corner_point(bot_idx, invis_c)
        if corner is not None:
            # Pie-slice: rotate look toward the open side of the turn.
            # Cross product of (bot→corner) × (corner→hidden) gives turn dir.
            bc_x = corner[0] - bot_pos[0]
            bc_y = corner[1] - bot_pos[1]
            ch_x = float(invis_c[0]) - corner[0]
            ch_y = float(invis_c[1]) - corner[1]
            cross = bc_x * ch_y - bc_y * ch_x

            if abs(cross) > 1.0:  # skip if nearly straight
                offset_rad = math.radians(self.PEEK_OFFSET_DEG)
                if cross > 0:     # left turn → look right
                    offset_rad = -offset_rad
                cos_a = math.cos(offset_rad)
                sin_a = math.sin(offset_rad)
                new_x = bc_x * cos_a - bc_y * sin_a
                new_y = bc_x * sin_a + bc_y * cos_a
                corner = (bot_pos[0] + new_x, bot_pos[1] + new_y, corner[2])

            return corner

        # Fallback: look at farthest visible centroid
        return (float(vis_c[0]), float(vis_c[1]), float(vis_c[2]))
