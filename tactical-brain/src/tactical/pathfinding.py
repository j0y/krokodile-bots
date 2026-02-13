"""Runtime path-based look direction using precomputed coarse routing.

Loads a walkgraph.npz and uses two-level routing:
  1. Coarse: O(1) next-hop lookup from precomputed all-pairs table
  2. Fine: string-pull along cell centroids using vismatrix visibility

Look targets are cell centroids (room/corridor centers), not cell-boundary
door points.  Centroids correspond to where threats actually are ("inside
the next room"), and the string-pull naturally skips open-space transitions
because the bot can see through to distant centroids.

Sweep: the bot watches the farthest visible centroid, gradually sweeping
toward the next hidden one as it approaches.  Transition is smooth because
at the instant the hidden centroid becomes visible the bot was already
looking near it.
"""

from __future__ import annotations

import logging
from typing import Callable

import numpy as np
from scipy.spatial import KDTree

log = logging.getLogger(__name__)


class PathFinder:
    """Precomputed coarse routing + runtime string-pulling for look direction."""

    # Distance at which the bot begins sweeping from the visible centroid
    # toward the hidden one.  At 220 u/s walk speed ≈ 2.3 s of sweep.
    SWEEP_DIST = 500.0

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

    def _is_visible(self, idx_a: int, idx_b: int) -> bool:
        """Check if two grid points can see each other (vismatrix lookup)."""
        start, count = self.vis_adj_index[idx_a]
        if count == 0:
            return False
        visible = self.vis_adj_list[start:start + count]
        return int(idx_b) in visible

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
            # Can't see any centroid — look toward the first one
            c = self.coarse_centroids[waypoints[0][1]]
            return (float(c[0]), float(c[1]), float(c[2]))

        if last_visible + 1 >= len(waypoints):
            # Can see all waypoints in lookahead — last leg
            return None

        # ── Gradual sweep ────────────────────────────────────────────
        #
        # vis_c  = farthest visible centroid (threat area the weapon covers)
        # invis_c = first hidden centroid    (area beyond the next corner)
        #
        # As the bot approaches vis_c the blend sweeps into invis_c.
        # When the bot rounds the corner and invis_c becomes visible,
        # the look target was already near it — smooth handoff.

        vis_c = self.coarse_centroids[waypoints[last_visible][1]]
        invis_c = self.coarse_centroids[waypoints[last_visible + 1][1]]

        # 2D distance to the visible centroid
        dx = bot_pos[0] - float(vis_c[0])
        dy = bot_pos[1] - float(vis_c[1])
        dist = (dx * dx + dy * dy) ** 0.5

        # t = 0 far away (look at visible room), t = 1 close (look beyond)
        t = max(0.0, 1.0 - dist / self.SWEEP_DIST)

        return (
            float(vis_c[0]) + t * (float(invis_c[0]) - float(vis_c[0])),
            float(vis_c[1]) + t * (float(invis_c[1]) - float(vis_c[1])),
            float(vis_c[2]) + t * (float(invis_c[2]) - float(vis_c[2])),
        )
