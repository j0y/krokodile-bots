"""Runtime path-based look direction using precomputed coarse routing.

Loads a walkgraph.npz and uses two-level routing:
  1. Coarse: O(1) next-hop lookup from precomputed all-pairs table
  2. Fine: string-pull along door points using vismatrix visibility checks

Look direction uses a "slice the pie" sweep: the bot watches the farthest
visible corner (weapon covers the edge), then gradually sweeps toward the
area beyond it as it approaches.  At the instant the next door becomes
visible the bot was already looking near it, so the handoff is smooth.
"""

from __future__ import annotations

import logging
from typing import Callable

import numpy as np

log = logging.getLogger(__name__)


class PathFinder:
    """Precomputed coarse routing + runtime string-pulling for look direction."""

    def __init__(
        self,
        walkgraph_path: str,
        points: np.ndarray,
        vis_adj_index: np.ndarray,
        vis_adj_list: np.ndarray,
    ) -> None:
        wg = np.load(walkgraph_path)
        self.fine_to_coarse: np.ndarray = wg["fine_to_coarse"]       # uint16[N]
        self.coarse_next_hop: np.ndarray = wg["coarse_next_hop"]     # int16[C, C]
        self.coarse_centroids: np.ndarray = wg["coarse_centroids"]   # float32[C, 3]
        self.door_adj_index: np.ndarray = wg["door_adj_index"]       # int32[C, 2]
        self.door_adj_list: np.ndarray = wg["door_adj_list"]         # int32[E]
        self.door_grid_points: np.ndarray = wg["door_grid_points"]   # int32[E]

        self.points = points
        self.vis_adj_index = vis_adj_index
        self.vis_adj_list = vis_adj_list

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

    def _get_door_point(self, from_cell: int, to_cell: int) -> int | None:
        """Get the fine grid point index for the door from from_cell to to_cell."""
        start, count = self.door_adj_index[from_cell]
        for k in range(count):
            if self.door_adj_list[start + k] == to_cell:
                return int(self.door_grid_points[start + k])
        return None

    # Distance at which the bot begins sweeping from the visible corner
    # toward the area beyond it.  At 220 u/s walk speed ≈ 2.3 s of sweep.
    SWEEP_DIST = 500.0

    def find_look_target(
        self,
        bot_pos: tuple[float, float, float],
        goal_pos: tuple[float, float, float],
        nearest_point_fn: Callable[[tuple[float, float, float]], int],
    ) -> tuple[float, float, float] | None:
        """Determine where a walking bot should look.

        Uses a "slice the pie" sweep:
          - Far from corner: weapon covers the visible corner edge (D_vis)
          - Approaching: gradually sweep toward the area beyond (D_invis)
          - At the corner: fully covering the next corridor

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

        # Collect door point grid indices along the path
        door_indices: list[int] = []
        for i in range(len(path) - 1):
            dp = self._get_door_point(path[i], path[i + 1])
            if dp is not None:
                door_indices.append(dp)

        if not door_indices:
            return None

        # String-pull: find farthest visible door from bot position
        last_visible = -1
        for i, dp_idx in enumerate(door_indices):
            if self._is_visible(bot_idx, dp_idx):
                last_visible = i

        if last_visible < 0:
            # Can't see any door — look at the first one (direction to go)
            dp = door_indices[0]
            return (float(self.points[dp, 0]), float(self.points[dp, 1]), float(self.points[dp, 2]))

        if last_visible + 1 >= len(door_indices):
            # Can see all door points — last leg
            return None

        # ── Gradual sweep ("slice the pie") ─────────────────────────
        #
        # D_vis  = farthest visible door (the corner edge — weapon covers it)
        # D_invis = first invisible door (the area beyond the corner)
        #
        # As the bot approaches D_vis the blend shifts from watching the
        # corner toward covering the next corridor.  When the bot finally
        # rounds the corner and D_invis becomes visible, the look target
        # was already near D_invis, so the handoff to the next pair is
        # nearly continuous.

        vis_pos = self.points[door_indices[last_visible]]
        invis_pos = self.points[door_indices[last_visible + 1]]

        # 2D distance to the visible corner
        dx = bot_pos[0] - float(vis_pos[0])
        dy = bot_pos[1] - float(vis_pos[1])
        dist_to_corner = (dx * dx + dy * dy) ** 0.5

        # t = 0 far away (look at corner), t = 1 at corner (look beyond)
        t = max(0.0, 1.0 - dist_to_corner / self.SWEEP_DIST)

        return (
            float(vis_pos[0]) + t * (float(invis_pos[0]) - float(vis_pos[0])),
            float(vis_pos[1]) + t * (float(invis_pos[1]) - float(vis_pos[1])),
            float(vis_pos[2]) + t * (float(invis_pos[2]) - float(vis_pos[2])),
        )
