"""Wave front: tracks enemy danger progression from spawn through the map.

Precomputes BFS hop distances from enemy spawn on the coarse walkgraph,
then overlays visibility so that areas visible from enemy-reachable cells
become "danger" areas earlier.  The wave front advances in real-time at
SECONDS_PER_HOP, and bots use it to decide approach (safe) vs investigate
(danger) movement.

Resets on every objectives_lost change and on phase → "active".
"""

from __future__ import annotations

import logging
from collections import deque

import numpy as np

from tactical.influence_map import InfluenceMap
from tactical.pathfinding import PathFinder

log = logging.getLogger(__name__)


class WaveFront:
    SECONDS_PER_HOP = 2.5

    def __init__(self, pathfinder: PathFinder, influence_map: InfluenceMap) -> None:
        self._pathfinder = pathfinder
        self._influence_map = influence_map

        num_cells = len(pathfinder.coarse_centroids)
        # Per-cell: minimum BFS hops from enemy spawn
        self._cell_hops: np.ndarray = np.full(num_cells, 9999, dtype=np.int32)
        # Per-cell: minimum hops among cells that can see this cell
        self._danger_hops: np.ndarray = np.full(num_cells, 9999, dtype=np.int32)

        self._last_objectives_lost: int = -1
        self._last_phase: str = ""
        self._wave_start: float = 0.0
        self._valid: bool = False

    def update(
        self, objectives_lost: int, phase: str,
        enemy_spawn: tuple[float, float, float] | None, now: float,
    ) -> None:
        """Call each tick.  Recomputes on objectives_lost change or phase reset."""
        needs_recompute = False

        if objectives_lost != self._last_objectives_lost:
            needs_recompute = True
            self._last_objectives_lost = objectives_lost

        if phase == "active" and self._last_phase != "active":
            needs_recompute = True
        self._last_phase = phase

        if needs_recompute:
            if enemy_spawn is not None:
                self._recompute(enemy_spawn, now)
            else:
                self._valid = False

    def is_area_danger(self, area_center: tuple[float, float, float], now: float) -> bool:
        """Check if an area (by its center position) is in the danger zone."""
        if not self._valid:
            return True  # conservative: treat everything as danger if no data

        # Map area center to nearest fine grid point, then to coarse cell
        fine_idx = self._influence_map.nearest_point(area_center)
        cell = int(self._pathfinder.fine_to_coarse[fine_idx])

        elapsed = now - self._wave_start
        wave_hops = elapsed / self.SECONDS_PER_HOP

        return float(self._danger_hops[cell]) <= wave_hops

    def _recompute(self, enemy_spawn: tuple[float, float, float], now: float) -> None:
        """BFS from enemy spawn, then overlay visibility for danger_hops."""
        pf = self._pathfinder
        num_cells = len(pf.coarse_centroids)

        # Find spawn's coarse cell
        fine_idx = self._influence_map.nearest_point(enemy_spawn)
        spawn_cell = int(pf.fine_to_coarse[fine_idx])

        # BFS on coarse graph
        cell_hops = np.full(num_cells, 9999, dtype=np.int32)
        cell_hops[spawn_cell] = 0
        queue: deque[int] = deque([spawn_cell])

        while queue:
            current = queue.popleft()
            next_dist = int(cell_hops[current]) + 1
            for neighbor in pf.coarse_neighbors(current):
                if next_dist < cell_hops[neighbor]:
                    cell_hops[neighbor] = next_dist
                    queue.append(neighbor)

        self._cell_hops = cell_hops

        # Build reverse visibility: for each cell, which cells can see it?
        # Use centroid grid indices and the vismatrix.
        # cells_that_see[C] = set of cells D where D's centroid can see C's centroid
        cells_that_see: list[list[int]] = [[] for _ in range(num_cells)]

        for cell_id in range(num_cells):
            centroid_grid_idx = int(pf.centroid_grid_idx[cell_id])
            visible_fine = pf._visible_from(centroid_grid_idx)
            if len(visible_fine) == 0:
                continue
            # Map visible fine points to coarse cells (unique)
            visible_cells = set(int(x) for x in pf.fine_to_coarse[visible_fine])
            for vc in visible_cells:
                if vc != cell_id:
                    cells_that_see[vc].append(cell_id)

        # danger_hops[C] = min cell_hops[D] for D in cells_that_see[C]
        danger_hops = np.full(num_cells, 9999, dtype=np.int32)
        for cell_id in range(num_cells):
            # The cell itself is always "seen" by itself
            min_hop = int(cell_hops[cell_id])
            for observer in cells_that_see[cell_id]:
                h = int(cell_hops[observer])
                if h < min_hop:
                    min_hop = h
            danger_hops[cell_id] = min_hop

        self._danger_hops = danger_hops
        self._wave_start = now
        self._valid = True

        log.info(
            "WaveFront recomputed: spawn_cell=%d, reachable=%d/%d cells",
            spawn_cell,
            int((cell_hops < 9999).sum()),
            num_cells,
        )
