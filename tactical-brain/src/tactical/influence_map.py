"""Runtime influence scorer: loads precomputed vismatrix + influence data
and scores grid positions based on weight profiles.

All directional queries (threat from enemies, sightline to objectives)
are driven by the adjacency list in the vismatrix — no raycasting at runtime.

Weight dimensions:
    concealment — static geometric hiddenness (few points can see you)
    sightline   — can see objective/kill zone (vismatrix lookup)
    objective   — proximity to active objective
    threat      — visible to known enemies (directional, penalty)
    spread      — proximity to friendlies (penalty)
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
from scipy.spatial import KDTree

log = logging.getLogger(__name__)

WEIGHT_PROFILES: dict[str, dict[str, float]] = {
    "defend":  {"concealment": 0.0, "sightline": 0.6, "objective": 0.9, "threat": 0.7, "spread": 0.5},
    "push":    {"concealment": 0.0, "sightline": 0.8, "objective": 1.0, "threat": 0.3, "spread": 0.3},
    "ambush":  {"concealment": 0.9, "sightline": 0.4, "objective": 0.2, "threat": 0.5, "spread": 0.8},
    "sniper":  {"concealment": 0.7, "sightline": 1.0, "objective": 0.3, "threat": 0.6, "spread": 0.9},
    "overrun": {"concealment": 0.0, "sightline": 0.5, "objective": 1.0, "threat": 0.1, "spread": 0.2},
}


class InfluenceMap:
    """Load vismatrix + influence, score positions at runtime."""

    def __init__(self, vismatrix_path: str, influence_path: str) -> None:
        vm = np.load(vismatrix_path)
        self.points: np.ndarray = vm["point_positions"]       # [N, 3]
        self.adj_index: np.ndarray = vm["adj_index"]           # [N, 2]
        self.adj_list: np.ndarray = vm["adj_list"]             # [M]
        self.max_distance: float = float(vm["max_distance"])

        inf = np.load(influence_path)
        self.concealment: np.ndarray = inf["cover"].astype(np.float32)  # [N] static geometric hiddenness

        self.n = len(self.points)
        self.tree = KDTree(self.points)

        log.info(
            "InfluenceMap loaded: %d points, %d adj edges, max_dist=%.0f",
            self.n, len(self.adj_list), self.max_distance,
        )

    def nearest_point(self, pos: tuple[float, float, float]) -> int:
        """Find nearest grid point index to a world position."""
        _, idx = self.tree.query(pos)
        return int(idx)

    def visible_from(self, point_idx: int) -> np.ndarray:
        """All point indices visible from a given point (adjacency list lookup)."""
        start, count = self.adj_index[point_idx]
        if count == 0:
            return np.empty(0, dtype=np.int32)
        return self.adj_list[start:start + count]

    def compute_threat(self, enemy_positions: list[tuple[float, float, float]]) -> np.ndarray:
        """Per-point threat from actual enemy positions.

        For each enemy: find nearest grid point, look up visible points,
        mark those as threatened with distance decay.
        """
        threat = np.zeros(self.n, dtype=np.float32)
        if not enemy_positions:
            return threat

        for epos in enemy_positions:
            eidx = self.nearest_point(epos)
            visible = self.visible_from(eidx)
            if len(visible) == 0:
                continue
            diffs = self.points[visible] - np.array(epos, dtype=np.float32)
            dists = np.linalg.norm(diffs, axis=1)
            decay = np.maximum(0.0, 1.0 - dists / self.max_distance)
            threat[visible] += decay

        max_val = threat.max()
        if max_val > 0:
            threat /= max_val
        return threat

    def compute_sightline(
        self, objective_positions: list[tuple[float, float, float]],
    ) -> np.ndarray:
        """Per-point sightline to objective zone.

        For each objective point: look up visible points via adj_list,
        increment sightline for all visible points.
        """
        sightline = np.zeros(self.n, dtype=np.float32)
        if not objective_positions:
            return sightline

        for opos in objective_positions:
            oidx = self.nearest_point(opos)
            visible = self.visible_from(oidx)
            if len(visible) > 0:
                sightline[visible] += 1.0

        max_val = sightline.max()
        if max_val > 0:
            sightline /= max_val
        return sightline

    def compute_team_presence(
        self, friendly_positions: list[tuple[float, float, float]],
    ) -> np.ndarray:
        """Distance falloff from each friendly (spread penalty)."""
        presence = np.zeros(self.n, dtype=np.float32)
        if not friendly_positions:
            return presence

        spread_radius = 500.0
        for fpos in friendly_positions:
            diffs = self.points - np.array(fpos, dtype=np.float32)
            dists = np.linalg.norm(diffs, axis=1)
            decay = np.maximum(0.0, 1.0 - dists / spread_radius)
            presence += decay

        max_val = presence.max()
        if max_val > 0:
            presence /= max_val
        return presence

    def compute_objective_relevance(
        self, objective_pos: tuple[float, float, float],
    ) -> np.ndarray:
        """Distance falloff from active objective point."""
        diffs = self.points - np.array(objective_pos, dtype=np.float32)
        dists = np.linalg.norm(diffs, axis=1)
        max_dist = dists.max()
        if max_dist > 0:
            relevance = 1.0 - (dists / max_dist)
        else:
            relevance = np.ones(self.n, dtype=np.float32)
        return relevance.astype(np.float32)

    def score(
        self,
        weights: dict[str, float],
        *,
        enemy_positions: list[tuple[float, float, float]] | None = None,
        objective_positions: list[tuple[float, float, float]] | None = None,
        objective_center: tuple[float, float, float] | None = None,
        friendly_positions: list[tuple[float, float, float]] | None = None,
    ) -> np.ndarray:
        """Weighted score across all N grid points.

        score = concealment*W1 + sightline*W2 + objective*W3 - threat*W4 - spread*W5
        """
        s = np.zeros(self.n, dtype=np.float32)

        w_concealment = weights.get("concealment", 0.0)
        w_sightline = weights.get("sightline", 0.0)
        w_objective = weights.get("objective", 0.0)
        w_threat = weights.get("threat", 0.0)
        w_spread = weights.get("spread", 0.0)

        if w_concealment != 0.0:
            s += self.concealment * w_concealment

        if w_sightline != 0.0 and objective_positions:
            s += self.compute_sightline(objective_positions) * w_sightline

        if w_objective != 0.0 and objective_center:
            s += self.compute_objective_relevance(objective_center) * w_objective

        if w_threat != 0.0 and enemy_positions:
            s -= self.compute_threat(enemy_positions) * w_threat

        if w_spread != 0.0 and friendly_positions:
            s -= self.compute_team_presence(friendly_positions) * w_spread

        return s

    def best_positions(
        self,
        weights: dict[str, float],
        num: int = 8,
        *,
        enemy_positions: list[tuple[float, float, float]] | None = None,
        objective_positions: list[tuple[float, float, float]] | None = None,
        objective_center: tuple[float, float, float] | None = None,
        friendly_positions: list[tuple[float, float, float]] | None = None,
    ) -> list[tuple[float, float, float]]:
        """Top N scored positions as world coordinates."""
        scores = self.score(
            weights,
            enemy_positions=enemy_positions,
            objective_positions=objective_positions,
            objective_center=objective_center,
            friendly_positions=friendly_positions,
        )
        top_indices = np.argsort(scores)[-num:][::-1]
        return [(float(self.points[i, 0]), float(self.points[i, 1]), float(self.points[i, 2]))
                for i in top_indices]
