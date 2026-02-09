"""Runtime loader for precomputed radial clearance maps."""

from __future__ import annotations

import logging
import math
from pathlib import Path

import numpy as np

log = logging.getLogger(__name__)


class ClearanceMap:
    """Per-area radial clearance loaded from a {map}_clearance.npz file.

    Provides fast lookups of wall distance in any horizontal direction
    from sampled positions within each nav area.
    """

    def __init__(self, path: Path) -> None:
        data = np.load(path)
        self._area_ids: np.ndarray = data["area_ids"]        # int32[N]
        self._centers: np.ndarray = data["centers"]           # float32[N, 3]
        self._sample_pos: np.ndarray = data["sample_positions"]  # float32[T, 3]
        self._sample_idx: np.ndarray = data["sample_index"]   # int32[N, 2]
        self._clearance: np.ndarray = data["clearance"]       # float16[T, H, A]
        self._ray_heights: np.ndarray = data["ray_heights"]   # float32[H]
        self._ray_azimuths: np.ndarray = data["ray_azimuths"]  # float32[A]
        self._max_range: float = float(data["max_range"])
        self._num_azimuths: int = len(self._ray_azimuths)
        self._azimuth_step: float = 2.0 * math.pi / self._num_azimuths

        # area_id → index lookup
        self._id_to_idx: dict[int, int] = {
            int(aid): i for i, aid in enumerate(self._area_ids)
        }

        log.info(
            "ClearanceMap loaded: %d areas, %d samples, %d heights, %d azimuths from %s",
            len(self._area_ids), len(self._sample_pos),
            len(self._ray_heights), self._num_azimuths, path,
        )

    def _angle_to_bin(self, angle: float) -> int:
        """Convert an angle (radians) to the nearest azimuth bin index."""
        a = angle % (2.0 * math.pi)
        return int(round(a / self._azimuth_step)) % self._num_azimuths

    def _center_sample_idx(self, area_idx: int) -> int:
        """Return the index of the sample closest to area center (first sample)."""
        return int(self._sample_idx[area_idx, 0])

    def get_clearance(self, area_id: int, angle: float, height: int = 2) -> float:
        """Clearance from area center sample in a given direction.

        Args:
            area_id: Nav area ID.
            angle: Horizontal angle in radians.
            height: Height ring index (0=foot, 1=knee, 2=eye).

        Returns:
            Distance to nearest wall, or max_range if no wall.
        """
        idx = self._id_to_idx.get(area_id)
        if idx is None:
            return self._max_range
        s = self._center_sample_idx(idx)
        a_bin = self._angle_to_bin(angle)
        return float(self._clearance[s, height, a_bin])

    def get_clearance_at(
        self, area_id: int, x: float, y: float, angle: float, height: int = 2,
    ) -> float:
        """Clearance from the sample nearest to (x, y) within the area.

        Args:
            area_id: Nav area ID.
            x, y: World position to query from.
            angle: Horizontal angle in radians.
            height: Height ring index (0=foot, 1=knee, 2=eye).

        Returns:
            Distance to nearest wall, or max_range if no wall.
        """
        idx = self._id_to_idx.get(area_id)
        if idx is None:
            return self._max_range

        start, count = int(self._sample_idx[idx, 0]), int(self._sample_idx[idx, 1])
        if count <= 0:
            return self._max_range

        if count == 1:
            s = start
        else:
            # Find nearest sample by 2D distance
            positions = self._sample_pos[start : start + count, :2]  # [count, 2]
            dx = positions[:, 0] - x
            dy = positions[:, 1] - y
            dists_sq = dx * dx + dy * dy
            s = start + int(np.argmin(dists_sq))

        a_bin = self._angle_to_bin(angle)
        return float(self._clearance[s, height, a_bin])

    def get_open_direction(self, area_id: int, height: int = 2) -> float:
        """Horizontal angle (radians) with maximum clearance from area center.

        Useful for stuck recovery: move in the most open direction.
        """
        idx = self._id_to_idx.get(area_id)
        if idx is None:
            return 0.0
        s = self._center_sample_idx(idx)
        ring = self._clearance[s, height, :]  # [A]
        best = int(np.argmax(ring))
        return float(self._ray_azimuths[best])

    def get_wall_normal(self, area_id: int, height: int = 2) -> tuple[float, float] | None:
        """Unit vector pointing away from nearest wall at area center.

        Returns None if no wall is within range (all clearances at max_range).
        """
        idx = self._id_to_idx.get(area_id)
        if idx is None:
            return None
        s = self._center_sample_idx(idx)
        ring = self._clearance[s, height, :]  # [A]

        min_dist = float(np.min(ring))
        if min_dist >= self._max_range - 1.0:
            return None  # no nearby wall

        # Direction away from closest wall = opposite of the min-clearance azimuth
        closest_bin = int(np.argmin(ring))
        away_angle = float(self._ray_azimuths[closest_bin]) + math.pi
        return (math.cos(away_angle), math.sin(away_angle))

    def get_repulsion(
        self, area_id: int, x: float, y: float, height: int = 1,
    ) -> tuple[float, float, float]:
        """Weighted repulsion vector pushing away from nearby walls.

        Sums inverse-distance contributions from all azimuth bins at the
        nearest sample.  Walls closer than REPULSION_RADIUS produce a
        force; farther walls contribute nothing.

        Returns (dx, dy, strength) where (dx, dy) is a unit vector and
        strength is in [0, 1].  Strength 0 means no nearby walls.
        """
        idx = self._id_to_idx.get(area_id)
        if idx is None:
            return (0.0, 0.0, 0.0)

        start, count = int(self._sample_idx[idx, 0]), int(self._sample_idx[idx, 1])
        if count <= 0:
            return (0.0, 0.0, 0.0)

        # Find nearest sample
        if count == 1:
            s = start
        else:
            positions = self._sample_pos[start : start + count, :2]
            dx = positions[:, 0] - x
            dy = positions[:, 1] - y
            dists_sq = dx * dx + dy * dy
            s = start + int(np.argmin(dists_sq))

        ring = self._clearance[s, height, :].astype(np.float32)  # [A]
        min_dist = float(np.min(ring))

        # No wall within repulsion radius → no force
        if min_dist >= _REPULSION_RADIUS:
            return (0.0, 0.0, 0.0)

        # Weighted sum: each bin contributes a push AWAY from its direction,
        # weighted by how close the wall is (inverse linear)
        push_x = 0.0
        push_y = 0.0
        for i in range(self._num_azimuths):
            d = float(ring[i])
            if d >= _REPULSION_RADIUS:
                continue
            # Weight: 1 at distance 0, 0 at REPULSION_RADIUS
            w = 1.0 - d / _REPULSION_RADIUS
            # Push AWAY from this direction (negate the azimuth vector)
            angle = float(self._ray_azimuths[i])
            push_x -= w * math.cos(angle)
            push_y -= w * math.sin(angle)

        mag = math.sqrt(push_x * push_x + push_y * push_y)
        if mag < 0.001:
            return (0.0, 0.0, 0.0)

        # Strength: how urgently we need to move (0..1 based on closest wall)
        strength = min(1.0, 1.0 - min_dist / _REPULSION_RADIUS)
        return (push_x / mag, push_y / mag, strength)


# Wall repulsion activates when closest wall is within this distance
_REPULSION_RADIUS = 80.0
