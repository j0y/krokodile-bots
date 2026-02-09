"""Runtime loader for precomputed area-to-area visibility maps."""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np

log = logging.getLogger(__name__)


class VisibilityMap:
    """Area-to-area line-of-sight visibility lookup.

    Loads a .npz file produced by bspMeshExporter and provides O(1)
    can_see() checks via a set of canonical (min, max) area ID pairs.
    """

    def __init__(self, path: Path) -> None:
        data = np.load(path)
        pairs = data["visible_pairs"]
        self._visible: set[tuple[int, int]] = {(int(r[0]), int(r[1])) for r in pairs}
        self.num_areas: int = len(data["area_ids"])
        self.num_pairs: int = len(pairs)
        log.info(
            "VisibilityMap loaded: %d areas, %d visible pairs from %s",
            self.num_areas, self.num_pairs, path,
        )

    def can_see(self, area_a: int, area_b: int) -> bool:
        """Check if two areas have line-of-sight visibility."""
        return (min(area_a, area_b), max(area_a, area_b)) in self._visible
