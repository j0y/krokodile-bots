"""Derive per-point cover scalar from a precomputed visibility matrix.

Lightweight — just reads adjacency list lengths and normalizes.

Output arrays:
    point_positions:  float32[N, 3]  — same grid as vismatrix
    cover:            float32[N]     — 0.0 (fully exposed) to 1.0 (well-covered)
    visibility_count: int32[N]       — raw count of visible points
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np

log = logging.getLogger(__name__)


@dataclass
class InfluenceResult:
    """Per-point cover and visibility count."""

    point_positions: np.ndarray   # float32[N, 3]
    cover: np.ndarray             # float32[N]
    visibility_count: np.ndarray  # int32[N]

    def save(self, path: str | Path) -> None:
        np.savez_compressed(
            str(path),
            point_positions=self.point_positions,
            cover=self.cover,
            visibility_count=self.visibility_count,
        )
        size = Path(path).stat().st_size
        log.info(
            "Saved influence: %d points, %.1f KB -> %s",
            len(self.point_positions), size / 1024, path,
        )


def compute_influence(vismatrix_path: str | Path) -> InfluenceResult:
    """Derive per-point cover from a visibility matrix NPZ.

    cover[i] = 1.0 - (visibility_count[i] / max(visibility_count))
    """
    data = np.load(str(vismatrix_path))
    point_positions = data["point_positions"]
    adj_index = data["adj_index"]  # [N, 2] — (start, count)

    visibility_count = adj_index[:, 1].astype(np.int32)
    max_count = int(visibility_count.max()) if len(visibility_count) > 0 else 1

    cover = 1.0 - (visibility_count.astype(np.float32) / max(max_count, 1))

    log.info(
        "Influence: %d points, vis_count min=%d median=%d max=%d, "
        "cover min=%.2f median=%.2f max=%.2f",
        len(point_positions),
        int(visibility_count.min()), int(np.median(visibility_count)), max_count,
        float(cover.min()), float(np.median(cover)), float(cover.max()),
    )

    return InfluenceResult(
        point_positions=point_positions,
        cover=cover,
        visibility_count=visibility_count,
    )
