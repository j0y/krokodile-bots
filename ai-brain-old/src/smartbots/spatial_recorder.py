"""Records bot positions and hull trace hits for spatial mapping."""

from __future__ import annotations

import logging
import math
from pathlib import Path

import duckdb
import numpy as np

log = logging.getLogger(__name__)

DEDUP_DIST = 5.0  # Only record when bot moves >5u from last recorded pos

# Lidar trace config — must match SM plugin constants
TRACE_DIRS = 24
TRACE_ANGLES = [i * 15.0 for i in range(TRACE_DIRS)]  # 0°..345° world yaw
TRACE_RANGE = 200.0
# Heights relative to bot feet — must match g_fTraceHeights in SM plugin
TRACE_HEIGHTS = [8.0, 32.0]  # foot (z-8..z+24 with hull), waist (z+16..z+48 with hull)
TRACE_TOTAL = TRACE_DIRS * len(TRACE_HEIGHTS)  # 48

# Voxel grid config
VOXEL_SIZE = 32.0
VOXEL_UNKNOWN: np.uint8 = np.uint8(0)
VOXEL_EMPTY: np.uint8 = np.uint8(1)
VOXEL_SOLID: np.uint8 = np.uint8(2)

# Initial grid dimensions (will grow dynamically)
_INIT_CELLS = 128


class SpatialRecorder:
    """Accumulates walkable (x,y,z) points and hull trace hits into a voxel grid."""

    def __init__(self, map_name: str, data_dir: str = "/app/data") -> None:
        self._map_name = map_name
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._data_dir / f"{map_name}_traces.duckdb"
        self._collision_path = self._data_dir / f"{map_name}_collision.npz"

        self._db = duckdb.connect(":memory:")
        self._db.execute("CREATE TABLE traces (x REAL, y REAL, z REAL)")

        self._last_pos: dict[int, tuple[float, float, float]] = {}
        self._buffer: list[tuple[float, float, float]] = []
        self._total_rows = 0

        # Voxel grid — load existing or start fresh
        self._trace_hits = 0
        if self._collision_path.exists():
            prev = np.load(self._collision_path)
            self._grid = prev["grid"].copy()
            self._origin = prev["origin"].copy()
            self._origin_set = True
            prev_solid = int(np.sum(self._grid == VOXEL_SOLID))
            prev_empty = int(np.sum(self._grid == VOXEL_EMPTY))
            log.info(
                "SpatialRecorder: loaded existing grid %s shape=%s solid=%d empty=%d",
                self._collision_path, self._grid.shape, prev_solid, prev_empty,
            )
        else:
            self._grid = np.zeros(
                (_INIT_CELLS, _INIT_CELLS, _INIT_CELLS), dtype=np.uint8
            )
            self._origin = np.array([0.0, 0.0, 0.0])
            self._origin_set = False

        log.info("SpatialRecorder: in-memory DB ready, will save to %s", self._db_path)
        log.info("SpatialRecorder: collision grid will save to %s", self._collision_path)

    # ── Position recording (unchanged) ──

    def record(self, bot_id: int, pos: tuple[float, float, float]) -> None:
        last = self._last_pos.get(bot_id)
        if last is not None:
            dx = pos[0] - last[0]
            dy = pos[1] - last[1]
            dz = pos[2] - last[2]
            if math.sqrt(dx * dx + dy * dy + dz * dz) < DEDUP_DIST:
                return
        self._last_pos[bot_id] = pos
        self._buffer.append((round(pos[0], 1), round(pos[1], 1), round(pos[2], 1)))
        if len(self._buffer) >= 1000:
            self._flush_to_memory()

    # ── Trace recording → voxel grid ──

    def record_traces(
        self, bot_id: int, pos: tuple[float, float, float], traces: list[float],
    ) -> None:
        """Record hull trace results into the voxel grid.

        pos is the bot's feet position. Traces layout: [height0_dir0..dir23, height1_dir0..dir23].
        """
        if len(traces) != TRACE_TOTAL:
            return

        start_x = pos[0]
        start_y = pos[1]

        idx = 0
        for height in TRACE_HEIGHTS:
            start_z = pos[2] + height

            # Mark bot position as empty at this height
            self._set_voxel(start_x, start_y, start_z, VOXEL_EMPTY)

            for angle in TRACE_ANGLES:
                frac = traces[idx]
                idx += 1

                rad = math.radians(angle)
                dir_x = math.cos(rad)
                dir_y = math.sin(rad)

                if frac < 1.0:
                    # Hit: mark hit voxel as solid
                    hit_x = start_x + frac * TRACE_RANGE * dir_x
                    hit_y = start_y + frac * TRACE_RANGE * dir_y
                    self._set_voxel(hit_x, hit_y, start_z, VOXEL_SOLID)
                    self._trace_hits += 1

                # Mark voxels along the ray before the hit as empty
                ray_len = frac * TRACE_RANGE
                steps = int(ray_len / VOXEL_SIZE)
                for s in range(1, steps):
                    d = s * VOXEL_SIZE
                    ex = start_x + d * dir_x
                    ey = start_y + d * dir_y
                    self._set_voxel(ex, ey, start_z, VOXEL_EMPTY)

    def _world_to_grid(self, x: float, y: float, z: float) -> tuple[int, int, int]:
        """Convert world coordinates to grid indices, growing grid if needed."""
        if not self._origin_set:
            # Center the grid around the first point
            half = (_INIT_CELLS // 2) * VOXEL_SIZE
            self._origin[0] = x - half
            self._origin[1] = y - half
            self._origin[2] = z - half
            self._origin_set = True

        ix = int((x - self._origin[0]) / VOXEL_SIZE)
        iy = int((y - self._origin[1]) / VOXEL_SIZE)
        iz = int((z - self._origin[2]) / VOXEL_SIZE)

        # Grow grid if out of bounds
        shape = self._grid.shape
        if (
            ix < 0 or iy < 0 or iz < 0
            or ix >= shape[0] or iy >= shape[1] or iz >= shape[2]
        ):
            self._grow_grid(ix, iy, iz)
            # Recalculate after growth (origin may have shifted)
            ix = int((x - self._origin[0]) / VOXEL_SIZE)
            iy = int((y - self._origin[1]) / VOXEL_SIZE)
            iz = int((z - self._origin[2]) / VOXEL_SIZE)

        return (ix, iy, iz)

    def _grow_grid(self, ix: int, iy: int, iz: int) -> None:
        """Expand grid to include the given indices."""
        shape = self._grid.shape
        # Determine padding needed on each side
        pad_neg = [0, 0, 0]
        pad_pos = [0, 0, 0]
        for dim, idx, sz in [(0, ix, shape[0]), (1, iy, shape[1]), (2, iz, shape[2])]:
            if idx < 0:
                pad_neg[dim] = -idx + 32  # extra margin
            if idx >= sz:
                pad_pos[dim] = idx - sz + 33  # extra margin

        if any(p > 0 for p in pad_neg) or any(p > 0 for p in pad_pos):
            self._grid = np.pad(
                self._grid,
                [(pad_neg[0], pad_pos[0]), (pad_neg[1], pad_pos[1]), (pad_neg[2], pad_pos[2])],
                mode="constant",
                constant_values=0,
            )
            # Adjust origin for negative padding
            self._origin[0] -= pad_neg[0] * VOXEL_SIZE
            self._origin[1] -= pad_neg[1] * VOXEL_SIZE
            self._origin[2] -= pad_neg[2] * VOXEL_SIZE
            log.info(
                "Grid grew to %s (origin=%.0f,%.0f,%.0f)",
                self._grid.shape, self._origin[0], self._origin[1], self._origin[2],
            )

    def _set_voxel(self, x: float, y: float, z: float, value: np.uint8) -> None:
        """Set a voxel value. Solid takes priority over empty."""
        ix, iy, iz = self._world_to_grid(x, y, z)
        current = self._grid[ix, iy, iz]
        if value == VOXEL_SOLID or current == VOXEL_UNKNOWN:
            self._grid[ix, iy, iz] = value

    # ── Persistence ──

    def maybe_save(self, tick: int) -> None:
        pass

    def save(self) -> None:
        """Flush buffer to memory DB, then export everything to disk."""
        self._flush_to_memory()

        # Save position traces to DuckDB
        if self._total_rows > 0:
            try:
                self._db.execute(f"ATTACH '{self._db_path}' AS disk")
                self._db.execute(
                    "CREATE TABLE IF NOT EXISTS disk.traces (x REAL, y REAL, z REAL)"
                )
                self._db.execute("INSERT INTO disk.traces SELECT * FROM traces")
                count = self._db.execute(
                    "SELECT COUNT(*) FROM disk.traces"
                ).fetchone()[0]  # type: ignore[index]
                self._db.execute("DETACH disk")
                log.info(
                    "Saved %d new rows to %s (%d total on disk)",
                    self._total_rows, self._db_path, count,
                )
            except Exception:
                log.exception("Failed to save traces to disk")

        # Save collision voxel grid
        if self._trace_hits > 0:
            # Trim grid to non-zero bounding box to save space
            nonzero = np.argwhere(self._grid > 0)
            if len(nonzero) > 0:
                mins = nonzero.min(axis=0)
                maxs = nonzero.max(axis=0) + 1
                trimmed = self._grid[mins[0]:maxs[0], mins[1]:maxs[1], mins[2]:maxs[2]]
                trim_origin = np.array([
                    self._origin[0] + mins[0] * VOXEL_SIZE,
                    self._origin[1] + mins[1] * VOXEL_SIZE,
                    self._origin[2] + mins[2] * VOXEL_SIZE,
                ])
                np.savez_compressed(
                    self._collision_path,
                    grid=trimmed,
                    origin=trim_origin,
                    voxel_size=np.float64(VOXEL_SIZE),
                )
                solid_count = int(np.sum(trimmed == VOXEL_SOLID))
                empty_count = int(np.sum(trimmed == VOXEL_EMPTY))
                log.info(
                    "Saved collision grid %s: shape=%s solid=%d empty=%d hits=%d",
                    self._collision_path, trimmed.shape, solid_count, empty_count,
                    self._trace_hits,
                )
            else:
                log.info("No non-zero voxels to save")
        else:
            log.info("No trace hits recorded, skipping collision grid save")

    def _flush_to_memory(self) -> None:
        if not self._buffer:
            return
        self._db.executemany("INSERT INTO traces VALUES (?, ?, ?)", self._buffer)
        self._total_rows += len(self._buffer)
        self._buffer.clear()
