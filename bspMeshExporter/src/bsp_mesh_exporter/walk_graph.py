"""Precompute walk graph + coarse routing table from vismatrix.

Pipeline:
    1. Filter vismatrix edges to walk_radius → walk graph (walkable adjacency)
    2. Partition grid into cell_size spatial cells → coarse graph
    3. All-pairs shortest path → next-hop routing table (O(1) lookup)
    4. Compute door points for cell transitions (string-pull anchors)

Output: *_walkgraph.npz consumed by tactical-brain PathFinder at runtime.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import shortest_path

log = logging.getLogger(__name__)


@dataclass
class WalkGraphResult:
    """Walk graph + coarse routing precomputed data."""

    # Walk graph (fine grid)
    walk_adj_index: np.ndarray   # int32[N, 2] — (start, count)
    walk_adj_list: np.ndarray    # int32[M']
    walk_adj_dist: np.ndarray    # float32[M'] — edge distances

    # Coarse routing
    fine_to_coarse: np.ndarray   # uint16[N] — grid point → coarse cell
    coarse_centroids: np.ndarray  # float32[C, 3] — cell representative positions
    coarse_next_hop: np.ndarray  # int16[C, C] — all-pairs routing table

    # Door points (per-cell exit anchors)
    door_adj_index: np.ndarray   # int32[C, 2] — (start, count) into door arrays
    door_adj_list: np.ndarray    # int32[E] — target coarse cell IDs
    door_grid_points: np.ndarray  # int32[E] — fine grid point index for each door

    def save(self, path: str | Path) -> None:
        np.savez_compressed(
            str(path),
            walk_adj_index=self.walk_adj_index,
            walk_adj_list=self.walk_adj_list,
            walk_adj_dist=self.walk_adj_dist,
            fine_to_coarse=self.fine_to_coarse,
            coarse_centroids=self.coarse_centroids,
            coarse_next_hop=self.coarse_next_hop,
            door_adj_index=self.door_adj_index,
            door_adj_list=self.door_adj_list,
            door_grid_points=self.door_grid_points,
        )
        size = Path(path).stat().st_size
        log.info(
            "Saved walk graph: %d fine points, %d coarse cells, %.1f MB -> %s",
            len(self.fine_to_coarse), len(self.coarse_centroids), size / 1e6, path,
        )


def compute_walk_graph(
    vismatrix_path: str | Path,
    walk_radius: float = 100.0,
    cell_size: float = 256.0,
) -> WalkGraphResult:
    """Build walk graph + coarse routing table from a vismatrix."""

    log.info("Loading vismatrix from %s", vismatrix_path)
    vm = np.load(str(vismatrix_path))
    points = vm["point_positions"]   # [N, 3]
    adj_index = vm["adj_index"]      # [N, 2]
    adj_list = vm["adj_list"]        # [M]

    n = len(points)
    log.info("Vismatrix: %d points, %d visibility edges", n, len(adj_list))

    # ── Step 1: Filter visibility edges to walk radius ──────────────

    log.info("Building walk graph (radius=%.0f)...", walk_radius)

    counts = adj_index[:, 1]
    src_of_edge = np.repeat(np.arange(n, dtype=np.int32), counts)

    src_pos = points[src_of_edge]
    dst_pos = points[adj_list]
    edge_dists = np.linalg.norm(dst_pos - src_pos, axis=1).astype(np.float32)

    walk_mask = edge_dists <= walk_radius
    walk_src = src_of_edge[walk_mask]
    walk_dst = adj_list[walk_mask]
    walk_dist = edge_dists[walk_mask]

    # Rebuild adjacency index
    walk_counts = np.bincount(walk_src, minlength=n).astype(np.int32)
    walk_starts = np.zeros(n, dtype=np.int32)
    if n > 1:
        np.cumsum(walk_counts[:-1], out=walk_starts[1:])
    walk_adj_index = np.column_stack([walk_starts, walk_counts])

    connected = int(np.sum(walk_counts > 0))
    log.info("Walk graph: %d edges, %d/%d connected points", len(walk_dst), connected, n)

    # ── Step 2: Partition into coarse cells ─────────────────────────

    log.info("Partitioning into coarse cells (size=%.0f)...", cell_size)

    cell_xy = np.floor(points[:, :2] / cell_size).astype(np.int32)
    unique_cells, fine_to_coarse = np.unique(cell_xy, axis=0, return_inverse=True)
    fine_to_coarse = fine_to_coarse.astype(np.uint16)
    num_cells = len(unique_cells)

    # Cell centroids: mean position of fine points in each cell
    coarse_centroids = np.zeros((num_cells, 3), dtype=np.float32)
    for c in range(num_cells):
        mask = fine_to_coarse == c
        coarse_centroids[c] = points[mask].mean(axis=0)

    log.info("Coarse cells: %d", num_cells)

    # ── Step 3: Build coarse graph from walk edges ──────────────────

    walk_src_cells = fine_to_coarse[walk_src]
    walk_dst_cells = fine_to_coarse[walk_dst]
    cross_mask = walk_src_cells != walk_dst_cells

    cross_pairs = np.column_stack([
        walk_src_cells[cross_mask],
        walk_dst_cells[cross_mask],
    ])
    if len(cross_pairs) > 0:
        unique_pairs = np.unique(cross_pairs, axis=0)
    else:
        unique_pairs = np.empty((0, 2), dtype=np.uint16)

    rows, cols, weights = [], [], []
    for ci, cj in unique_pairs:
        dist = float(np.linalg.norm(coarse_centroids[ci] - coarse_centroids[cj]))
        rows.append(int(ci))
        cols.append(int(cj))
        weights.append(dist)

    coarse_graph = csr_matrix(
        (weights, (rows, cols)), shape=(num_cells, num_cells),
    )
    log.info("Coarse graph: %d directed edges", len(rows))

    # ── Step 4: All-pairs shortest path → next-hop table ───────────

    log.info("Computing all-pairs shortest path (%d cells)...", num_cells)
    dist_matrix, predecessors = shortest_path(
        coarse_graph, method='D', return_predecessors=True,
    )

    log.info("Deriving next-hop table...")
    next_hop = np.full((num_cells, num_cells), -1, dtype=np.int16)
    for i in range(num_cells):
        next_hop[i, i] = i
        for j in range(num_cells):
            if i == j:
                continue
            if predecessors[i, j] == -9999:
                continue
            # Trace back from j to find the cell right after i
            k = j
            while predecessors[i, k] != i:
                prev = predecessors[i, k]
                if prev == -9999:
                    k = -1
                    break
                k = prev
            next_hop[i, j] = k

    reachable = int(np.sum(next_hop >= 0)) - num_cells
    total = num_cells * (num_cells - 1)
    log.info(
        "Next-hop table: %d/%d reachable pairs (%.1f%%)",
        reachable, total, 100.0 * reachable / max(total, 1),
    )

    # ── Step 5: Door points ─────────────────────────────────────────

    log.info("Computing door points...")

    # For each coarse edge (a→b), find the fine point in cell a that:
    #   1. Has a walk edge to a point in cell b
    #   2. Is closest to cell b's centroid
    cross_src_fine = walk_src[cross_mask]
    cross_src_cells_arr = walk_src_cells[cross_mask]
    cross_dst_cells_arr = walk_dst_cells[cross_mask]

    door_list: list[list[tuple[int, int]]] = [[] for _ in range(num_cells)]

    for pair_idx in range(len(unique_pairs)):
        ci, cj = int(unique_pairs[pair_idx, 0]), int(unique_pairs[pair_idx, 1])
        pair_mask = (cross_src_cells_arr == ci) & (cross_dst_cells_arr == cj)
        candidate_fine = cross_src_fine[pair_mask]
        if len(candidate_fine) == 0:
            continue
        # Deduplicate candidates (multiple edges from same fine point)
        candidate_fine = np.unique(candidate_fine)
        dists = np.linalg.norm(
            points[candidate_fine] - coarse_centroids[cj], axis=1,
        )
        best = int(candidate_fine[np.argmin(dists)])
        door_list[ci].append((cj, best))

    # Pack door points into flat arrays
    door_adj_index = np.empty((num_cells, 2), dtype=np.int32)
    all_door_targets: list[int] = []
    all_door_points: list[int] = []
    for c in range(num_cells):
        door_adj_index[c, 0] = len(all_door_targets)
        door_adj_index[c, 1] = len(door_list[c])
        for target_cell, fine_point in door_list[c]:
            all_door_targets.append(target_cell)
            all_door_points.append(fine_point)

    door_adj_list_arr = (
        np.array(all_door_targets, dtype=np.int32)
        if all_door_targets else np.empty(0, dtype=np.int32)
    )
    door_grid_points = (
        np.array(all_door_points, dtype=np.int32)
        if all_door_points else np.empty(0, dtype=np.int32)
    )

    log.info("Door points: %d total", len(all_door_targets))

    return WalkGraphResult(
        walk_adj_index=walk_adj_index,
        walk_adj_list=walk_dst,
        walk_adj_dist=walk_dist,
        fine_to_coarse=fine_to_coarse,
        coarse_centroids=coarse_centroids,
        coarse_next_hop=next_hop,
        door_adj_index=door_adj_index,
        door_adj_list=door_adj_list_arr,
        door_grid_points=door_grid_points,
    )
