"""Flow-based nav mesh segmentation.

Agglomerative clustering: starts with each nav area as its own segment,
then repeatedly merges the pair of adjacent segments connected by the
widest total opening (sum of shared-edge widths across all boundary
connections).  Stops when remaining boundaries are narrow (doorways).

Doorways have low aggregate boundary width (1-3 narrow edges ≈ 50-100u).
Room interiors have high aggregate boundary width (many parallel edges ≈ 200u+).

After merging, segments are ordered by Dijkstra distance from enemy spawn.

Usage:
    python cluster_nav.py <map.nav> --objectives obj.json [-o output.json]
    python cluster_nav.py --batch --nav-dir DIR --data-dir DIR
"""

from __future__ import annotations

import argparse
import heapq
import json
import math
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

from parse_nav import NavArea, NavMesh, parse_nav

# ── Thresholds ─────────────────────────────────────────────────────

MERGE_THRESHOLD = 120.0  # stop merging when widest boundary < this (units)
MIN_SEGMENT = 5          # merge segments with fewer areas into neighbors
BRIDGE_MAX_DIST = 500.0  # max distance to bridge disconnected nav components


# ── Helpers ────────────────────────────────────────────────────────

def nearest_area(mesh: NavMesh, pos: tuple[float, float, float]) -> int:
    """Find the nav area whose center is closest to *pos* (2D)."""
    px, py = pos[0], pos[1]
    best_id = -1
    best_d2 = float("inf")
    for aid, area in mesh.areas.items():
        c = area.center()
        d2 = (c.x - px) ** 2 + (c.y - py) ** 2
        if d2 < best_d2:
            best_d2 = d2
            best_id = aid
    return best_id


def find_nav_components(mesh: NavMesh) -> list[set[int]]:
    """Find connected components of the nav mesh graph."""
    remaining = set(mesh.areas.keys())
    components: list[set[int]] = []
    while remaining:
        start = next(iter(remaining))
        visited: set[int] = set()
        queue = deque([start])
        visited.add(start)
        while queue:
            aid = queue.popleft()
            for nid in mesh.areas[aid].neighbor_ids():
                if nid in remaining and nid not in visited:
                    visited.add(nid)
                    queue.append(nid)
        components.append(visited)
        remaining -= visited
    components.sort(key=len, reverse=True)
    return components


def bridge_components(
    mesh: NavMesh, max_dist: float = BRIDGE_MAX_DIST,
) -> list[tuple[int, int]]:
    """Find nearest area pairs between disconnected nav components."""
    components = find_nav_components(mesh)
    if len(components) <= 1:
        return []

    bridges: list[tuple[int, int]] = []
    main_comp = components[0]
    main_centers = {
        aid: (mesh.areas[aid].center().x, mesh.areas[aid].center().y)
        for aid in main_comp
    }

    for comp in components[1:]:
        best_d2 = max_dist * max_dist
        best_pair: tuple[int, int] | None = None
        for aid in comp:
            ac = mesh.areas[aid].center()
            for mid, (mx, my) in main_centers.items():
                d2 = (ac.x - mx) ** 2 + (ac.y - my) ** 2
                if d2 < best_d2:
                    best_d2 = d2
                    best_pair = (aid, mid)
        if best_pair is not None:
            bridges.append(best_pair)

    return bridges


def dijkstra(
    mesh: NavMesh,
    start: int,
    extra_edges: list[tuple[int, int]] | None = None,
) -> dict[int, float]:
    """Shortest-path distances from *start*."""
    extra_adj: dict[int, list[int]] = defaultdict(list)
    if extra_edges:
        for a, b in extra_edges:
            extra_adj[a].append(b)
            extra_adj[b].append(a)

    dist: dict[int, float] = {start: 0.0}
    heap = [(0.0, start)]
    while heap:
        d, aid = heapq.heappop(heap)
        if d > dist.get(aid, float("inf")):
            continue
        area = mesh.areas[aid]
        ac = area.center()
        neighbors = list(area.neighbor_ids())
        if aid in extra_adj:
            neighbors.extend(extra_adj[aid])
        for nid in neighbors:
            if nid not in mesh.areas:
                continue
            nc = mesh.areas[nid].center()
            edge_len = (
                (ac.x - nc.x) ** 2 + (ac.y - nc.y) ** 2 + (ac.z - nc.z) ** 2
            ) ** 0.5
            new_d = d + edge_len
            if new_d < dist.get(nid, float("inf")):
                dist[nid] = new_d
                heapq.heappush(heap, (new_d, nid))
    return dist


def connection_width(area_a: NavArea, area_b: NavArea, dir_from_a: int) -> float:
    """Shared-edge overlap between two adjacent nav areas.

    dir_from_a: 0=N, 1=E, 2=S, 3=W (which side of area_a faces area_b).
    In Source engine nav meshes: nw = (min_x, min_y), se = (max_x, max_y).
    """
    if dir_from_a in (0, 2):  # N or S → overlap along X
        return max(
            0.0,
            min(area_a.se.x, area_b.se.x) - max(area_a.nw.x, area_b.nw.x),
        )
    else:  # E or W → overlap along Y
        return max(
            0.0,
            min(area_a.se.y, area_b.se.y) - max(area_a.nw.y, area_b.nw.y),
        )


def load_spawn_pos(objectives_path: Path) -> tuple[float, float, float] | None:
    """Read enemy spawn position from objectives JSON."""
    data = json.loads(objectives_path.read_text())
    for name, obj in data.items():
        if obj.get("role") == "enemy_spawn":
            c = obj["center"]
            return (c[0], c[1], c[2])
    for name, obj in data.items():
        if obj.get("role") == "enemy_approach":
            c = obj["center"]
            return (c[0], c[1], c[2])
    return None


# ── Agglomerative segmentation ─────────────────────────────────────

@dataclass
class Segment:
    name: str
    area_ids: list[int]
    centroid: tuple[float, float, float]


def agglomerative_segment(
    mesh: NavMesh,
    threshold: float = MERGE_THRESHOLD,
    min_segment: int = MIN_SEGMENT,
) -> list[list[int]]:
    """Segment nav areas by agglomerative merging.

    Merges adjacent area-clusters connected by wide openings (high
    aggregate boundary width).  Stops when remaining boundaries are
    narrow (doorways/chokepoints).
    """
    # ── Compute connection widths ──────────────────────────────────
    edge_widths: dict[tuple[int, int], float] = {}
    seen: set[tuple[int, int]] = set()
    for aid, area in mesh.areas.items():
        for dir_idx, connected_ids in enumerate(area.connections):
            for nid in connected_ids:
                if nid not in mesh.areas:
                    continue
                key = (min(aid, nid), max(aid, nid))
                if key in seen:
                    continue
                seen.add(key)
                edge_widths[key] = connection_width(area, mesh.areas[nid], dir_idx)

    # ── Initialize clusters ────────────────────────────────────────
    cluster_of: dict[int, int] = {aid: aid for aid in mesh.areas}
    cluster_areas: dict[int, set[int]] = {aid: {aid} for aid in mesh.areas}

    # Boundary width: for each pair of adjacent clusters, the total
    # shared-edge width across all connections between them.
    # neighbors[c] = {other_cluster: total_boundary_width}
    neighbors: dict[int, dict[int, float]] = defaultdict(lambda: defaultdict(float))

    for (a, b), w in edge_widths.items():
        ca, cb = cluster_of[a], cluster_of[b]
        if ca != cb:
            neighbors[ca][cb] += w
            neighbors[cb][ca] += w

    # Max-heap of boundary widths (negate for min-heap)
    heap: list[tuple[float, int, int]] = []
    pushed: set[tuple[int, int]] = set()
    for c1, nbrs in neighbors.items():
        for c2, bw in nbrs.items():
            key = (min(c1, c2), max(c1, c2))
            if key not in pushed:
                pushed.add(key)
                heapq.heappush(heap, (-bw, key[0], key[1]))

    # ── Merge loop ─────────────────────────────────────────────────
    merge_count = 0
    while heap:
        neg_bw, c1, c2 = heapq.heappop(heap)
        bw = -neg_bw

        if bw < threshold:
            break

        # Validate: both clusters still exist and boundary is current
        if c1 not in cluster_areas or c2 not in cluster_areas:
            continue
        actual_bw = neighbors.get(c1, {}).get(c2, 0.0)
        if abs(actual_bw - bw) > 0.01:
            # Stale entry — re-push if still valid
            if actual_bw >= threshold:
                heapq.heappush(heap, (-actual_bw, min(c1, c2), max(c1, c2)))
            continue

        # Merge c2 into c1
        for aid in cluster_areas[c2]:
            cluster_of[aid] = c1
        cluster_areas[c1] |= cluster_areas[c2]
        del cluster_areas[c2]

        # Update neighbor boundaries
        for other, obw in list(neighbors[c2].items()):
            if other == c1:
                continue
            if other not in cluster_areas:
                continue
            # Transfer c2's boundary with 'other' to c1
            neighbors[c1][other] += obw
            neighbors[other][c1] += obw
            # Remove c2 from other's neighbors
            if c2 in neighbors[other]:
                del neighbors[other][c2]
            # Push updated boundary
            new_bw = neighbors[c1][other]
            heapq.heappush(heap, (-new_bw, min(c1, other), max(c1, other)))

        # Clean up c2
        del neighbors[c2]
        if c2 in neighbors[c1]:
            del neighbors[c1][c2]

        merge_count += 1

    print(f"  Merges: {merge_count}, clusters: {len(cluster_areas)}")

    # ── Collect clusters ───────────────────────────────────────────
    sorted_comps = sorted(cluster_areas.values(), key=len, reverse=True)

    # Merge small fragments into the large segment they share the
    # most nav mesh connections with (not nearest centroid).
    large: list[list[int]] = []
    small: list[list[int]] = []
    for comp in sorted_comps:
        comp_list = list(comp)
        if len(comp_list) >= min_segment:
            large.append(comp_list)
        else:
            small.append(comp_list)

    if large and small:
        # Build area → large-segment index
        area_to_large: dict[int, int] = {}
        for i, comp in enumerate(large):
            for aid in comp:
                area_to_large[aid] = i

        for frag in small:
            # Count nav mesh connections to each large segment
            conn_counts: dict[int, int] = defaultdict(int)
            for aid in frag:
                for nid in mesh.areas[aid].neighbor_ids():
                    if nid in area_to_large:
                        conn_counts[area_to_large[nid]] += 1

            if conn_counts:
                best_idx = max(conn_counts, key=conn_counts.get)
            else:
                # No connections to any large segment — fall back to nearest
                fx = sum(mesh.areas[a].center().x for a in frag) / len(frag)
                fy = sum(mesh.areas[a].center().y for a in frag) / len(frag)
                best_idx = 0
                best_d2 = float("inf")
                for i, comp in enumerate(large):
                    cx = sum(mesh.areas[a].center().x for a in comp) / len(comp)
                    cy = sum(mesh.areas[a].center().y for a in comp) / len(comp)
                    d2 = (fx - cx) ** 2 + (fy - cy) ** 2
                    if d2 < best_d2:
                        best_d2 = d2
                        best_idx = i

            large[best_idx].extend(frag)
            # Update lookup so subsequent fragments see merged areas
            for aid in frag:
                area_to_large[aid] = best_idx

    print(f"  Segments: {len(large)} (merged {len(small)} fragments)")
    return large


# ── Output ─────────────────────────────────────────────────────────

def compute_adjacency(
    segments: list[Segment], mesh: NavMesh,
) -> dict[str, list[str]]:
    """Compute which segments share nav mesh connections."""
    area_to_name: dict[int, str] = {}
    for seg in segments:
        for aid in seg.area_ids:
            area_to_name[aid] = seg.name

    adj: dict[str, set[str]] = {seg.name: set() for seg in segments}
    for aid, area in mesh.areas.items():
        sname = area_to_name.get(aid)
        if sname is None:
            continue
        for nid in area.neighbor_ids():
            nname = area_to_name.get(nid)
            if nname is not None and nname != sname:
                adj[sname].add(nname)
                adj[nname].add(sname)

    return {name: sorted(neighbors) for name, neighbors in adj.items()}


def segments_to_json(
    segments: list[Segment], mesh: NavMesh, adjacency: dict[str, list[str]],
) -> dict:
    """Convert segments to JSON format compatible with AreaMap."""
    result = {}
    for seg in segments:
        max_dist = 0.0
        for aid in seg.area_ids:
            c = mesh.areas[aid].center()
            d = ((c.x - seg.centroid[0]) ** 2 + (c.y - seg.centroid[1]) ** 2) ** 0.5
            if d > max_dist:
                max_dist = d

        result[seg.name] = {
            "centroid": [round(seg.centroid[0]), round(seg.centroid[1]), round(seg.centroid[2])],
            "radius": round(max_dist),
            "adjacent": adjacency.get(seg.name, []),
            "nav_area_ids": seg.area_ids,
            "nav_area_count": len(seg.area_ids),
        }
    return result


# ── CLI ────────────────────────────────────────────────────────────

def process_map(
    nav_path: Path,
    objectives_path: Path,
    output_path: Path,
) -> None:
    """Process a single map."""
    mesh = parse_nav(str(nav_path))
    print(f"  Parsed {len(mesh.areas)} nav areas")

    spawn_pos = load_spawn_pos(objectives_path)
    if spawn_pos is None:
        print(f"  ERROR: no enemy_spawn in {objectives_path}")
        return

    # Segment by agglomerative merging
    raw_segments = agglomerative_segment(mesh)

    # Order segments by Dijkstra distance from spawn
    bridges = bridge_components(mesh)
    spawn_aid = nearest_area(mesh, spawn_pos)
    dist = dijkstra(mesh, spawn_aid, extra_edges=bridges)

    raw_segments.sort(
        key=lambda comp: min(dist.get(a, float("inf")) for a in comp)
    )

    # Build Segment objects
    segments: list[Segment] = []
    for i, comp in enumerate(raw_segments):
        cx = sum(mesh.areas[a].center().x for a in comp) / len(comp)
        cy = sum(mesh.areas[a].center().y for a in comp) / len(comp)
        cz = sum(mesh.areas[a].center().z for a in comp) / len(comp)
        segments.append(Segment(
            name=f"seg_{i}",
            area_ids=sorted(comp),
            centroid=(round(cx, 1), round(cy, 1), round(cz, 1)),
        ))

    adjacency = compute_adjacency(segments, mesh)
    result = segments_to_json(segments, mesh, adjacency)
    output_path.write_text(json.dumps(result, indent=2) + "\n")
    print(f"  Wrote {output_path} ({len(result)} segments)")

    # Summary
    by_size = sorted(segments, key=lambda s: len(s.area_ids), reverse=True)
    for seg in by_size[:10]:
        adj_count = len(adjacency.get(seg.name, []))
        print(f"    {seg.name:20s} ({len(seg.area_ids):4d} areas, {adj_count} adj)")
    if len(segments) > 10:
        print(f"    ... and {len(segments) - 10} more")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Flow-based nav mesh segmentation"
    )
    parser.add_argument("nav_file", nargs="?", help="Path to .nav file")
    parser.add_argument("--objectives", help="Path to objectives JSON")
    parser.add_argument("-o", "--output", help="Output JSON path")
    parser.add_argument("--batch", action="store_true",
                        help="Process all maps found in --nav-dir")
    parser.add_argument("--nav-dir", help="Directory containing .nav files")
    parser.add_argument("--data-dir", help="Directory with objectives + output")
    args = parser.parse_args()

    if args.batch:
        if not args.nav_dir or not args.data_dir:
            parser.error("--batch requires --nav-dir and --data-dir")
        nav_dir = Path(args.nav_dir)
        data_dir = Path(args.data_dir)

        for nav_path in sorted(nav_dir.glob("*_coop.nav")):
            map_name = nav_path.stem
            obj_path = data_dir / f"{map_name}_objectives.json"
            output_path = data_dir / f"{map_name}_clusters.json"

            print(f"\n=== {map_name} ===")
            if not obj_path.exists():
                print(f"  Skipping: no objectives file")
                continue

            process_map(nav_path, obj_path, output_path)
    else:
        if not args.nav_file:
            parser.error("nav_file is required (or use --batch)")
        nav_path = Path(args.nav_file)
        if not args.objectives:
            parser.error("--objectives is required for single-map mode")
        obj_path = Path(args.objectives)
        output_path = (
            Path(args.output) if args.output
            else nav_path.with_name(nav_path.stem + "_clusters.json")
        )

        print(f"Processing {nav_path.name}")
        process_map(nav_path, obj_path, output_path)


if __name__ == "__main__":
    main()
