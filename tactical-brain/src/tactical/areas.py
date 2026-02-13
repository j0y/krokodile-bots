"""Fuzzy tactical areas: objectives + room clusters with soft boundaries.

Objectives (from *_objectives.json) define capture/destroy points and spawns.
Clusters (from *_clusters.json) define room-like regions detected from BSP
wall geometry and nav mesh adjacency.

Each area has a center, radius, and falloff distance. Grid points within
the radius get weight 1.0; between radius and radius+falloff they linearly
decay to 0.0. Areas can be combined (union via max) or subtracted.
"""

from __future__ import annotations

import json
import logging
import math
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from scipy.spatial import KDTree

log = logging.getLogger(__name__)

VALID_ROLES = frozenset({"", "zone", "enemy_spawn", "enemy_approach", "objective"})


@dataclass(frozen=True, slots=True)
class AreaDef:
    name: str
    center: tuple[float, float, float]
    radius: float
    falloff: float
    role: str  # "" | "zone" | "enemy_spawn" | "enemy_approach" | "objective"
    order: int  # objective sequence (1-based), 0 for non-objectives
    obj_type: str  # "destroy" | "capture" | "" for non-objectives


class AreaMap:
    """Pre-computed fuzzy area weights over influence-map grid points."""

    def __init__(
        self,
        objectives_path: str,
        clusters_path: str | None,
        points: np.ndarray,
        concealment: np.ndarray,
        tree: KDTree,
    ) -> None:
        self.areas: dict[str, AreaDef] = {}
        self.zones: dict[str, AreaDef] = {}  # zone-only subset (clusters)
        self._weights: dict[str, np.ndarray] = {}
        self._points = points
        self._concealment = concealment
        self._tree = tree
        self._zone_centroids: np.ndarray | None = None  # Kx3 centroid array
        self._zone_names: list[str] = []  # parallel to _zone_centroids rows

        # Load objectives
        raw = json.loads(Path(objectives_path).read_text())
        for name, defn in raw.items():
            self._load_area(name, defn)

        # Load clusters (room-like regions from BSP wall detection)
        cluster_adjacency: dict[str, list[str]] = {}
        if clusters_path and Path(clusters_path).exists():
            raw_clusters = json.loads(Path(clusters_path).read_text())
            centroids: list[list[float]] = []
            for name, defn in raw_clusters.items():
                center = tuple(defn["centroid"])
                radius = float(defn.get("radius", 400))
                falloff = radius * 0.5
                area = AreaDef(
                    name=name,
                    center=(center[0], center[1], center[2]),
                    radius=radius,
                    falloff=falloff,
                    role="zone",
                    order=0,
                    obj_type="",
                )
                self.areas[name] = area
                self.zones[name] = area
                self._compute_weights(name, center, radius, falloff)
                centroids.append(list(center))
                self._zone_names.append(name)
                if "adjacent" in defn:
                    cluster_adjacency[name] = defn["adjacent"]
            if centroids:
                self._zone_centroids = np.array(centroids, dtype=np.float32)
            log.info("Loaded %d clusters from %s", len(self.zones), clusters_path)

        # Build adjacency graph from cluster doorway connections
        self._adjacency: dict[str, list[str]] = {name: [] for name in self.areas}
        if cluster_adjacency:
            # Use pre-computed adjacency from clustering (nav mesh doorway edges)
            for name, neighbors in cluster_adjacency.items():
                self._adjacency[name] = [n for n in neighbors if n in self.areas]
            # Connect objectives/spawns to their containing room + room's neighbors
            for name, area in self.areas.items():
                if area.role != "zone" and self._zone_centroids is not None:
                    zone = self.pos_to_zone(area.center)
                    if zone:
                        # Objective gets its room + room's neighbors
                        room_neighbors = cluster_adjacency.get(zone, [])
                        self._adjacency[name] = [zone] + [
                            n for n in room_neighbors if n in self.areas
                        ]
                        self._adjacency[zone].append(name)
        else:
            # Fallback: weight overlap (for maps without clusters)
            names = list(self.areas)
            for i, a in enumerate(names):
                wa = self._weights[a]
                for b in names[i + 1:]:
                    if np.any((wa > 0) & (self._weights[b] > 0)):
                        self._adjacency[a].append(b)
                        self._adjacency[b].append(a)

        log.info("AreaMap loaded: %d objectives + %d zones",
                 len(self.areas) - len(self.zones), len(self.zones))

    def _load_area(self, name: str, defn: dict) -> None:
        center = tuple(defn["center"])
        radius = float(defn["radius"])
        falloff = float(defn.get("falloff", 200.0))
        role = defn.get("role", "")
        if role not in VALID_ROLES:
            log.warning("Area '%s': unknown role '%s', ignoring", name, role)
            role = ""

        area = AreaDef(
            name=name,
            center=(center[0], center[1], center[2]),
            radius=radius,
            falloff=falloff,
            role=role,
            order=int(defn.get("order", 0)),
            obj_type=defn.get("type", ""),
        )
        self.areas[name] = area
        self._compute_weights(name, center, radius, falloff)

    def _compute_weights(self, name: str, center: tuple, radius: float, falloff: float) -> None:
        dists = np.linalg.norm(
            self._points - np.array(center, dtype=np.float32), axis=1,
        )
        w = np.zeros(len(self._points), dtype=np.float32)
        inner = dists <= radius
        w[inner] = 1.0
        if falloff > 0:
            falloff_mask = (dists > radius) & (dists <= radius + falloff)
            w[falloff_mask] = 1.0 - (dists[falloff_mask] - radius) / falloff
        self._weights[name] = w

    def build_mask(self, area_names: list[str]) -> np.ndarray:
        """Combine areas into a [N] float32 mask (0.0-1.0).

        Names without '-' prefix are unioned (max). Names with '-' prefix
        are subtracted (multiply by 1 - weight).
        """
        n = len(self._points)
        positives: list[str] = []
        negatives: list[str] = []

        for name in area_names:
            if name.startswith("-"):
                negatives.append(name[1:])
            else:
                positives.append(name)

        # Union of positives
        mask = np.zeros(n, dtype=np.float32)
        for name in positives:
            w = self._weights.get(name)
            if w is None:
                log.warning("build_mask: unknown area '%s', skipping", name)
                continue
            np.maximum(mask, w, out=mask)

        # Subtraction
        for name in negatives:
            w = self._weights.get(name)
            if w is None:
                log.warning("build_mask: unknown area '-%s', skipping", name)
                continue
            mask *= 1.0 - w

        return mask

    def area_centroid(self, area_names: list[str]) -> tuple[float, float, float]:
        """Weighted centroid of combined positive areas."""
        mask = self.build_mask([n for n in area_names if not n.startswith("-")])
        total = mask.sum()
        if total < 1e-6:
            # Fallback: average of area definition centers
            centers = [
                self.areas[n].center for n in area_names
                if not n.startswith("-") and n in self.areas
            ]
            if centers:
                arr = np.array(centers)
                c = arr.mean(axis=0)
                return (float(c[0]), float(c[1]), float(c[2]))
            return (0.0, 0.0, 0.0)

        weighted = self._points * mask[:, np.newaxis]
        centroid = weighted.sum(axis=0) / total
        return (float(centroid[0]), float(centroid[1]), float(centroid[2]))

    def _bfs_path(self, start: str, end: str) -> list[str] | None:
        """Shortest path between two areas via adjacency graph."""
        if start == end:
            return [start]
        visited = {start}
        queue: deque[list[str]] = deque([[start]])
        while queue:
            path = queue.popleft()
            for neighbor in self._adjacency[path[-1]]:
                if neighbor == end:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])
        return None

    def describe(self) -> str:
        """Auto-generated map briefing for LLM system prompt."""
        # Objective sequence
        obj_areas = sorted(
            [(a.order, a) for a in self.areas.values() if a.order > 0],
            key=lambda t: t[0],
        )
        lines: list[str] = []
        if obj_areas:
            parts: list[str] = []
            for _, a in obj_areas:
                zone = self.pos_to_zone(a.center)
                zone_str = f" [{zone}]" if zone else ""
                parts.append(f"{a.name} ({a.obj_type}{zone_str})")
            seq = " -> ".join(parts)
            lines.append(f"OBJECTIVE SEQUENCE (attackers complete in order): {seq}")
            lines.append("Threat comes from the direction of previously completed objectives.")
            lines.append("")

        # Zone descriptions
        if self.zones:
            lines.append("MAP ZONES (named regions):")
            for name, zone in self.zones.items():
                w = self._weights[name]
                nonzero = w > 0
                count = int(nonzero.sum())
                if count == 0:
                    continue
                avg_cover = float(self._concealment[nonzero].mean())
                cover_label = "Low" if avg_cover < 0.33 else "Moderate" if avg_cover < 0.66 else "High"
                avg_z = float(self._points[nonzero, 2].mean())
                elev_label = "low" if avg_z < -100 else "high" if avg_z > 100 else "mid"
                adj = [n for n in self._adjacency.get(name, []) if n in self.zones]
                adj_str = f". Adjacent: {', '.join(adj)}" if adj else ""
                lines.append(
                    f"- {name}: {cover_label} cover, {elev_label} elevation{adj_str}"
                )
            lines.append("")

        # Objective descriptions (non-zone areas)
        lines.append("OBJECTIVES AND TACTICAL AREAS:")
        for name, area in self.areas.items():
            if area.role == "zone":
                continue
            w = self._weights[name]
            nonzero = w > 0
            count = int(nonzero.sum())
            if count == 0:
                continue

            avg_cover = float(self._concealment[nonzero].mean())
            cover_label = "Low" if avg_cover < 0.33 else "Moderate" if avg_cover < 0.66 else "High"

            avg_z = float(self._points[nonzero, 2].mean())
            elev_label = "low" if avg_z < -100 else "high" if avg_z > 100 else "mid"

            size_label = "small" if count < 100 else "large" if count > 500 else "medium"

            role_prefix = ""
            if area.role == "enemy_spawn":
                role_prefix = "[ENEMY SPAWN] "
            elif area.role == "enemy_approach":
                role_prefix = "[ENEMY APPROACH] "
            elif area.role == "objective":
                type_tag = area.obj_type.upper() if area.obj_type else "OBJ"
                role_prefix = f"[{type_tag} #{area.order}] "

            zone = self.pos_to_zone(area.center)
            zone_str = f" (in {zone})" if zone else ""

            adj = self._adjacency.get(name, [])
            adj_str = f". Adjacent to: {', '.join(adj)}" if adj else ""
            lines.append(
                f"- {name}:{zone_str} {role_prefix}{cover_label} cover, "
                f"{elev_label} elevation, {size_label}{adj_str}"
            )

        # Attack routes from enemy spawn to each objective
        spawns = [a.name for a in self.areas.values() if a.role == "enemy_spawn"]
        if spawns and obj_areas:
            lines.append("")
            lines.append("ATTACK ROUTES (from enemy spawn to each objective):")
            for _, obj in obj_areas:
                for spawn in spawns:
                    path = self._bfs_path(spawn, obj.name)
                    if path and len(path) > 1:
                        lines.append(f"- {obj.name}: {' -> '.join(path)}")

        return "\n".join(lines)

    def pos_to_zone(self, pos: tuple[float, float, float]) -> str | None:
        """Map a world position to the nearest zone (cluster) by centroid distance.

        Uses 2D (XY) nearest-neighbor against cluster centroids.
        Returns None if no clusters are loaded.
        """
        if self._zone_centroids is None:
            return None
        pos_2d = np.array([pos[0], pos[1]], dtype=np.float32)
        dists = np.linalg.norm(self._zone_centroids[:, :2] - pos_2d, axis=1)
        idx = int(np.argmin(dists))
        return self._zone_names[idx]

    def pos_to_area(self, pos: tuple[float, float, float]) -> str | None:
        """Map a world position to the best-matching area name, or None.

        Prefers zone names (more descriptive) over objective names.
        Falls back to objective/spawn areas if no zone matches.
        """
        # Try zone labeling first (nearest-neighbor)
        zone = self.pos_to_zone(pos)
        if zone:
            return zone

        # Fallback to weight-based matching (objectives/spawns)
        if not self.areas:
            return None
        _, idx = self._tree.query(pos)
        idx = int(idx)
        best_name = ""
        best_w = 0.0
        for name, w in self._weights.items():
            if w[idx] > best_w:
                best_w = w[idx]
                best_name = name
        return best_name if best_name and best_w > 0 else None

    def enemies_per_area(
        self,
        enemy_positions: list[tuple[float, float, float]],
    ) -> dict[str, int]:
        """Count enemies per area.

        Uses zone labels when available for more descriptive reporting.
        """
        counts: dict[str, int] = {}
        if not enemy_positions or not self.areas:
            return counts

        for epos in enemy_positions:
            area_name = self.pos_to_area(epos)
            if area_name:
                counts[area_name] = counts.get(area_name, 0) + 1

        return counts
