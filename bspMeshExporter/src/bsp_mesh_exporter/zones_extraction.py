"""Extract named zones from BSP soundscape entities.

Source Engine maps define audio zones via env_soundscape + env_soundscape_proxy
entities.  Each soundscape has a descriptive name (e.g. "lobby", "garage",
"tunnel") and a set of positions that define its spatial extent.

This module extracts those zones and can label arbitrary world positions
with the nearest zone name using Voronoi (nearest-neighbor) assignment.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class Zone:
    name: str
    positions: list[tuple[float, float, float]] = field(default_factory=list)

    @property
    def centroid(self) -> tuple[float, float, float]:
        if not self.positions:
            return (0.0, 0.0, 0.0)
        n = len(self.positions)
        return (
            sum(p[0] for p in self.positions) / n,
            sum(p[1] for p in self.positions) / n,
            sum(p[2] for p in self.positions) / n,
        )


def _parse_origin(origin_str: str) -> tuple[float, float, float]:
    parts = origin_str.split()
    return (float(parts[0]), float(parts[1]), float(parts[2]))


def _dist_2d(a: tuple[float, float, float], b: tuple[float, float, float]) -> float:
    """2D (XY) distance — vertical separation ignored for zone assignment."""
    return math.sqrt((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2)


def _clean_name(raw: str) -> str:
    """Strip common prefixes to get a human-readable zone label."""
    name = raw
    for prefix in ("soundscape_", "soundscae_"):  # typo in revolt_coop
        if name.startswith(prefix):
            name = name[len(prefix):]
    # Strip map-specific prefixes like "heights_", "ir.ministry_"
    if name.startswith("ir."):
        name = name[3:]
    return name


def extract_zones(bsp_path: str | Path) -> dict[str, Zone]:
    """Extract named zones from BSP soundscape entities.

    Returns a dict mapping cleaned zone names to Zone objects.
    """
    import bsp_tool
    from bsp_tool.branches.valve import sdk_2013

    bsp_path = Path(bsp_path)
    log.info("Extracting zones from %s", bsp_path)
    bsp = bsp_tool.load_bsp(str(bsp_path), force_branch=sdk_2013)
    ents = bsp.ENTITIES

    # Collect env_soundscape entities (main zone anchors)
    zones: dict[str, Zone] = {}
    # Map targetname → cleaned name for proxy lookup
    targetname_to_zone: dict[str, str] = {}

    for e in ents:
        if e.get("classname") != "env_soundscape":
            continue
        targetname = e.get("targetname", "")
        if not targetname:
            continue
        origin = e.get("origin")
        if not origin:
            continue

        name = _clean_name(targetname)
        targetname_to_zone[targetname] = name

        if name not in zones:
            zones[name] = Zone(name=name)
        zones[name].positions.append(_parse_origin(origin))

    # Collect env_soundscape_proxy entities (zone extent markers)
    for e in ents:
        if e.get("classname") != "env_soundscape_proxy":
            continue
        parent = e.get("MainSoundscapeName", "")
        origin = e.get("origin")
        if not parent or not origin:
            continue

        name = targetname_to_zone.get(parent)
        if name is None:
            # Try cleaning the parent name directly
            name = _clean_name(parent)
        if name not in zones:
            zones[name] = Zone(name=name)
        zones[name].positions.append(_parse_origin(origin))

    log.info("Extracted %d zones with %d total positions",
             len(zones), sum(len(z.positions) for z in zones.values()))
    return zones


def label_position(
    pos: tuple[float, float, float],
    zones: dict[str, Zone],
) -> str | None:
    """Find the nearest zone name for a given world position (2D distance)."""
    best_name: str | None = None
    best_dist = float("inf")

    for zone in zones.values():
        for zp in zone.positions:
            d = _dist_2d(pos, zp)
            if d < best_dist:
                best_dist = d
                best_name = zone.name

    return best_name


def zones_to_dict(zones: dict[str, Zone]) -> dict[str, Any]:
    """Convert zones to a JSON-serializable dict.

    Each zone includes centroid, radius (max 2D distance from centroid to any
    marker), and marker positions for nearest-neighbor assignment.
    """
    result: dict[str, Any] = {}
    for name, z in sorted(zones.items()):
        c = z.centroid
        # Radius = max 2D distance from centroid to any marker
        radius = max((_dist_2d(c, p) for p in z.positions), default=200.0)
        radius = max(radius, 200.0)  # minimum radius
        result[name] = {
            "centroid": [round(c[0]), round(c[1]), round(c[2])],
            "radius": round(radius),
            "markers": [
                [round(p[0]), round(p[1]), round(p[2])] for p in z.positions
            ],
        }
    return result
