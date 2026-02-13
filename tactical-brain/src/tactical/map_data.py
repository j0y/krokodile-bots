"""Per-map preloaded data and map registry."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class MapData:
    """All preloaded data for a single map."""

    name: str
    influence_map: "InfluenceMap | None"
    area_map: "AreaMap | None"
    pathfinder: "PathFinder | None"


def discover_maps(data_dir: str) -> list[str]:
    """Scan data_dir for maps that have at least an objectives JSON."""
    d = Path(data_dir)
    maps: set[str] = set()
    for f in d.glob("*_objectives.json"):
        map_name = f.name.removesuffix("_objectives.json")
        maps.add(map_name)
    return sorted(maps)


def load_map(map_name: str, data_dir: str) -> MapData | None:
    """Load all data for a single map.

    Returns None if the vismatrix/influence files are missing (can't do
    tactical positioning without them).
    """
    from tactical.areas import AreaMap
    from tactical.influence_map import InfluenceMap

    d = Path(data_dir)

    vismatrix_path = d / f"{map_name}_vismatrix.npz"
    influence_path = d / f"{map_name}_influence.npz"
    objectives_path = d / f"{map_name}_objectives.json"
    clusters_path = d / f"{map_name}_clusters.json"
    walkgraph_path = d / f"{map_name}_walkgraph.npz"

    if not (vismatrix_path.exists() and influence_path.exists()):
        log.info("Map %s: no vismatrix/influence, skipping", map_name)
        return None

    influence_map = InfluenceMap(str(vismatrix_path), str(influence_path))

    area_map = None
    if objectives_path.exists():
        area_map = AreaMap(
            str(objectives_path),
            str(clusters_path) if clusters_path.exists() else None,
            influence_map.points,
            influence_map.concealment,
            influence_map.tree,
        )

    pathfinder = None
    if walkgraph_path.exists():
        from tactical.pathfinding import PathFinder

        pathfinder = PathFinder(
            str(walkgraph_path),
            influence_map.points,
            influence_map.adj_index,
            influence_map.adj_list,
            influence_map.tree,
        )

    return MapData(
        name=map_name,
        influence_map=influence_map,
        area_map=area_map,
        pathfinder=pathfinder,
    )


def preload_all_maps(data_dir: str) -> dict[str, MapData]:
    """Discover and load all maps. Returns {map_name: MapData}."""
    registry: dict[str, MapData] = {}
    for map_name in discover_maps(data_dir):
        md = load_map(map_name, data_dir)
        if md is not None:
            registry[map_name] = md
            log.info(
                "Preloaded map: %s (areas=%d, pathfinder=%s)",
                map_name,
                len(md.area_map.areas) if md.area_map else 0,
                md.pathfinder is not None,
            )
    log.info("Preloaded %d maps total", len(registry))
    return registry
