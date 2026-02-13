"""Extract objective and spawn area definitions from BSP entity lumps.

Produces *_areas.json files compatible with tactical.areas.AreaMap.
Works for Insurgency checkpoint/coop maps.

Entity mapping:
- point_controlpoint          → objective locations (capture & destroy)
- trigger_capture_zone        → identifies which CPs are capture type
- ins_spawnzone               → phase definitions, team spawn locations
- ins_spawnpoint              → individual spawn positions (for centroid estimation)

Phases without a point_controlpoint are assumed to be destroy objectives
whose positions are estimated from the insurgent (team 3) spawnpoint centroid.
"""

from __future__ import annotations

import json
import logging
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Team numbers in Insurgency
TEAM_SECURITY = "2"  # human attackers in coop
TEAM_INSURGENT = "3"  # bot defenders in coop


def _parse_origin(origin_str: str) -> tuple[float, float, float]:
    """Parse "x y z" origin string to tuple."""
    parts = origin_str.split()
    return (float(parts[0]), float(parts[1]), float(parts[2]))


def _entity_origin(ent: dict[str, str], bsp: Any) -> tuple[float, float, float] | None:
    """Get entity world-space center, using origin field or brush model bounds."""
    if "origin" in ent:
        return _parse_origin(ent["origin"])

    # For brush entities with a model field (*N), compute center from model bounds
    model_str = ent.get("model", "")
    if model_str.startswith("*"):
        try:
            idx = int(model_str[1:])
            m = bsp.MODELS[idx]
            mins = m.bounds.mins
            maxs = m.bounds.maxs
            return (
                (float(mins.x) + float(maxs.x)) / 2,
                (float(mins.y) + float(maxs.y)) / 2,
                (float(mins.z) + float(maxs.z)) / 2,
            )
        except (IndexError, AttributeError, ValueError):
            pass

    return None


def _dist(a: tuple[float, float, float], b: tuple[float, float, float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def _centroid(points: list[tuple[float, float, float]]) -> tuple[float, float, float]:
    if not points:
        return (0.0, 0.0, 0.0)
    n = len(points)
    return (
        sum(p[0] for p in points) / n,
        sum(p[1] for p in points) / n,
        sum(p[2] for p in points) / n,
    )


def _phase_from_name(name: str) -> int | None:
    """Extract phase number from a control point or cachepoint name.

    Handles: cp1, cp_1, cap_1, cachepoint_b (letter→number).
    Returns None if no phase can be determined.
    """
    # Try numeric suffix first: cp3, cp_3, cap_3
    m = re.search(r"(\d+)$", name)
    if m:
        return int(m.group(1))

    # Try letter suffix for cachepoint_X
    m = re.match(r"cachepoint_([a-z])$", name, re.IGNORECASE)
    if m:
        return ord(m.group(1).lower()) - ord("a") + 1

    # Try letter suffix for cp_X or cap_X
    m = re.match(r"(?:cp|cap)_([a-z])$", name, re.IGNORECASE)
    if m:
        return ord(m.group(1).lower()) - ord("a") + 1

    return None


def extract_areas(bsp_path: str | Path) -> dict[str, Any]:
    """Extract area definitions from a BSP file.

    Returns a dict ready to be serialized as JSON, matching the
    format expected by tactical.areas.AreaMap.
    """
    import bsp_tool
    from bsp_tool.branches.valve import sdk_2013

    bsp_path = Path(bsp_path)
    log.info("Loading BSP entities: %s", bsp_path)
    bsp = bsp_tool.load_bsp(str(bsp_path), force_branch=sdk_2013)
    ents = bsp.ENTITIES

    # ── Collect relevant entities ────────────────────────────────────

    control_points: list[dict[str, str]] = []
    capture_zones: list[dict[str, str]] = []
    spawnzones: list[dict[str, str]] = []
    spawnpoints: list[dict[str, str]] = []

    for e in ents:
        cls = e.get("classname", "")
        if cls == "point_controlpoint":
            control_points.append(e)
        elif cls == "trigger_capture_zone":
            capture_zones.append(e)
        elif cls == "ins_spawnzone":
            spawnzones.append(e)
        elif cls == "ins_spawnpoint":
            spawnpoints.append(e)

    # ── Determine which CPs are capture vs destroy ───────────────────

    capture_cp_names = {cz.get("controlpoint", "") for cz in capture_zones}

    # ── Determine phases from spawnzones ─────────────────────────────

    phase_nums: set[int] = set()
    # phase → team → list of origins
    phase_spawns: dict[int, dict[str, list[tuple[float, float, float]]]] = defaultdict(
        lambda: defaultdict(list)
    )

    for sz in spawnzones:
        tn = sz.get("targetname", "")
        # Match numbered zones: spawnzone_3, spawnzone3, sz_3
        m = re.search(r"(\d+)", tn)
        if not m:
            # Match lettered zones: sz_a, sz_b, ...
            m_letter = re.match(r"sz_([a-z])$", tn, re.IGNORECASE)
            if m_letter:
                phase = ord(m_letter.group(1).lower()) - ord("a") + 1
            else:
                continue
        else:
            phase = int(m.group(1))
        phase_nums.add(phase)
        team = sz.get("TeamNum", "")
        origin = _entity_origin(sz, bsp)
        if origin is not None:
            phase_spawns[phase][team].append(origin)

    if not phase_nums:
        log.warning("No numbered spawnzones found — cannot determine phases")

    # ── Map control points to phases ─────────────────────────────────

    # cp_name → (origin, is_capture, phase_num)
    cp_info: dict[str, tuple[tuple[float, float, float], bool, int | None]] = {}
    for cp in control_points:
        name = cp.get("targetname", "")
        if not name:
            continue
        origin = _entity_origin(cp, bsp)
        if origin is None:
            continue
        is_capture = name in capture_cp_names
        phase = _phase_from_name(name)
        cp_info[name] = (origin, is_capture, phase)

    # For CPs without a phase number, try spatial matching to spawnzones.
    # The objective for phase N should be nearest to the Security spawnzone
    # for that phase (since Security is attacking toward it).
    unassigned_cps = {n: info for n, info in cp_info.items() if info[2] is None}
    assigned_phases = {info[2] for info in cp_info.values() if info[2] is not None}

    if unassigned_cps and phase_nums:
        available_phases = sorted(phase_nums - assigned_phases)
        for cp_name, (origin, is_cap, _) in sorted(unassigned_cps.items()):
            if not available_phases:
                break
            # Find closest phase by Security spawnzone proximity
            best_phase = None
            best_dist = float("inf")
            for p in available_phases:
                sec_origins = phase_spawns[p].get(TEAM_SECURITY, [])
                for so in sec_origins:
                    d = _dist(origin, so)
                    if d < best_dist:
                        best_dist = d
                        best_phase = p
            if best_phase is not None:
                cp_info[cp_name] = (origin, is_cap, best_phase)
                available_phases.remove(best_phase)
                log.info(
                    "Spatially matched CP '%s' to phase %d (dist=%.0f)",
                    cp_name, best_phase, best_dist,
                )

    # ── Build phase → objective mapping ──────────────────────────────

    # phase → (origin, type)
    phase_objectives: dict[int, tuple[tuple[float, float, float], str]] = {}

    for cp_name, (origin, is_capture, phase) in cp_info.items():
        if phase is None:
            log.warning("CP '%s' could not be assigned to a phase", cp_name)
            continue
        obj_type = "capture" if is_capture else "destroy"
        phase_objectives[phase] = (origin, obj_type)

    # For phases without a CP: estimate destroy objective from insurgent spawnpoints.
    # Heuristic: the weapon cache is near the insurgent spawnzone that is farthest
    # from the Security spawn for that phase (deeper in enemy territory).
    if phase_nums:
        ins_points = [
            _parse_origin(sp["origin"])
            for sp in spawnpoints
            if sp.get("TeamNum") == TEAM_INSURGENT and sp.get("origin")
        ]

        for phase in sorted(phase_nums):
            if phase in phase_objectives:
                continue
            ins_zones = phase_spawns[phase].get(TEAM_INSURGENT, [])
            if not ins_zones:
                log.warning("Phase %d: no insurgent spawnzone, cannot estimate destroy location", phase)
                continue

            # Pick the insurgent zone farthest from Security spawn centroid
            sec_origins = phase_spawns[phase].get(TEAM_SECURITY, [])
            if sec_origins:
                sec_center = _centroid(sec_origins)
                target_zone = max(ins_zones, key=lambda z: _dist(z, sec_center))
            else:
                target_zone = ins_zones[0]

            # Find spawnpoints near the chosen zone only
            nearby: list[tuple[float, float, float]] = []
            for sp in ins_points:
                if _dist(sp, target_zone) < 600:
                    nearby.append(sp)

            if nearby:
                center = _centroid(nearby)
            else:
                center = target_zone

            phase_objectives[phase] = (center, "destroy")
            log.info(
                "Phase %d: estimated destroy at (%.0f, %.0f, %.0f) [%d spawnpoints near zone (%.0f, %.0f, %.0f)]",
                phase, center[0], center[1], center[2],
                len(nearby), target_zone[0], target_zone[1], target_zone[2],
            )

    # ── Build output areas dict ──────────────────────────────────────

    areas: dict[str, Any] = {}

    # Objectives in phase order
    for phase in sorted(phase_objectives.keys()):
        origin, obj_type = phase_objectives[phase]
        # Generate a name
        letter = chr(ord("a") + phase - 1) if phase <= 26 else str(phase)
        name = f"obj_{letter}"

        areas[name] = {
            "center": [round(origin[0]), round(origin[1]), round(origin[2])],
            "radius": 400,
            "falloff": 250,
            "role": "objective",
            "order": phase,
            "type": obj_type,
        }

    # Attacker spawn — Security (team 2) phase 1 spawnzone
    if phase_nums:
        first_phase = min(phase_nums)
        sec_spawns = phase_spawns[first_phase].get(TEAM_SECURITY, [])
        if sec_spawns:
            center = _centroid(sec_spawns)
            areas["attacker_spawn"] = {
                "center": [round(center[0]), round(center[1]), round(center[2])],
                "radius": 500,
                "falloff": 300,
                "role": "enemy_spawn",
            }

    # Enemy approach — midpoint between attacker spawn and first objective
    if "attacker_spawn" in areas and phase_objectives:
        first_phase = min(phase_objectives.keys())
        obj_origin = phase_objectives[first_phase][0]
        spawn_center = tuple(areas["attacker_spawn"]["center"])
        mid = (
            (spawn_center[0] + obj_origin[0]) / 2,
            (spawn_center[1] + obj_origin[1]) / 2,
            (spawn_center[2] + obj_origin[2]) / 2,
        )
        areas["approach"] = {
            "center": [round(mid[0]), round(mid[1]), round(mid[2])],
            "radius": 700,
            "falloff": 300,
            "role": "enemy_approach",
        }

    log.info(
        "Extracted %d objectives + %d support areas",
        len([a for a in areas.values() if a.get("role") == "objective"]),
        len([a for a in areas.values() if a.get("role") != "objective"]),
    )

    return areas
