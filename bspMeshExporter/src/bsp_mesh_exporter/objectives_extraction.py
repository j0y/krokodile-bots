"""Extract objective and spawn definitions from BSP + cpsetup config.

Produces *_objectives.json files for use by the tactical brain.
Works for Insurgency checkpoint/coop maps.

Primary data source: maps/<mapname>.txt (cpsetup config, extracted from VPK).
  - Defines objective sequence (controlpoint names in order)
  - Contains exact weapon cache positions (obj_weapon_cache entities)
  - Contains dynamically-spawned point_controlpoint entities for caches

Secondary data source: BSP entity lump (always present).
  - point_controlpoint origins for capture objectives
  - trigger_capture_zone → identifies capture vs destroy
  - ins_spawnzone → phase team spawns (for attacker_spawn)
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

TEAM_SECURITY = "2"
TEAM_INSURGENT = "3"


def _parse_origin(origin_str: str) -> tuple[float, float, float]:
    parts = origin_str.split()
    return (float(parts[0]), float(parts[1]), float(parts[2]))


def _entity_origin(ent: dict[str, str], bsp: Any) -> tuple[float, float, float] | None:
    """Get entity world-space center, using origin field or brush model bounds."""
    if "origin" in ent:
        return _parse_origin(ent["origin"])
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


def _centroid(points: list[tuple[float, float, float]]) -> tuple[float, float, float]:
    if not points:
        return (0.0, 0.0, 0.0)
    n = len(points)
    return (
        sum(p[0] for p in points) / n,
        sum(p[1] for p in points) / n,
        sum(p[2] for p in points) / n,
    )


# ── Valve KeyValues parser (minimal, for cpsetup.txt) ───────────────


def _parse_kv(text: str) -> dict[str, Any]:
    """Parse Valve KeyValues format into nested dicts.

    Handles repeated keys (like multiple "controlpoint") by collecting
    them into lists.
    """
    tokens: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c in (" ", "\t", "\n", "\r"):
            i += 1
        elif c == "/" and i + 1 < len(text) and text[i + 1] == "/":
            # Line comment
            while i < len(text) and text[i] != "\n":
                i += 1
        elif c == '"':
            # Quoted string
            j = i + 1
            while j < len(text) and text[j] != '"':
                if text[j] == "\\":
                    j += 1
                j += 1
            tokens.append(text[i + 1 : j])
            i = j + 1
        elif c in ("{", "}"):
            tokens.append(c)
            i += 1
        else:
            # Unquoted token
            j = i
            while j < len(text) and text[j] not in (" ", "\t", "\n", "\r", '"', "{", "}"):
                j += 1
            tokens.append(text[i:j])
            i = j

    def _parse_block(pos: int) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        while pos < len(tokens):
            if tokens[pos] == "}":
                return result, pos + 1
            key = tokens[pos]
            pos += 1
            if pos >= len(tokens):
                break
            if tokens[pos] == "{":
                val, pos = _parse_block(pos + 1)
            else:
                val = tokens[pos]
                pos += 1
            # Handle repeated keys by collecting into list
            if key in result:
                existing = result[key]
                if isinstance(existing, list):
                    existing.append(val)
                else:
                    result[key] = [existing, val]
            else:
                result[key] = val
        return result, pos

    block, _ = _parse_block(0)
    return block


# ── Main extraction ─────────────────────────────────────────────────


def extract_objectives(bsp_path: str | Path) -> dict[str, Any]:
    """Extract area definitions from a BSP file + cpsetup config.

    Returns a dict ready to be serialized as JSON, matching the
    format expected by tactical.areas.AreaMap.
    """
    import bsp_tool
    from bsp_tool.branches.valve import sdk_2013

    bsp_path = Path(bsp_path)
    map_name = bsp_path.stem
    log.info("Loading BSP entities: %s", bsp_path)
    bsp = bsp_tool.load_bsp(str(bsp_path), force_branch=sdk_2013)
    ents = bsp.ENTITIES

    # ── Parse cpsetup config if available ────────────────────────────

    cpsetup_path = bsp_path.parent / f"{map_name}.txt"
    cpsetup: dict[str, Any] | None = None
    if cpsetup_path.exists():
        log.info("Found cpsetup config: %s", cpsetup_path)
        cpsetup = _parse_kv(cpsetup_path.read_text())
        # Navigate to the checkpoint block
        root = cpsetup.get("cpsetup.txt", cpsetup)
        cpsetup = root.get("checkpoint", root)

    # ── Collect BSP entities ─────────────────────────────────────────

    bsp_control_points: dict[str, dict[str, str]] = {}
    capture_zones: list[dict[str, str]] = []
    spawnzones: list[dict[str, str]] = []

    for e in ents:
        cls = e.get("classname", "")
        if cls == "point_controlpoint":
            tn = e.get("targetname", "")
            if tn:
                bsp_control_points[tn] = e
        elif cls == "trigger_capture_zone":
            capture_zones.append(e)
        elif cls == "ins_spawnzone":
            spawnzones.append(e)

    capture_cp_names = {cz.get("controlpoint", "") for cz in capture_zones}

    # ── Determine objective sequence and positions ───────────────────

    # Ordered list of (cp_name, origin, obj_type)
    objectives: list[tuple[str, tuple[float, float, float], str]] = []

    if cpsetup is not None:
        # Get objective order from cpsetup
        cp_list = cpsetup.get("controlpoint", [])
        if isinstance(cp_list, str):
            cp_list = [cp_list]

        # Collect cache/CP entities defined in cpsetup
        cpsetup_entities: dict[str, dict[str, str]] = {}
        ent_block = cpsetup.get("entities", {})
        if isinstance(ent_block, dict):
            # Entities can be repeated under the same classname key
            for cls_key in ("obj_weapon_cache", "point_controlpoint"):
                items = ent_block.get(cls_key, [])
                if isinstance(items, dict):
                    items = [items]
                elif not isinstance(items, list):
                    continue
                for item in items:
                    if isinstance(item, dict):
                        tn = item.get("targetname", "")
                        if tn:
                            cpsetup_entities[tn] = item

        for cp_name in cp_list:
            # Determine type: capture if BSP has a trigger_capture_zone for it
            is_capture = cp_name in capture_cp_names
            # Also check name pattern
            if not is_capture and not cp_name.startswith("cachepoint"):
                is_capture = True
            obj_type = "capture" if is_capture else "destroy"

            # Find position: prefer cache entity from cpsetup, then cpsetup CP,
            # then BSP CP
            origin: tuple[float, float, float] | None = None

            if obj_type == "destroy":
                # Look for obj_weapon_cache with matching ControlPoint
                for tn, ent_data in cpsetup_entities.items():
                    if ent_data.get("ControlPoint") == cp_name and "origin" in ent_data:
                        origin = _parse_origin(ent_data["origin"])
                        break
                # Fallback: cpsetup point_controlpoint
                if origin is None and cp_name in cpsetup_entities and "origin" in cpsetup_entities[cp_name]:
                    origin = _parse_origin(cpsetup_entities[cp_name]["origin"])

            # For capture or if still no origin: try BSP entity
            if origin is None and cp_name in bsp_control_points:
                origin = _entity_origin(bsp_control_points[cp_name], bsp)

            # Last resort: cpsetup CP origin
            if origin is None and cp_name in cpsetup_entities and "origin" in cpsetup_entities[cp_name]:
                origin = _parse_origin(cpsetup_entities[cp_name]["origin"])

            if origin is None:
                log.warning("Objective '%s': no position found, skipping", cp_name)
                continue

            objectives.append((cp_name, origin, obj_type))
            log.info(
                "Objective %d '%s' (%s) at (%.0f, %.0f, %.0f)",
                len(objectives), cp_name, obj_type,
                origin[0], origin[1], origin[2],
            )
    else:
        log.warning("No cpsetup config found — using BSP entities only (less accurate)")
        # Fallback: BSP-only extraction (original heuristic approach)
        objectives = _extract_from_bsp_only(bsp, ents, bsp_control_points, capture_cp_names, spawnzones)

    # ── Determine attacker spawn from spawnzones ─────────────────────

    # phase → team → list of origins
    phase_spawns: dict[int, dict[str, list[tuple[float, float, float]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for sz in spawnzones:
        tn = sz.get("targetname", "")
        m = re.search(r"(\d+)", tn)
        if not m:
            m_letter = re.match(r"sz_([a-z])$", tn, re.IGNORECASE)
            if m_letter:
                phase = ord(m_letter.group(1).lower()) - ord("a") + 1
            else:
                continue
        else:
            phase = int(m.group(1))
        team = sz.get("TeamNum", "")
        origin = _entity_origin(sz, bsp)
        if origin is not None:
            phase_spawns[phase][team].append(origin)

    # ── Build output areas dict ──────────────────────────────────────

    areas: dict[str, Any] = {}

    for i, (cp_name, origin, obj_type) in enumerate(objectives, 1):
        letter = chr(ord("a") + i - 1) if i <= 26 else str(i)
        name = f"obj_{letter}"
        areas[name] = {
            "center": [round(origin[0]), round(origin[1]), round(origin[2])],
            "radius": 400,
            "falloff": 250,
            "role": "objective",
            "order": i,
            "type": obj_type,
        }

    # Attacker spawn — Security phase 1
    if phase_spawns:
        first_phase = min(phase_spawns.keys())
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
    if "attacker_spawn" in areas and objectives:
        obj_origin = objectives[0][1]
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


def _extract_from_bsp_only(
    bsp: Any,
    ents: list[dict[str, str]],
    bsp_control_points: dict[str, dict[str, str]],
    capture_cp_names: set[str],
    spawnzones: list[dict[str, str]],
) -> list[tuple[str, tuple[float, float, float], str]]:
    """Fallback: extract objectives from BSP entities only (no cpsetup)."""
    import math

    phase_nums: set[int] = set()
    phase_spawns: dict[int, dict[str, list[tuple[float, float, float]]]] = defaultdict(
        lambda: defaultdict(list)
    )

    for sz in spawnzones:
        tn = sz.get("targetname", "")
        m = re.search(r"(\d+)", tn)
        if not m:
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

    # Map CPs to phases by name
    cp_phases: dict[str, int] = {}
    for cp_name in bsp_control_points:
        m = re.search(r"(\d+)$", cp_name)
        if m:
            cp_phases[cp_name] = int(m.group(1))
        else:
            m = re.match(r"(?:cp|cap|cachepoint)_([a-z])$", cp_name, re.IGNORECASE)
            if m:
                cp_phases[cp_name] = ord(m.group(1).lower()) - ord("a") + 1

    objectives: list[tuple[str, tuple[float, float, float], str]] = []
    for phase in sorted(phase_nums):
        matched_cp = None
        for cp_name, p in cp_phases.items():
            if p == phase:
                matched_cp = cp_name
                break

        if matched_cp is not None:
            origin = _entity_origin(bsp_control_points[matched_cp], bsp)
            if origin is None:
                continue
            is_capture = matched_cp in capture_cp_names
            obj_type = "capture" if is_capture else "destroy"
            objectives.append((matched_cp, origin, obj_type))
        else:
            # Estimate destroy location from insurgent spawnpoints
            ins_zones = phase_spawns[phase].get(TEAM_INSURGENT, [])
            sec_origins = phase_spawns[phase].get(TEAM_SECURITY, [])
            if ins_zones:
                if sec_origins:
                    sec_center = _centroid(sec_origins)
                    target = max(ins_zones, key=lambda z: math.sqrt(
                        sum((a - b) ** 2 for a, b in zip(z, sec_center))
                    ))
                else:
                    target = ins_zones[0]

                ins_points = [
                    _parse_origin(sp["origin"])
                    for sp in ents
                    if sp.get("classname") == "ins_spawnpoint"
                    and sp.get("TeamNum") == TEAM_INSURGENT
                    and sp.get("origin")
                ]
                nearby = [p for p in ins_points if math.sqrt(
                    sum((a - b) ** 2 for a, b in zip(p, target))
                ) < 600]
                center = _centroid(nearby) if nearby else target
                objectives.append((f"phase_{phase}", center, "destroy"))

    return objectives
