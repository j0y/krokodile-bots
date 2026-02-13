"""Tactical planner: score grid positions using the influence map and assign bots."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import numpy as np

from tactical.areas import AreaMap
from tactical.influence_map import InfluenceMap, WEIGHT_PROFILES
from tactical.protocol import BotCommand
from tactical.state import GameState
from tactical.telemetry import BotCommandRow

log = logging.getLogger(__name__)


SPOTTED_COOLDOWN = 5.0  # seconds to remember enemy after losing sight


@dataclass(frozen=True, slots=True)
class Order:
    areas: list[str]   # e.g. ["lobby", "courtyard"] or ["lobby", "-balcony"]
    posture: str       # weight profile name
    bots: int          # number of bots to assign


class Planner:
    def __init__(
        self,
        controlled_team: int = 2,
        influence_map: InfluenceMap | None = None,
        area_map: AreaMap | None = None,
    ) -> None:
        self.controlled_team = controlled_team
        self.influence_map = influence_map
        self.area_map = area_map
        self.profile_name = "defend"  # set by strategist, used for telemetry context
        self.orders: list[Order] | None = None
        self._spotted_memory: dict[int, tuple[float, tuple[float, float, float]]] = {}

    def compute_commands(
        self, state: GameState,
    ) -> tuple[list[BotCommand], list[BotCommandRow]]:
        # Our bots: alive fake clients on the controlled team
        our_bots = [
            b for b in state.bots.values()
            if b.alive and b.is_bot and b.team == self.controlled_team
        ]
        if not our_bots:
            return [], []

        # Friendly = all alive players on our team (bots + humans, for spread penalty)
        friendly_positions = [
            b.pos for b in state.bots.values()
            if b.alive and b.team == self.controlled_team
        ]
        # Fog-of-war: collect currently spotted enemy IDs from all friendly bots
        spotted_ids: set[int] = set()
        for b in state.bots.values():
            if b.alive and b.team == self.controlled_team:
                spotted_ids.update(b.sees)

        # All alive enemies (for position lookup)
        all_enemies = {
            b.id: b for b in state.bots.values()
            if b.alive and b.team != self.controlled_team and b.team > 1
        }

        # Update spotted memory: refresh timestamp for currently-seen enemies
        now = time.monotonic()
        for eid in spotted_ids:
            if eid in all_enemies:
                self._spotted_memory[eid] = (now, all_enemies[eid].pos)

        # Prune expired entries
        self._spotted_memory = {
            eid: (t, pos) for eid, (t, pos) in self._spotted_memory.items()
            if now - t < SPOTTED_COOLDOWN
        }

        # Enemy positions = currently seen (live pos) + recently seen (last known pos)
        enemy_positions: list[tuple[float, float, float]] = []
        for eid, (t, pos) in self._spotted_memory.items():
            if eid in spotted_ids and eid in all_enemies:
                enemy_positions.append(all_enemies[eid].pos)  # live position
            else:
                enemy_positions.append(pos)  # last known position

        # Build per-bot profile map for telemetry
        bot_profiles: dict[int, str] = {}

        if self.orders is not None and self.area_map is not None and self.influence_map is not None:
            commands = self._area_commands(
                our_bots, friendly_positions, enemy_positions, bot_profiles,
            )
        else:
            # No strategist orders — send nothing, let vanilla AI control all bots
            commands = []

        rows = [
            BotCommandRow(
                tick=state.tick,
                bot_id=cmd.id,
                target_x=cmd.move_target[0],
                target_y=cmd.move_target[1],
                target_z=cmd.move_target[2],
                profile=bot_profiles.get(cmd.id, "unknown"),
            )
            for cmd in commands
        ]
        return commands, rows

    def _approach_positions(self) -> list[tuple[float, float, float]]:
        """Centroids of enemy_spawn and enemy_approach areas."""
        assert self.area_map is not None
        return [
            a.center for a in self.area_map.areas.values()
            if a.role in ("enemy_spawn", "enemy_approach")
        ]

    def _objective_centroid(self, area_names: list[str]) -> tuple[float, float, float]:
        """Centroid of only the objective-role area within area_names.

        Falls back to full area centroid if no objective-role area is found.
        """
        assert self.area_map is not None
        obj_only = [
            n for n in area_names
            if not n.startswith("-") and n in self.area_map.areas
            and self.area_map.areas[n].role == "objective"
        ]
        if obj_only:
            return self.area_map.area_centroid(obj_only)
        return self.area_map.area_centroid(area_names)

    def _area_commands(
        self,
        our_bots: list,
        friendly_positions: list[tuple[float, float, float]],
        enemy_positions: list[tuple[float, float, float]],
        bot_profiles: dict[int, str],
    ) -> list[BotCommand]:
        """Assign bots to area-based orders from the strategist."""
        assert self.influence_map is not None
        assert self.area_map is not None
        assert self.orders is not None

        commands: list[BotCommand] = []
        assigned_ids: set[int] = set()
        remaining = list(our_bots)

        approach_positions = self._approach_positions()

        for order in self.orders:
            if not remaining:
                break

            n = min(order.bots, len(remaining))
            mask = self.area_map.build_mask(order.areas)

            # For defend orders with adjacent areas, use only the objective area
            # for proximity pull so bots aren't pulled toward adjacent centroids
            obj_centroid = self._objective_centroid(order.areas)
            centroid = self.area_map.area_centroid(order.areas)

            # Determine sightline targets (what should bots watch?)
            if order.posture in ("defend", "ambush", "sniper"):
                # Watch approaches + recent threats instead of objective center
                sightline_targets = approach_positions + enemy_positions
            else:
                # push/overrun: look at objective
                sightline_targets = [centroid]

            # Sort unassigned bots by distance to area centroid, take closest N
            centroid_arr = np.array(centroid, dtype=np.float32)
            remaining.sort(
                key=lambda b: float(np.linalg.norm(
                    np.array(b.pos, dtype=np.float32) - centroid_arr,
                )),
            )
            batch = remaining[:n]
            remaining = remaining[n:]

            weights = WEIGHT_PROFILES.get(order.posture, WEIGHT_PROFILES["defend"])
            positions = self.influence_map.best_positions(
                weights,
                num=len(batch),
                mask=mask,
                objective_center=obj_centroid,
                objective_positions=sightline_targets if sightline_targets else [obj_centroid],
                friendly_positions=friendly_positions,
                enemy_positions=enemy_positions,
            )

            profile_tag = f"area:{order.posture}"
            for bot, target in zip(batch, positions):
                commands.append(BotCommand(
                    id=bot.id,
                    move_target=target,
                    look_target=target,
                    flags=0,
                ))
                bot_profiles[bot.id] = profile_tag
                assigned_ids.add(bot.id)

        # Leftover bots (not assigned by any order): no commands sent,
        # vanilla AI controls them.

        return commands
