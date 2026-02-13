"""Tactical planner: score grid positions using the influence map and assign bots."""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass

import numpy as np

from tactical.areas import AreaMap
from tactical.influence_map import InfluenceMap, WEIGHT_PROFILES
from tactical.pathfinding import PathFinder
from tactical.protocol import BotCommand
from tactical.state import GameState
from tactical.telemetry import BotCommandRow

log = logging.getLogger(__name__)


SPOTTED_COOLDOWN = 5.0  # seconds to remember enemy after losing sight
MAX_PREDICT_TIME = 2.0  # max seconds to extrapolate enemy movement
THREAT_LOOK_RANGE = 1500.0  # look at threats within this distance while walking


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
        pathfinder: PathFinder | None = None,
    ) -> None:
        self.controlled_team = controlled_team
        self.influence_map = influence_map
        self.area_map = area_map
        self.pathfinder = pathfinder
        self.profile_name = "defend"  # set by strategist, used for telemetry context
        self.orders: list[Order] | None = None
        # (timestamp, position, velocity_xy)
        self._spotted_memory: dict[
            int, tuple[float, tuple[float, float, float], tuple[float, float]]
        ] = {}

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

        # Update spotted memory: refresh timestamp + track velocity
        now = time.monotonic()
        for eid in spotted_ids:
            if eid in all_enemies:
                new_pos = all_enemies[eid].pos
                vx, vy = 0.0, 0.0
                if eid in self._spotted_memory:
                    old_t, old_pos, old_vel = self._spotted_memory[eid]
                    dt = now - old_t
                    if dt > 0.05:
                        vx = (new_pos[0] - old_pos[0]) / dt
                        vy = (new_pos[1] - old_pos[1]) / dt
                    else:
                        vx, vy = old_vel
                self._spotted_memory[eid] = (now, new_pos, (vx, vy))

        # Prune expired entries
        self._spotted_memory = {
            eid: entry for eid, entry in self._spotted_memory.items()
            if now - entry[0] < SPOTTED_COOLDOWN
        }

        # Enemy positions = live pos OR extrapolated from last known + velocity
        enemy_positions: list[tuple[float, float, float]] = []
        for eid, (t, pos, vel) in self._spotted_memory.items():
            if eid in spotted_ids and eid in all_enemies:
                enemy_positions.append(all_enemies[eid].pos)
            else:
                dt = min(now - t, MAX_PREDICT_TIME)
                enemy_positions.append((
                    pos[0] + vel[0] * dt,
                    pos[1] + vel[1] * dt,
                    pos[2],
                ))

        # Build per-bot profile map for telemetry
        bot_profiles: dict[int, str] = {}

        if self.orders is not None and self.area_map is not None and self.influence_map is not None:
            commands = self._area_commands(
                our_bots, friendly_positions, enemy_positions, bot_profiles,
                objectives_lost=state.objectives_lost,
            )
        else:
            # No strategist orders — send nothing, let vanilla AI control all bots
            commands = []

        rows = []
        for cmd in commands:
            dx = cmd.look_target[0] - cmd.move_target[0]
            dy = cmd.look_target[1] - cmd.move_target[1]
            yaw = math.degrees(math.atan2(dy, dx)) if (dx * dx + dy * dy) > 1.0 else 0.0
            rows.append(BotCommandRow(
                tick=state.tick,
                bot_id=cmd.id,
                target_x=cmd.move_target[0],
                target_y=cmd.move_target[1],
                target_z=cmd.move_target[2],
                look_x=cmd.look_target[0],
                look_y=cmd.look_target[1],
                look_z=cmd.look_target[2],
                look_yaw=yaw,
                profile=bot_profiles.get(cmd.id, "unknown"),
            ))
        return commands, rows

    def _approach_positions(self) -> list[tuple[float, float, float]]:
        """Centroids of enemy_spawn and enemy_approach areas."""
        assert self.area_map is not None
        return [
            a.center for a in self.area_map.areas.values()
            if a.role in ("enemy_spawn", "enemy_approach")
        ]

    def _enemy_spawn(self, objectives_lost: int = 0) -> tuple[float, float, float] | None:
        """Current enemy spawn: last captured objective, or original spawn."""
        assert self.area_map is not None
        if objectives_lost > 0:
            for a in self.area_map.areas.values():
                if a.role == "objective" and a.order == objectives_lost:
                    return a.center
        for a in self.area_map.areas.values():
            if a.role == "enemy_spawn":
                return a.center
        return None

    @staticmethod
    def _nearest_approach(
        pos: tuple[float, float, float],
        approaches: list[tuple[float, float, float]],
    ) -> tuple[float, float, float] | None:
        """Return the approach centroid closest to *pos*."""
        if not approaches:
            return None
        best = approaches[0]
        best_d2 = sum((a - b) ** 2 for a, b in zip(pos, best))
        for ap in approaches[1:]:
            d2 = sum((a - b) ** 2 for a, b in zip(pos, ap))
            if d2 < best_d2:
                best_d2 = d2
                best = ap
        return best

    @staticmethod
    def _look_past_approach(
        approach: tuple[float, float, float],
        obj_centroid: tuple[float, float, float],
    ) -> tuple[float, float, float]:
        """Project 2000u past the approach centroid, away from the objective.

        Uses only XY for direction so bots look horizontally, not up/down.
        Z is kept at the approach height.
        """
        dx = approach[0] - obj_centroid[0]
        dy = approach[1] - obj_centroid[1]
        length = (dx * dx + dy * dy) ** 0.5
        if length < 1.0:
            return approach
        scale = 2000.0 / length
        return (
            approach[0] + dx * scale,
            approach[1] + dy * scale,
            approach[2],
        )

    @staticmethod
    def _nearest_enemy(
        bot_pos: tuple[float, float, float],
        enemy_positions: list[tuple[float, float, float]],
        max_dist: float = THREAT_LOOK_RANGE,
    ) -> tuple[float, float, float] | None:
        """Return the nearest enemy position within max_dist (2D), or None."""
        best: tuple[float, float, float] | None = None
        best_d2 = max_dist * max_dist
        for ep in enemy_positions:
            dx = ep[0] - bot_pos[0]
            dy = ep[1] - bot_pos[1]
            d2 = dx * dx + dy * dy
            if d2 < best_d2:
                best_d2 = d2
                best = ep
        return best

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
        objectives_lost: int = 0,
    ) -> list[BotCommand]:
        """Assign bots to area-based orders from the strategist."""
        assert self.influence_map is not None
        assert self.area_map is not None
        assert self.orders is not None

        commands: list[BotCommand] = []
        assigned_ids: set[int] = set()
        remaining = list(our_bots)

        approach_positions = self._approach_positions()
        enemy_spawn = self._enemy_spawn(objectives_lost)

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
                # Arrived look: approach-watching for defensive postures
                if order.posture in ("defend", "ambush", "sniper"):
                    nearest = self._nearest_approach(target, approach_positions)
                    if nearest is not None:
                        arrived_look = self._look_past_approach(nearest, obj_centroid)
                    else:
                        arrived_look = target
                else:
                    arrived_look = target

                # Walking vs arrived dispatch
                dx = bot.pos[0] - target[0]
                dy = bot.pos[1] - target[1]
                dist2 = dx * dx + dy * dy

                if dist2 < 150.0 * 150.0:
                    look = arrived_look
                else:
                    # Threat priority: look at nearest remembered enemy
                    threat = self._nearest_enemy(bot.pos, enemy_positions)
                    if threat is not None:
                        look = threat
                    elif self.pathfinder is not None and self.influence_map is not None \
                            and enemy_spawn is not None:
                        # Slice-the-pie toward enemy spawn entrance
                        corner = self.pathfinder.find_look_target(
                            bot.pos, enemy_spawn, self.influence_map.nearest_point,
                        )
                        look = corner if corner else arrived_look
                    else:
                        look = arrived_look

                # Force horizontal aim — avoid looking up/down due to
                # centroid Z averaging across floors
                look = (look[0], look[1], bot.pos[2])

                commands.append(BotCommand(
                    id=bot.id,
                    move_target=target,
                    look_target=look,
                    flags=0,
                ))
                bot_profiles[bot.id] = profile_tag
                assigned_ids.add(bot.id)

        # Leftover bots (not assigned by any order): no commands sent,
        # vanilla AI controls them.

        return commands
