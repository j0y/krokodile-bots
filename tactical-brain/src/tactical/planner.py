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
from tactical.protocol import BotCommand, CMD_FLAG_INVESTIGATE
from tactical.state import GameState
from tactical.telemetry import BotCommandRow
from tactical.wave_front import WaveFront

log = logging.getLogger(__name__)


SPOTTED_COOLDOWN = 5.0  # seconds to remember enemy after losing sight
MAX_PREDICT_TIME = 2.0  # max seconds to extrapolate enemy movement
THREAT_LOOK_RANGE = 1500.0  # look at threats within this distance while walking
STUCK_THRESHOLD = 50.0  # bot must move this far to be considered "not stuck"
STUCK_SECONDS = 3.0     # seconds without movement before releasing to native AI
STUCK_MIN_DIST = 300.0  # only release if bot is this far from its move target
COMMIT_TIMEOUT = 15.0   # max seconds to reach a position before re-scoring
HOLD_DURATION = 8.0     # seconds to hold at position after arriving
INTERMEDIATE_HOLD = 2.0 # seconds to pause at intermediate areas en route
ARRIVE_RADIUS = 150.0   # distance to target to be considered "arrived"

# Posture → (priority, voice concept ID).  Higher priority = more likely to be called out.
# Only the single highest-priority changed posture triggers a callout per tick.
# See reverseEngineering/analysis/voice-concepts.md
POSTURE_VOICE: dict[str, tuple[int, int]] = {
    "defend":  (1, 101),  # TLK_RADIAL_HOLD_POSITION — "Hold position!"
    "ambush":  (2,  94),  # TLK_RADIAL_GET_READY     — "Get ready!"
    "sniper":  (2,  96),  # TLK_RADIAL_WATCH_AREA    — "Watch that area"
    "push":    (3,  82),  # TLK_RADIAL_MOVING        — "Moving!"
    "overrun": (4,  97),  # TLK_RADIAL_GO            — "Go go go!"
}


@dataclass(frozen=True, slots=True)
class Order:
    areas: list[str]   # e.g. ["lobby", "courtyard"] or ["lobby", "-balcony"]
    posture: str       # weight profile name
    bots: int          # number of bots to assign


@dataclass(slots=True)
class Commitment:
    target: tuple[float, float, float]
    assigned_at: float
    hold_until: float  # 0 = still moving; >0 = holding at position until this time
    order_key: tuple[tuple[str, ...], str]  # (areas, posture) — invalidates on change
    intermediate: bool = False  # True = en-route area, short hold; False = final area


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
        self.wave_front: WaveFront | None = None
        self.profile_name = "defend"  # set by strategist, used for telemetry context
        self.orders: list[Order] | None = None
        # (timestamp, position, velocity_xy)
        self._spotted_memory: dict[
            int, tuple[float, tuple[float, float, float], tuple[float, float]]
        ] = {}
        # Stuck detection: {bot_id: (last_pos, stuck_since, logged)}
        self._stuck_tracker: dict[int, tuple[tuple[float, float], float, bool]] = {}
        # Position commitment: bots stick to their target for a while
        self._commitments: dict[int, Commitment] = {}
        # Previous orders snapshot — voice callouts only fire when strategist changes orders
        self._prev_orders_key: tuple | None = None
        # Cache key for approach exposure precomputation
        self._cached_approach_key: tuple = ()

    def compute_commands(
        self, state: GameState,
    ) -> tuple[list[BotCommand], list[BotCommandRow]]:
        # Our bots: alive fake clients on the controlled team
        our_bots = [
            b for b in state.bots.values()
            if b.alive and b.is_bot and b.team == self.controlled_team
        ]
        alive_ids = {b.id for b in our_bots}
        self._stuck_tracker = {
            k: v for k, v in self._stuck_tracker.items() if k in alive_ids
        }
        self._commitments = {
            k: v for k, v in self._commitments.items() if k in alive_ids
        }
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

        # Update wave front (danger progression from enemy spawn)
        if self.wave_front is not None:
            enemy_spawn = self._enemy_spawn(state.objectives_lost)
            self.wave_front.update(
                state.objectives_lost, state.phase, enemy_spawn, now,
            )

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

    def _compute_look(
        self,
        bot,
        target: tuple[float, float, float],
        order_posture: str,
        approach_positions: list[tuple[float, float, float]],
        obj_centroid: tuple[float, float, float],
        enemy_positions: list[tuple[float, float, float]],
        enemy_spawn: tuple[float, float, float] | None,
    ) -> tuple[float, float, float]:
        """Compute look direction for a bot given its move target."""
        # Arrived look: approach-watching for defensive postures
        if order_posture in ("defend", "ambush", "sniper"):
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

        if dist2 < ARRIVE_RADIUS * ARRIVE_RADIUS:
            look = arrived_look
        else:
            look = None
            # Threat priority: look at nearest remembered enemy,
            # but only if visible (not behind a wall)
            threat = self._nearest_enemy(bot.pos, enemy_positions)
            if threat is not None and self.influence_map is not None:
                bot_idx = self.influence_map.nearest_point(bot.pos)
                thr_idx = self.influence_map.nearest_point(threat)
                if thr_idx in self.influence_map.visible_from(bot_idx):
                    look = threat

            # Fall through: watch the corner toward last known
            # enemy position, or enemy spawn if no contacts
            if look is None and self.pathfinder is not None \
                    and self.influence_map is not None:
                look_goal = threat if threat is not None else enemy_spawn
                if look_goal is not None:
                    corner = self.pathfinder.find_look_target(
                        bot.pos, look_goal,
                        self.influence_map.nearest_point,
                    )
                    if corner is not None:
                        look = corner

            if look is None:
                look = arrived_look

        # Force horizontal aim — avoid looking up/down due to
        # centroid Z averaging across floors
        return (look[0], look[1], bot.pos[2])

    def _check_stuck(
        self, bot, target: tuple[float, float, float], now: float,
    ) -> bool:
        """Return True if bot is stuck and should be released to native AI."""
        dx = bot.pos[0] - target[0]
        dy = bot.pos[1] - target[1]
        dist2 = dx * dx + dy * dy
        bot_xy = (bot.pos[0], bot.pos[1])

        if bot.id in self._stuck_tracker:
            last_pos, stuck_since, logged = self._stuck_tracker[bot.id]
            moved = ((bot_xy[0] - last_pos[0]) ** 2
                     + (bot_xy[1] - last_pos[1]) ** 2) ** 0.5
            if moved > STUCK_THRESHOLD:
                self._stuck_tracker[bot.id] = (bot_xy, now, False)
            elif dist2 > STUCK_MIN_DIST ** 2 \
                    and now - stuck_since > STUCK_SECONDS:
                if not logged:
                    log.info("Bot %d stuck at (%.0f,%.0f), %.0fu from target, releasing to native AI",
                             bot.id, bot.pos[0], bot.pos[1], dist2 ** 0.5)
                    self._stuck_tracker[bot.id] = (last_pos, stuck_since, True)
                return True
        else:
            self._stuck_tracker[bot.id] = (bot_xy, now, False)
        return False

    @staticmethod
    def _has_nearby_teammate(
        bot,
        friendly_positions: list[tuple[float, float, float]],
        radius: float = 1000.0,
    ) -> bool:
        """Return True if any friendly (excluding self) is within radius (2D)."""
        r2 = radius * radius
        for fp in friendly_positions:
            dx = fp[0] - bot.pos[0]
            dy = fp[1] - bot.pos[1]
            d2 = dx * dx + dy * dy
            if 1.0 < d2 < r2:  # >1 to skip self (same position)
                return True
        return False

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
        now = time.monotonic()

        # Detect strategist order change (not per-bot reassignment)
        orders_key = tuple((tuple(o.areas), o.posture, o.bots) for o in self.orders)
        orders_changed = orders_key != self._prev_orders_key
        self._prev_orders_key = orders_key
        # (priority, concept_id, cmd_index, posture, bot_id) — best picked after all orders
        voice_candidates: list[tuple[int, int, int, str, int]] = []

        approach_positions = self._approach_positions()
        enemy_spawn = self._enemy_spawn(objectives_lost)

        # Precompute approach exposure (only when approach positions change)
        approach_key = tuple(approach_positions)
        if approach_key != self._cached_approach_key:
            self._cached_approach_key = approach_key
            self.influence_map.precompute_approach_exposure(approach_positions)

        for order in self.orders:
            if not remaining:
                break

            n = min(order.bots, len(remaining))
            order_key = (tuple(order.areas), order.posture)

            # Auto-expand areas: include 1-hop adjacent rooms so bots
            # have room to spread.  The strategist only names the target
            # area; the planner decides where around it to position bots.
            expanded = list(order.areas)
            for a in order.areas:
                if a.startswith("-"):
                    continue
                for neighbor in self.area_map._adjacency.get(a, []):
                    if neighbor not in expanded:
                        expanded.append(neighbor)

            # For defend orders with adjacent areas, use only the objective area
            # for proximity pull so bots aren't pulled toward adjacent centroids
            obj_centroid = self._objective_centroid(order.areas)
            centroid = self.area_map.area_centroid(order.areas)

            # Determine sightline targets (what should bots watch?)
            if order.posture in ("defend", "ambush", "sniper"):
                sightline_targets = approach_positions + enemy_positions
            else:
                sightline_targets = [centroid]

            # Partition: bots already committed to this order first, then by distance.
            # This keeps the same bots on the same order when orders don't change.
            committed_here = [b for b in remaining
                              if b.id in self._commitments
                              and self._commitments[b.id].order_key == order_key]
            others = [b for b in remaining if b not in committed_here]
            centroid_arr = np.array(centroid, dtype=np.float32)
            others.sort(
                key=lambda b: float(np.linalg.norm(
                    np.array(b.pos, dtype=np.float32) - centroid_arr,
                )),
            )
            pool = committed_here + others
            batch = pool[:n]
            remaining = [b for b in remaining if b not in batch]

            # --- Commitment-based assignment ---
            # Separate batch into committed (holding/moving) vs needs-new-position
            holding: list = []
            moving: list = []
            needs_assignment: list = []

            for bot in batch:
                c = self._commitments.get(bot.id)
                if c is not None and c.order_key == order_key:
                    if c.hold_until > 0 and now < c.hold_until:
                        holding.append(bot)
                    elif c.hold_until > 0:
                        # Hold expired → needs new position
                        del self._commitments[bot.id]
                        needs_assignment.append(bot)
                    elif now - c.assigned_at < COMMIT_TIMEOUT:
                        # Still moving toward target, check if arrived
                        dx = bot.pos[0] - c.target[0]
                        dy = bot.pos[1] - c.target[1]
                        if dx * dx + dy * dy < ARRIVE_RADIUS * ARRIVE_RADIUS:
                            hold_dur = INTERMEDIATE_HOLD if c.intermediate else HOLD_DURATION
                            c.hold_until = now + hold_dur
                            holding.append(bot)
                            log.debug("Bot %d arrived (%s), holding for %.0fs",
                                      bot.id, "intermediate" if c.intermediate else "final", hold_dur)
                        else:
                            moving.append(bot)
                    else:
                        # Commit timeout — re-score
                        del self._commitments[bot.id]
                        needs_assignment.append(bot)
                else:
                    # No commitment or order changed
                    if bot.id in self._commitments:
                        del self._commitments[bot.id]
                    needs_assignment.append(bot)

            # --- Bounding overwatch ---
            # If group > 1 and nobody is holding, force one bot to cover.
            # Pick the bot closest to enemy spawn (forward on threat axis).
            # Use coarse hop count for topology, Euclidean as tiebreaker.
            if len(batch) > 1 and not holding and needs_assignment:
                cover_ref = enemy_spawn
                if cover_ref is None and approach_positions:
                    cover_ref = approach_positions[0]
                if cover_ref is not None:
                    use_hops = self.pathfinder is not None and self.influence_map is not None
                    needs_assignment.sort(
                        key=lambda b: (
                            self.pathfinder.hop_count(
                                b.pos, cover_ref,
                                self.influence_map.nearest_point,
                            ) if use_hops else 0,
                            (b.pos[0] - cover_ref[0]) ** 2
                            + (b.pos[1] - cover_ref[1]) ** 2,
                        ),
                    )
                # First bot becomes coverer — holds at current position
                coverer = needs_assignment.pop(0)
                self._commitments[coverer.id] = Commitment(
                    target=coverer.pos,
                    assigned_at=now,
                    hold_until=now + HOLD_DURATION / 2,
                    order_key=order_key,
                )
                holding.append(coverer)
                log.debug("Bot %d designated as coverer at (%.0f,%.0f)",
                          coverer.id, coverer.pos[0], coverer.pos[1])

            # Score new positions — area-by-area routing for distant bots
            if needs_assignment:
                weights = WEIGHT_PROFILES.get(order.posture, WEIGHT_PROFILES["defend"])

                # Group bots by their scoring area (next area on path or final)
                # groups: {(area_mask_key, is_intermediate): [bot, ...]}
                final_bots: list = []
                intermediate_groups: dict[str, list] = {}  # next_area_name -> bots

                for bot in needs_assignment:
                    bot_area = self.area_map.pos_to_area(bot.pos)
                    in_target = bot_area is not None and bot_area in expanded

                    if in_target or bot_area is None:
                        final_bots.append(bot)
                    else:
                        # Find next area on path toward the first target area
                        target_area = order.areas[0]
                        path = self.area_map._bfs_path(bot_area, target_area)
                        if path and len(path) > 1:
                            next_area = path[1]
                            intermediate_groups.setdefault(next_area, []).append(bot)
                        else:
                            # No path — fall back to final scoring
                            final_bots.append(bot)

                # Score final-area bots (existing behavior)
                if final_bots:
                    mask = self.area_map.build_mask(expanded)
                    positions = self.influence_map.best_positions(
                        weights,
                        num=len(final_bots),
                        mask=mask,
                        objective_center=obj_centroid,
                        objective_positions=sightline_targets if sightline_targets else [obj_centroid],
                        friendly_positions=friendly_positions,
                        enemy_positions=enemy_positions,
                    )
                    for bot, target in zip(final_bots, positions):
                        self._commitments[bot.id] = Commitment(
                            target=target,
                            assigned_at=now,
                            hold_until=0,
                            order_key=order_key,
                            intermediate=False,
                        )
                        moving.append(bot)

                # Score intermediate-area bots (grouped by next area)
                for next_area_name, group in intermediate_groups.items():
                    area_mask = self.area_map.build_mask([next_area_name])
                    positions = self.influence_map.best_positions(
                        weights,
                        num=len(group),
                        mask=area_mask,
                        objective_center=obj_centroid,
                        objective_positions=sightline_targets if sightline_targets else [obj_centroid],
                        friendly_positions=friendly_positions,
                        enemy_positions=enemy_positions,
                    )
                    for bot, target in zip(group, positions):
                        self._commitments[bot.id] = Commitment(
                            target=target,
                            assigned_at=now,
                            hold_until=0,
                            order_key=order_key,
                            intermediate=True,
                        )
                        moving.append(bot)

            # Emit commands for all bots (holding + moving)
            profile_tag = f"area:{order.posture}"
            voice_candidate_chosen = False
            for bot in holding + moving:
                c = self._commitments.get(bot.id)
                if c is None:
                    continue
                target = c.target

                # Holding bots: offset target toward approach so
                # CINSBotInvestigate has somewhere to walk (patrol).
                # Without this, investigate to current pos completes
                # instantly and the bot stands frozen.
                is_holding = c.hold_until > 0 and now < c.hold_until
                if is_holding:
                    nearest_app = self._nearest_approach(target, approach_positions)
                    if nearest_app is not None:
                        dx = nearest_app[0] - target[0]
                        dy = nearest_app[1] - target[1]
                        length = (dx * dx + dy * dy) ** 0.5
                        if length > 1.0:
                            scale = 400.0 / length
                            target = (
                                target[0] + dx * scale,
                                target[1] + dy * scale,
                                target[2],
                            )

                if self._check_stuck(bot, target, now):
                    continue  # release to native AI

                look = self._compute_look(
                    bot, target, order.posture,
                    approach_positions, obj_centroid,
                    enemy_positions, enemy_spawn,
                )

                # Voice callouts disabled — causes realloc crash in C++ extension
                # TODO: investigate C++ side before re-enabling
                # cmd_idx = len(commands)
                # if orders_changed and not voice_candidate_chosen \
                #         and len(batch) > 1 \
                #         and self._has_nearby_teammate(bot, friendly_positions):
                #     pv = POSTURE_VOICE.get(order.posture)
                #     if pv is not None:
                #         voice_candidate_chosen = True
                #         voice_candidates.append((pv[0], pv[1], cmd_idx, order.posture, bot.id))

                # Distance to target — approach (run) when far, investigate (cautious) when close.
                # CINSBotInvestigate is designed for short-range cautious movement;
                # using it at 1500u+ makes bots crawl instead of repositioning.
                dx_t = bot.pos[0] - target[0]
                dy_t = bot.pos[1] - target[1]
                dist_to_target = (dx_t * dx_t + dy_t * dy_t) ** 0.5
                investigate_threshold = 500.0

                if dist_to_target < investigate_threshold:
                    # Close to target — cautious approach
                    flags = CMD_FLAG_INVESTIGATE
                elif c.intermediate and self.wave_front is not None:
                    # Far, intermediate — run through safe areas, cautious in danger
                    tgt_area = self.area_map.pos_to_area(target)
                    if tgt_area and tgt_area in self.area_map.areas:
                        area_center = self.area_map.areas[tgt_area].center
                        flags = CMD_FLAG_INVESTIGATE if self.wave_front.is_area_danger(area_center, now) else 0
                    else:
                        flags = 0
                else:
                    # Far, final area — run to get there, will switch to investigate when close
                    flags = 0

                commands.append(BotCommand(
                    id=bot.id,
                    move_target=target,
                    look_target=look,
                    flags=flags,
                ))
                bot_profiles[bot.id] = profile_tag
                assigned_ids.add(bot.id)

        # Pick the single highest-priority voice callout across all orders.
        # Offensive postures (overrun, push) beat defensive (defend).
        if voice_candidates:
            voice_candidates.sort(key=lambda c: c[0], reverse=True)
            _prio, concept, cmd_idx, posture, bot_id = voice_candidates[0]
            commands[cmd_idx] = BotCommand(
                id=commands[cmd_idx].id,
                move_target=commands[cmd_idx].move_target,
                look_target=commands[cmd_idx].look_target,
                flags=commands[cmd_idx].flags,
                voice=concept,
            )
            log.info("Bot %d calls out posture '%s' (concept %d)",
                     bot_id, posture, concept)

        # Leftover bots (not assigned by any order): no commands sent,
        # vanilla AI controls them.

        return commands
