"""LLM Strategist (Layer 1): observes game state, detects tactical events,
and issues per-area orders for the planner."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass

import httpx

from tactical.areas import AreaMap
from tactical.influence_map import WEIGHT_PROFILES
from tactical.planner import Order, Planner
from tactical.state import GameState

log = logging.getLogger(__name__)

VALID_PROFILES = frozenset(WEIGHT_PROFILES.keys())


def _build_system_prompt(area_map: AreaMap) -> str:
    area_desc = area_map.describe()

    # Collect roles for enemy intel
    approach_areas = [
        a.name for a in area_map.areas.values()
        if a.role in ("enemy_spawn", "enemy_approach")
    ]
    approach_note = ""
    if approach_areas:
        approach_note = (
            "\n\nEnemy likely approaches from: "
            + ", ".join(approach_areas) + "."
        )

    return f"""\
You are a tactical AI commander for a team of bots in Insurgency (2014).
Your team is defending against human attackers. Issue per-area orders
to position your bots effectively.

{area_desc}

Available postures:
- "defend": Hold positions with good cover and sightlines near the objective.
- "push": Aggressively advance toward the objective. Low concern for cover.
- "ambush": Hide in concealed positions. Surprise enemies who pass by.
- "sniper": Long sightlines, elevated positions, spread out.
- "overrun": All-out rush to the objective. Ignore threats.
{approach_note}
Rules:
- Respond ONLY with JSON: {{"orders": [{{"areas": ["area1", ...], "posture": "<name>", "bots": N}}, ...], "reasoning": "<1 sentence>"}}
- Each order assigns N bots to the listed areas with a posture.
- You can combine areas: ["lobby", "courtyard"] covers both.
- You can subtract areas: ["-balcony"] removes that zone from the order.
- Total bots across all orders should roughly match your team size.
- If taking heavy losses, consider changing postures.
- If stalemate, try something more aggressive.
- Vary your choices — don't always pick "defend".\
"""


@dataclass(frozen=True, slots=True)
class _Snapshot:
    timestamp: float
    friendly_alive: int
    friendly_total: int
    enemy_alive: int
    spotted_enemy_ids: frozenset[int]
    friendly_ids_alive: frozenset[int]
    enemy_ids_alive: frozenset[int]
    current_profile: str


class Strategist:
    def __init__(
        self,
        planner: Planner,
        area_map: AreaMap,
        api_key: str,
        model: str = "anthropic/claude-3.5-haiku",
        base_url: str = "https://openrouter.ai/api/v1",
        min_interval: float = 12.0,
    ) -> None:
        self._planner = planner
        self._area_map = area_map
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._min_interval = min_interval

        self._system_prompt = _build_system_prompt(area_map)
        self._client = httpx.AsyncClient()
        self._pending_state: GameState | None = None

        self._prev_snapshot: _Snapshot | None = None
        self._last_call_time: float = 0.0
        self._last_event_time: float = 0.0

        # Last 5 decisions for context
        self._profile_history: list[tuple[float, str, str]] = []  # (time, profile, reasoning)

        self._task: asyncio.Task[None] | None = None
        self._heavy_losses_triggered = False

    def update_state(self, state: GameState) -> None:
        """Called from datagram_received — just stash the latest state."""
        self._pending_state = state

    def start(self) -> None:
        """Start the background polling task on the current event loop."""
        self._task = asyncio.create_task(self._run())
        log.info("Strategist background task started")

    async def close(self) -> None:
        """Cancel the background task and close the HTTP client."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Strategist tick error")

    async def _tick(self) -> None:
        state = self._pending_state
        if state is None:
            return

        controlled = self._planner.controlled_team
        friendly_alive = [
            b for b in state.bots.values()
            if b.alive and b.team == controlled
        ]
        if not friendly_alive:
            return

        curr = self._take_snapshot(state, controlled)
        now = curr.timestamp

        events = self._detect_events(self._prev_snapshot, curr)

        # Check stalemate (separate timer)
        if not events and self._prev_snapshot is not None:
            if now - self._last_event_time >= 30.0:
                events.append(f"STALEMATE: no change for {int(now - self._last_event_time)}s")

        if events:
            self._last_event_time = now

        self._prev_snapshot = curr

        if not events:
            return

        # Rate limiting — consume events but skip LLM call
        if now - self._last_call_time < self._min_interval:
            log.debug("Strategist: rate limited, skipping LLM call (events: %s)", events)
            return

        # Build enemy positions for area mapping
        enemy_positions: list[tuple[float, float, float]] = []
        for b in state.bots.values():
            if b.alive and b.team != controlled and b.team > 1:
                if b.id in curr.spotted_enemy_ids:
                    enemy_positions.append(b.pos)

        sitrep = self._build_sitrep(curr, events, enemy_positions)
        log.info("Strategist: triggering LLM call -- events: %s", events)

        self._last_call_time = now
        reasoning, orders = await self._call_llm(sitrep)

        if orders is not None:
            self._planner.orders = orders
            self._planner.profile_name = orders[0].posture  # fallback for unassigned
            summary = ", ".join(
                f"{o.posture}@{'+'.join(o.areas)}({o.bots})" for o in orders
            )
            self._profile_history.append((now, summary, reasoning or ""))
            if len(self._profile_history) > 5:
                self._profile_history.pop(0)
            log.info("Strategist: area orders: %s (%s)", summary, reasoning)

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def _take_snapshot(self, state: GameState, controlled_team: int) -> _Snapshot:
        friendly_alive_ids: set[int] = set()
        friendly_total = 0
        enemy_alive_ids: set[int] = set()
        spotted: set[int] = set()

        for b in state.bots.values():
            if b.team == controlled_team:
                friendly_total += 1
                if b.alive:
                    friendly_alive_ids.add(b.id)
                    spotted.update(b.sees)
            elif b.team > 1:
                if b.alive:
                    enemy_alive_ids.add(b.id)

        return _Snapshot(
            timestamp=time.monotonic(),
            friendly_alive=len(friendly_alive_ids),
            friendly_total=friendly_total,
            enemy_alive=len(enemy_alive_ids),
            spotted_enemy_ids=frozenset(spotted),
            friendly_ids_alive=frozenset(friendly_alive_ids),
            enemy_ids_alive=frozenset(enemy_alive_ids),
            current_profile=self._planner.profile_name,
        )

    # ------------------------------------------------------------------
    # Event detection
    # ------------------------------------------------------------------

    def _detect_events(self, prev: _Snapshot | None, curr: _Snapshot) -> list[str]:
        events: list[str] = []

        if prev is None:
            events.append(
                f"ROUND_START: {curr.friendly_alive} friendlies vs {curr.enemy_alive} enemies"
            )
            return events

        # Round restart: everyone was dead, now alive again
        if prev.friendly_alive == 0 and curr.friendly_alive > 0:
            events.append(
                f"ROUND_START: {curr.friendly_alive} friendlies vs {curr.enemy_alive} enemies"
            )
            self._heavy_losses_triggered = False
            return events

        # Friendly casualties
        lost = prev.friendly_ids_alive - curr.friendly_ids_alive
        if lost:
            events.append(
                f"CASUALTY: lost {len(lost)} friendlies ({curr.friendly_alive} remaining)"
            )

        # Enemy down
        killed = prev.enemy_ids_alive - curr.enemy_ids_alive
        if killed:
            events.append(
                f"ENEMY_DOWN: {len(killed)} eliminated ({curr.enemy_alive} remaining)"
            )

        # New contacts
        new_contacts = curr.spotted_enemy_ids - prev.spotted_enemy_ids
        if new_contacts:
            events.append(
                f"CONTACT: {len(new_contacts)} new enemies spotted "
                f"({len(curr.spotted_enemy_ids)} total)"
            )

        # Lost all contact
        if prev.spotted_enemy_ids and not curr.spotted_enemy_ids:
            events.append("LOST_CONTACT: no enemies visible")

        # Heavy losses threshold (trigger once per round)
        if (
            not self._heavy_losses_triggered
            and curr.friendly_total > 0
            and curr.friendly_alive <= curr.friendly_total * 0.5
            and prev.friendly_alive > prev.friendly_total * 0.5
        ):
            self._heavy_losses_triggered = True
            events.append(
                f"HEAVY_LOSSES: below 50% strength "
                f"({curr.friendly_alive}/{curr.friendly_total})"
            )

        return events

    # ------------------------------------------------------------------
    # SITREP builder
    # ------------------------------------------------------------------

    def _build_sitrep(
        self,
        curr: _Snapshot,
        events: list[str],
        enemy_positions: list[tuple[float, float, float]],
    ) -> str:
        now = curr.timestamp
        profile_age = int(now - (self._profile_history[-1][0] if self._profile_history else now))

        lines = [
            "SITREP:",
            f"- Friendly: {curr.friendly_alive}/{curr.friendly_total} alive",
            f"- Enemy: ~{curr.enemy_alive} alive, "
            f"{len(curr.spotted_enemy_ids)} currently spotted",
            f"- Current posture: {curr.current_profile} ({profile_age}s)",
        ]

        # Per-area enemy info
        enemies_by_area = self._area_map.enemies_per_area(enemy_positions)
        approach_areas = [
            a.name for a in self._area_map.areas.values()
            if a.role in ("enemy_spawn", "enemy_approach")
        ]
        lines.append("")
        lines.append("ENEMY SITUATION:")
        if enemies_by_area:
            spotted_parts = [f"{name} ({count})" for name, count in enemies_by_area.items()]
            lines.append(f"- Spotted: {', '.join(spotted_parts)}")
        else:
            lines.append("- Spotted: none")
        if approach_areas:
            lines.append(f"- Likely approach: {', '.join(approach_areas)}")

        lines.append("")
        lines.append("EVENTS:")
        for ev in events:
            lines.append(f"- {ev}")

        if self._profile_history:
            lines.append("")
            lines.append("RECENT DECISIONS:")
            for t, profile, reasoning in self._profile_history:
                ago = int(now - t)
                lines.append(f"- {ago}s ago: {profile} (\"{reasoning}\")")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # LLM call
    # ------------------------------------------------------------------

    async def _call_llm(self, sitrep: str) -> tuple[str | None, list[Order] | None]:
        """Returns (reasoning, orders) or (None, None) on failure."""
        try:
            response = await self._client.post(
                f"{self._base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model,
                    "messages": [
                        {"role": "system", "content": self._system_prompt},
                        {"role": "user", "content": sitrep},
                    ],
                    "temperature": 0.7,
                    "max_tokens": 1024,
                },
                timeout=5.0,
            )
            response.raise_for_status()
        except httpx.TimeoutException:
            log.warning("Strategist: LLM call timed out")
            return None, None
        except httpx.HTTPStatusError as exc:
            log.warning("Strategist: LLM HTTP %d: %s", exc.response.status_code, exc.response.text[:200])
            return None, None
        except httpx.HTTPError as exc:
            log.warning("Strategist: LLM request failed: %s", exc)
            return None, None

        return self._parse_response(response.json())

    def _parse_response(self, body: dict) -> tuple[str | None, list[Order] | None]:
        """Parse OpenAI-compatible chat completion response into orders."""
        try:
            text = body["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError, TypeError):
            log.warning("Strategist: unexpected response structure: %s", body)
            return None, None

        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            log.warning("Strategist: could not parse LLM response as JSON: %s", text[:200])
            return None, None

        reasoning = obj.get("reasoning", "")
        raw_orders = obj.get("orders")
        if not isinstance(raw_orders, list) or not raw_orders:
            log.warning("Strategist: no valid orders in response: %s", text[:200])
            return None, None

        orders: list[Order] = []
        for entry in raw_orders:
            try:
                areas = entry["areas"]
                posture = entry["posture"].lower().strip()
                bots = int(entry["bots"])
            except (KeyError, TypeError, ValueError) as exc:
                log.warning("Strategist: invalid order entry %s: %s", entry, exc)
                continue

            if not isinstance(areas, list) or not areas:
                log.warning("Strategist: order has empty areas: %s", entry)
                continue
            if posture not in VALID_PROFILES:
                log.warning("Strategist: invalid posture '%s', skipping order", posture)
                continue
            if bots < 1:
                continue

            orders.append(Order(areas=areas, posture=posture, bots=bots))

        if not orders:
            log.warning("Strategist: all orders invalid in response: %s", text[:200])
            return None, None

        return reasoning, orders
