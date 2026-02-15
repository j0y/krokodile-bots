"""LLM Strategist: calls an OpenRouter-compatible chat API to decide orders."""

from __future__ import annotations

import json
import logging
import re

import httpx

from tactical.areas import AreaMap
from tactical.planner import Order, Planner
from tactical.strategist import VALID_PROFILES, BaseStrategist, TacticalEvent, _Snapshot
from tactical.telemetry import TelemetryClient

log = logging.getLogger(__name__)


_SYSTEM_PROMPT = """\
You are a tactical AI commander for a team of bots in Insurgency (2014).
Your team is defending against human attackers who capture objectives in sequence.

Available postures:
- "defend": Hold positions with good cover and sightlines near the area.
- "push": Aggressively advance toward the area. Low concern for cover.
- "ambush": Hide in concealed positions near the area.
- "sniper": Long sightlines, elevated positions, spread out.
- "overrun": All-out rush. Ignore threats.

Rules:
- Respond with a SINGLE LINE of compact JSON: {"orders": [{"area": "<area>", "posture": "<name>", "bots": N}, ...], "reasoning": "<1 sentence>"}
- Each order names ONE target area. Bots automatically spread to adjacent rooms.
- Use ONLY area names from the AREA NAMES list in the sitrep.
- Total bots should match your team size.
- Distribute bots across approach corridors to create crossfire from multiple directions. Don't cluster everyone on one area.
- Keep a small backstop (~20%) on the objective itself.
- When enemies are spotted, push toward the hotspot while flanking from adjacent corridors.
- If taking heavy losses, pull back tight to the objective.\
"""


class LLMStrategist(BaseStrategist):
    def __init__(
        self,
        planner: Planner,
        area_map: AreaMap,
        api_key: str,
        model: str = "anthropic/claude-3.5-haiku",
        base_url: str = "https://openrouter.ai/api/v1",
        min_interval: float = 12.0,
        telemetry: TelemetryClient | None = None,
    ) -> None:
        super().__init__(planner, area_map, min_interval=min_interval, telemetry=telemetry)
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient()
        # Last 5 decisions for context in sitrep
        self._profile_history: list[tuple[float, str, str]] = []

        # Pre-compute objective sequence and spawn names
        self._objectives = sorted(
            (a for a in area_map.areas.values() if a.role == "objective"),
            key=lambda a: a.order,
        )
        self._spawn_names = [
            a.name for a in area_map.areas.values()
            if a.role in ("enemy_spawn", "enemy_approach")
        ]

    async def close(self) -> None:
        await super().close()
        await self._client.aclose()

    # ------------------------------------------------------------------
    # _decide  →  sitrep  →  LLM call  →  parse
    # ------------------------------------------------------------------

    async def _decide(
        self,
        snapshot: _Snapshot,
        events: list[TacticalEvent],
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str | None, list[Order] | None]:
        # Counter-attack: skip LLM, release all bots to vanilla AI.
        # The engine's native push logic is better than anything we
        # can plan in 60s, and bots respawn after anyway.
        if snapshot.counter_attack:
            log.info("LLMStrategist: counter-attack → vanilla AI takes over")
            self._planner.orders = None
            self._planner._commitments.clear()
            return "COUNTER-ATTACK: releasing to vanilla AI", None

        sitrep = self._build_sitrep(snapshot, events, enemy_positions)
        reasoning, orders = await self._call_llm(sitrep)

        if orders is not None:
            summary = ", ".join(
                f"{o.posture}@{'+'.join(o.areas)}({o.bots})" for o in orders
            )
            self._profile_history.append(
                (snapshot.timestamp, summary, reasoning or "")
            )
            if len(self._profile_history) > 5:
                self._profile_history.pop(0)

        return reasoning, orders

    # ------------------------------------------------------------------
    # Tactical context: current objective, enemy spawn, entry corridors
    # ------------------------------------------------------------------

    def _tactical_context(self, objectives_lost: int) -> tuple[str, list[str]]:
        """Build dynamic tactical context based on objectives_lost.

        Returns (context_text, valid_area_names).
        """
        lines: list[str] = []
        valid_names: list[str] = []

        # Current objective
        obj_name: str | None = None
        if objectives_lost < len(self._objectives):
            obj = self._objectives[objectives_lost]
            obj_name = obj.name
            lines.append(f"Defending: {obj_name}")
            valid_names.append(obj_name)
        else:
            lines.append("All objectives lost!")

        # Enemy spawn location
        if objectives_lost > 0 and objectives_lost <= len(self._objectives):
            spawn_names = [self._objectives[objectives_lost - 1].name]
            lines.append(f"Enemy spawns at: {spawn_names[0]} (last captured)")
        else:
            spawn_names = list(self._spawn_names)
            lines.append(f"Enemy spawns at: {', '.join(spawn_names)}")

        # Approach corridors: zones between current spawn and objective
        if obj_name:
            corridors = self._area_map.approach_corridors(spawn_names, obj_name)
            if corridors:
                lines.append(
                    f"Approach corridors (zones between spawn and objective): "
                    f"{', '.join(corridors)}"
                )
                valid_names.extend(corridors)

        return "\n".join(lines), valid_names

    # ------------------------------------------------------------------
    # SITREP builder
    # ------------------------------------------------------------------

    def _build_sitrep(
        self,
        curr: _Snapshot,
        events: list[TacticalEvent],
        enemy_positions: list[tuple[float, float, float]],
    ) -> str:
        now = curr.timestamp
        profile_age = int(
            now - (self._profile_history[-1][0] if self._profile_history else now)
        )

        # Dynamic tactical context
        context, valid_names = self._tactical_context(curr.objectives_lost)

        lines = [
            "SITREP:",
            f"- Friendly: {curr.friendly_alive}/{curr.friendly_total} alive",
            f"- Enemy: ~{curr.enemy_alive} alive, "
            f"{len(curr.spotted_enemy_ids)} currently spotted",
            f"- Current posture: {curr.current_profile} ({profile_age}s)",
            f"- {context.replace(chr(10), chr(10) + '- ')}",
        ]

        # Note: counter-attack is handled before _build_sitrep is called
        # (vanilla AI takes over), so this branch shouldn't be reached.
        if curr.counter_attack:
            obj_name = self._objectives[curr.objectives_lost - 1].name if curr.objectives_lost > 0 else "unknown"
            lines.append(f"- COUNTER-ATTACK PHASE: retake {obj_name}!")
        if curr.capping_cp >= 0:
            lines.append(f"- ALERT: Enemy capturing point {curr.capping_cp}!")

        # Per-area enemy info
        enemies_by_area = self._area_map.enemies_per_area(enemy_positions)
        lines.append("")
        lines.append("ENEMY SITUATION:")
        if enemies_by_area:
            spotted_parts = [
                f"{name} ({count})" for name, count in enemies_by_area.items()
            ]
            lines.append(f"- Spotted: {', '.join(spotted_parts)}")
        else:
            lines.append("- Spotted: none")

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

        lines.append("")
        lines.append(f"AREA NAMES (use these): {', '.join(valid_names)}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # LLM call
    # ------------------------------------------------------------------

    async def _call_llm(
        self, sitrep: str,
    ) -> tuple[str | None, list[Order] | None]:
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
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": sitrep},
                    ],
                    "temperature": 0.7,
                    "max_tokens": 1024,
                },
                timeout=5.0,
            )
            response.raise_for_status()
        except httpx.TimeoutException:
            log.warning("LLMStrategist: call timed out")
            return None, None
        except httpx.HTTPStatusError as exc:
            log.warning(
                "LLMStrategist: HTTP %d: %s",
                exc.response.status_code,
                exc.response.text[:200],
            )
            return None, None
        except httpx.HTTPError as exc:
            log.warning("LLMStrategist: request failed: %s", exc)
            return None, None

        return self._parse_response(response.json())

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _salvage_truncated(text: str) -> dict | None:
        """Try to extract complete order objects from truncated JSON."""
        pattern = (
            r'\{"area(?:s)?"\s*:\s*(?:\[[^\]]*\]|"[^"]+")\s*,\s*'
            r'"posture"\s*:\s*"[^"]+"\s*,\s*'
            r'"bots"\s*:\s*\d+\s*\}'
        )
        matches = re.findall(pattern, text)
        if not matches:
            return None
        orders = []
        for m in matches:
            try:
                orders.append(json.loads(m))
            except json.JSONDecodeError:
                continue
        if not orders:
            return None
        log.info(
            "LLMStrategist: salvaged %d orders from truncated response",
            len(orders),
        )
        return {"orders": orders, "reasoning": "truncated"}

    def _parse_response(
        self, body: dict,
    ) -> tuple[str | None, list[Order] | None]:
        """Parse OpenAI-compatible chat completion response into orders."""
        try:
            text = body["choices"][0]["message"]["content"].strip()
            finish_reason = body["choices"][0].get("finish_reason", "unknown")
        except (KeyError, IndexError, TypeError):
            log.warning(
                "LLMStrategist: unexpected response structure: %s", body,
            )
            return None, None

        log.info("LLMStrategist: raw response (finish=%s): %s", finish_reason, text)

        if finish_reason == "length":
            log.warning(
                "LLMStrategist: response truncated (finish_reason=length)",
            )

        # Strip markdown code fences if present
        if text.startswith("```"):
            first_nl = text.find("\n")
            if first_nl != -1:
                text = text[first_nl + 1 :]
            last_fence = text.rfind("```")
            if last_fence != -1:
                text = text[:last_fence]
            text = text.strip()

        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = self._salvage_truncated(text)
            if obj is None:
                log.warning(
                    "LLMStrategist: could not parse response as JSON: %s",
                    text[:300],
                )
                return None, None

        reasoning = obj.get("reasoning", "")
        raw_orders = obj.get("orders")
        if not isinstance(raw_orders, list) or not raw_orders:
            log.warning(
                "LLMStrategist: no valid orders in response: %s", text[:200],
            )
            return None, None

        orders: list[Order] = []
        for entry in raw_orders:
            try:
                # Accept both "area" (string) and "areas" (list) formats
                raw_area = entry.get("area", entry.get("areas"))
                if isinstance(raw_area, str):
                    areas = [raw_area]
                elif isinstance(raw_area, list) and raw_area:
                    areas = raw_area[:1]  # take only the first area
                else:
                    log.warning(
                        "LLMStrategist: order has no area: %s", entry,
                    )
                    continue
                posture = entry["posture"].lower().strip()
                bots = int(entry["bots"])
            except (KeyError, TypeError, ValueError) as exc:
                log.warning(
                    "LLMStrategist: invalid order entry %s: %s", entry, exc,
                )
                continue
            if posture not in VALID_PROFILES:
                log.warning(
                    "LLMStrategist: invalid posture '%s', skipping", posture,
                )
                continue
            if bots < 1:
                continue

            orders.append(Order(areas=areas, posture=posture, bots=bots))

        if not orders:
            log.warning(
                "LLMStrategist: all orders invalid: %s", text[:200],
            )
            return None, None

        return reasoning, orders

    # ------------------------------------------------------------------
    # Telemetry hooks
    # ------------------------------------------------------------------

    def _get_state_name(self) -> str:
        return "LLM"

    def _get_prev_state_name(self) -> str | None:
        return "LLM"
