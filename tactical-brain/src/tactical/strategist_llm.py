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


def _build_system_prompt(area_map: AreaMap) -> str:
    area_desc = area_map.describe()
    area_names = sorted(area_map.areas.keys())

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

    # Pick two example names for the prompt
    ex1 = area_names[0] if len(area_names) > 0 else "area1"
    ex2 = area_names[1] if len(area_names) > 1 else "area2"

    return f"""\
You are a tactical AI commander for a team of bots in Insurgency (2014).
Your team is defending against human attackers. Issue per-area orders
to position your bots effectively.

{area_desc}

VALID AREA NAMES (use ONLY these): {", ".join(area_names)}

Available postures:
- "defend": Hold positions with good cover and sightlines near the objective.
- "push": Aggressively advance toward the objective. Low concern for cover.
- "ambush": Hide in concealed positions. Surprise enemies who pass by.
- "sniper": Long sightlines, elevated positions, spread out.
- "overrun": All-out rush to the objective. Ignore threats.
{approach_note}
Rules:
- Respond with a SINGLE LINE of compact JSON (no markdown, no code fences, no newlines): {{"orders": [{{"areas": ["{ex1}", ...], "posture": "<name>", "bots": N}}, ...], "reasoning": "<1 sentence>"}}
- Use ONLY the area names listed above. Do NOT invent new names.
- Each order assigns N bots to the listed areas with a posture.
- You can combine areas: ["{ex1}", "{ex2}"] covers both.
- You can subtract areas: ["-{ex2}"] removes that zone from the order.
- Use at most 3 orders. Keep it simple.
- Total bots across all orders should roughly match your team size.
- If taking heavy losses, consider changing postures.
- If stalemate, try something more aggressive.
- Vary your choices — don't always pick "defend".\
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
        self._system_prompt = _build_system_prompt(area_map)
        self._client = httpx.AsyncClient()
        # Last 5 decisions for context in sitrep
        self._profile_history: list[tuple[float, str, str]] = []

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

        lines = [
            "SITREP:",
            f"- Friendly: {curr.friendly_alive}/{curr.friendly_total} alive",
            f"- Enemy: ~{curr.enemy_alive} alive, "
            f"{len(curr.spotted_enemy_ids)} currently spotted",
            f"- Current posture: {curr.current_profile} ({profile_age}s)",
            f"- Objectives lost: {curr.objectives_captured}",
        ]

        if curr.counter_attack:
            lines.append("- COUNTER-ATTACK PHASE: push aggressively to retake the lost objective!")
        if curr.capping_cp >= 0:
            lines.append(f"- ALERT: Enemy capturing point {curr.capping_cp}!")

        # Per-area enemy info
        enemies_by_area = self._area_map.enemies_per_area(enemy_positions)
        approach_areas = [
            a.name for a in self._area_map.areas.values()
            if a.role in ("enemy_spawn", "enemy_approach")
        ]
        lines.append("")
        lines.append("ENEMY SITUATION:")
        if enemies_by_area:
            spotted_parts = [
                f"{name} ({count})" for name, count in enemies_by_area.items()
            ]
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
            r'\{"areas"\s*:\s*\[[^\]]*\]\s*,\s*'
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
                areas = entry["areas"]
                posture = entry["posture"].lower().strip()
                bots = int(entry["bots"])
            except (KeyError, TypeError, ValueError) as exc:
                log.warning(
                    "LLMStrategist: invalid order entry %s: %s", entry, exc,
                )
                continue

            if not isinstance(areas, list) or not areas:
                log.warning(
                    "LLMStrategist: order has empty areas: %s", entry,
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
