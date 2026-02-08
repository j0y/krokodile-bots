"""JSON encode/decode for the SM ↔ Python protocol.

State (SM → Python): JSON
    {"tick": 123, "bots": [{"id": 3, "pos": [x,y,z], "ang": [p,y,r], "hp": 100, "alive": 1, "team": 2}]}

Commands (Python → SM): line-based text, one bot per line
    <id> <target_x> <target_y> <target_z> <speed>\n
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from smartbots.state import BotState, GameState


def decode_state(data: bytes) -> GameState:
    """Parse a state JSON packet from SM into a GameState."""
    raw: dict[str, Any] = json.loads(data)
    bots: dict[int, BotState] = {}
    for b in raw.get("bots", []):
        bot = BotState(
            id=int(b["id"]),
            pos=tuple(b["pos"]),  # type: ignore[arg-type]
            ang=tuple(b["ang"]),  # type: ignore[arg-type]
            health=int(b["hp"]),
            alive=bool(b["alive"]),
            team=int(b["team"]),
        )
        bots[bot.id] = bot
    return GameState(tick=int(raw.get("tick", 0)), bots=bots)


@dataclass
class BotCommand:
    """A movement command for a single bot."""

    id: int
    target: tuple[float, float, float]
    speed: float = 1.0


def encode_commands(commands: list[BotCommand]) -> bytes:
    """Encode a list of bot commands into the line-based text format for SM."""
    lines: list[str] = []
    for cmd in commands:
        lines.append(
            f"{cmd.id} {cmd.target[0]:.1f} {cmd.target[1]:.1f} {cmd.target[2]:.1f} {cmd.speed:.2f}"
        )
    return "\n".join(lines).encode("utf-8")
