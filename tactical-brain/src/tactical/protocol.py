"""JSON encode/decode for the C++ extension <-> Python protocol.

State (C++ -> Python): JSON
    {"tick": 123, "bots": [{"id": 3, "pos": [x,y,z], "ang": [p,y,r], "hp": 100, "alive": 1, "team": 2, "bot": 1}]}

Commands (Python -> C++): line-based text, one bot per line
    <id> <mx> <my> <mz> <lx> <ly> <lz> <flags>\n
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from tactical.state import BotState, GameState

# Action flag bitmask constants (must match C++ extension)
FLAG_JUMP = 1
FLAG_DUCK = 2
FLAG_ATTACK = 4
FLAG_RELOAD = 8
FLAG_WALK = 16
FLAG_SPRINT = 32
FLAG_USE = 64
FLAG_ATTACK2 = 128
FLAG_TELEPORT = 256


def decode_state(data: bytes) -> GameState:
    """Parse a state JSON packet from C++ into a GameState."""
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
            is_bot=bool(b.get("bot", 1)),
            sees=b.get("sees", []),
            traces=b.get("traces", []),
        )
        bots[bot.id] = bot
    return GameState(
        tick=int(raw.get("tick", 0)),
        bots=bots,
        objectives_captured=int(raw.get("obj", 0)),
        phase=raw.get("phase", "active"),
        capping_cp=int(raw.get("cap", -1)),
        ca_disabled=bool(raw.get("ca_off", 0)),
        ca_duration=int(raw.get("ca_dur", 65)),
        ca_duration_finale=int(raw.get("ca_dur_f", 120)),
    )


@dataclass
class BotCommand:
    """A movement + look + action command for a single bot."""

    id: int
    move_target: tuple[float, float, float]
    look_target: tuple[float, float, float]
    flags: int = 0


def encode_commands(commands: list[BotCommand]) -> bytes:
    """Encode a list of bot commands into the line-based text format for C++."""
    lines: list[str] = []
    for cmd in commands:
        lines.append(
            f"{cmd.id}"
            f" {cmd.move_target[0]:.1f} {cmd.move_target[1]:.1f} {cmd.move_target[2]:.1f}"
            f" {cmd.look_target[0]:.1f} {cmd.look_target[1]:.1f} {cmd.look_target[2]:.1f}"
            f" {cmd.flags}"
        )
    return "\n".join(lines).encode("utf-8")
