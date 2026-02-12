from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BotState:
    id: int
    pos: tuple[float, float, float]
    ang: tuple[float, float, float]
    health: int
    alive: bool
    team: int
    is_bot: bool = True
    traces: list[float] = field(default_factory=list)


@dataclass
class GameState:
    tick: int
    bots: dict[int, BotState] = field(default_factory=dict)
