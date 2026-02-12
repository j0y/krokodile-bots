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
    sees: list[int] = field(default_factory=list)
    traces: list[float] = field(default_factory=list)


@dataclass
class GameState:
    tick: int
    bots: dict[int, BotState] = field(default_factory=dict)
    objectives_captured: int = 0
    phase: str = "active"    # "preround", "active", "over"
    capping_cp: int = -1     # CP index being captured by enemy, -1 if none
    # Counter-attack state from engine
    counter_attack: bool = False  # CINSRules::IsCounterAttack() — live flag
    ca_disabled: bool = False     # mp_checkpoint_counterattack_disable
    ca_duration: int = 65         # mp_checkpoint_counterattack_duration
    ca_duration_finale: int = 120 # mp_checkpoint_counterattack_duration_finale
    # Active control point index from g_pObjectiveResource
    active_cp: int = -1
