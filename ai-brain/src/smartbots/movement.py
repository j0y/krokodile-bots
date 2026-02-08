"""Movement controller — MVP: send all alive bots to a fixed convergence point."""

from __future__ import annotations

from smartbots.protocol import BotCommand
from smartbots.state import GameState

# Fixed convergence point on ministry_coop (central area, ground level).
# Bots typically spawn around x=1800-2500, y=-500 to -1400.
# This point is within the accessible area.
TARGET = (2200.0, -1100.0, 32.0)


def compute_commands(state: GameState) -> list[BotCommand]:
    """For each alive bot, return a command to walk toward the fixed target."""
    commands: list[BotCommand] = []
    for bot in state.bots.values():
        if not bot.alive:
            continue
        commands.append(BotCommand(id=bot.id, target=TARGET, speed=1.0))
    return commands
