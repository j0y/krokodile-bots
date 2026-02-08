"""Movement controller — MVP: send all alive bots to a hardcoded waypoint on ministry."""

from __future__ import annotations

from smartbots.protocol import BotCommand
from smartbots.state import GameState

# Hardcoded waypoint on ministry (near Security spawn, ground level)
# This is a known walkable position on ministry_coop.
TARGET = (480.0, 1440.0, 0.0)


def compute_commands(state: GameState) -> list[BotCommand]:
    """For each alive bot, return a command to walk toward the hardcoded target."""
    commands: list[BotCommand] = []
    for bot in state.bots.values():
        if not bot.alive:
            continue
        commands.append(BotCommand(id=bot.id, target=TARGET, speed=1.0))
    return commands
