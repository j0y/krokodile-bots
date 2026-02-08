"""Async UDP server — receives bot state from SM, sends commands back."""

from __future__ import annotations

import asyncio
import logging
import os
import signal

from smartbots.behavior import BotManager
from smartbots.navigation import NavGraph
from smartbots.protocol import BotCommand, decode_state, encode_commands
from smartbots.spatial_recorder import SpatialRecorder
from smartbots.state import GameState
from smartbots.strategy import GatheringStrategy
from smartbots.terrain import TerrainAnalyzer

log = logging.getLogger(__name__)


class AIBrainProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for the AI brain."""

    def __init__(self, manager: BotManager, recorder: SpatialRecorder | None = None) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.last_state: GameState | None = None
        self.manager = manager
        self.recorder = recorder

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        log.info("UDP server ready")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            state = decode_state(data)
        except Exception:
            log.exception("Failed to decode state packet")
            return

        self.last_state = state
        bot_count = len(state.bots)
        alive_count = sum(1 for b in state.bots.values() if b.alive)

        # Record positions when enabled
        if self.recorder is not None:
            for b in state.bots.values():
                if b.alive:
                    self.recorder.record(b.id, b.pos)
            self.recorder.maybe_save(state.tick)

        # Log per-bot details every ~5 seconds (tick divisible by 40 at 8Hz)
        if state.tick % 40 == 0:
            log.info("tick=%d bots=%d alive=%d from=%s", state.tick, bot_count, alive_count, addr)
            for b in state.bots.values():
                log.info(
                    "  bot=%d alive=%s team=%d hp=%d pos=(%.0f,%.0f,%.0f) ang=(%.0f,%.0f,%.0f)",
                    b.id, b.alive, b.team, b.health,
                    b.pos[0], b.pos[1], b.pos[2],
                    b.ang[0], b.ang[1], b.ang[2],
                )

        # Compute commands and send back
        commands: list[BotCommand] = self.manager.compute_commands(state)
        if commands and self.transport is not None:
            payload = encode_commands(commands)
            self.transport.sendto(payload, addr)
            if state.tick % 40 == 0:
                log.info("  -> sent %d commands (%d bytes)", len(commands), len(payload))
        elif state.tick % 40 == 0:
            log.info("  -> no commands (no alive bots or all arrived)")


def _build_manager() -> tuple[BotManager, SpatialRecorder | None]:
    """Load nav mesh and create the bot manager."""
    nav_map = os.environ.get("NAV_MAP", "ministry_coop")
    maps_dir = os.environ.get("NAV_MAPS_DIR", "/app/maps")
    nav_path = os.path.join(maps_dir, f"{nav_map}.nav")
    nav = NavGraph(nav_path)
    terrain = TerrainAnalyzer(nav)
    strategy = GatheringStrategy()
    log.info("Strategy: gathering")

    recorder: SpatialRecorder | None = None
    if os.environ.get("RECORD_POSITIONS", "").strip() == "1":
        data_dir = os.environ.get("SPATIAL_DATA_DIR", "/app/data")
        recorder = SpatialRecorder(nav_map, data_dir)
        log.info("Position recording enabled (dir=%s)", data_dir)

    return BotManager(nav, terrain, strategy), recorder


async def run_server(host: str, port: int) -> None:
    """Start the UDP server and run forever."""
    log.info("Starting AI brain on %s:%d", host, port)

    manager, recorder = _build_manager()

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: AIBrainProtocol(manager, recorder),
        local_addr=(host, port),
    )

    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    await stop.wait()
    log.info("Shutdown signal received")
    if recorder is not None:
        recorder.save()
    transport.close()
