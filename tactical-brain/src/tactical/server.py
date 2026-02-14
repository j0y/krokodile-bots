"""Asyncio UDP server: receives bot state from C++ extension, sends commands back."""

from __future__ import annotations

import asyncio
import logging
import signal
import socket
from collections.abc import Callable

from tactical.map_data import MapData
from tactical.planner import Planner
from tactical.protocol import decode_state, encode_commands
from tactical.state import GameState
from tactical.strategist import BaseStrategist
from tactical.telemetry import BotStateRow, TelemetryClient

log = logging.getLogger(__name__)


class TacticalProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        planner: Planner,
        telemetry: TelemetryClient | None = None,
        strategist: BaseStrategist | None = None,
        map_registry: dict[str, MapData] | None = None,
        strategist_factory: Callable[[MapData], BaseStrategist | None] | None = None,
    ) -> None:
        self.planner = planner
        self.telemetry = telemetry
        self.strategist = strategist
        self.transport: asyncio.DatagramTransport | None = None
        self._recv_count = 0
        self._send_count = 0
        self._map_registry = map_registry or {}
        self._strategist_factory = strategist_factory
        self._active_map = ""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        log.info("UDP server ready")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._recv_count += 1

        try:
            state: GameState = decode_state(data)
        except Exception:
            log.exception("Failed to decode state packet (%d bytes)", len(data))
            return

        # Map change detection
        if state.map_name and state.map_name != self._active_map:
            self._switch_map(state.map_name)

        # Log periodically
        if self._recv_count == 1 or self._recv_count % 240 == 0:
            alive = sum(1 for b in state.bots.values() if b.alive)
            log.info(
                "State #%d: tick=%d map=%s bots=%d alive=%d",
                self._recv_count,
                state.tick,
                self._active_map,
                len(state.bots),
                alive,
            )

        if self.strategist is not None:
            self.strategist.update_state(state)

        commands, cmd_rows = self.planner.compute_commands(state)

        if self.telemetry is not None:
            state_rows = [
                BotStateRow(
                    tick=state.tick,
                    bot_id=b.id,
                    alive=b.alive,
                    team=b.team,
                    health=b.health,
                    pos_x=b.pos[0],
                    pos_y=b.pos[1],
                    pos_z=b.pos[2],
                    is_bot=b.is_bot,
                )
                for b in state.bots.values()
            ]
            self.telemetry.record_state(state_rows)
            if cmd_rows:
                self.telemetry.record_commands(cmd_rows)

        if commands and self.transport is not None:
            payload = encode_commands(commands)
            self.transport.sendto(payload, addr)
            self._send_count += 1

    def _switch_map(self, map_name: str) -> None:
        log.info("Map change detected: %s -> %s", self._active_map or "(none)", map_name)
        self._active_map = map_name

        md = self._map_registry.get(map_name)
        if md is None:
            log.warning("No data for map %s, falling back to vanilla AI", map_name)
            self.planner.influence_map = None
            self.planner.area_map = None
            self.planner.pathfinder = None
            self.planner.orders = None
            if self.strategist is not None:
                asyncio.get_event_loop().create_task(self.strategist.close())
                self.strategist = None
            return

        # Swap planner data
        self.planner.influence_map = md.influence_map
        self.planner.area_map = md.area_map
        self.planner.pathfinder = md.pathfinder
        self.planner.orders = None
        self.planner._spotted_memory.clear()
        self.planner._stuck_tracker.clear()
        self.planner._commitments.clear()

        # Recreate strategist with new area_map
        if self.strategist is not None:
            asyncio.get_event_loop().create_task(self.strategist.close())
            self.strategist = None

        if md.area_map is not None and self._strategist_factory is not None:
            self.strategist = self._strategist_factory(md)
            if self.strategist is not None:
                self.strategist.start()
                log.info("Strategist started for map %s", map_name)
        else:
            log.info("No area_map or factory for %s, strategist disabled", map_name)

        # Update telemetry session
        if self.telemetry is not None:
            try:
                self.telemetry._conn.execute(
                    "UPDATE sessions SET map_name = %s WHERE session_id = %s",
                    (map_name, self.telemetry.session_id),
                )
                self.telemetry._conn.commit()
            except Exception:
                log.warning("Failed to update session map_name for %s", map_name)

        log.info("Switched to map %s (influence=%s, areas=%d)",
                 map_name,
                 md.influence_map is not None,
                 len(md.area_map.areas) if md.area_map else 0)

    def error_received(self, exc: Exception) -> None:
        log.error("UDP error: %s", exc)


async def run_server(
    host: str,
    port: int,
    planner: Planner,
    telemetry: TelemetryClient | None = None,
    strategist: BaseStrategist | None = None,
    map_registry: dict[str, MapData] | None = None,
    strategist_factory: Callable[[MapData], BaseStrategist | None] | None = None,
) -> None:
    log.info("Starting tactical brain on %s:%d", host, port)
    if map_registry:
        log.info("Maps available: %s", ", ".join(sorted(map_registry.keys())))
    else:
        log.info("No map registry — vanilla AI only")

    loop = asyncio.get_running_loop()

    # Create socket with SO_REUSEADDR to allow quick restarts
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: TacticalProtocol(
            planner, telemetry, strategist,
            map_registry=map_registry,
            strategist_factory=strategist_factory,
        ),
        sock=sock,
    )

    if strategist is not None:
        strategist.start()

    stop = loop.create_future()

    def _signal_handler() -> None:
        if not stop.done():
            stop.set_result(None)

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _signal_handler)

    log.info("Tactical brain running — waiting for state packets")

    try:
        await stop
    finally:
        transport.close()
        proto = protocol  # type: ignore[assignment]
        if isinstance(proto, TacticalProtocol) and proto.strategist is not None:
            await proto.strategist.close()
        elif strategist is not None:
            await strategist.close()
        if telemetry is not None:
            telemetry.close()
        log.info("Tactical brain stopped")
