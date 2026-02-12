"""Asyncio UDP server: receives bot state from C++ extension, sends commands back."""

from __future__ import annotations

import asyncio
import logging
import signal
import socket

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
    ) -> None:
        self.planner = planner
        self.telemetry = telemetry
        self.strategist = strategist
        self.transport: asyncio.DatagramTransport | None = None
        self._recv_count = 0
        self._send_count = 0

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

        # Log periodically
        if self._recv_count == 1 or self._recv_count % 240 == 0:
            alive = sum(1 for b in state.bots.values() if b.alive)
            log.info(
                "State #%d: tick=%d bots=%d alive=%d",
                self._recv_count,
                state.tick,
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

    def error_received(self, exc: Exception) -> None:
        log.error("UDP error: %s", exc)


async def run_server(
    host: str,
    port: int,
    planner: Planner,
    telemetry: TelemetryClient | None = None,
    strategist: BaseStrategist | None = None,
) -> None:
    log.info("Starting tactical brain on %s:%d", host, port)
    log.info("Rally point: (%.1f, %.1f, %.1f)", *planner.rally)
    if planner.influence_map:
        log.info("Influence map active: %d grid points", planner.influence_map.n)
    else:
        log.info("No influence map — using rally point fallback")

    loop = asyncio.get_running_loop()

    # Create socket with SO_REUSEADDR to allow quick restarts
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))

    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: TacticalProtocol(planner, telemetry, strategist),
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
        if strategist is not None:
            await strategist.close()
        if telemetry is not None:
            telemetry.close()
        log.info("Tactical brain stopped")
