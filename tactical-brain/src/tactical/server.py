"""Asyncio UDP server: receives bot state from C++ extension, sends commands back."""

from __future__ import annotations

import asyncio
import logging
import signal

from tactical.planner import Planner
from tactical.protocol import BotCommand, decode_state, encode_commands
from tactical.state import GameState

log = logging.getLogger(__name__)


class TacticalProtocol(asyncio.DatagramProtocol):
    def __init__(self, planner: Planner) -> None:
        self.planner = planner
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

        commands: list[BotCommand] = self.planner.compute_commands(state)
        if commands and self.transport is not None:
            payload = encode_commands(commands)
            self.transport.sendto(payload, addr)
            self._send_count += 1

    def error_received(self, exc: Exception) -> None:
        log.error("UDP error: %s", exc)


async def run_server(host: str, port: int, planner: Planner) -> None:
    log.info("Starting tactical brain on %s:%d", host, port)
    log.info("Rally point: (%.1f, %.1f, %.1f)", *planner.rally)

    loop = asyncio.get_running_loop()

    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: TacticalProtocol(planner),
        local_addr=(host, port),
    )

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
        log.info("Tactical brain stopped")
