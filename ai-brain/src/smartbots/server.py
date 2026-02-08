"""Async UDP server — receives bot state from SM, sends commands back."""

from __future__ import annotations

import asyncio
import logging

from smartbots.movement import compute_commands
from smartbots.protocol import BotCommand, decode_state, encode_commands
from smartbots.state import GameState

log = logging.getLogger(__name__)


class AIBrainProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for the AI brain."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.last_state: GameState | None = None

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
        log.info("tick=%d bots=%d alive=%d from=%s", state.tick, bot_count, alive_count, addr)

        # Compute commands and send back
        commands: list[BotCommand] = compute_commands(state)
        if commands and self.transport is not None:
            payload = encode_commands(commands)
            self.transport.sendto(payload, addr)


async def run_server(host: str, port: int) -> None:
    """Start the UDP server and run forever."""
    log.info("Starting AI brain on %s:%d", host, port)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        AIBrainProtocol,
        local_addr=(host, port),
    )
    try:
        await asyncio.Event().wait()  # run forever
    finally:
        transport.close()
