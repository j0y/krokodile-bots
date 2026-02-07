"""
Insurgency Smart Bot AI Brain

This service connects to the Insurgency server via RCON and communicates
with a thin SourceMod plugin to control bot behavior.

Architecture:
  1. SM plugin sends game state via UDP to this service every tick
  2. This service processes state, runs tactical AI
  3. This service sends commands back via RCON or UDP

For now, this is a scaffold showing the architecture.
The SM plugin bridge needs to be built to match.
"""

import asyncio
import json
import logging
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class GameState:
    """Represents the current state of the game world."""

    def __init__(self):
        self.bots: dict[str, BotState] = {}
        self.enemies: dict[str, EnemyState] = {}
        self.objectives: list[dict] = []
        self.tick: int = 0

    def update(self, data: dict):
        """Update game state from SM plugin data."""
        self.tick = data.get("tick", self.tick)

        for bot_data in data.get("bots", []):
            bot_id = bot_data["id"]
            if bot_id not in self.bots:
                self.bots[bot_id] = BotState(bot_id)
            self.bots[bot_id].update(bot_data)

        for enemy_data in data.get("enemies", []):
            enemy_id = enemy_data["id"]
            if enemy_id not in self.enemies:
                self.enemies[enemy_id] = EnemyState(enemy_id)
            self.enemies[enemy_id].update(enemy_data)


class BotState:
    """State of a single bot we control."""

    def __init__(self, bot_id: str):
        self.id = bot_id
        self.position = (0.0, 0.0, 0.0)
        self.angle = (0.0, 0.0, 0.0)
        self.health = 100
        self.armor = 0
        self.weapon = ""
        self.ammo = 0
        self.is_alive = True
        self.team = ""
        self.role = "assault"  # assault, flank, overwatch, support

    def update(self, data: dict):
        self.position = tuple(data.get("pos", self.position))
        self.angle = tuple(data.get("ang", self.angle))
        self.health = data.get("health", self.health)
        self.is_alive = data.get("alive", self.is_alive)
        self.weapon = data.get("weapon", self.weapon)
        self.team = data.get("team", self.team)


class EnemyState:
    """Known/suspected enemy position."""

    def __init__(self, enemy_id: str):
        self.id = enemy_id
        self.position = (0.0, 0.0, 0.0)
        self.last_seen_tick = 0
        self.is_alive = True
        self.confidence = 1.0  # Decays over time if not re-spotted

    def update(self, data: dict):
        self.position = tuple(data.get("pos", self.position))
        self.last_seen_tick = data.get("tick", self.last_seen_tick)
        self.is_alive = data.get("alive", self.is_alive)


class TacticalAI:
    """
    The brain that decides what each bot should do.

    Uses a utility AI system where each possible action is scored
    and the highest-scoring action is chosen.
    """

    def __init__(self):
        self.squad_roles = {}  # bot_id -> role

    def assign_roles(self, game_state: GameState):
        """Assign tactical roles to each bot based on team composition."""
        bots = [b for b in game_state.bots.values() if b.is_alive]
        if not bots:
            return

        # Simple role assignment: 50% assault, 25% flank, 25% overwatch
        for i, bot in enumerate(bots):
            if i % 4 == 0:
                bot.role = "overwatch"
            elif i % 4 == 1:
                bot.role = "flank"
            else:
                bot.role = "assault"

        logger.debug(f"Roles assigned: {[(b.id, b.role) for b in bots]}")

    def decide_actions(self, game_state: GameState) -> list[dict]:
        """
        For each bot, decide what action to take.
        Returns a list of commands to send to the SM plugin.
        """
        commands = []

        for bot in game_state.bots.values():
            if not bot.is_alive:
                continue

            action = self._score_actions(bot, game_state)
            commands.append(action)

        return commands

    def _score_actions(self, bot: BotState, state: GameState) -> dict:
        """
        Score possible actions for a single bot using utility AI.

        Each action gets a score based on the current situation.
        The highest-scoring action wins.
        """
        scores = {}

        # ---- Push toward objective ----
        push_score = 0.5  # Base desire to push
        if bot.health > 70:
            push_score += 0.2
        if bot.role == "assault":
            push_score += 0.3
        scores["push"] = push_score

        # ---- Hold position / overwatch ----
        hold_score = 0.3
        if bot.role == "overwatch":
            hold_score += 0.5
        if bot.health < 30:
            hold_score += 0.3
        scores["hold"] = hold_score

        # ---- Flank ----
        flank_score = 0.2
        if bot.role == "flank":
            flank_score += 0.6
        if len(state.enemies) > 0:
            flank_score += 0.2  # More reason to flank if enemies known
        scores["flank"] = flank_score

        # ---- Retreat ----
        retreat_score = 0.0
        if bot.health < 20:
            retreat_score += 0.7
        if bot.ammo <= 0:
            retreat_score += 0.5
        scores["retreat"] = retreat_score

        # Pick best action
        best_action = max(scores, key=scores.get)

        return {
            "bot_id": bot.id,
            "action": best_action,
            "score": scores[best_action],
            # Movement target would be computed here based on nav mesh analysis
            "target_pos": None,
        }


class AIBridgeServer:
    """
    UDP server that receives game state from the SourceMod plugin
    and sends back commands.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 9000):
        self.host = host
        self.port = port
        self.game_state = GameState()
        self.tactical_ai = TacticalAI()

    async def run(self):
        """Start the UDP server."""
        logger.info(f"AI Brain starting on {self.host}:{self.port}")

        # Create UDP endpoint
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: AIProtocol(self),
            local_addr=(self.host, self.port)
        )

        logger.info("AI Brain ready, waiting for game state...")

        try:
            # Keep running
            while True:
                await asyncio.sleep(1)
        finally:
            transport.close()

    def process_state(self, data: dict) -> list[dict]:
        """Process incoming game state and return commands."""
        self.game_state.update(data)
        self.tactical_ai.assign_roles(self.game_state)
        commands = self.tactical_ai.decide_actions(self.game_state)
        return commands


class AIProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for game state communication."""

    def __init__(self, server: AIBridgeServer):
        self.server = server
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        try:
            state_data = json.loads(data.decode())
            commands = self.server.process_state(state_data)

            # Send commands back to the SM plugin
            response = json.dumps({"commands": commands}).encode()
            self.transport.sendto(response, addr)
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON from {addr}")
        except Exception as e:
            logger.error(f"Error processing state: {e}")


async def main():
    host = os.getenv("AI_LISTEN_HOST", "0.0.0.0")
    port = int(os.getenv("AI_LISTEN_PORT", "9000"))

    server = AIBridgeServer(host, port)
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
