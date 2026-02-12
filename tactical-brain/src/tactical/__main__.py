"""Entry point: python -m tactical"""

from __future__ import annotations

import asyncio
import logging
import os

from tactical.planner import Planner
from tactical.server import run_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)


def main() -> None:
    host = os.environ.get("LISTEN_HOST", "0.0.0.0")
    port = int(os.environ.get("LISTEN_PORT", "9000"))

    rally_x = float(os.environ.get("RALLY_X", "0"))
    rally_y = float(os.environ.get("RALLY_Y", "0"))
    rally_z = float(os.environ.get("RALLY_Z", "0"))

    planner = Planner(rally=(rally_x, rally_y, rally_z))
    asyncio.run(run_server(host, port, planner))


main()
