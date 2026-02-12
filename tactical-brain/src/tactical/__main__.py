"""Entry point: python -m tactical"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from tactical.planner import Planner
from tactical.server import run_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)

log = logging.getLogger(__name__)


def main() -> None:
    host = os.environ.get("LISTEN_HOST", "0.0.0.0")
    port = int(os.environ.get("LISTEN_PORT", "9000"))

    rally_x = float(os.environ.get("RALLY_X", "0"))
    rally_y = float(os.environ.get("RALLY_Y", "0"))
    rally_z = float(os.environ.get("RALLY_Z", "0"))

    influence_map = None
    map_name = os.environ.get("MAP_NAME", "")
    data_dir = os.environ.get("DATA_DIR", "/app/data")

    if map_name:
        vismatrix_path = Path(data_dir) / f"{map_name}_vismatrix.npz"
        influence_path = Path(data_dir) / f"{map_name}_influence.npz"

        if vismatrix_path.exists() and influence_path.exists():
            from tactical.influence_map import InfluenceMap
            influence_map = InfluenceMap(str(vismatrix_path), str(influence_path))
            log.info("Loaded influence map for %s", map_name)
        else:
            log.warning(
                "Map data not found for %s (looked in %s), falling back to rally point",
                map_name, data_dir,
            )

    telemetry = None
    if os.environ.get("TELEMETRY") == "1":
        from tactical.telemetry import TelemetryClient
        tele_host = os.environ.get("TELEMETRY_HOST", "localhost")
        tele_port = int(os.environ.get("TELEMETRY_PORT", "5432"))
        telemetry = TelemetryClient(host=tele_host, port=tele_port)

    controlled_team = int(os.environ.get("CONTROLLED_TEAM", "2"))
    planner = Planner(
        rally=(rally_x, rally_y, rally_z),
        controlled_team=controlled_team,
        influence_map=influence_map,
    )
    asyncio.run(run_server(host, port, planner, telemetry=telemetry))


main()
