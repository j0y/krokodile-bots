"""Entry point: python -m tactical"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
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

    controlled_team = int(os.environ.get("CONTROLLED_TEAM", "2"))

    telemetry = None
    session_id = str(uuid.uuid4())
    if os.environ.get("TELEMETRY") == "1":
        from tactical.telemetry import TelemetryClient
        tele_host = os.environ.get("TELEMETRY_HOST", "localhost")
        tele_port = int(os.environ.get("TELEMETRY_PORT", "5432"))
        # strategist_type determined below, placeholder for now
        telemetry = TelemetryClient(
            session_id=session_id,
            map_name=map_name or "unknown",
            controlled_team=controlled_team,
            strategist_type="none",  # updated after strategist selection
            host=tele_host,
            port=tele_port,
        )

    # Load area definitions (if available)
    area_map = None
    if influence_map is not None and map_name:
        areas_path = Path(data_dir) / f"{map_name}_areas.json"
        if areas_path.exists():
            from tactical.areas import AreaMap
            area_map = AreaMap(
                str(areas_path),
                influence_map.points,
                influence_map.concealment,
                influence_map.tree,
            )
            log.info("Loaded area definitions for %s (%d areas)", map_name, len(area_map.areas))
        else:
            log.info("No area definitions for %s", map_name)

    planner = Planner(
        controlled_team=controlled_team,
        influence_map=influence_map,
        area_map=area_map,
    )

    strategist = None
    strategist_type = "none"
    openrouter_key = os.environ.get("OPENROUTER_API_KEY", "")
    if openrouter_key and area_map is not None:
        from tactical.strategist_llm import LLMStrategist
        strategist = LLMStrategist(
            planner=planner,
            area_map=area_map,
            api_key=openrouter_key,
            model=os.environ.get("OPENROUTER_MODEL", "anthropic/claude-3.5-haiku"),
            base_url=os.environ.get("OPENROUTER_URL", "https://openrouter.ai/api/v1"),
            min_interval=float(os.environ.get("STRATEGIST_MIN_INTERVAL", "12")),
            telemetry=telemetry,
        )
        strategist_type = "llm"
        log.info("LLM strategist enabled (model=%s)", strategist._model)
    elif area_map is not None:
        from tactical.strategist_sm import SMStrategist
        strategist = SMStrategist(planner=planner, area_map=area_map, telemetry=telemetry)
        strategist_type = "sm"
        log.info("State machine strategist enabled")
    else:
        log.info("Strategist disabled (no area definitions)")

    # Update the session row with the actual strategist type
    if telemetry is not None and strategist_type != "none":
        try:
            telemetry._conn.execute(
                "UPDATE sessions SET strategist_type = %s WHERE session_id = %s",
                (strategist_type, session_id),
            )
            telemetry._conn.commit()
        except Exception:
            log.warning("Failed to update session strategist_type")

    asyncio.run(run_server(host, port, planner, telemetry=telemetry, strategist=strategist))


main()
