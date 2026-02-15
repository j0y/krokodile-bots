"""Entry point: python -m tactical"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid

from tactical.map_data import MapData, preload_all_maps
from tactical.planner import Planner
from tactical.server import run_server
from tactical.strategist import BaseStrategist

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)

log = logging.getLogger(__name__)


def main() -> None:
    host = os.environ.get("LISTEN_HOST", "0.0.0.0")
    port = int(os.environ.get("LISTEN_PORT", "9000"))
    data_dir = os.environ.get("DATA_DIR", "/app/data")
    controlled_team = int(os.environ.get("CONTROLLED_TEAM", "2"))

    # Preload all available maps
    map_registry = preload_all_maps(data_dir)

    # Telemetry setup
    telemetry = None
    session_id = str(uuid.uuid4())
    if os.environ.get("TELEMETRY") == "1":
        from tactical.telemetry import TelemetryClient
        tele_host = os.environ.get("TELEMETRY_HOST", "localhost")
        tele_port = int(os.environ.get("TELEMETRY_PORT", "5432"))
        try:
            telemetry = TelemetryClient(
                session_id=session_id,
                map_name="pending",
                controlled_team=controlled_team,
                strategist_type="none",
                host=tele_host,
                port=tele_port,
            )
        except Exception as exc:
            log.warning("Telemetry unavailable (%s), continuing without it", exc)

    # Planner starts empty — populated on first map switch from C++ packet
    planner = Planner(controlled_team=controlled_team)

    # Strategist factory: captures config, creates strategist for a given map
    openrouter_key = os.environ.get("OPENROUTER_API_KEY", "")
    openrouter_model = os.environ.get("OPENROUTER_MODEL", "anthropic/claude-3.5-haiku")
    openrouter_url = os.environ.get("OPENROUTER_URL", "https://openrouter.ai/api/v1")
    strategist_min_interval = float(os.environ.get("STRATEGIST_MIN_INTERVAL", "12"))

    def make_strategist(md: MapData) -> BaseStrategist | None:
        if md.area_map is None:
            return None
        if openrouter_key:
            from tactical.strategist_llm import LLMStrategist
            strat = LLMStrategist(
                planner=planner,
                area_map=md.area_map,
                api_key=openrouter_key,
                model=openrouter_model,
                base_url=openrouter_url,
                min_interval=strategist_min_interval,
                telemetry=telemetry,
            )
            log.info("Created LLM strategist for %s (model=%s)", md.name, openrouter_model)
            return strat
        else:
            from tactical.strategist_sm import SMStrategist
            strat = SMStrategist(
                planner=planner,
                area_map=md.area_map,
                telemetry=telemetry,
            )
            log.info("Created SM strategist for %s", md.name)
            return strat

    asyncio.run(run_server(
        host, port, planner,
        telemetry=telemetry,
        map_registry=map_registry,
        strategist_factory=make_strategist,
    ))


main()
