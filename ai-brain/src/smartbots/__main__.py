"""Entry point for the SmartBots AI brain."""

import asyncio
import logging
import os

from smartbots.server import run_server


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    host = os.environ.get("AI_LISTEN_HOST", "0.0.0.0")
    port = int(os.environ.get("AI_LISTEN_PORT", "9000"))

    asyncio.run(run_server(host, port))


if __name__ == "__main__":
    main()
