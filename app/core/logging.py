import logging
import sys


def configure_logging(log_level: str) -> None:
    """Configure process logging for the API application."""

    logging.basicConfig(
        level=log_level.upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
