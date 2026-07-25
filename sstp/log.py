import logging
import sys

_FORMAT = "%(asctime)s %(levelname)-7s %(name)-14s %(message)s"


def setup(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=_FORMAT,
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


def get(name: str) -> logging.Logger:
    return logging.getLogger(name)


def hexdump(data: bytes, limit: int = 96) -> str:
    shown = data[:limit]
    text = " ".join(f"{b:02x}" for b in shown)
    if len(data) > limit:
        text += f" ... (+{len(data) - limit} bytes)"
    return text
