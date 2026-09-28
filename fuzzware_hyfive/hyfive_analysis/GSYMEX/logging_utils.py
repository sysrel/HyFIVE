import logging

LOGGER_NAMES = (
    "VANA",
    "utils",
    "BASESTATE",
    "DETECTION",
    "EXPLORE",
    "MMIO",
    "LIVENESS",
    "TAINTED",
    "QUIRKS",
    "UTIL",
    "persist_results",
)

def set_log_levels(level):
    for name in LOGGER_NAMES:
        logger = logging.getLogger(name)
        logger.setLevel(level)
