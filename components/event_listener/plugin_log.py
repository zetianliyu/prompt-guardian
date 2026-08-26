"""Diagnostics that actually reach the WebUI plugin log panel.

LangBot builds that panel from the plugin's **stderr** (see
``PluginManager.get_plugin_logs``), so ``print()`` — which goes to stdout — is
invisible there. Its log buffer also parses a level out of each line with

    ^\\[[^\\]]+\\]\\s.*?-\\s\\[(?P<level>[A-Z]+)\\]\\s:\\s

and only accepts DEBUG / INFO / WARNING / ERROR / CRITICAL. The formatter below
matches that shape so entries arrive tagged rather than inheriting whatever
level came before them.
"""

from __future__ import annotations

import logging
import sys

LOGGER_NAME = "PromptGuardian"

LOG_FORMAT = (
    "[%(asctime)s.%(msecs)03d] %(filename)s (%(lineno)d) - [%(levelname)s] : %(message)s"
)
LOG_DATEFMT = "%m-%d %H:%M:%S"


def get_logger() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        # LangBot configures the root logger for its own output; propagating
        # would duplicate every line into the host log.
        logger.propagate = False
    return logger


log = get_logger()
