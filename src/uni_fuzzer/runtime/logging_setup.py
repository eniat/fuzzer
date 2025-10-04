import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from ..core.utility import get_cfg
cfg = get_cfg()

def setupLogging (level="INFO", logFile= "Uni-fuzzer.log", toConsole=True, jsonMode =False, maxBytes=0, backUpCount=1):
    """
        To configure the logging for the fuzzer
    """

    root = logging.getLogger()

    # Prevents duplicate handlers
    if getattr(root, "_uf_configured", False):
        return
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    fmt = cfg["logging"]["json_format"] if jsonMode else cfg["logging"]["format"]

    datefmt = cfg["logging"]["date_format"]

    if logFile:
        Path(logFile).parent.mkdir(parents=True, exist_ok=True)
        fileHandler = (RotatingFileHandler(logFile, maxBytes=maxBytes, backupCount=backUpCount, encoding="utf-8")
                       if maxBytes else logging.FileHandler(logFile, encoding="utf-8"))
        fileHandler.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
        fileHandler.setLevel(root.level)
        root.addHandler(fileHandler)

    if toConsole:
        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
        consoleHandler.setLevel(root.level)
        root.addHandler(consoleHandler)

    root._uf_configured = True