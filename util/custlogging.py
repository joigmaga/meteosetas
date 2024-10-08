import sys
import logging

CRITICAL = logging.CRITICAL
ERROR    = logging.ERROR
WARNING  = logging.WARNING
INFO     = logging.INFO
DEBUG    = logging.DEBUG

def get_logger(name, level=WARNING):

    logging.addLevelName(CRITICAL, "critical")
    logging.addLevelName(ERROR,    "error")
    logging.addLevelName(WARNING,  "warning")
    logging.addLevelName(INFO,     "info")
    logging.addLevelName(DEBUG,    "debug")

    logger = logging.getLogger(name)
    logger.setLevel(level)

    modname = name.split('.')[-1]
    ch  = logging.StreamHandler()

    kwargs = {"fmt": "%(asctime)s %(my_name)s: [%(levelname)s] %(message)s",
              "datefmt": "%Y/%m/%d:%H:%M:%S"}
    if sys.version_info.major >= 3 and sys.version_info.minor >= 10:
        kwargs |= {"defaults": {"my_name": modname[:8].upper()}}

    fmt = logging.Formatter(**kwargs)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger
