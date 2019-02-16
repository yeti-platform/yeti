import logging

from logging import FileHandler
from logging import Formatter
from core.config.config import yeti_config

LOG_FORMAT = (
    "%(asctime)s [%(levelname)s]: %(message)s")
LOG_LEVEL = logging.INFO

# user logger
USER_LOG_FILE = yeti_config.get('logging', 'filename')


userLogger = logging.getLogger("userLogger.messaging")
userLogger.setLevel(LOG_LEVEL)
userLogger_file_handler = FileHandler(USER_LOG_FILE)
userLogger_file_handler.setLevel(LOG_LEVEL)
userLogger_file_handler.setFormatter(Formatter(LOG_FORMAT))
userLogger.addHandler(userLogger_file_handler)
