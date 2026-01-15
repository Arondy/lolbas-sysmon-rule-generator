import sys

from loguru import logger as _logger


def setup_logger():
    _logger.remove()
    color_log_format = "<green>{time:DD-MM HH:mm:ss}</green> | <level>{level}</level> | <fg #808080>{extra[class_name]}</fg #808080> | {message}"
    _logger.add(sys.stdout, level="DEBUG", format=color_log_format, backtrace=True)
    return _logger.patch(lambda record: record["extra"].setdefault("class_name", ""))


logger = setup_logger()
