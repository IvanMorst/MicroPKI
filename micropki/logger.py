import logging
import sys
import os
from pathlib import Path


def setup_logger(log_file=None):
    """Configure root logger to write to file or stderr."""
    handlers = [logging.StreamHandler(sys.stderr)]

    if log_file:
        # Создаем директорию для лог-файла, если она не существует
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        handlers.append(logging.FileHandler(str(log_path), mode='a'))

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s.%(msecs)03d %(levelname)s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
        handlers=handlers
    )