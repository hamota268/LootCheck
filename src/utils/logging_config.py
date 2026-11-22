"""Logging configuration for LootCheck."""

import logging
import os
from src.utils.constants import get_config_dir


class APIKeyFilter(logging.Filter):
    """Filter to prevent API keys from appearing in logs."""

    REDACTED = "[REDACTED]"

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            # Redact anything that looks like a hex API key (64 chars)
            import re
            record.msg = re.sub(r'[a-fA-F0-9]{64}', self.REDACTED, record.msg)
        if record.args:
            new_args = []
            for arg in record.args if isinstance(record.args, tuple) else [record.args]:
                if isinstance(arg, str):
                    import re
                    arg = re.sub(r'[a-fA-F0-9]{64}', self.REDACTED, arg)
                new_args.append(arg)
            record.args = tuple(new_args)
        return True


def setup_logging(debug: bool = False) -> logging.Logger:
    """Configure application logging."""
    log_dir = get_config_dir()
    log_file = os.path.join(log_dir, 'lootcheck.log')

    logger = logging.getLogger('LootCheck')
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Clear existing handlers
    logger.handlers.clear()

    # File handler
    try:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        file_handler.addFilter(APIKeyFilter())
        logger.addHandler(file_handler)
    except (OSError, PermissionError):
        pass  # Can't write log file, continue without it

    # Console handler (for development)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    console_handler.addFilter(APIKeyFilter())
    logger.addHandler(console_handler)

    return logger
