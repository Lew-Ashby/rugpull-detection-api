import logging

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings

logger = logging.getLogger("rugpull_detection_api.security")

limiter = Limiter(key_func=get_remote_address)


def get_rate_limit() -> str:
    return f"{settings.rate_limit}/minute"
