import logging
from typing import Any, Dict, Tuple, Type

logger = logging.getLogger("rugpull_detection_api.x402")


def create_x402_middleware() -> Tuple[Type[Any], Dict[str, Any]]:
    logger.info("API configured for APIX marketplace (x402 handled by platform)")
    return _NoOpMiddleware, {}


class _NoOpMiddleware:
    def __init__(self, app: Any, **kwargs: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        await self.app(scope, receive, send)
