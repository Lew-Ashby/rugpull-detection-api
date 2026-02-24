import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.middleware.security import limiter
from app.middleware.x402 import create_x402_middleware
from app.routers import health, rugcheck

logger = logging.getLogger("rugpull_detection_api")

app = FastAPI(
    title=settings.app_name,
    description="Solana Token Rugpull Detection API for APIX x402 Marketplace",
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
)

middleware_cls, middleware_config = create_x402_middleware()
if middleware_config:
    app.add_middleware(middleware_cls, **middleware_config)


MAX_CONTENT_LENGTH = 1024  # 1KB max for any request body
MAX_URL_LENGTH = 2048  # 2KB max URL length


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_CONTENT_LENGTH:
        return JSONResponse(
            status_code=413,
            content={"detail": "Request entity too large", "error": "PAYLOAD_TOO_LARGE"},
        )

    if len(str(request.url)) > MAX_URL_LENGTH:
        return JSONResponse(
            status_code=414,
            content={"detail": "URI too long", "error": "URI_TOO_LONG"},
        )

    client_host = request.client.host if request.client else "unknown"
    logger.info(f"{request.method} {request.url.path} from {client_host}")
    response = await call_next(request)
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception for {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": "INTERNAL_ERROR"},
    )


app.include_router(health.router, tags=["Health"])
app.include_router(rugcheck.router, prefix="/api/v1", tags=["Rugcheck"])


@app.get("/", include_in_schema=False)
async def root():
    return {
        "name": settings.app_name,
        "version": "1.0.0",
        "docs": "/docs" if settings.debug else None,
        "endpoints": {
            "rugcheck": "/api/v1/rugcheck?contract={mint_address}",
            "rugcheck_alt": "/api/v1/rugcheck/{mint_address}",
            "health": "/health",
        },
    }
