"""
Nubicustos - REST API

FastAPI application for managing security scans and querying findings.

Features:
- Structured JSON logging with request correlation IDs
- Graceful shutdown with in-flight request handling
- Health check endpoints for load balancers and Kubernetes
- API key authentication (optional)
- Rate limiting to prevent abuse
"""

import asyncio
import secrets
import signal
import time
from collections import defaultdict
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from types import FrameType

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from logging_config import get_logger, get_request_id, set_request_id, setup_logging

from config import get_settings
from models.database import engine
from routers import (
    assumed_roles_router,
    attack_paths_router,
    cloudfox_router,
    compliance_router,
    credentials_router,
    enumerate_iam_router,
    executions_router,
    exports_router,
    exposed_credentials_router,
    findings_router,
    health_router,
    imds_checks_router,
    lambda_analysis_router,
    pacu_router,
    privesc_paths_router,
    public_exposures_router,
    scans_router,
    settings_router,
    severity_overrides_router,
    sync_router,
)
from routers.aws_profiles import router as aws_profiles_router
from routers.database import router as database_router
from routers.health import set_startup_time


# ============================================================================
# Rate Limiting Implementation
# ============================================================================
class RateLimiter:
    """Simple in-memory rate limiter using sliding window algorithm.

    For production with multiple workers, consider using Redis-based rate limiting.
    """

    def __init__(self, requests_per_minute: int = 100, burst_limit: int = 20) -> None:
        self.requests_per_minute: int = requests_per_minute
        self.burst_limit: int = burst_limit
        self.window_seconds: int = 60
        self.requests: dict[str, list[float]] = defaultdict(list)

    def _get_client_id(self, request: Request) -> str:
        """Get client identifier from request (IP or API key)."""
        # Prefer API key for identification if present
        api_key = request.headers.get("X-API-Key", "")
        if api_key:
            return f"key:{api_key[:8]}"  # Use prefix for privacy

        # Fall back to IP address
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _cleanup_old_requests(self, client_id: str, current_time: float) -> None:
        """Remove requests outside the current window."""
        cutoff = current_time - self.window_seconds
        self.requests[client_id] = [t for t in self.requests[client_id] if t > cutoff]

    def is_allowed(self, request: Request) -> tuple[bool, dict[str, str]]:
        """Check if request is allowed and return rate limit info.

        Returns:
            Tuple of (is_allowed, rate_limit_headers)
        """
        current_time = time.time()
        client_id = self._get_client_id(request)

        # Cleanup old requests
        self._cleanup_old_requests(client_id, current_time)

        # Count requests in current window
        request_count = len(self.requests[client_id])

        # Check burst limit (requests in last second)
        recent_cutoff = current_time - 1
        recent_requests = sum(1 for t in self.requests[client_id] if t > recent_cutoff)

        # Calculate remaining requests
        remaining = max(0, self.requests_per_minute - request_count)
        reset_time = int(current_time + self.window_seconds)

        rate_headers = {
            "X-RateLimit-Limit": str(self.requests_per_minute),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_time),
        }

        # Check if rate limited
        if request_count >= self.requests_per_minute:
            rate_headers["Retry-After"] = str(self.window_seconds)
            return False, rate_headers

        # Check burst limit
        if recent_requests >= self.burst_limit:
            rate_headers["Retry-After"] = "1"
            return False, rate_headers

        # Record this request
        self.requests[client_id].append(current_time)
        rate_headers["X-RateLimit-Remaining"] = str(remaining - 1)

        return True, rate_headers


# Get settings
settings = get_settings()

# Initialize rate limiter with settings
rate_limiter = RateLimiter(
    requests_per_minute=settings.rate_limit_requests_per_minute,
    burst_limit=settings.rate_limit_burst,
)

# Configure structured logging
setup_logging(
    log_level=settings.log_level, log_format=settings.log_format, service_name="nubicustos-api"
)
logger = get_logger(__name__)

# Graceful shutdown state
_shutdown_event = asyncio.Event()
_in_flight_requests = 0
_shutdown_lock = asyncio.Lock()


async def increment_in_flight() -> None:
    """Increment the in-flight request counter."""
    global _in_flight_requests
    async with _shutdown_lock:
        _in_flight_requests += 1


async def decrement_in_flight() -> None:
    """Decrement the in-flight request counter."""
    global _in_flight_requests
    async with _shutdown_lock:
        _in_flight_requests -= 1


def handle_sigterm(signum: int, frame: FrameType | None) -> None:
    """Handle SIGTERM signal for graceful shutdown."""
    logger.info("Received SIGTERM signal, initiating graceful shutdown")
    _shutdown_event.set()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager for startup and shutdown.

    Handles:
    - Setting up startup time for uptime tracking
    - Registering signal handlers for graceful shutdown
    - Waiting for in-flight requests to complete on shutdown
    - Closing database connections cleanly
    """
    # Startup
    logger.info("Starting Nubicustos API")
    logger.info(f"Log level: {settings.log_level}, format: {settings.log_format}")
    logger.info(f"CORS origins: {settings.cors_origins_list}")
    logger.info(f"Database: {settings.db_host}:{settings.db_port}/{settings.db_name}")

    # Set startup time for uptime tracking
    set_startup_time()

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)

    logger.info("Nubicustos API started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Nubicustos API")

    # Wait for in-flight requests to complete
    shutdown_start = time.time()
    while _in_flight_requests > 0:
        elapsed = time.time() - shutdown_start
        if elapsed > settings.shutdown_timeout:
            logger.warning(
                f"Shutdown timeout exceeded ({settings.shutdown_timeout}s), "
                f"{_in_flight_requests} requests still in flight"
            )
            break
        logger.info(f"Waiting for {_in_flight_requests} in-flight requests to complete...")
        await asyncio.sleep(0.5)

    # Close database connections
    try:
        engine.dispose()
        logger.info("Database connections closed")
    except Exception as e:
        logger.error(f"Error closing database connections: {e}")

    logger.info("Nubicustos API shutdown complete")


# Create FastAPI application with lifespan
app = FastAPI(
    title="Nubicustos API",
    description="""
REST API for the Nubicustos Cloud Security Audit Stack.

## Features

- **Scans**: Trigger and manage security scans
- **Findings**: Query and update security findings
- **Exports**: Export findings as CSV or JSON
- **Health**: Service health checks with Kubernetes probes

## Authentication

API key authentication can be enabled by setting the `API_KEY` environment variable.

## Health Endpoints

- `GET /api/health` - Basic health check for load balancers
- `GET /api/health/detailed` - Detailed health with all dependencies
- `GET /api/health/live` - Kubernetes liveness probe
- `GET /api/health/ready` - Kubernetes readiness probe
    """,
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request tracking middleware with correlation ID and rate limiting
@app.middleware("http")
async def request_tracking_middleware(request: Request, call_next):
    """
    Track requests with correlation IDs, timing, and rate limiting.

    - Generates or extracts request ID from X-Request-ID header
    - Adds X-Request-ID and X-Process-Time headers to response
    - Applies rate limiting (configurable via settings)
    - Logs request start and completion
    - Tracks in-flight requests for graceful shutdown
    """
    # Check for shutdown - reject new requests during shutdown
    if _shutdown_event.is_set():
        return JSONResponse(
            status_code=503,
            content={"detail": "Service is shutting down"},
            headers={"Retry-After": "30"},
        )

    # Get or generate request ID
    request_id = request.headers.get("X-Request-ID")
    request_id = set_request_id(request_id)

    # Apply rate limiting (skip health check endpoints)
    rate_headers = {}
    if settings.rate_limit_enabled and not request.url.path.startswith("/api/health"):
        allowed, rate_headers = rate_limiter.is_allowed(request)
        if not allowed:
            logger.warning(
                "Rate limit exceeded for client",
                extra={
                    "request_id": request_id,
                    "path": request.url.path,
                    "method": request.method,
                },
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please retry later."},
                headers=rate_headers,
            )

    # Track in-flight request
    await increment_in_flight()

    start_time = time.time()

    # Log request start (skip health checks to reduce noise)
    if not request.url.path.startswith("/api/health"):
        logger.info(
            f"Request started: {request.method} {request.url.path}",
            extra={
                "method": request.method,
                "path": request.url.path,
                "client_ip": request.client.host if request.client else None,
            },
        )

    try:
        response = await call_next(request)

        # Add headers
        process_time = time.time() - start_time
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{process_time:.4f}"

        # Add rate limit headers to successful responses
        for header_name, header_value in rate_headers.items():
            if not header_name.startswith("Retry"):  # Don't add Retry-After to success
                response.headers[header_name] = header_value

        # Log request completion (skip health checks)
        if not request.url.path.startswith("/api/health"):
            logger.info(
                f"Request completed: {request.method} {request.url.path} - {response.status_code}",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": round(process_time * 1000, 2),
                },
            )

        return response
    except Exception as e:
        logger.error(
            f"Request failed: {request.method} {request.url.path}",
            exc_info=True,
            extra={
                "method": request.method,
                "path": request.url.path,
                "error": str(e),
            },
        )
        raise
    finally:
        await decrement_in_flight()


# API key validation middleware (optional)
@app.middleware("http")
async def validate_api_key(request: Request, call_next):
    """Validate API key if configured."""
    # Skip validation for docs and health endpoints
    skip_paths = [
        "/api/docs",
        "/api/redoc",
        "/api/openapi.json",
        "/api/health",
        "/api/health/",
        "/api/health/live",
        "/api/health/ready",
        "/api/health/detailed",
    ]
    if request.url.path in skip_paths:
        return await call_next(request)

    # Check if API key is required
    if settings.api_key:
        api_key = request.headers.get("X-API-Key") or ""
        # Use timing-safe comparison to prevent timing attacks
        if not secrets.compare_digest(api_key, settings.api_key):
            request_id = get_request_id()
            logger.warning(
                "Authentication failed: Invalid or missing API key",
                extra={"request_id": request_id, "path": request.url.path},
            )
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})

    return await call_next(request)


# Include routers
app.include_router(health_router, prefix="/api")
app.include_router(scans_router, prefix="/api")
app.include_router(findings_router, prefix="/api")
app.include_router(exports_router, prefix="/api")
app.include_router(attack_paths_router, prefix="/api")
app.include_router(sync_router, prefix="/api")
# Pentest feature routers
app.include_router(public_exposures_router, prefix="/api")
app.include_router(exposed_credentials_router, prefix="/api")
app.include_router(severity_overrides_router, prefix="/api")
app.include_router(privesc_paths_router, prefix="/api")
app.include_router(imds_checks_router, prefix="/api")
app.include_router(cloudfox_router, prefix="/api")
app.include_router(pacu_router, prefix="/api")
app.include_router(enumerate_iam_router, prefix="/api")
app.include_router(assumed_roles_router, prefix="/api")
app.include_router(lambda_analysis_router, prefix="/api")
app.include_router(executions_router, prefix="/api")
app.include_router(credentials_router, prefix="/api")
app.include_router(settings_router, prefix="/api")
app.include_router(database_router, prefix="/api")
app.include_router(aws_profiles_router, prefix="/api")
app.include_router(compliance_router, prefix="/api")


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Nubicustos API",
        "version": "1.0.0",
        "docs": "/api/docs",
        "health": "/api/health",
    }


@app.get("/api")
async def api_root():
    """API root endpoint."""
    return {
        "message": "Nubicustos API",
        "version": "1.0.0",
        "endpoints": {
            "health": "/api/health",
            "health_detailed": "/api/health/detailed",
            "health_live": "/api/health/live",
            "health_ready": "/api/health/ready",
            "scans": "/api/scans",
            "findings": "/api/findings",
            "exports": "/api/exports",
            "attack_paths": "/api/attack-paths",
            "sync": "/api/sync",
            "public_exposures": "/api/public-exposures",
            "exposed_credentials": "/api/exposed-credentials",
            "severity_overrides": "/api/severity-overrides",
            "privesc_paths": "/api/privesc-paths",
            "imds_checks": "/api/imds-checks",
            "cloudfox": "/api/cloudfox",
            "pacu": "/api/pacu",
            "enumerate_iam": "/api/enumerate-iam",
            "assumed_roles": "/api/assumed-roles",
            "lambda_analysis": "/api/lambda-analysis",
            "executions": "/api/executions",
            "credentials": "/api/credentials",
            "settings": "/api/settings",
        },
    }


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with structured logging."""
    request_id = get_request_id()
    logger.error(
        f"Unhandled exception: {exc}",
        exc_info=True,
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
        },
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "request_id": request_id,
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host=settings.api_host, port=settings.api_port, reload=settings.debug)
