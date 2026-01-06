"""
Cloud Security Audit Stack - REST API

FastAPI application for managing security scans and querying findings.
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import time

from config import get_settings
from routers import health_router, scans_router, findings_router, exports_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Get settings
settings = get_settings()

# Create FastAPI application
app = FastAPI(
    title="Cloud Security Audit Stack API",
    description="""
REST API for the Cloud Security Audit Stack.

## Features

- **Scans**: Trigger and manage security scans
- **Findings**: Query and update security findings
- **Exports**: Export findings as CSV or JSON
- **Health**: Service health checks

## Authentication

API key authentication can be enabled by setting the `API_KEY` environment variable.
    """,
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add X-Process-Time header to all responses."""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# API key validation middleware (optional)
@app.middleware("http")
async def validate_api_key(request: Request, call_next):
    """Validate API key if configured."""
    # Skip validation for docs and health endpoints
    if request.url.path in ["/api/docs", "/api/redoc", "/api/openapi.json", "/api/health", "/api/health/"]:
        return await call_next(request)

    # Check if API key is required
    if settings.api_key:
        api_key = request.headers.get("X-API-Key")
        if api_key != settings.api_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing API key"}
            )

    return await call_next(request)


# Include routers
app.include_router(health_router, prefix="/api")
app.include_router(scans_router, prefix="/api")
app.include_router(findings_router, prefix="/api")
app.include_router(exports_router, prefix="/api")


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Cloud Security Audit Stack API",
        "version": "1.0.0",
        "docs": "/api/docs",
        "health": "/api/health"
    }


@app.get("/api")
async def api_root():
    """API root endpoint."""
    return {
        "message": "Cloud Security Audit Stack API",
        "version": "1.0.0",
        "endpoints": {
            "health": "/api/health",
            "scans": "/api/scans",
            "findings": "/api/findings",
            "exports": "/api/exports"
        }
    }


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# Startup event
@app.on_event("startup")
async def startup_event():
    """Application startup tasks."""
    logger.info("Starting Cloud Security Audit Stack API")
    logger.info(f"CORS origins: {settings.cors_origins_list}")
    logger.info(f"Database: {settings.db_host}:{settings.db_port}/{settings.db_name}")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown tasks."""
    logger.info("Shutting down Cloud Security Audit Stack API")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug
    )
