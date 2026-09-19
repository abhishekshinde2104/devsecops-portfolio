"""Application factory.

Run with:  uvicorn --factory app.main:create_app
Using a factory (instead of a module-level ``app``) means importing the package
never requires secrets, and tests can build isolated app instances.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app import __version__
from app.config import Settings, get_settings
from app.db import Base, build_engine, build_session_factory
from app.logging_config import configure_logging
from app.metrics import HTTP_LATENCY, HTTP_REQUESTS
from app.ratelimit import RateLimiter, client_ip, enforce
from app.routers import admin, auth, integrations, invoices, users

log = logging.getLogger("app")

_UNMETERED_PATHS = {"/healthz", "/metrics"}

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}
# Swagger UI needs scripts/styles from its CDN; only relaxed when docs are on.
_DOCS_CSP = (
    "default-src 'self'; img-src 'self' data: https://fastapi.tiangolo.com; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; frame-ancestors 'none'"
)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging("DEBUG" if settings.env == "dev" else "INFO")

    engine = build_engine(settings.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        Base.metadata.create_all(engine)
        log.info("startup", extra={"env": settings.env, "version": __version__})
        yield
        engine.dispose()

    app = FastAPI(
        title="Secure Invoice API",
        version=__version__,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.session_factory = build_session_factory(engine)
    app.state.limiter = RateLimiter()

    for router in (auth.router, users.router, invoices.router, admin.router, integrations.router):
        app.include_router(router)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    if settings.metrics_enabled:

        @app.get("/metrics", include_in_schema=False)
        def metrics() -> Response:
            # Exposed on the app port for simplicity; in Kubernetes (Project 2)
            # a NetworkPolicy only lets the Prometheus namespace reach it.
            return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Never leak stack traces or internals to the client (CWE-209).
        log.exception("unhandled_error", extra={"path": request.url.path})
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    Next = Callable[[Request], Awaitable[Response]]

    @app.middleware("http")
    async def rate_limit(request: Request, call_next: Next) -> Response:
        if request.url.path not in _UNMETERED_PATHS:
            try:
                enforce(
                    request,
                    "global",
                    client_ip(request),
                    settings.global_rate_limit,
                    settings.global_rate_window_seconds,
                )
            except HTTPException as exc:
                return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Next) -> Response:
        response = await call_next(request)
        response.headers.update(_SECURITY_HEADERS)
        if settings.docs_enabled and request.url.path in {"/docs", "/docs/oauth2-redirect"}:
            response.headers["Content-Security-Policy"] = _DOCS_CSP
        request_id = request.headers.get("X-Request-ID", "")
        if not (0 < len(request_id) <= 64 and request_id.replace("-", "").isalnum()):
            request_id = uuid.uuid4().hex
        response.headers["X-Request-ID"] = request_id
        return response

    @app.middleware("http")
    async def observe(request: Request, call_next: Next) -> Response:
        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            route = request.scope.get("route")
            template = getattr(route, "path", "unmatched")
            if template not in _UNMETERED_PATHS:
                HTTP_REQUESTS.labels(request.method, template, str(status_code)).inc()
                HTTP_LATENCY.labels(request.method, template).observe(time.perf_counter() - start)

    return app
