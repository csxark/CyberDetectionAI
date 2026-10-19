"""FastAPI application factory for SentinelAI API service."""
from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes import router
from contracts.enums import ErrorCodePrefix
from contracts.models import ProblemDetail


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title="SentinelAI API",
        description="Safety-first agentic AI layer for defensive cybersecurity investigations",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Local CORS configuration for React frontend
    origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    custom_origin = os.getenv("CORS_ORIGIN")
    if custom_origin and custom_origin not in origins:
        origins.append(custom_origin)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Attach API routers
    app.include_router(router)

    # Global exception handler formatting into RFC 7807 ProblemDetail
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        problem = ProblemDetail(
            type="https://sentinel.ai/errors/sys_internal_error",
            title="Internal Server Anomaly",
            status=500,
            code=ErrorCodePrefix.SYS + "INTERNAL_ERROR",
            detail_template="An unexpected anomaly occurred during processing.",
            next_step_template="Verify service health or review server operational logs.",
        )
        return JSONResponse(status_code=500, content=problem.model_dump())

    return app


app = create_app()
