"""FastAPI composition root; importing does not connect or migrate databases."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse

from app.api import audit, auth, health, users
from app.api.dependencies import Principal, require
from app.core.config import Settings, get_settings
from app.core.errors import ApiError
from app.core.http import BodyLimitMiddleware
from app.core.observability import ObservabilityMiddleware, configure_logging
from app.core.permissions import Permission
from app.infrastructure.database import Database
from app.modules.audit.service import append_audit


def error_response(request: Request, status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        {"code": code, "message": message, "request_id": getattr(request.state, "request_id", "")},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        configuration = settings or get_settings()
        configure_logging()
        application.state.settings = configuration
        application.state.database = Database(configuration)
        application.state.redis = Redis.from_url(
            configuration.redis_url.get_secret_value(),
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        try:
            yield
        finally:
            application.state.redis.close()
            application.state.database.close()

    application = FastAPI(
        title="Aegis SOC Command Center",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
    )
    application.add_middleware(BodyLimitMiddleware)
    application.add_middleware(
        ObservabilityMiddleware, local_http=settings.local_http if settings else False
    )
    for router in (auth.router, users.router, audit.router, health.router):
        application.include_router(router)

    @application.exception_handler(ApiError)
    def api_error(request: Request, error: ApiError) -> JSONResponse:
        if error.status in {401, 403} and not getattr(request.state, "audit_recorded", False):
            try:
                with request.app.state.database.sessions() as db:
                    append_audit(
                        db,
                        action="security.rejected",
                        outcome="denied",
                        request_id=request.state.request_id,
                        details={"reason": error.code},
                    )
                    db.commit()
            except SQLAlchemyError:
                return error_response(
                    request, 503, "storage_unavailable", "Service temporarily unavailable"
                )
        response = error_response(request, error.status, error.code, error.message)
        response.headers.update(error.headers)
        return response

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
        # Pydantic error.input and ctx can contain plaintext passwords; never serialize them.
        return error_response(request, 422, "validation_error", "Request fields are invalid")

    @application.exception_handler(IntegrityError)
    async def conflict(request: Request, error: IntegrityError) -> JSONResponse:
        return error_response(request, 409, "conflict", "Resource conflicts with existing state")

    @application.exception_handler(SQLAlchemyError)
    @application.exception_handler(RedisError)
    async def dependency_error(request: Request, error: Exception) -> JSONResponse:
        return error_response(
            request, 503, "dependency_unavailable", "Service temporarily unavailable"
        )

    @application.exception_handler(HTTPException)
    async def http_error(request: Request, error: HTTPException) -> JSONResponse:
        return error_response(
            request, error.status_code, "http_error", "Request could not be handled"
        )

    @application.get("/api/v1/system/health", tags=["system"])
    def system_health(
        request: Request,
        principal: Annotated[Principal, Depends(require(Permission.SYSTEM_READ))],
    ) -> dict[str, object]:
        return health.detailed_status(request)

    return application


app = create_app()
