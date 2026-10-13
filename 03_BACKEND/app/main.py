from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from app.api.v1 import websockets
from fastapi.routing import APIRoute
from app.api.v1 import (
    routes_auth,
    routes_investigations,
    routes_investigations_export,
    routes_analysis_runs,
    routes_evidence,
    routes_findings,
    routes_ai,
    routes_ingest,
    routes_feedback,
    routes_enforcement,
    routes_sandbox,
    routes_tool,
    routes_action_drafts,
    routes_system,
    routes_admin_employees,
    routes_employee_portal,
)
from hopzero.tools.domain import domain_tool_router
from fastapi.middleware.cors import CORSMiddleware

import traceback, sys
from contextlib import asynccontextmanager
from app.config import get_settings, validate_settings
from app.database import init_db_with_backup
from app.services.imap_listener import start_imap_watcher

@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_settings(get_settings())
    init_db_with_backup()
    start_imap_watcher()
    yield



def custom_generate_unique_id(route: APIRoute) -> str:
    """Generates clean, stable OpenAPI operationId values for bot orchestration."""
    if route.operation_id:
        return route.operation_id
    clean_name = route.name
    if not clean_name.startswith("hopzero_"):
        clean_name = f"hopzero_{clean_name}"
    return clean_name


from hopzero import __version__ as HOPZERO_VERSION

app = FastAPI(
    title="HopZero Backend",
    version=HOPZERO_VERSION,
    lifespan=lifespan,
    generate_unique_id_function=custom_generate_unique_id,
    description=(
        "Investigation/AnalysisRun lifecycle, evidence ingestion, "
        "Fact/Finding persistence, the AI-candidate trust boundary, "
        "and the backend-owned deterministic Score Engine (category "
        "caps + critical-risk floors). Does NOT implement forensic "
        "detection logic, URL/domain/attachment analysis, or LLM "
        "reasoning itself -- only the deterministic boundary around "
        "AI output."
    ),
)

from app.config import get_settings

_settings = get_settings()
_cors_origins = [o.strip() for o in _settings.cors_origins.split(",") if o.strip()]
if _settings.public_url and _settings.public_url.strip():
    _cors_origins.append(_settings.public_url.strip().rstrip("/"))

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_origin_regex=r"^chrome-extension://[a-z]{32}$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

app.include_router(routes_auth.router)
app.include_router(routes_investigations.router)
app.include_router(routes_investigations_export.router)
app.include_router(routes_sandbox.router)
app.include_router(routes_analysis_runs.router)
app.include_router(routes_evidence.router)
app.include_router(routes_findings.router)
app.include_router(routes_ai.router)
app.include_router(routes_ingest.router)
app.include_router(routes_feedback.router)
app.include_router(routes_enforcement.router)
app.include_router(routes_tool.router)
app.include_router(routes_action_drafts.router)
app.include_router(routes_system.router, prefix="/api/v1")
app.include_router(routes_admin_employees.router)
app.include_router(routes_employee_portal.router)
app.include_router(domain_tool_router)
app.include_router(websockets.router, prefix="/api/v1")



@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error_code": f"HTTP_{exc.status_code}", "message": exc.detail, "details": None},
    )


@app.exception_handler(IntegrityError)
async def integrity_error_handler(request: Request, exc: IntegrityError):
    return JSONResponse(
        status_code=409,
        content={"error_code": "INTEGRITY_ERROR", "message": "Constraint violation", "details": str(exc.orig)},
    )


@app.get("/health", tags=["health"], operation_id="hopzero_health")
def health():
    return {"status": "ok"}
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    from app.config import get_settings
    settings = get_settings()
    tb = ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    print(tb, file=sys.stderr)
    
    if settings.environment == "development":
        return JSONResponse(status_code=500, content={'detail': tb})
    return JSONResponse(status_code=500, content={'detail': 'Internal Server Error'})


# Static frontend mount (if built)
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

_frontend_dist = Path(__file__).resolve().parent.parent.parent / "04_FRONTEND" / "dist"
if _frontend_dist.exists() and (_frontend_dist / "index.html").exists():
    if (_frontend_dist / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(_frontend_dist / "assets")), name="frontend_assets")

    @app.get("/", include_in_schema=False)
    async def serve_spa_root():
        return FileResponse(_frontend_dist / "index.html")

    @app.get("/portal", include_in_schema=False)
    @app.get("/portal/{rest:path}", include_in_schema=False)
    async def serve_spa_portal(rest: str = ""):
        return FileResponse(_frontend_dist / "index.html")

