from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from app.api.v1 import websockets
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
)
from fastapi.middleware.cors import CORSMiddleware

import traceback, sys; from starlette.requests import Request; from starlette.responses import JSONResponse;
from contextlib import asynccontextmanager
from app.services.imap_listener import start_imap_watcher

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        from app.database import Base, engine, SessionLocal
        Base.metadata.create_all(bind=engine)
        
        db = SessionLocal()
        try:
            from app.models import Organization, User, UserRole
            from app.security import hash_password
            
            org = db.query(Organization).first()
            if not org:
                org = Organization(name="HopZero Primary")
                db.add(org)
                db.flush()
            
            users_to_seed = [
                ("analyst@hopzero.io", "admin123", UserRole.ANALYST),
                ("admin@hopzero.io", "admin123", UserRole.ADMIN),
                ("admin@hopzero.local", "changeme123", UserRole.ADMIN),
            ]
            for email, pwd, role in users_to_seed:
                if not db.query(User).filter(User.email == email).first():
                    u = User(
                        organization_id=org.id,
                        email=email,
                        hashed_password=hash_password(pwd),
                        role=role,
                    )
                    db.add(u)
            db.commit()
        except Exception as seed_err:
            print(f"Startup DB seed warning: {seed_err}", file=sys.stderr)
        finally:
            db.close()
    except Exception as db_init_err:
        print(f"Database init warning: {db_init_err}", file=sys.stderr)

    start_imap_watcher()
    yield

app = FastAPI(
    title="HopZero Backend",
    version="2.0.0",
    lifespan=lifespan,
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


@app.get("/health", tags=["health"])
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

