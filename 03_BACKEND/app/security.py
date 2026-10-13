"""
Server-side authentication/authorization.

All authorization decisions are enforced here, in dependencies used by
the route layer -- never trusted from client-supplied organization_id
or investigation_id alone. A request can only read/act on rows whose
organization_id matches the authenticated user's organization_id.
"""
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
import bcrypt
from fastapi.security import OAuth2PasswordBearer
try:
    import jwt  # type: ignore
    from jwt.exceptions import PyJWTError as JWTError  # type: ignore
except ImportError:
    from jose import jwt, JWTError  # type: ignore
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import User

settings = get_settings()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

logger = logging.getLogger("hopzero.security")


def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")[:72]
    return bcrypt.hashpw(pwd_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8")[:72], hashed.encode("utf-8"))
    except Exception:
        return False



def create_access_token(*, user_id: str, organization_id: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": user_id,
        "org_id": organization_id,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_employee_token(*, code_id: str, organization_id: str, employee_email: str, employee_name: Optional[str] = None) -> str:
    """Creates a scoped 30-day JWT token for an enrolled employee with restricted EMPLOYEE role."""
    expire = datetime.now(timezone.utc) + timedelta(days=30)
    payload = {
        "sub": code_id,
        "org_id": organization_id,
        "role": "EMPLOYEE",
        "employee_email": employee_email,
        "employee_name": employee_name or employee_email,
        "is_employee": True,
        "exp": expire,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def get_current_employee(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> dict:
    """Dependency validating an employee session token."""
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        if not payload.get("is_employee") or payload.get("role") != "EMPLOYEE":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not an employee session token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        code_id = payload.get("sub")
        org_id = payload.get("org_id")
        if not code_id or not org_id:
            raise _credentials_exception()
    except JWTError:
        raise _credentials_exception()

    from app.models import EmployeeEnrollmentCode
    enrollment = db.get(EmployeeEnrollmentCode, code_id)
    if not enrollment or not bool(getattr(enrollment, "is_active", False)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Employee access code has expired or been revoked",
        )

    return {
        "enrollment": enrollment,
        "code_id": code_id,
        "organization_id": org_id,
        "employee_email": enrollment.employee_email,
        "employee_name": enrollment.employee_name or enrollment.employee_email,
        "department": enrollment.department,
    }


def _credentials_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    # Extension API Key Authentication Support
    if settings.hopzero_api_key and secrets.compare_digest(token, settings.hopzero_api_key):
        from app.models import Organization, UserRole
        # Ensure API key callers strictly bind to Analyst role (least privilege)
        # Prevents privilege escalation to ADMIN or SUPERADMIN accounts.
        user = (
            db.query(User)
            .filter(User.is_active == True, User.role == UserRole.ANALYST)
            .first()
        )
        if not user:
            # Auto-create a default analyst service user if none exists (handles fresh installs gracefully)
            org = db.query(Organization).first()
            if not org:
                org = Organization(name="SIH Demo Organization")
                db.add(org)
                db.flush()
            user = User(
                organization_id=org.id,
                email="analyst@hopzero.test",
                hashed_password="[API_KEY_LOGIN_NO_PASSWORD]",
                role=UserRole.ANALYST,
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        return user
            
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        user_id: Optional[str] = payload.get("sub")
        if user_id is None:
            raise _credentials_exception()
    except JWTError:
        raise _credentials_exception()

    user = db.get(User, user_id)
    if user is None or not bool(getattr(user, "is_active", False)):
        raise _credentials_exception()
    return user


def require_role(*roles: str):
    def _dep(user: User = Depends(get_current_user)) -> User:
        if user.role.value not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role for this operation",
            )
        return user
    return _dep


def assert_same_org(user: User, resource_organization_id: str) -> None:
    """
    The single enforcement point for organization scoping. Every
    service function that loads a row owned by an organization must
    call this before returning it to a route handler.
    """
    if str(user.organization_id) != str(resource_organization_id):
        # 404 instead of 403 to avoid confirming the resource exists
        # in another org.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


# --------------------------------------------------------------------
# Trusted deterministic-producer authentication.
#
# This is a SEPARATE trust boundary from the normal user JWT. A valid
# user JWT proves "this is an authenticated HopZero user"; it does NOT
# prove "this caller is an authorized deterministic analyzer allowed
# to submit Findings directly, bypassing the AI candidate pipeline."
# Previously that second claim was taken at face value from the
# request body's own `produced_by` string, which is not a credential
# at all -- any authenticated user could type
# `"produced_by": "deterministic"`. The header below is the
# actual credential; `produced_by` remains only a descriptive label
# once this dependency has already authorized the caller.
# --------------------------------------------------------------------

INTERNAL_SERVICE_KEY_HEADER = "X-Internal-Service-Key"


def require_internal_service_producer(
    x_internal_service_key: Optional[str] = Header(default=None, alias=INTERNAL_SERVICE_KEY_HEADER),
) -> None:
    """
    Option-B behavior (locked): if HOPZERO_INTERNAL_SERVICE_KEY is not
    configured on this deployment, the trusted deterministic-producer
    path is simply unavailable -- the backend keeps running, but this
    dependency always rejects. This is a SERVER configuration state,
    not evidence the caller sent bad credentials, so it's logged
    differently from a genuine wrong-key attempt -- but the external
    response is identical (plain 403, no detail that leaks which case
    applies) in both cases.

    There is no fallback/default secret value anywhere in this
    function or in app/config.py.
    """
    configured_key = get_settings().hopzero_internal_service_key

    if not configured_key:
        logger.warning(
            "Internal producer authentication unavailable: "
            "HOPZERO_INTERNAL_SERVICE_KEY is not configured. "
            "Rejecting request to the trusted deterministic-producer path."
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    if not x_internal_service_key or not secrets.compare_digest(x_internal_service_key, configured_key):
        # Deliberately the same status/detail as the missing-config
        # case above -- the caller should not be able to distinguish
        # "server isn't configured for this" from "your key is wrong"
        # from the response alone.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


N8N_INGEST_KEY_HEADER = "X-N8N-Ingest-Key"


def require_n8n_ingest_key(
    x_n8n_ingest_key: Optional[str] = Header(default=None, alias=N8N_INGEST_KEY_HEADER),
) -> None:
    """
    Ingestion authentication for n8n webhook / automated ingestion.
    Requires header X-N8N-Ingest-Key matching configured HOPZERO_N8N_INGEST_KEY.
    """
    configured_key = get_settings().hopzero_n8n_ingest_key
    if not configured_key:
        logger.warning(
            "n8n ingest authentication unavailable: "
            "HOPZERO_N8N_INGEST_KEY is not configured."
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    if not x_n8n_ingest_key or not secrets.compare_digest(x_n8n_ingest_key, configured_key):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

