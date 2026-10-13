import time
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import TokenResponse
from app.security import verify_password, create_access_token

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# In-memory sliding window rate limiter: IP -> list of timestamps
_LOGIN_ATTEMPTS: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_WINDOW = 60.0  # seconds
_MAX_ATTEMPTS = 10  # max attempts per minute


def get_trusted_client_ip(request: Request) -> str:
    """Safely extracts client IP, honoring Cloudflare or reverse proxy headers if on loopback."""
    forwarded = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For")
    if forwarded and request.client and request.client.host in ("127.0.0.1", "::1", "localhost"):
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_auth_rate_limit(
    request: Request,
    key_prefix: str = "login",
    max_attempts: int = _MAX_ATTEMPTS,
    window_seconds: float = _RATE_LIMIT_WINDOW,
) -> None:
    client_ip = get_trusted_client_ip(request)
    limiter_key = f"{key_prefix}:{client_ip}"
    now = time.time()
    cutoff = now - window_seconds

    # Prune old attempts
    attempts = [t for t in _LOGIN_ATTEMPTS[limiter_key] if t > cutoff]
    if len(attempts) >= max_attempts:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts. Please wait before retrying.",
        )
    attempts.append(now)
    _LOGIN_ATTEMPTS[limiter_key] = attempts


def _check_rate_limit(request: Request) -> None:
    check_auth_rate_limit(request, key_prefix="login")


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    _check_rate_limit(request)
    user = db.query(User).filter(User.email == form_data.username).one_or_none()
    if user is None or not verify_password(form_data.password, str(user.hashed_password)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    if not bool(getattr(user, "is_active", False)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is inactive")
    token = create_access_token(user_id=str(user.id), organization_id=str(user.organization_id), role=str(user.role.value))
    return TokenResponse(access_token=token)
