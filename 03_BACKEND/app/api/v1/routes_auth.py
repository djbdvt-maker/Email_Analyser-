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


def _check_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    cutoff = now - _RATE_LIMIT_WINDOW

    # Prune old attempts
    attempts = [t for t in _LOGIN_ATTEMPTS[client_ip] if t > cutoff]
    if len(attempts) >= _MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts. Please wait before retrying.",
        )
    attempts.append(now)
    _LOGIN_ATTEMPTS[client_ip] = attempts


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    _check_rate_limit(request)
    user = db.query(User).filter(User.email == form_data.username).one_or_none()
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is inactive")
    token = create_access_token(user_id=user.id, organization_id=user.organization_id, role=user.role.value)
    return TokenResponse(access_token=token)
