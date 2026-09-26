"""
SQLAlchemy engine/session wiring.

The engine URL is fully driven by configuration so the same models work
against PostgreSQL (production, via Alembic-managed migrations) and
SQLite (used only by the test suite for speed/portability). No
model in this codebase relies on a Postgres-only type, to keep that
portability honest rather than accidental.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import get_settings

settings = get_settings()

_connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(settings.database_url, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine, future=True)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
