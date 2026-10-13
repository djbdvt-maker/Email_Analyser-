"""
SQLAlchemy engine/session wiring.

The engine URL is fully driven by configuration so the same models work
against PostgreSQL (production, via Alembic-managed migrations) and
SQLite (used only by the test suite for speed/portability). No
model in this codebase relies on a Postgres-only type, to keep that
portability honest rather than accidental.
"""
import shutil
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import get_settings

settings = get_settings()

_connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(settings.database_url, connect_args=_connect_args, future=True)

# Performance & concurrent lock mitigation for SQLite Desktop editions
if settings.database_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine, future=True)

Base = declarative_base()


def backup_database_before_upgrade() -> None:
    """Creates a timestamped snapshot of local SQLite database before migrations."""
    if settings.database_url.startswith("sqlite:///"):
        db_path_str = settings.database_url.replace("sqlite:///", "")
        # Remove sqlite query params if any
        if "?" in db_path_str:
            db_path_str = db_path_str.split("?")[0]
        db_path = Path(db_path_str).resolve()
        if db_path.exists() and db_path.is_file() and db_path.stat().st_size > 0:
            backup_dir = db_path.parent / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_file = backup_dir / f"{db_path.stem}_{timestamp}.bak"
            shutil.copy2(db_path, backup_file)


def ensure_default_admin() -> None:
    """Ensures at least one administrator account exists for initial evaluation."""
    db = SessionLocal()
    try:
        from app.models import User, Organization, UserRole
        from app.security import hash_password
        admin = db.query(User).filter(User.email == "admin@hopzero.local").first()
        if admin is None:
            org = db.query(Organization).first()
            if org is None:
                org = Organization(name="HopZero Primary")
                db.add(org)
                db.flush()
            admin = User(
                organization_id=org.id,
                email="admin@hopzero.local",
                hashed_password=hash_password("changeme123"),
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(admin)
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def migrate_schema_columns() -> None:
    """Safely adds newly introduced columns to existing SQLite tables if missing."""
    if not settings.database_url.startswith("sqlite"):
        return
    with engine.connect() as conn:
        from sqlalchemy import text
        try:
            res = conn.execute(text("PRAGMA table_info(investigations)"))
            cols = {row[1] for row in res.fetchall()}
            if "reported_by_employee" not in cols:
                conn.execute(text("ALTER TABLE investigations ADD COLUMN reported_by_employee VARCHAR(255)"))
            if "employee_code_id" not in cols:
                conn.execute(text("ALTER TABLE investigations ADD COLUMN employee_code_id VARCHAR(36)"))
            if "employee_notes" not in cols:
                conn.execute(text("ALTER TABLE investigations ADD COLUMN employee_notes TEXT"))
            conn.commit()
        except Exception:
            pass


def init_db_with_backup() -> None:
    """Executes pre-migration backup and initializes database schema on startup."""
    backup_database_before_upgrade()
    Base.metadata.create_all(bind=engine)
    migrate_schema_columns()
    ensure_default_admin()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

