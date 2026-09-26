"""
Audit event writer.

This module only ever INSERTs. There is no update_audit_event or
delete_audit_event function anywhere in this codebase, and there
must never be one -- audit integrity depends on that being true at
the code layer in addition to the DB-level trigger in the initial
Alembic migration.
"""
from sqlalchemy.orm import Session

from app.models import AuditEvent, AuditAction


def record_audit_event(
    db: Session,
    *,
    organization_id: str,
    action: AuditAction,
    investigation_id: str | None = None,
    actor_user_id: str | None = None,
    metadata: dict | None = None,
) -> AuditEvent:
    event = AuditEvent(
        organization_id=organization_id,
        investigation_id=investigation_id,
        actor_user_id=actor_user_id,
        action=action,
        metadata_json=metadata or {},
    )
    db.add(event)
    db.flush()
    return event
