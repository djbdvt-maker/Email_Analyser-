from sqlalchemy.orm import Session

from app.models import Fact, User
from app.schemas import FactCreate
from app.services.investigation_service import get_investigation


def persist_fact(db: Session, *, user: User, investigation_id: str, payload: FactCreate) -> Fact:
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    fact = Fact(
        investigation_id=inv.id,
        analysis_run_id=payload.analysis_run_id,
        fact_type=payload.fact_type,
        payload=payload.payload,
        produced_by=payload.produced_by,
    )
    db.add(fact)
    db.commit()
    db.refresh(fact)
    return fact


def list_facts(db: Session, *, user: User, investigation_id: str) -> list[Fact]:
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    return db.query(Fact).filter(Fact.investigation_id == inv.id).all()
