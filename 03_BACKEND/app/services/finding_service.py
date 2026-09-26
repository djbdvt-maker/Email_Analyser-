from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.audit import record_audit_event
from app.models import Finding, AuditAction, User
from app.schemas import FindingCreate
from app.qualification_registry import get_qualification, get_bucket_max_strength, STRENGTH_ORDER
from app.services.investigation_service import get_investigation

# NOTE: there used to be a DETERMINISTIC_PRODUCERS allow-list here that
# checked payload.produced_by against a fixed set of strings. That was
# removed: it inspected a caller-supplied, self-declared field with no
# credential behind it, so any authenticated user could type
# `"produced_by": "deterministic"` and pass it. The real
# authorization now happens at the route layer via
# app/security.py::require_internal_service_producer (the
# X-Internal-Service-Key header, checked BEFORE this function is ever
# called). `produced_by` is now purely descriptive metadata recorded
# on the Finding, not a security check.


def _dedup_query(db: Session, *, investigation_id: str, analysis_run_id: str, payload: FindingCreate):
    """
    Dedup query always scoped to (investigation_id, analysis_run_id).
    There is no NULL-run branch -- every Finding must belong to a run.
    """
    return db.query(Finding).filter(
        Finding.investigation_id == investigation_id,
        Finding.analysis_run_id == analysis_run_id,
        Finding.category == payload.category,
        Finding.qualification_code == payload.qualification_code,
        Finding.claim_signature == payload.claim_signature,
        Finding.normalized_subject_or_target == payload.normalized_subject_or_target,
    )


def persist_finding(db: Session, *, user: User, investigation_id: str, payload: FindingCreate) -> Finding:
    """
    Public entry point for a Finding submitted DIRECTLY (not via the AI
    trust boundary). Callers reach this function only after the route
    layer's `require_internal_service_producer` dependency has already
    authorized the request via X-Internal-Service-Key -- this function
    itself performs no producer-identity check.
    """
    return _persist_or_merge(db, user=user, investigation_id=investigation_id, payload=payload)


def persist_finding_from_trust_boundary(
    db: Session, *, user: User, investigation_id: str, payload: FindingCreate
) -> Finding:
    """
    Internal entry point used ONLY by
    app/services/trust_boundary_service.py after an AICandidate has
    passed every validation stage and had its strength computed
    deterministically. Not exposed as a public route.
    """
    return _persist_or_merge(db, user=user, investigation_id=investigation_id, payload=payload)


def _persist_or_merge(db: Session, *, user: User, investigation_id: str, payload: FindingCreate) -> Finding:
    """
    Dedup key: (investigation_id, analysis_run_id, category, qualification_code,
    claim_signature, normalized_subject_or_target). Never computes or
    changes strength based on how many times a claim has been
    observed -- only merges evidence references.

    analysis_run_id is REQUIRED. A Finding without a run is rejected.
    """
    inv = get_investigation(db, user=user, investigation_id=investigation_id)

    # Enforce the locked invariant: every Finding must belong to a run.
    if not payload.analysis_run_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="analysis_run_id is required. Every Finding must belong to an AnalysisRun.",
        )

    # Validate qualification and claim signature - reject unknown or invalid without remapping
    q_entry = get_qualification(payload.qualification_code)
    if q_entry is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown qualification_code '{payload.qualification_code}'",
        )
    if q_entry.allowed_claim_signatures and payload.claim_signature not in q_entry.allowed_claim_signatures:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid claim_signature '{payload.claim_signature}' for qualification '{payload.qualification_code}'",
        )

    # Enforce registry maximum_strength: analyzer/caller cannot exceed qualification maximum
    effective_strength = payload.strength
    if q_entry.maximum_strength in STRENGTH_ORDER and effective_strength in STRENGTH_ORDER:
        if STRENGTH_ORDER.index(effective_strength) > STRENGTH_ORDER.index(q_entry.maximum_strength):
            effective_strength = q_entry.maximum_strength
    # Enforce category scoring_bucket max_strength
    b_max = get_bucket_max_strength(payload.category)
    if b_max and b_max in STRENGTH_ORDER and effective_strength in STRENGTH_ORDER:
        if STRENGTH_ORDER.index(effective_strength) > STRENGTH_ORDER.index(b_max):
            effective_strength = b_max

    # AI candidates cannot be submitted directly as deterministic findings
    if payload.produced_by == "ai_reasoner" and not q_entry.ai_eligible:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Producer 'ai_reasoner' is not allowed for qualification '{payload.qualification_code}'",
        )

    target_run_id = payload.analysis_run_id
    existing = _dedup_query(
        db,
        investigation_id=inv.id,
        analysis_run_id=target_run_id,
        payload=payload,
    ).one_or_none()

    if existing is None:
        finding = Finding(
            investigation_id=inv.id,
            analysis_run_id=target_run_id,
            category=payload.category,
            qualification_code=payload.qualification_code,
            qualification_version=payload.qualification_version,
            strength=effective_strength,
            mitre_id=payload.mitre_id,
            normalized_subject_or_target=payload.normalized_subject_or_target,
            claim_signature=payload.claim_signature,
            supporting_fact_ids=list(payload.supporting_fact_ids),
            supporting_text=payload.supporting_text,
            produced_by=payload.produced_by,
        )
        db.add(finding)
        try:
            db.flush()
        except IntegrityError:
            # Lost a race with a concurrent insert of the same dedup key;
            # fall back to the merge path instead of erroring the caller.
            db.rollback()
            existing = _dedup_query(
                db,
                investigation_id=inv.id,
                analysis_run_id=target_run_id,
                payload=payload,
            ).one()
            return _merge_into_existing(db, user=user, existing=existing, payload=payload)

        record_audit_event(
            db,
            organization_id=user.organization_id,
            action=AuditAction.FINDING_PERSISTED,
            investigation_id=inv.id,
            actor_user_id=user.id,
            metadata={"finding_id": finding.id, "qualification_code": finding.qualification_code},
        )
        db.commit()
        db.refresh(finding)
        return finding

    return _merge_into_existing(db, user=user, existing=existing, payload=payload)


def _merge_into_existing(db: Session, *, user: User, existing: Finding, payload: FindingCreate) -> Finding:
    merged_fact_ids = sorted(set(existing.supporting_fact_ids) | set(payload.supporting_fact_ids))
    existing.supporting_fact_ids = merged_fact_ids

    if payload.supporting_text and payload.supporting_text not in existing.supporting_text:
        existing.supporting_text = f"{existing.supporting_text}\n---\n{payload.supporting_text}"

    strength_conflict = existing.strength != payload.strength

    # Deliberately NOT doing: existing.strength = max(existing.strength, payload.strength)
    # Repeated/corroborating observations of the same claim must never
    # upgrade strength on their own. If upstream genuinely disagrees on
    # strength for what dedups to the same claim, that is a data-quality
    # signal to audit, not something this layer resolves by picking the
    # larger value.
    db.flush()
    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.FINDING_MERGED,
        investigation_id=existing.investigation_id,
        actor_user_id=user.id,
        metadata={
            "finding_id": existing.id,
            "merged_fact_ids": merged_fact_ids,
            "strength_conflict": strength_conflict,
            "kept_strength": existing.strength,
            "incoming_strength": payload.strength,
        },
    )
    db.commit()
    db.refresh(existing)
    return existing


def list_findings(
    db: Session, *, user: User, investigation_id: str, analysis_run_id: Optional[str] = None
) -> list[Finding]:
    """
    List findings for an investigation, optionally filtered by run.
    When analysis_run_id is omitted, returns ALL findings for the
    investigation (across all runs) -- never a NULL-run branch.
    """
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    query = db.query(Finding).filter(Finding.investigation_id == inv.id)
    if analysis_run_id:
        query = query.filter(Finding.analysis_run_id == analysis_run_id)
    return query.all()
