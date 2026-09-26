"""
The AI candidate trust boundary.

    AICandidate
        |
        v
    [1] schema validation          (Pydantic, at the route layer)
    [2] qualification validation   (exists, AI-eligible, produced_by allowed)
    [3] claim_signature validation (permitted for this qualification)
    [4] grounding validation       (supporting_text is a real substring)
    [5] validity_requirements      (H2 semantic gate; local disqualifiers)
    [6] deterministic strength     (registry default/maximum + strength_rules)
        |
        v
    FindingCandidate (transient, in-memory only -- see _FindingCandidate)
        |
        v
    dedup (finding_service._persist_or_merge)
        |
        v
    Finding

Every AICandidate submission is persisted (ACCEPTED or REJECTED) for
audit, but ONLY an ACCEPTED one ever reaches finding_service. A
REJECTED candidate never creates a Fact, a Finding, a Score
contribution, or a floor contribution.
"""
import re
from dataclasses import dataclass

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.models import AICandidate, AICandidateStatus, AuditAction, Fact, User
from app.qualification_registry import get_qualification, strength_at_least, max_strength
from app.schemas import AICandidateCreate, FindingCreate
from app.services import validity_engine
from app.services.ai_execution_service import get_ai_execution
from app.services.analysis_run_service import get_analysis_run
from app.services.finding_service import persist_finding_from_trust_boundary
from app.services.investigation_service import get_investigation


@dataclass
class _FindingCandidate:
    """
    Transient, in-memory representation of "passed validation, not yet
    a persisted Finding". Intentionally not an ORM model/table -- see
    app/models.py module docstring for why.
    """
    category: str
    qualification_code: str
    qualification_version: str
    strength: str
    normalized_subject_or_target: str
    claim_signature: str
    supporting_fact_ids: list
    supporting_text: str
    produced_by: str


class _Rejected(Exception):
    def __init__(self, stage: str, reason: str):
        self.stage = stage
        self.reason = reason
        super().__init__(f"[{stage}] {reason}")


def submit_ai_candidate(
    db: Session, *, user: User, investigation_id: str, run_id: str, payload: AICandidateCreate,
) -> AICandidate:
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    run = get_analysis_run(db, user=user, run_id=run_id, investigation_id=inv.id)
    execution = get_ai_execution(db, user=user, investigation_id=inv.id, run_id=run.id)

    source_fact = db.get(Fact, payload.source_fact_id)
    if source_fact is None or source_fact.investigation_id != inv.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail="source_fact_id does not reference a Fact in this investigation")
    if source_fact.analysis_run_id != run.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail="source_fact_id does not reference a Fact in this analysis run")

    resulting_finding_id = None
    try:
        finding_candidate = _validate_candidate(payload=payload, source_fact=source_fact)
        mitre_mapping = {
            "CREDENTIAL_PHISHING_LINK": "T1566.002",
            "MALICIOUS_ATTACHMENT": "T1566.001",
            "SPOOFED_DISPLAY_NAME": "T1566.002",
            "DOMAIN_IMPERSONATION": "T1566.002",
            "SUSPICIOUS_URGENCY": "T1566",
            "BRAND_IMPERSONATION": "T1566.002",
        }
        mitre_id = mitre_mapping.get(finding_candidate.qualification_code, "T1566")

        finding = persist_finding_from_trust_boundary(
            db, user=user, investigation_id=inv.id,
            payload=FindingCreate(
                analysis_run_id=run.id,
                category=finding_candidate.category,
                qualification_code=finding_candidate.qualification_code,
                qualification_version=finding_candidate.qualification_version,
                strength=finding_candidate.strength,
                mitre_id=mitre_id,
                normalized_subject_or_target=finding_candidate.normalized_subject_or_target,
                claim_signature=finding_candidate.claim_signature,
                supporting_fact_ids=finding_candidate.supporting_fact_ids,
                supporting_text=finding_candidate.supporting_text,
                produced_by=finding_candidate.produced_by,
            ),
        )
        resulting_finding_id = finding.id
        candidate_row = AICandidate(
            investigation_id=inv.id,
            analysis_run_id=run.id,
            ai_execution_id=execution.id,
            qualification_code=payload.qualification_code,
            claim_signature=payload.claim_signature,
            supporting_text=payload.supporting_text,
            source_fact_id=source_fact.id,
            model_suggested_strength=payload.model_suggested_strength,
            model_confidence=payload.model_confidence,
            produced_by=payload.produced_by,
            status=AICandidateStatus.ACCEPTED,
            resulting_finding_id=resulting_finding_id,
        )
        audit_action = AuditAction.AI_CANDIDATE_ACCEPTED
        audit_metadata = {
            "qualification_code": payload.qualification_code,
            "resulting_finding_id": resulting_finding_id,
            "deterministic_strength": finding_candidate.strength,
            "model_suggested_strength": payload.model_suggested_strength,
        }
    except _Rejected as rejected:
        candidate_row = AICandidate(
            investigation_id=inv.id,
            analysis_run_id=run.id,
            ai_execution_id=execution.id,
            qualification_code=payload.qualification_code,
            claim_signature=payload.claim_signature,
            supporting_text=payload.supporting_text,
            source_fact_id=source_fact.id,
            model_suggested_strength=payload.model_suggested_strength,
            model_confidence=payload.model_confidence,
            produced_by=payload.produced_by,
            status=AICandidateStatus.REJECTED,
            rejection_stage=rejected.stage,
            rejection_reason=rejected.reason,
        )
        audit_action = AuditAction.AI_CANDIDATE_REJECTED
        audit_metadata = {
            "qualification_code": payload.qualification_code,
            "rejection_stage": rejected.stage,
            "rejection_reason": rejected.reason,
        }

    db.add(candidate_row)
    db.flush()
    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=audit_action,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={**audit_metadata, "ai_candidate_id": candidate_row.id},
    )
    db.commit()
    db.refresh(candidate_row)
    return candidate_row


def _validate_candidate(*, payload: AICandidateCreate, source_fact) -> _FindingCandidate:
    source_text = (source_fact.payload or {}).get("text", "")
    if not isinstance(source_text, str) or not source_text:
        raise _Rejected("schema_validation", "source Fact has no 'text' payload to ground against")

    # [2] qualification validation: exists + AI-eligible
    entry = get_qualification(payload.qualification_code)
    if entry is None:
        raise _Rejected(
            "qualification_validation",
            f"unknown qualification_code '{payload.qualification_code}' -- "
            f"hard-rejected, NOT remapped to GENERIC_SUSPICION",
        )
    if not entry.ai_eligible:
        raise _Rejected(
            "qualification_validation",
            f"qualification_code '{payload.qualification_code}' is not AI-eligible",
        )
    if payload.produced_by not in entry.produced_by_allowed:
        raise _Rejected(
            "qualification_validation",
            f"produced_by '{payload.produced_by}' is not allowed for "
            f"qualification '{payload.qualification_code}'",
        )

    # [3] claim_signature validation
    if payload.claim_signature not in entry.allowed_claim_signatures:
        raise _Rejected(
            "claim_signature_validation",
            f"claim_signature '{payload.claim_signature}' is not permitted for "
            f"qualification '{payload.qualification_code}'",
        )

    # [4] grounding validation
    grounding = validity_engine.check_grounding(source_text, payload.supporting_text)
    if not grounding.is_valid:
        raise _Rejected("grounding_validation", grounding.reason)

    # [5] validity_requirements (H2 semantic gate)
    disqualifiers = entry.validity_requirements.get("disqualifier_phrases", ())
    h2_result = validity_engine.check_h2_semantic_validity(source_text, payload.supporting_text, disqualifiers)
    if not h2_result.is_valid:
        # Per corrections doc: complete rejection, never downgraded to
        # Weak/Moderate.
        raise _Rejected("validity_requirements", h2_result.reason)

    # [5b] deterministic corroboration (locked specification for proposal assistance)
    if payload.qualification_code == "CREDENTIAL_PHISHING_LINK":
        text_lower = payload.supporting_text.lower()
        has_corroboration = bool(
            re.search(r"https?://|www\.|[a-z0-9\-\.]+\.[a-z]{2,}(?:/[^\s]*)?", text_lower)
            or any(kw in text_lower for kw in ("login", "sign in", "signin", "verify", "password", "credential", "click here", "update account"))
        )
        if not has_corroboration:
            raise _Rejected(
                "deterministic_corroboration",
                "CREDENTIAL_PHISHING_LINK proposal lacks deterministic link or credential keyword corroboration in supporting text",
            )

    # [6] deterministic strength evaluation -- model_suggested_strength is
    # NEVER read here. Only entry.default_strength / maximum_strength /
    # strength_rules and the grounded local window matter.
    window = validity_engine.get_local_window(source_text, payload.supporting_text)
    strength = entry.default_strength
    for rule in entry.strength_rules:
        if all(validity_engine.evaluate_predicate(name, window, payload.supporting_text)
               for name in rule.predicate_names):
            strength = max_strength(strength, rule.target_strength)
    if not strength_at_least(entry.maximum_strength, strength):
        strength = entry.maximum_strength  # safety clamp, should be unreachable

    return _FindingCandidate(
        category=entry.category,
        qualification_code=entry.qualification_code,
        qualification_version=entry.version,
        strength=strength,
        normalized_subject_or_target=payload.claim_signature,  # starter normalization; see V4_CHANGELOG.md
        claim_signature=payload.claim_signature,
        supporting_fact_ids=[source_fact.id],
        supporting_text=payload.supporting_text,
        produced_by=payload.produced_by,
    )
