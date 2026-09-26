"""
Spec Compliance Regression Tests
=================================
Comprehensive coverage for the locked specification:
  - Score Engine / Conclusion Generator separation (Section 6)
  - Score rules (Section 7)
  - Q40 locked definition (Section 2)
  - Q41 bounded definition (Section 3)
  - CF-06 deterministic evidence-grounded (Section 4)
  - CF-01 through CF-05 floor definitions (Section 5)
  - Analysis run lifecycle (Section 10)
  - Canonical analyst actions (Section 12)
  - Export hash (Section 14)
  - AI trust boundary (Section 9)
  - Registry authority (Section 1)
"""
import hashlib
import io
import json
import zipfile
import pytest

from dataclasses import dataclass

from app.models import (
    UserRole,
    InvestigationStatus,
    AnalysisRunStatus,
    AuditAction,
    AuditEvent,
    ScoreConclusion,
    Finding,
)
from app.services.score_engine import (
    compute_score,
    ScoreResult,
    ScoreOutput,
    CATEGORY_CAPS,
    STRENGTH_POINTS,
)
from app.services.conclusion_generator import ConclusionGenerator, ConclusionOutput
from app.services.floor_engine import evaluate_floors
from app.qualification_registry import (
    get_qualification,
    get_scoring_buckets,
    get_floors,
    get_category_caps,
)
from tests.conftest import (
    auth_headers,
    _make_user,
    create_investigation,
    create_run,
    internal_service_headers,
)


# --------------------------------------------------------------------------
# Mock Finding for unit tests
# --------------------------------------------------------------------------

@dataclass
class MockFinding:
    id: str
    category: str
    strength: str
    qualification_code: str


# ==========================================================================
# SECTION 6: Score Engine / Conclusion Generator Separation
# ==========================================================================

class TestScoreConclusionSeparation:
    """Score Engine owns numeric scoring. Conclusion Generator owns verdict/text.
    Score Engine must NEVER instantiate or invoke ConclusionGenerator."""

    def test_score_engine_returns_score_output_only(self):
        """compute_score() returns ScoreResult with NO verdict/conclusion attributes."""
        findings = [
            MockFinding("f1", "Content", "Moderate", "FINANCIAL_REQUEST"),
            MockFinding("f2", "Identity", "Moderate", "EXECUTIVE_IMPERSONATION"),
        ]
        result = compute_score(findings)
        assert isinstance(result, ScoreResult)
        assert isinstance(result.total_score, int)
        assert isinstance(result.severity, str)
        assert isinstance(result.category_breakdown, dict)
        assert isinstance(result.triggered_floor_codes, list)
        # Score Engine must NOT produce verdict or explanations
        assert not hasattr(result, "verdict")
        assert not hasattr(result, "one_line_explanation")
        assert not hasattr(result, "why_explanation")

    def test_score_engine_source_has_no_conclusion_import(self):
        """score_engine.py must not import ConclusionGenerator."""
        import inspect
        import app.services.score_engine as se_module
        source = inspect.getsource(se_module)
        assert "from app.services.conclusion_generator" not in source
        assert "from app.interfaces.conclusion_generator" not in source
        assert "import ConclusionGenerator" not in source

    def test_score_engine_service_has_separate_functions(self):
        """score_engine_service.py must expose compute_and_persist_score and
        generate_and_persist_conclusion as separate functions."""
        from app.services import score_engine_service as ses
        assert hasattr(ses, "compute_and_persist_score")
        assert hasattr(ses, "generate_and_persist_conclusion")
        assert callable(ses.compute_and_persist_score)
        assert callable(ses.generate_and_persist_conclusion)

    def test_conclusion_generator_accepts_score_output(self):
        """ConclusionGenerator.generate() accepts ScoreOutput and produces ConclusionOutput."""
        findings = [MockFinding("f1", "Links", "Strong", "CONFIRMED_MALICIOUS_INDICATOR")]
        score = compute_score(findings)
        cg = ConclusionGenerator()
        conclusion = cg.generate(score_output=score, findings=findings)
        assert isinstance(conclusion, ConclusionOutput)
        assert conclusion.verdict is not None
        assert conclusion.one_line_explanation is not None
        assert conclusion.why_explanation is not None

    def test_conclusion_generator_floor_driven_verdicts(self):
        """Specific floor codes produce specific canonical verdicts."""
        cg = ConclusionGenerator()

        # CF-05 -> MALICIOUS
        co = cg.generate(total_score=30, severity="HIGH",
                         triggered_floor_codes=["CF-05"])
        assert co.verdict == "MALICIOUS"

        # CF-06 -> SUSPICIOUS
        co = cg.generate(total_score=30, severity="HIGH",
                         triggered_floor_codes=["CF-06"])
        assert co.verdict == "SUSPICIOUS"

        # CF-03 -> SUSPICIOUS
        co = cg.generate(total_score=36, severity="HIGH",
                         triggered_floor_codes=["CF-03"])
        assert co.verdict == "SUSPICIOUS"

        # CF-02 -> SUSPICIOUS
        co = cg.generate(total_score=36, severity="HIGH",
                         triggered_floor_codes=["CF-02"])
        assert co.verdict == "SUSPICIOUS"

        # CF-01 -> SUSPICIOUS
        co = cg.generate(total_score=36, severity="HIGH",
                         triggered_floor_codes=["CF-01"])
        assert co.verdict == "SUSPICIOUS"

        # CF-04 -> SUSPICIOUS
        co = cg.generate(total_score=36, severity="HIGH",
                         triggered_floor_codes=["CF-04"])
        assert co.verdict == "SUSPICIOUS"

    def test_clean_verdict_without_floors(self):
        """Clean/Low severity without findings -> BENIGN."""
        cg = ConclusionGenerator()
        co = cg.generate(total_score=0, severity="LOW",
                         triggered_floor_codes=[])
        assert co.verdict == "BENIGN"


# ==========================================================================
# SECTION 7: Score Rules
# ==========================================================================

class TestScoreRules:
    """Verify locked score constants and rules."""

    def test_strength_point_values(self):
        assert STRENGTH_POINTS["Weak"] == 0.5
        assert STRENGTH_POINTS["Moderate"] == 1.0
        assert STRENGTH_POINTS["Strong"] == 1.5
        assert STRENGTH_POINTS.get("Negligible", 0) == 0.0

    def test_category_caps_from_registry(self):
        """Category caps must come from canonical registry."""
        registry_caps = get_category_caps()
        assert CATEGORY_CAPS == registry_caps

    def test_floors_independent_of_additive_scoring(self):
        """Floors activate regardless of total additive score."""
        findings = [MockFinding("1", "Links", "Strong", "CONFIRMED_MALICIOUS_INDICATOR")]
        result = compute_score(findings)
        assert "CF-05" in result.triggered_floor_codes
        assert result.severity == "HIGH"  # Floor drives severity up

    def test_weak_only_ceiling(self):
        """If ALL findings are Weak and no floors trigger, score is capped at 40."""
        findings = [
            MockFinding(f"w{i}", cat, "Weak", "SPF_NONE")
            for i, cat in enumerate(["Authentication", "Domain", "Links",
                                       "Content", "Identity", "Attachments",
                                       "Infrastructure"])
        ]
        result = compute_score(findings)
        assert result.total_score <= 40

    def test_global_score_cap_100(self):
        """Total score cannot exceed 100."""
        findings = [
            MockFinding("1", "Content", "Strong", "FINANCIAL_REQUEST"),
            MockFinding("2", "Identity", "Strong", "EXECUTIVE_IMPERSONATION"),
            MockFinding("3", "Links", "Strong", "CREDENTIAL_PHISHING_LINK"),
            MockFinding("4", "Domain", "Strong", "PROTECTED_BRAND_LOOKALIKE_DOMAIN"),
        ]
        result = compute_score(findings)
        assert result.total_score <= 100


# ==========================================================================
# SECTIONS 2, 3, 4: Q40, Q41, CF-06
# ==========================================================================

class TestCF06Routing:
    """CF-06 subtype evaluation and boundary conditions."""

    def test_q40_registered_in_registry(self):
        """Q40 (CF-06:INDEPENDENT_TRUSTED_CONTRADICTION) exists in canonical registry."""
        q = get_qualification("CF-06:INDEPENDENT_TRUSTED_CONTRADICTION")
        assert q is not None
        assert q.category.lower().replace(" ", "_") in ("routing", "routing_fabrication", "routing fabrication")
        assert "independent_trusted_contradiction" in q.allowed_claim_signatures
        assert q.ai_eligible is False
        assert "deterministic" in q.produced_by_allowed

    def test_q41_registered_in_registry(self):
        """Q41 (CF-06:STRUCTURAL_IMPLAUSIBILITY) exists in canonical registry."""
        q = get_qualification("CF-06:STRUCTURAL_IMPLAUSIBILITY")
        assert q is not None
        assert "structural_implausibility" in q.allowed_claim_signatures
        assert q.ai_eligible is False

    def test_temporal_contradiction_registered(self):
        """CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE exists in registry."""
        q = get_qualification("CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE")
        assert q is not None
        assert "temporal_contradiction_beyond_tolerance" in q.allowed_claim_signatures

    def test_cf06_floor_uses_or_operator(self):
        """CF-06 floor uses OR operator — any single subtype triggers it."""
        floors = get_floors()
        assert "CF-06" in floors
        cf06 = floors["CF-06"]
        assert cf06.operator == "OR"
        assert cf06.target_severity == "High"

    def test_cf06_all_subtypes_trigger_individually(self):
        """Each CF-06 subtype independently triggers the CF-06 floor."""
        subtypes = [
            "CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE",
            "CF-06:INDEPENDENT_TRUSTED_CONTRADICTION",
            "CF-06:STRUCTURAL_IMPLAUSIBILITY",
            "ROUTING_FABRICATION_QUALIFIED",
        ]
        for code in subtypes:
            result = evaluate_floors([MockFinding("x", "Routing fabrication", "Strong", code)])
            assert "CF-06" in result, f"{code} should trigger CF-06"

    def test_cf06_negative_conditions(self):
        """Authentication failures, unknown IPs, or LLM suspicion must NOT trigger CF-06."""
        non_triggers = [
            MockFinding("a1", "Authentication", "Moderate", "DMARC_FAIL"),
            MockFinding("a2", "Authentication", "Moderate", "SPF_FAIL"),
            MockFinding("a3", "Authentication", "Moderate", "DKIM_FAIL"),
            MockFinding("a4", "Infrastructure", "Weak", "NEWLY_OBSERVED_INFRASTRUCTURE"),
            MockFinding("a5", "Content", "Weak", "GENERIC_SUSPICION"),
        ]
        result = evaluate_floors(non_triggers)
        assert "CF-06" not in result


# ==========================================================================
# SECTION 5: Other Six Floors (CF-01 through CF-05)
# ==========================================================================

class TestFloorDefinitions:
    """Verify locked floor predicates from canonical registry."""

    def test_cf01_requires_both_halves(self):
        """CF-01: PROTECTED_BRAND_LOOKALIKE_DOMAIN AND EXPLICIT_BRAND_REPRESENTATION_CLAIM."""
        # Both present -> triggers
        both = [
            MockFinding("1", "Domain", "Moderate", "PROTECTED_BRAND_LOOKALIKE_DOMAIN"),
            MockFinding("2", "Identity", "Moderate", "EXPLICIT_BRAND_REPRESENTATION_CLAIM"),
        ]
        assert "CF-01" in evaluate_floors(both)

        # Only one -> does not trigger
        only_domain = [MockFinding("1", "Domain", "Moderate", "PROTECTED_BRAND_LOOKALIKE_DOMAIN")]
        assert "CF-01" not in evaluate_floors(only_domain)

        only_claim = [MockFinding("2", "Identity", "Moderate", "EXPLICIT_BRAND_REPRESENTATION_CLAIM")]
        assert "CF-01" not in evaluate_floors(only_claim)

    def test_cf02_requires_both_halves(self):
        """CF-02: EXECUTIVE_IMPERSONATION AND FINANCIAL_REQUEST."""
        both = [
            MockFinding("1", "Identity", "Moderate", "EXECUTIVE_IMPERSONATION"),
            MockFinding("2", "Content", "Moderate", "FINANCIAL_REQUEST"),
        ]
        assert "CF-02" in evaluate_floors(both)
        assert "CF-02" not in evaluate_floors([both[0]])
        assert "CF-02" not in evaluate_floors([both[1]])

    def test_cf03_requires_both_halves(self):
        """CF-03: CREDENTIAL_PHISHING_LINK AND IDENTITY_ANOMALY."""
        both = [
            MockFinding("1", "Links", "Moderate", "CREDENTIAL_PHISHING_LINK"),
            MockFinding("2", "Identity", "Moderate", "IDENTITY_ANOMALY"),
        ]
        assert "CF-03" in evaluate_floors(both)
        assert "CF-03" not in evaluate_floors([both[0]])

    def test_cf04_requires_both_halves(self):
        """CF-04: SUSPICIOUS_ATTACHMENT AND IDENTITY_ANOMALY."""
        both = [
            MockFinding("1", "Attachments", "Moderate", "SUSPICIOUS_ATTACHMENT"),
            MockFinding("2", "Identity", "Moderate", "IDENTITY_ANOMALY"),
        ]
        assert "CF-04" in evaluate_floors(both)
        assert "CF-04" not in evaluate_floors([both[0]])

    def test_cf05_single_requirement(self):
        """CF-05: CONFIRMED_MALICIOUS_INDICATOR alone at Strong triggers."""
        strong = [MockFinding("1", "Links", "Strong", "CONFIRMED_MALICIOUS_INDICATOR")]
        assert "CF-05" in evaluate_floors(strong)

        # Moderate does NOT trigger CF-05 (requires Strong)
        moderate = [MockFinding("1", "Links", "Moderate", "CONFIRMED_MALICIOUS_INDICATOR")]
        assert "CF-05" not in evaluate_floors(moderate)

    def test_all_floors_target_high(self):
        """All 6 floors target High severity."""
        floors = get_floors()
        for code in ("CF-01", "CF-02", "CF-03", "CF-04", "CF-05", "CF-06"):
            assert floors[code].target_severity == "High", f"{code} target severity should be High"


# ==========================================================================
# SECTION 10: Analysis Run Lifecycle
# ==========================================================================

class TestAnalysisRunLifecycle:
    """Verify AnalysisRun status enum and current_analysis_run_id semantics."""

    def test_analysis_run_statuses(self):
        """Exactly these statuses exist: QUEUED, PARSING, ANALYZING, SCORING, COMPLETED, FAILED, CANCELLED."""
        expected = {"QUEUED", "PARSING", "ANALYZING", "SCORING", "COMPLETED", "FAILED", "CANCELLED"}
        actual = {s.value for s in AnalysisRunStatus}
        assert actual == expected

    def test_awaiting_analysis_is_not_analysis_run_status(self):
        """AWAITING_ANALYSIS is InvestigationStatus only, not AnalysisRunStatus."""
        assert hasattr(InvestigationStatus, "AWAITING_ANALYSIS")
        assert not hasattr(AnalysisRunStatus, "AWAITING_ANALYSIS")

    def test_completed_run_becomes_current(self, client, user, db_session):
        """A COMPLETED run updates current_analysis_run_id."""
        inv = create_investigation(client, user)
        run = create_run(client, user, inv["id"])
        # Advance to COMPLETED
        for st in ("PARSING", "ANALYZING", "SCORING", "COMPLETED"):
            resp = client.post(
                f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/status",
                json={"status": st},
                headers=auth_headers(user),
            )
            assert resp.status_code == 200

        inv_resp = client.get(f"/api/v1/investigations/{inv['id']}", headers=auth_headers(user))
        assert inv_resp.json()["current_analysis_run_id"] == run["id"]

    def test_failed_run_does_not_replace_current(self, client, user, db_session):
        """A FAILED run must not replace current_analysis_run_id."""
        inv = create_investigation(client, user)

        # Complete run 1
        run1 = create_run(client, user, inv["id"])
        for st in ("PARSING", "ANALYZING", "SCORING", "COMPLETED"):
            client.post(
                f"/api/v1/investigations/{inv['id']}/analysis-runs/{run1['id']}/status",
                json={"status": st}, headers=auth_headers(user),
            )

        # Fail run 2
        run2 = create_run(client, user, inv["id"])
        client.post(
            f"/api/v1/investigations/{inv['id']}/analysis-runs/{run2['id']}/status",
            json={"status": "PARSING"}, headers=auth_headers(user),
        )
        client.post(
            f"/api/v1/investigations/{inv['id']}/analysis-runs/{run2['id']}/status",
            json={"status": "FAILED", "failure_reason": "test"},
            headers=auth_headers(user),
        )

        inv_resp = client.get(f"/api/v1/investigations/{inv['id']}", headers=auth_headers(user))
        assert inv_resp.json()["current_analysis_run_id"] == run1["id"]

    def test_cancelled_run_does_not_replace_current(self, client, user, db_session):
        """A CANCELLED run must not replace current_analysis_run_id."""
        inv = create_investigation(client, user)
        run1 = create_run(client, user, inv["id"])
        for st in ("PARSING", "ANALYZING", "SCORING", "COMPLETED"):
            client.post(
                f"/api/v1/investigations/{inv['id']}/analysis-runs/{run1['id']}/status",
                json={"status": st}, headers=auth_headers(user),
            )

        run2 = create_run(client, user, inv["id"])
        client.post(
            f"/api/v1/investigations/{inv['id']}/analysis-runs/{run2['id']}/status",
            json={"status": "CANCELLED"}, headers=auth_headers(user),
        )

        inv_resp = client.get(f"/api/v1/investigations/{inv['id']}", headers=auth_headers(user))
        assert inv_resp.json()["current_analysis_run_id"] == run1["id"]


# ==========================================================================
# SECTION 12: Canonical Analyst Actions
# ==========================================================================

class TestCanonicalAnalystActions:
    """Verify canonical action vocabulary and legacy rejection."""

    def test_canonical_actions_accepted(self, client, user, db_session):
        """add_note is always accepted."""
        inv = create_investigation(client, user)
        # Advance run to COMPLETED
        run = create_run(client, user, inv["id"])
        for st in ("PARSING", "ANALYZING", "SCORING", "COMPLETED"):
            client.post(
                f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/status",
                json={"status": st}, headers=auth_headers(user),
            )

        resp = client.post(
            f"/api/v1/investigations/{inv['id']}/actions",
            json={"action": "add_note", "note": "test note"},
            headers=auth_headers(user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "add_note"

    def test_legacy_aliases_rejected(self, client, user, db_session):
        """Legacy action aliases must be rejected with 422."""
        inv = create_investigation(client, user)
        for alias in ("CONFIRM", "CONFIRM_MALICIOUS", "MARK_FALSE_POSITIVE", "ESCALATE", "NOTE"):
            resp = client.post(
                f"/api/v1/investigations/{inv['id']}/actions",
                json={"action": alias},
                headers=auth_headers(user),
            )
            assert resp.status_code == 422, f"Alias '{alias}' should be rejected"

    def test_add_note_does_not_change_status(self, client, user, db_session):
        """add_note must NOT change investigation status."""
        inv = create_investigation(client, user)
        run = create_run(client, user, inv["id"])
        for st in ("PARSING", "ANALYZING", "SCORING", "COMPLETED"):
            client.post(
                f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/status",
                json={"status": st}, headers=auth_headers(user),
            )

        before = client.get(f"/api/v1/investigations/{inv['id']}", headers=auth_headers(user)).json()
        client.post(
            f"/api/v1/investigations/{inv['id']}/actions",
            json={"action": "add_note", "note": "observation"},
            headers=auth_headers(user),
        )
        after = client.get(f"/api/v1/investigations/{inv['id']}", headers=auth_headers(user)).json()
        assert before["status"] == after["status"]

    def test_add_note_emits_note_added_event(self, client, user, db_session):
        """add_note must emit NOTE_ADDED audit event, not INVESTIGATION_STATUS_CHANGED."""
        inv = create_investigation(client, user)
        client.post(
            f"/api/v1/investigations/{inv['id']}/actions",
            json={"action": "add_note", "note": "my observation"},
            headers=auth_headers(user),
        )
        events = db_session.query(AuditEvent).filter(
            AuditEvent.investigation_id == inv["id"],
            AuditEvent.action == AuditAction.NOTE_ADDED,
        ).all()
        assert len(events) >= 1
        assert events[-1].metadata_json["note"] == "my observation"

    def test_false_positive_requires_rationale(self, client, user, db_session):
        """false_positive without rationale returns 422."""
        inv = create_investigation(client, user)
        run = create_run(client, user, inv["id"])
        for st in ("PARSING", "ANALYZING", "SCORING", "COMPLETED"):
            client.post(
                f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/status",
                json={"status": st}, headers=auth_headers(user),
            )

        resp = client.post(
            f"/api/v1/investigations/{inv['id']}/actions",
            json={"action": "false_positive"},
            headers=auth_headers(user),
        )
        assert resp.status_code == 422

    def test_false_positive_with_rationale_accepted(self, client, user, db_session):
        """false_positive with rationale transitions to FALSE_POSITIVE."""
        inv = create_investigation(client, user)
        inv_id = inv["id"]
        client.post(
            f"/api/v1/investigations/{inv_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers=auth_headers(user),
        )

        resp = client.post(
            f"/api/v1/investigations/{inv_id}/actions",
            json={"action": "false_positive", "falsePositiveReason": "Verified internal test email"},
            headers=auth_headers(user),
        )
        assert resp.status_code == 200

        inv_resp = client.get(f"/api/v1/investigations/{inv['id']}", headers=auth_headers(user))
        assert inv_resp.json()["status"] == "FALSE_POSITIVE"

    def test_viewer_cannot_confirm_malicious(self, client, user, db_session, org):
        """USER/VIEWER cannot perform confirm_malicious (requires ANALYST/ADMIN)."""
        viewer = _make_user(db_session, org, "viewer@acme.test", role=UserRole.USER)
        inv = create_investigation(client, user)
        run = create_run(client, user, inv["id"])
        for st in ("PARSING", "ANALYZING", "SCORING", "COMPLETED"):
            client.post(
                f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/status",
                json={"status": st}, headers=auth_headers(user),
            )

        resp = client.post(
            f"/api/v1/investigations/{inv['id']}/actions",
            json={"action": "confirm_malicious"},
            headers=auth_headers(viewer),
        )
        assert resp.status_code == 403


# ==========================================================================
# SECTION 14: Export Hash
# ==========================================================================

class TestExportHash:
    """export_bundle_sha256 must hash the ACTUAL exported bundle bytes."""

    def test_export_hash_is_actual_bundle_hash(self, client, user, db_session):
        """Export hash must be computed from the zip bundle bytes, not the original .eml."""
        inv = create_investigation(client, user)

        # Upload artifact
        eml_content = b"Subject: Test\nFrom: test@example.com\n\nBody"
        import io
        resp = client.post(
            f"/api/v1/investigations/{inv['id']}/artifacts",
            files={"file": ("test.eml", io.BytesIO(eml_content), "message/rfc822")},
            headers=auth_headers(user),
        )
        assert resp.status_code == 201
        artifact = resp.json()
        artifact_id = artifact["id"]
        original_sha = artifact["original_artifact_sha256"]

        # Export
        exp_resp = client.post(
            f"/api/v1/investigations/{inv['id']}/evidence/{artifact_id}/export",
            headers=auth_headers(user),
        )
        assert exp_resp.status_code == 200
        export_data = exp_resp.json()
        export_hash = export_data["export_bundle_sha256"]

        # Export hash must exist and be different from original hash
        assert export_hash is not None
        assert len(export_hash) == 64
        assert export_hash != original_sha, \
            "export_bundle_sha256 must hash the ZIP bundle, not the original .eml"


# ==========================================================================
# SECTION 1: Canonical Registry
# ==========================================================================

class TestCanonicalRegistry:
    """Verify registry is authoritative and consistent."""

    def test_registry_sha256_matches(self):
        """registry-v1.sha256 must match actual registry-v1.json hash."""
        import os
        registry_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "01_REGISTRY", "releases"
        )
        registry_path = os.path.join(registry_dir, "registry-v1.json")
        sha_path = os.path.join(registry_dir, "registry-v1.sha256")

        if not os.path.exists(registry_path) or not os.path.exists(sha_path):
            pytest.skip("Registry release files not found in expected path")

        with open(registry_path, "rb") as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()

        with open(sha_path, "r") as f:
            expected_hash = f.read().strip().split()[0]

        assert actual_hash == expected_hash

    def test_all_scoring_buckets_registered(self):
        """All 9 canonical scoring buckets exist with correct caps."""
        expected_buckets = {
            "Identity": 20,
            "Authentication": 16,
            "Domain": 16,
            "URL": 22,
            "Attachment": 20,
            "Infrastructure": 14,
            "Routing": 20,
            "Social Engineering": 14,
            "Threat Intelligence": 24,
        }
        caps = get_category_caps()
        for name, expected_cap in expected_buckets.items():
            assert name in caps, f"Bucket '{name}' missing from registry"
            assert caps[name] == expected_cap, f"Bucket '{name}' cap mismatch"

    def test_credential_phishing_link_is_ai_eligible(self):
        """CREDENTIAL_PHISHING_LINK must be AI-eligible per locked registry."""
        q = get_qualification("CREDENTIAL_PHISHING_LINK")
        assert q is not None
        assert q.ai_eligible is True
        assert "ai_reasoner" in q.produced_by_allowed


# ==========================================================================
# SECTION 9: AI Trust Boundary
# ==========================================================================

class TestAITrustBoundary:
    """AI must never assign score, severity, floor, or final verdict."""

    def test_ai_eligible_set_from_registry(self):
        """AI-eligible qualifications must come from registry, not hard-coded."""
        from app.qualification_registry import all_qualifications
        all_quals = list(all_qualifications().values())
        ai_eligible = [q for q in all_quals if q.ai_eligible]
        # At least CREDENTIAL_PHISHING_LINK, EXECUTIVE_IMPERSONATION, FINANCIAL_REQUEST,
        # EXPLICIT_BRAND_REPRESENTATION_CLAIM, GENERIC_SUSPICION
        ai_codes = {q.qualification_code for q in ai_eligible}
        assert "CREDENTIAL_PHISHING_LINK" in ai_codes
        assert "EXECUTIVE_IMPERSONATION" in ai_codes
        assert "FINANCIAL_REQUEST" in ai_codes
        assert "GENERIC_SUSPICION" in ai_codes
        assert "EXPLICIT_BRAND_REPRESENTATION_CLAIM" in ai_codes


# ==========================================================================
# SECTION 11: Public API Reconciliation
# ==========================================================================

class TestPublicAPIReconciliation:
    """Verify canonical endpoints exist and legacy routes are deprecated."""

    def test_canonical_endpoints_exist(self, client, user, db_session):
        """All canonical API endpoints must respond."""
        inv = create_investigation(client, user)
        inv_id = inv["id"]
        h = auth_headers(user)

        # GET /investigations
        assert client.get("/api/v1/investigations", headers=h).status_code == 200

        # GET /investigations/{id}
        assert client.get(f"/api/v1/investigations/{inv_id}", headers=h).status_code == 200

        # GET /investigations/{id}/audit
        assert client.get(f"/api/v1/investigations/{inv_id}/audit", headers=h).status_code == 200

        # GET /investigations/{id}/evidence
        assert client.get(f"/api/v1/investigations/{inv_id}/evidence", headers=h).status_code == 200

        # GET /investigations/{id}/findings
        assert client.get(f"/api/v1/investigations/{inv_id}/findings", headers=h).status_code == 200

        # POST /investigations/{id}/actions
        resp = client.post(
            f"/api/v1/investigations/{inv_id}/actions",
            json={"action": "add_note", "note": "api test"},
            headers=h,
        )
        assert resp.status_code == 200

    def test_legacy_details_route_deprecated(self): pass


# ==========================================================================
# SECTION 1, 2, 3: Locked InvestigationStatus & Human Disposition
# ==========================================================================

class TestLockedInvestigationStatus:
    """Canonical InvestigationStatus values and lifecycle rules."""

    def test_analyzed_does_not_exist_in_investigation_status(self):
        """ANALYZED must not exist in InvestigationStatus enum."""
        assert not hasattr(InvestigationStatus, "ANALYZED")
        canonical = {
            "AWAITING_ANALYSIS",
            "UNDER_REVIEW",
            "CONFIRMED",
            "FALSE_POSITIVE",
            "ESCALATED",
            "CLOSED",
        }
        assert {s.value for s in InvestigationStatus} == canonical

    def test_new_investigation_is_awaiting_analysis(self, client, user):
        """New investigation always begins in AWAITING_ANALYSIS."""
        inv = create_investigation(client, user)
        assert inv["status"] == "AWAITING_ANALYSIS"

    def test_pipeline_transitions_awaiting_analysis_to_under_review(self, client, user, db_session):
        """Usable completed automated analysis transitions AWAITING_ANALYSIS -> UNDER_REVIEW."""
        from app.services.pipeline_service import execute_analysis_pipeline
        inv = create_investigation(client, user)
        eml_bytes = b"Subject: Test\nFrom: sender@example.com\nTo: recipient@example.com\n\nHello"
        up_resp = client.post(
            f"/api/v1/investigations/{inv['id']}/artifacts",
            files={"file": ("sample.eml", io.BytesIO(eml_bytes), "message/rfc822")},
            headers=auth_headers(user),
        )
        assert up_resp.status_code == 201
        artifact_id = up_resp.json()["id"]

        run = create_run(client, user, inv["id"])
        res = execute_analysis_pipeline(
            db_session,
            user=user,
            investigation_id=inv["id"],
            run_id=run["id"],
            artifact_id=artifact_id,
        )
        assert res["investigation_id"] == inv["id"]
        inv_after = client.get(f"/api/v1/investigations/{inv['id']}", headers=auth_headers(user)).json()
        assert inv_after["status"] == "UNDER_REVIEW"

    def test_new_analysis_does_not_erase_human_disposition(self, client, user, db_session):
        """A new analysis does NOT overwrite CONFIRMED, FALSE_POSITIVE, ESCALATED, or CLOSED."""
        from app.services.pipeline_service import execute_analysis_pipeline
        inv = create_investigation(client, user)
        inv_id = inv["id"]

        # Move to UNDER_REVIEW then CONFIRMED
        client.post(f"/api/v1/investigations/{inv_id}/status", json={"status": "UNDER_REVIEW"}, headers=auth_headers(user))
        client.post(f"/api/v1/investigations/{inv_id}/actions", json={"action": "confirm_malicious"}, headers=auth_headers(user))
        assert client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()["status"] == "CONFIRMED"

        # Ingest new artifact and run new analysis
        eml_bytes = b"Subject: Re-analysis\nFrom: sender@example.com\n\nContent"
        up_resp = client.post(
            f"/api/v1/investigations/{inv_id}/artifacts",
            files={"file": ("second.eml", io.BytesIO(eml_bytes), "message/rfc822")},
            headers=auth_headers(user),
        )
        artifact_id = up_resp.json()["id"]
        run2 = create_run(client, user, inv_id)
        execute_analysis_pipeline(db_session, user=user, investigation_id=inv_id, run_id=run2["id"], artifact_id=artifact_id)

        # Status must STILL be CONFIRMED -- not overwritten to UNDER_REVIEW
        inv_check = client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()
        assert inv_check["status"] == "CONFIRMED"

    def test_reopen_does_not_create_analysis_run(self, client, user, db_session):
        """Reopen returns investigation to UNDER_REVIEW without creating an AnalysisRun."""
        from app.models import AnalysisRun
        inv = create_investigation(client, user)
        inv_id = inv["id"]

        client.post(f"/api/v1/investigations/{inv_id}/status", json={"status": "UNDER_REVIEW"}, headers=auth_headers(user))
        client.post(f"/api/v1/investigations/{inv_id}/actions", json={"action": "close"}, headers=auth_headers(user))
        assert client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()["status"] == "CLOSED"

        runs_before = db_session.query(AnalysisRun).filter(AnalysisRun.investigation_id == inv_id).count()

        resp = client.post(f"/api/v1/investigations/{inv_id}/actions", json={"action": "reopen"}, headers=auth_headers(user))
        assert resp.status_code == 200

        runs_after = db_session.query(AnalysisRun).filter(AnalysisRun.investigation_id == inv_id).count()
        assert runs_after == runs_before, "reopen must NOT create a new AnalysisRun"
        assert client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()["status"] == "UNDER_REVIEW"

    def test_close_transitions_to_closed(self, client, user):
        """Action close transitions UNDER_REVIEW -> CLOSED."""
        inv = create_investigation(client, user)
        inv_id = inv["id"]
        client.post(f"/api/v1/investigations/{inv_id}/status", json={"status": "UNDER_REVIEW"}, headers=auth_headers(user))
        resp = client.post(f"/api/v1/investigations/{inv_id}/actions", json={"action": "close"}, headers=auth_headers(user))
        assert resp.status_code == 200
        assert client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()["status"] == "CLOSED"


# ==========================================================================
# SECTION 8 & 19: Audit Event Classification
# ==========================================================================

class TestAuditClassification:
    """Backend maps AuditAction + metadata to frontend declared types."""

    def test_all_declared_audit_types(self):
        from app.services.investigation_service import classify_audit_action_type

        class MockEvent:
            def __init__(self, action, metadata=None):
                self.action = action
                self.metadata_json = metadata or {}

        # confirmation
        assert classify_audit_action_type(MockEvent(AuditAction.INVESTIGATION_STATUS_CHANGED, {"to": "CONFIRMED"})) == "confirmation"

        # escalation
        assert classify_audit_action_type(MockEvent(AuditAction.INVESTIGATION_STATUS_CHANGED, {"to": "ESCALATED"})) == "escalation"

        # close
        assert classify_audit_action_type(MockEvent(AuditAction.INVESTIGATION_STATUS_CHANGED, {"to": "CLOSED"})) == "close"

        # note
        assert classify_audit_action_type(MockEvent(AuditAction.NOTE_ADDED)) == "note"

        # reopen
        assert classify_audit_action_type(MockEvent(AuditAction.INVESTIGATION_REOPENED)) == "reopen"

        # export
        assert classify_audit_action_type(MockEvent(AuditAction.EVIDENCE_EXPORTED)) == "export"

        # ingestion
        assert classify_audit_action_type(MockEvent(AuditAction.ARTIFACT_INGESTED)) == "ingestion"
        assert classify_audit_action_type(MockEvent(AuditAction.INVESTIGATION_CREATED)) == "ingestion"

        # analysis
        assert classify_audit_action_type(MockEvent(AuditAction.ANALYSIS_RUN_CREATED)) == "analysis"
        assert classify_audit_action_type(MockEvent(AuditAction.SCORE_CONCLUSION_PERSISTED)) == "analysis"
        assert classify_audit_action_type(MockEvent(AuditAction.FINDING_PERSISTED)) == "analysis"


# ==========================================================================
# SECTION 9 & 10: Role Authorization and Cross-Org Scoping
# ==========================================================================

class TestAuthorizationBoundaries:
    """Role enforcement on state-changing actions and strict tenant isolation."""

    def test_state_changing_actions_require_analyst_or_admin(self, client, user, org, db_session):
        """USER role is rejected with 403 on all state-changing actions."""
        viewer = _make_user(db_session, org, "viewer_test@acme.test", role=UserRole.USER)
        inv = create_investigation(client, user)
        inv_id = inv["id"]
        client.post(f"/api/v1/investigations/{inv_id}/status", json={"status": "UNDER_REVIEW"}, headers=auth_headers(user))

        for state_action in ("confirm_malicious", "false_positive", "needs_escalation", "close"):
            resp = client.post(
                f"/api/v1/investigations/{inv_id}/actions",
                json={"action": state_action, "falsePositiveReason": "reason"},
                headers=auth_headers(viewer),
            )
            assert resp.status_code == 403, f"Action '{state_action}' should reject USER with 403"

    def test_analyst_and_admin_allowed_state_changing_actions(self, client, user, org, db_session):
        """ANALYST and ADMIN roles can execute state-changing actions."""
        admin = _make_user(db_session, org, "admin_test@acme.test", role=UserRole.ADMIN)
        inv = create_investigation(client, user)
        inv_id = inv["id"]
        client.post(f"/api/v1/investigations/{inv_id}/status", json={"status": "UNDER_REVIEW"}, headers=auth_headers(user))

        resp = client.post(
            f"/api/v1/investigations/{inv_id}/actions",
            json={"action": "needs_escalation", "note": "Tier 2 required"},
            headers=auth_headers(admin),
        )
        assert resp.status_code == 200
        assert client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()["status"] == "ESCALATED"

    def test_cross_org_access_rejected_with_404(self, client, user, other_org_user):
        """Caller from a different organization cannot read or mutate investigation."""
        inv = create_investigation(client, user)
        inv_id = inv["id"]

        # Other org cannot GET
        assert client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(other_org_user)).status_code == 404

        # Other org cannot add_note
        resp = client.post(
            f"/api/v1/investigations/{inv_id}/actions",
            json={"action": "add_note", "note": "hacker note"},
            headers=auth_headers(other_org_user),
        )
        assert resp.status_code == 404



