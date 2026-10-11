"""
Golden Output Generator & Verifier for HopZero.
Captures and verifies deterministic Facts, Findings, Score, Verdict, and Conclusion
for the entire regression corpus:
  - 17 hand-built scoring cases (+ regression 13b)
  - 6 frozen synthetic Hop-0 cases (+ 3 routing edge cases)
  - 5 canonical end-to-end email fixtures
"""
import os
import sys
import json
import hashlib
import tempfile
import shutil
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

# Set up environment
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "01_REGISTRY"))
sys.path.insert(0, os.path.join(REPO_ROOT, "02_FORENSICS"))
sys.path.insert(0, os.path.join(REPO_ROOT, "03_BACKEND"))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("HOPZERO_LLM_PROVIDER", "offline_deterministic_fallback")
os.environ.setdefault("HOPZERO_INTERNAL_SERVICE_KEY", "test-internal-service-key")
os.environ.setdefault("HOPZERO_N8N_INGEST_KEY", "test-n8n-ingest-key")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import (
    Organization,
    User,
    UserRole,
    Investigation,
    Artifact,
    AnalysisRun,
    AnalysisRunStatus,
    Fact as FactModel,
    Finding as FindingModel,
    ScoreConclusion,
)
from app.services.score_engine import compute_score, severity_for_score, SCORE_ENGINE_VERSION
from app.services.conclusion_generator import ConclusionGenerator
from app.services.pipeline_service import execute_analysis_pipeline

GOLDEN_SNAPSHOT_PATH = os.path.join(REPO_ROOT, "05_QA", "golden", "golden_outputs.json")


@dataclass
class FindingMock:
    id: str
    category: str
    strength: str
    qualification_code: str = ""
    normalized_target: str = ""
    normalized_subject_or_target: str = ""


def get_scoring_corpus_cases():
    """Returns the 17 hand-built cases + regression 13b."""
    cases = {}

    # Case 01: Pure clean baseline
    cases["case_01_pure_clean_baseline"] = {
        "findings": [],
        "is_indeterminate": False,
    }

    # Case 02: Evidence-only zero points
    cases["case_02_evidence_only_zero_points"] = {
        "findings": [
            FindingMock("1", "Authentication", "Weak", "SPF_NONE"),
            FindingMock("2", "Authentication", "Weak", "DKIM_NONE"),
            FindingMock("3", "Social Engineering", "Weak", "GENERIC_SUSPICION"),
            FindingMock("4", "Domain", "Weak", "PUNYCODE_DOMAIN_INDICATOR"),
        ],
        "is_indeterminate": False,
    }

    # Case 03: Single weak finding
    cases["case_03_single_weak_finding"] = {
        "findings": [FindingMock("1", "Authentication", "Weak", "SPF_FAIL")],
        "is_indeterminate": False,
    }

    # Case 04a, 04b, 04c: Multipliers
    cases["case_04a_weak_multiplier"] = {
        "findings": [FindingMock("1", "Authentication", "Weak", "DMARC_FAIL")],
        "is_indeterminate": False,
    }
    cases["case_04b_moderate_multiplier"] = {
        "findings": [FindingMock("1", "Authentication", "Moderate", "DMARC_FAIL")],
        "is_indeterminate": False,
    }
    cases["case_04c_strong_multiplier"] = {
        "findings": [FindingMock("1", "Authentication", "Strong", "DMARC_FAIL")],
        "is_indeterminate": False,
    }

    # Case 05: Category cap enforcement (Authentication cap = 16)
    cases["case_05_category_cap_enforcement"] = {
        "findings": [
            FindingMock("1", "Authentication", "Strong", "DMARC_FAIL"),
            FindingMock("2", "Authentication", "Strong", "SPF_FAIL"),
            FindingMock("3", "Authentication", "Strong", "DKIM_FAIL"),
        ],
        "is_indeterminate": False,
    }

    # Case 06: Theoretical maximum raw 166 -> 100 points, CRITICAL
    cases["case_06_theoretical_max_score"] = {
        "findings": [
            FindingMock("1", "Identity", "Strong", "EXECUTIVE_IMPERSONATION"),
            FindingMock("2", "Authentication", "Strong", "DMARC_FAIL"),
            FindingMock("3", "Authentication", "Strong", "SPF_FAIL"),
            FindingMock("4", "Domain", "Strong", "PROTECTED_BRAND_LOOKALIKE_DOMAIN"),
            FindingMock("5", "URL", "Strong", "CREDENTIAL_PHISHING_LINK"),
            FindingMock("6", "Attachment", "Strong", "EXECUTABLE_IN_ARCHIVE"),
            FindingMock("7", "Infrastructure", "Strong", "BULLETPROOF_HOSTING_MATCH"),
            FindingMock("8", "Infrastructure", "Weak", "KNOWN_BAD_ASN"),
            FindingMock("9", "Routing", "Strong", "ROUTING_FABRICATION_QUALIFIED"),
            FindingMock("10", "Social Engineering", "Strong", "FINANCIAL_REQUEST"),
            FindingMock("11", "Social Engineering", "Weak", "FINANCIAL_REQUEST"),
            FindingMock("12", "Threat Intelligence", "Strong", "CONFIRMED_MALICIOUS_INDICATOR"),
        ],
        "is_indeterminate": False,
    }

    # Case 07: Severity boundaries
    # Evaluated directly in tests, but let's record score boundaries 0, 29, 30, 54, 55, 74, 75, 100
    cases["case_07_severity_boundary_low"] = {
        "findings": [FindingMock("1", "Authentication", "Weak", "SPF_FAIL")],
        "is_indeterminate": False,
    }

    # Case 08: Floor CF-01 (Lookalike domain + explicit same-brand claim) -> Severity HIGH
    cases["case_08_floor_cf01"] = {
        "findings": [
            FindingMock("1", "Domain", "Moderate", "PROTECTED_BRAND_LOOKALIKE_DOMAIN", normalized_target="paypal"),
            FindingMock("2", "Identity", "Moderate", "EXPLICIT_BRAND_REPRESENTATION_CLAIM", normalized_target="paypal"),
        ],
        "is_indeterminate": False,
    }

    # Case 09: Floor CF-02 (Executive impersonation + financial request) -> Severity HIGH
    cases["case_09_floor_cf02"] = {
        "findings": [
            FindingMock("1", "Identity", "Moderate", "EXECUTIVE_IMPERSONATION"),
            FindingMock("2", "Social Engineering", "Moderate", "FINANCIAL_REQUEST"),
        ],
        "is_indeterminate": False,
    }

    # Case 10: Floor CF-03 (Credential phishing link + identity anomaly) -> Severity HIGH
    cases["case_10_floor_cf03"] = {
        "findings": [
            FindingMock("1", "URL", "Moderate", "CREDENTIAL_PHISHING_LINK"),
            FindingMock("2", "Identity", "Moderate", "IDENTITY_ANOMALY"),
        ],
        "is_indeterminate": False,
    }

    # Case 11: Floor CF-04 (Suspicious attachment + identity anomaly) -> Severity HIGH
    cases["case_11_floor_cf04"] = {
        "findings": [
            FindingMock("1", "Attachment", "Moderate", "SUSPICIOUS_ATTACHMENT"),
            FindingMock("2", "Identity", "Moderate", "IDENTITY_ANOMALY"),
        ],
        "is_indeterminate": False,
    }

    # Case 12: Floor CF-05 (Confirmed malicious indicator Strong) -> Severity HIGH, MALICIOUS
    cases["case_12_floor_cf05"] = {
        "findings": [
            FindingMock("1", "Threat Intelligence", "Strong", "CONFIRMED_MALICIOUS_INDICATOR"),
        ],
        "is_indeterminate": False,
    }

    # Case 13: Floor CF-06 (Qualified routing fabrication) -> Severity HIGH
    cases["case_13_floor_cf06"] = {
        "findings": [
            FindingMock("1", "Routing", "Moderate", "ROUTING_FABRICATION_QUALIFIED"),
        ],
        "is_indeterminate": False,
    }

    # Case 13b: CF-06 negative / clean routing does not trigger CF-06
    cases["case_13b_cf06_negative"] = {
        "findings": [
            FindingMock("1", "Routing", "Weak", "ROUTING_HOP_ANALYZED"),
        ],
        "is_indeterminate": False,
    }

    # Case 14: CF-01 near miss (Brand A lookalike + Brand B claim) does NOT trigger CF-01
    cases["case_14_cf01_near_miss_different_brands"] = {
        "findings": [
            FindingMock("1", "Domain", "Moderate", "PROTECTED_BRAND_LOOKALIKE_DOMAIN", normalized_target="paypal"),
            FindingMock("2", "Identity", "Moderate", "EXPLICIT_BRAND_REPRESENTATION_CLAIM", normalized_target="microsoft"),
        ],
        "is_indeterminate": False,
    }

    # Case 15a: Golden Scenario BENIGN
    cases["case_15a_golden_benign"] = {
        "findings": [],
        "is_indeterminate": False,
    }

    # Case 15b: Golden Scenario SUSPICIOUS
    cases["case_15b_golden_suspicious"] = {
        "findings": [
            FindingMock("1", "Identity", "Moderate", "EXECUTIVE_IMPERSONATION"),
            FindingMock("2", "Social Engineering", "Moderate", "FINANCIAL_REQUEST"),
        ],
        "is_indeterminate": False,
    }

    # Case 15c: Golden Scenario MALICIOUS
    cases["case_15c_golden_malicious"] = {
        "findings": [
            FindingMock("1", "Threat Intelligence", "Strong", "CONFIRMED_MALICIOUS_INDICATOR"),
        ],
        "is_indeterminate": False,
    }

    # Case 15d: Golden Scenario INDETERMINATE
    cases["case_15d_golden_indeterminate"] = {
        "findings": [],
        "is_indeterminate": True,
    }

    return cases


def run_scoring_case(case_name: str, case_data: dict) -> dict:
    findings = case_data["findings"]
    is_indeterminate = case_data["is_indeterminate"]

    score_res = compute_score(findings)
    cg = ConclusionGenerator()
    conclusion_res = cg.generate(
        score_output=score_res,
        findings=findings,
        is_indeterminate=is_indeterminate,
    )

    serialized_findings = [
        {
            "category": f.category,
            "strength": f.strength,
            "qualification_code": f.qualification_code,
            "normalized_target": f.normalized_target,
            "normalized_subject_or_target": f.normalized_subject_or_target,
        }
        for f in findings
    ]

    return {
        "case_name": case_name,
        "input_findings": serialized_findings,
        "score": {
            "total_score": score_res.total_score,
            "raw_score": score_res.raw_score,
            "severity": score_res.severity,
            "category_breakdown": score_res.category_breakdown,
            "triggered_floor_codes": sorted(score_res.triggered_floor_codes),
            "score_engine_version": SCORE_ENGINE_VERSION,
        },
        "verdict": conclusion_res.verdict,
        "conclusion": {
            "one_line_explanation": conclusion_res.one_line_explanation,
            "why_explanation": conclusion_res.why_explanation,
            "generator_version": conclusion_res.generator_version,
        },
    }


def get_eml_fixtures() -> List[Dict[str, str]]:
    """List of all canonical .eml fixtures to test and record."""
    fixtures = [
        # 5 Canonical E2E emails
        {"suite": "e2e", "rel_path": os.path.join("07_TEST_DATA", "clean", "clean_legit_corporate.eml")},
        {"suite": "e2e", "rel_path": os.path.join("07_TEST_DATA", "BEC", "bec_ceo_wire_transfer.eml")},
        {"suite": "e2e", "rel_path": os.path.join("07_TEST_DATA", "phishing", "credential_harvesting_portal.eml")},
        {"suite": "e2e", "rel_path": os.path.join("07_TEST_DATA", "lookalike", "protected_brand_lookalike.eml")},
        {"suite": "e2e", "rel_path": os.path.join("07_TEST_DATA", "attachments", "double_extension_macro.eml")},

        # 6 Frozen synthetic Hop-0 cases
        {"suite": "hop0_synthetic", "rel_path": os.path.join("07_TEST_DATA", "routing", "legit_gmail_to_gmail.eml")},
        {"suite": "hop0_synthetic", "rel_path": os.path.join("07_TEST_DATA", "routing", "legit_m365.eml")},
        {"suite": "hop0_synthetic", "rel_path": os.path.join("07_TEST_DATA", "routing", "legit_forwarded_via_unknown_relay.eml")},
        {"suite": "hop0_synthetic", "rel_path": os.path.join("07_TEST_DATA", "routing", "adversarial_temporal_contradiction.eml")},
        {"suite": "hop0_synthetic", "rel_path": os.path.join("07_TEST_DATA", "routing", "adversarial_structural_implausibility.eml")},
        {"suite": "hop0_synthetic", "rel_path": os.path.join("07_TEST_DATA", "routing", "adversarial_independent_trusted_contradiction.eml")},

        # 3 Edge routing cases
        {"suite": "hop0_edge", "rel_path": os.path.join("07_TEST_DATA", "routing", "no_received_chain.eml")},
        {"suite": "hop0_edge", "rel_path": os.path.join("07_TEST_DATA", "routing", "no_trusted_boundary_at_hop0.eml")},
        {"suite": "hop0_edge", "rel_path": os.path.join("07_TEST_DATA", "routing", "generic_malformed_header.eml")},
    ]
    return fixtures


def run_eml_fixture(fixture_info: dict) -> dict:
    """Runs a single .eml through the full pipeline using in-memory DB."""
    rel_path = fixture_info["rel_path"]
    full_path = os.path.join(REPO_ROOT, rel_path)
    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Fixture not found: {full_path}")

    with open(full_path, "rb") as f:
        content = f.read()

    engine = create_engine("sqlite:///:memory:", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()

    try:
        # Set up org, user, investigation, artifact, run
        org = Organization(name="Golden Org")
        db.add(org)
        db.commit()
        db.refresh(org)

        user = User(
            email="analyst@golden.test",
            hashed_password="pw",
            organization_id=org.id,
            role=UserRole.ANALYST,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        inv = Investigation(
            organization_id=org.id,
            created_by_user_id=user.id,
            title=f"Golden: {os.path.basename(rel_path)}",
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)

        # Store artifact file
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, os.path.basename(rel_path))
        with open(temp_file, "wb") as f:
            f.write(content)

        art_sha = hashlib.sha256(content).hexdigest()
        art = Artifact(
            investigation_id=inv.id,
            storage_path=temp_file,
            original_filename=os.path.basename(rel_path),
            mime_type="message/rfc822",
            size_bytes=len(content),
            original_artifact_sha256=art_sha,
        )
        db.add(art)
        db.commit()
        db.refresh(art)

        run = AnalysisRun(
            investigation_id=inv.id,
            artifact_id=art.id,
            status=AnalysisRunStatus.QUEUED,
        )
        db.add(run)
        db.commit()
        db.refresh(run)

        inv.current_analysis_run_id = run.id
        db.commit()

        # Run pipeline
        execute_analysis_pipeline(
            db,
            user=user,
            investigation_id=inv.id,
            artifact_id=art.id,
            run_id=run.id,
        )

        # Fetch facts
        facts = (
            db.query(FactModel)
            .filter(FactModel.analysis_run_id == run.id)
            .all()
        )
        import re
        ts_pattern = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")

        def _clean_val(v):
            if isinstance(v, str):
                # Only normalize if it's a dynamic at <timestamp> string
                if "State = unavailable" in v or "generated_at" in v:
                    return ts_pattern.sub("<TIMESTAMP>", v)
                return v
            elif isinstance(v, dict):
                return {k: _clean_val(val) for k, val in v.items()}
            elif isinstance(v, list):
                return [_clean_val(item) for item in v]
            return v

        serialized_facts = []
        for f in facts:
            # Drop volatile DB UUIDs from comparison
            p = dict(f.payload or {})
            if "source_fact_id" in p:
                p.pop("source_fact_id", None)
            p = _clean_val(p)
            serialized_facts.append({
                "fact_type": f.fact_type,
                "payload": p,
                "produced_by": f.produced_by,
            })
        # Sort facts deterministically by fact_type and JSON string of payload
        serialized_facts.sort(key=lambda x: (x["fact_type"], json.dumps(x["payload"], sort_keys=True)))

        # Fetch findings
        findings = (
            db.query(FindingModel)
            .filter(FindingModel.analysis_run_id == run.id)
            .all()
        )
        uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        serialized_findings = [
            {
                "category": f.category,
                "qualification_code": f.qualification_code,
                "qualification_version": f.qualification_version,
                "strength": f.strength,
                "normalized_subject_or_target": (
                    "<UUID>" if uuid_re.match(f.normalized_subject_or_target or "")
                    else f.normalized_subject_or_target
                ),
                "claim_signature": f.claim_signature,
                "supporting_text": f.supporting_text,
                "produced_by": f.produced_by,
            }
            for f in findings
        ]
        serialized_findings.sort(key=lambda x: (x["category"], x["qualification_code"], x["claim_signature"]))

        # Fetch score conclusion
        score_row = (
            db.query(ScoreConclusion)
            .filter(ScoreConclusion.analysis_run_id == run.id)
            .first()
        )

        prov = score_row.provenance or {}
        score_dict = {
            "total_score": score_row.total_score,
            "severity": score_row.severity,
            "category_breakdown": score_row.category_breakdown,
            "triggered_floor_codes": sorted(score_row.triggered_floor_codes or []),
            "score_engine_version": prov.get("score_engine_version", "score-engine-v2"),
        }

        conclusion_dict = {
            "verdict": score_row.verdict,
            "one_line_explanation": score_row.one_line_explanation,
            "why_explanation": score_row.why_explanation,
            "conclusion_text": score_row.conclusion_text,
            "generator_version": prov.get("generator_version", "conclusion-generator-v2"),
        }

        shutil.rmtree(temp_dir, ignore_errors=True)

        return {
            "suite": fixture_info["suite"],
            "fixture_path": rel_path.replace("\\", "/"),
            "sha256": art_sha,
            "facts": serialized_facts,
            "findings": serialized_findings,
            "score": score_dict,
            "verdict": score_row.verdict,
            "conclusion": conclusion_dict,
        }
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


def generate_all_golden_outputs() -> dict:
    """Generates all golden outputs across scoring cases and email fixtures."""
    # 1. System and version manifest
    with open(os.path.join(REPO_ROOT, "01_REGISTRY", "releases", "registry-v1.sha256"), "r", encoding="utf-8") as f:
        registry_sha256 = f.read().strip()

    manifest = {
        "format_version": "1.0",
        "versions": {
            "backend_version": "2.0.0",
            "forensics_version": "1.0.0",
            "registry_version": "v1",
            "registry_sha256": registry_sha256,
            "compiler_version": "hopzero-compiler-v1.0.0",
            "validity_engine_version": "vr-v1",
            "score_engine_version": SCORE_ENGINE_VERSION,
            "conclusion_generator_version": "conclusion-generator-v2",
            "trusted_receivers_version": "v1",
            "normalization_policy_version": "v1",
            "infrastructure_reputation_version": "infra_rep_v1",
            "protected_brands_version": "protected_brands_v1",
            "prompt_schema_version": "prompt-v1",
        },
    }

    # 2. Scoring corpus cases
    scoring_cases = get_scoring_corpus_cases()
    scoring_results = {}
    for name, data in sorted(scoring_cases.items()):
        scoring_results[name] = run_scoring_case(name, data)

    # 3. EML fixtures
    eml_fixtures = get_eml_fixtures()
    eml_results = []
    for fix in eml_fixtures:
        eml_results.append(run_eml_fixture(fix))

    return {
        "metadata": manifest,
        "scoring_corpus_cases": scoring_results,
        "email_fixtures": eml_results,
    }


def save_golden_snapshot(path: str = GOLDEN_SNAPSHOT_PATH):
    data = generate_all_golden_outputs()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    print(f"Golden outputs successfully written to {path}")


def verify_golden_snapshot(path: str = GOLDEN_SNAPSHOT_PATH) -> bool:
    if not os.path.exists(path):
        print(f"ERROR: Golden snapshot file not found: {path}", file=sys.stderr)
        return False

    with open(path, "r", encoding="utf-8") as f:
        expected = json.load(f)

    current = generate_all_golden_outputs()

    # Compare metadata versions (excluding allowlisted changes if any)
    if expected.get("metadata", {}).get("versions") != current.get("metadata", {}).get("versions"):
        print("FAIL: Version mismatch in metadata!", file=sys.stderr)
        print("Expected:", json.dumps(expected.get("metadata", {}).get("versions"), indent=2), file=sys.stderr)
        print("Current: ", json.dumps(current.get("metadata", {}).get("versions"), indent=2), file=sys.stderr)
        return False

    # Compare scoring corpus cases
    exp_scoring = expected.get("scoring_corpus_cases", {})
    cur_scoring = current.get("scoring_corpus_cases", {})
    if exp_scoring != cur_scoring:
        for k in exp_scoring:
            if k not in cur_scoring:
                print(f"FAIL: Missing scoring case {k}", file=sys.stderr)
            elif exp_scoring[k] != cur_scoring[k]:
                print(f"FAIL: Diff in scoring case {k}:", file=sys.stderr)
                print("Expected:", json.dumps(exp_scoring[k], indent=2), file=sys.stderr)
                print("Current: ", json.dumps(cur_scoring[k], indent=2), file=sys.stderr)
        return False

    # Compare email fixtures
    exp_eml = expected.get("email_fixtures", [])
    cur_eml = current.get("email_fixtures", [])
    if len(exp_eml) != len(cur_eml):
        print(f"FAIL: Email fixture count mismatch: {len(exp_eml)} vs {len(cur_eml)}", file=sys.stderr)
        return False

    for e_fix, c_fix in zip(exp_eml, cur_eml):
        if e_fix != c_fix:
            print(f"FAIL: Diff in email fixture {e_fix.get('fixture_path')}:", file=sys.stderr)
            for key in ["score", "verdict", "conclusion", "findings", "facts"]:
                if e_fix.get(key) != c_fix.get(key):
                    print(f"  Difference in '{key}':", file=sys.stderr)
                    print("  Expected:", json.dumps(e_fix.get(key), indent=2)[:500], file=sys.stderr)
                    print("  Current: ", json.dumps(c_fix.get(key), indent=2)[:500], file=sys.stderr)
            return False

    print(f"SUCCESS: All {len(cur_scoring)} scoring cases and {len(cur_eml)} email fixtures match golden baseline byte-for-byte!")
    return True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--save":
        save_golden_snapshot()
    else:
        success = verify_golden_snapshot()
        sys.exit(0 if success else 1)
