"""
Phase 2: Registry Drift Test Suite

Statically audits every deterministic analyzer in 02_FORENSICS/hopzero_forensics/analyzers/
to verify that every emitted qualification_code and claim_signature strictly exists
within the canonical compiled registry release (01_REGISTRY/releases/registry-v1.json),
preventing any runtime drift, unknown qualifications, or unmapped claim signatures.
"""
import ast
import os
import pytest
from app.qualification_registry import all_qualifications, get_bucket_max_strength, STRENGTH_ORDER


def _extract_analyzer_emitted_candidates():
    """
    Parses the AST of all analyzers in 02_FORENSICS/hopzero_forensics/analyzers/
    to discover all emitted (qualification_code, claim_signature, strength) tuples.
    """
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    analyzers_dir = os.path.join(repo_root, "02_FORENSICS", "hopzero_forensics", "analyzers")
    
    assert os.path.isdir(analyzers_dir), f"Analyzers directory not found: {analyzers_dir}"

    emitted = []

    for fname in os.listdir(analyzers_dir):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        fpath = os.path.join(analyzers_dir, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=fname)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                code = None
                claim_sig = None
                strength = None

                if func_name == "_candidate":
                    # Signature: _candidate(code, strength, subject, target, claim_sig, facts, text)
                    if len(node.args) >= 1 and isinstance(node.args[0], ast.Constant):
                        code = node.args[0].value
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                        strength = node.args[1].value
                    if len(node.args) >= 5 and isinstance(node.args[4], ast.Constant):
                        claim_sig = node.args[4].value

                    # Check keyword overrides
                    for kw in node.keywords:
                        if kw.arg == "code" and isinstance(kw.value, ast.Constant):
                            code = kw.value.value
                        elif kw.arg == "strength" and isinstance(kw.value, ast.Constant):
                            strength = kw.value.value
                        elif kw.arg == "claim_sig" and isinstance(kw.value, ast.Constant):
                            claim_sig = kw.value.value

                elif func_name == "FindingCandidate":
                    for kw in node.keywords:
                        if kw.arg == "qualification_code" and isinstance(kw.value, ast.Constant):
                            code = kw.value.value
                        elif kw.arg == "claim_signature" and isinstance(kw.value, ast.Constant):
                            claim_sig = kw.value.value
                        elif kw.arg == "strength" and isinstance(kw.value, ast.Constant):
                            strength = kw.value.value

                if code and claim_sig:
                    emitted.append((fname, code, claim_sig, strength))

    return emitted


def test_all_analyzer_candidates_exist_in_compiled_registry():
    """Verify that every analyzer-emitted qualification and claim signature is registered."""
    registry = all_qualifications()
    assert len(registry) > 0, "Compiled registry has no qualifications!"

    emitted = _extract_analyzer_emitted_candidates()
    assert len(emitted) > 0, "Found zero emitted candidates across analyzers!"

    drift_errors = []

    for fname, code, claim_sig, strength in emitted:
        if code not in registry:
            drift_errors.append(f"[{fname}] Unknown qualification_code '{code}'")
            continue

        q_entry = registry[code]

        # Verify claim signature
        if q_entry.allowed_claim_signatures:
            if claim_sig not in q_entry.allowed_claim_signatures:
                drift_errors.append(
                    f"[{fname}] Invalid claim_signature '{claim_sig}' for qualification '{code}'. "
                    f"Allowed: {q_entry.allowed_claim_signatures}"
                )

        # Verify strength ceiling if constant string
        if strength and isinstance(strength, str):
            norm_strength = strength.capitalize()
            if norm_strength in STRENGTH_ORDER and q_entry.maximum_strength in STRENGTH_ORDER:
                if STRENGTH_ORDER.index(norm_strength) > STRENGTH_ORDER.index(q_entry.maximum_strength):
                    drift_errors.append(
                        f"[{fname}] Emitted strength '{norm_strength}' exceeds maximum_strength "
                        f"'{q_entry.maximum_strength}' for '{code}'"
                    )

            # Category bucket max strength check
            b_max = get_bucket_max_strength(q_entry.category)
            if b_max and b_max in STRENGTH_ORDER and norm_strength in STRENGTH_ORDER:
                if STRENGTH_ORDER.index(norm_strength) > STRENGTH_ORDER.index(b_max):
                    drift_errors.append(
                        f"[{fname}] Emitted strength '{norm_strength}' exceeds bucket max_strength "
                        f"'{b_max}' for category '{q_entry.category}'"
                    )

    assert not drift_errors, "Registry drift detected:\n" + "\n".join(drift_errors)


def test_registry_qualifications_produced_by_allowed():
    """Verify all deterministic qualifications in registry allow deterministic producer."""
    registry = all_qualifications()
    for code, q_entry in registry.items():
        assert "deterministic" in q_entry.produced_by_allowed or "ai_reasoner" in q_entry.produced_by_allowed
        if "ai_reasoner" in q_entry.produced_by_allowed:
            assert q_entry.ai_eligible is True
            assert q_entry.validity_requirements is not None
