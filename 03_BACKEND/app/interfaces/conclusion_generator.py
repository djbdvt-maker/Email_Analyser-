"""
Conclusion Generator interface.

IMPORTANT: No LLM calls, prompt templates, or semantic reasoning may
be added here or anywhere in the backend package. This is a contract
boundary only -- the real conclusion-writing component is a separate
service that the backend invokes and then validates the output of.
"""
from abc import ABC, abstractmethod


class ConclusionGenerator(ABC):
    @abstractmethod
    def generate(self, *, investigation_id: str, analysis_run_id: str,
                 finding_ids: list[str], total_score: int, severity: str) -> str:
        """
        Returns human-readable conclusion text. Implementations that
        actually call an LLM belong in a separate, clearly-labeled
        component -- not in this backend package.
        """
        raise NotImplementedError


class NotConfiguredConclusionGenerator(ConclusionGenerator):
    def generate(self, *, investigation_id: str, analysis_run_id: str,
                 finding_ids: list[str], total_score: int, severity: str,
                 triggered_floor_codes: list[str] | None = None) -> str:
        raise NotImplementedError(
            "No Conclusion Generator is configured. Wire a real "
            "implementation from the separate conclusion-generation component."
        )


class DeterministicConclusionGenerator(ConclusionGenerator):
    """
    Deterministic rule/template-based conclusion generator.
    Produces structured, human-readable conclusion narratives without calling an LLM.
    """
    def generate(
        self,
        *,
        investigation_id: str,
        analysis_run_id: str,
        finding_ids: list[str],
        total_score: int,
        severity: str,
        triggered_floor_codes: list[str] | None = None,
    ) -> str:
        floors_str = ", ".join(triggered_floor_codes) if triggered_floor_codes else "none"
        floors_desc = f"Triggered floors: {floors_str}."
        findings_count = len(finding_ids)
        findings_desc = f"{findings_count} validated finding{'s' if findings_count != 1 else ''} evaluated."

        verdict_summary = {
            "Clean": "No significant email security threats detected.",
            "Low": "Minor low-risk anomalies observed; proceed with standard vigilance.",
            "Medium": "Suspicious email indicators detected; cautionary review advised.",
            "High": "High-risk indicators identified; potential phishing or malicious intent.",
            "Critical": "Critical security threat confirmed; immediate containment recommended.",
        }.get(severity, "Investigation evaluated.")

        return (
            f"Severity: {severity} (score {total_score}/100). "
            f"{floors_desc} {verdict_summary} {findings_desc}"
        )
