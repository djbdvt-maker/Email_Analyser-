import os
import logging
from typing import List
import maxminddb

from hopzero_forensics.interfaces import (
    AnalyzerOutput,
    CanonicalEmail,
    Fact,
    FindingCandidate,
    SignalState,
)

ANALYZER_NAME = "routing_geolocation"
ANALYZER_VERSION = "1.0.0"

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "GeoLite2-Country.mmdb")

def _fact(f_id: str, f_type: str, state: SignalState, val: str, detail: str) -> Fact:
    return Fact(fact_id=f_id, fact_type=f_type, state=state, value=val, detail=detail)

def _candidate(
    q_code: str, strength: str, claim: str, s_text: str, fact_ids: List[str], detail: str
) -> FindingCandidate:
    return FindingCandidate(
        qualification_code=q_code,
        model_suggested_strength=strength,
        claim_signature=claim,
        supporting_text=s_text,
        source_fact_ids=fact_ids,
        detail=detail,
    )

def analyze_geolocation(email: CanonicalEmail, normalized_evidence=None) -> AnalyzerOutput:
    facts: List[Fact] = []
    candidates: List[FindingCandidate] = []

    if not os.path.exists(DB_PATH):
        logger.warning(f"GeoLite2 DB not found at {DB_PATH}")
        return AnalyzerOutput(analyzer_name=ANALYZER_NAME, analyzer_version=ANALYZER_VERSION, facts=[], candidates=[])

    try:
        with maxminddb.open_database(DB_PATH) as reader:
            for i, hop in enumerate(email.received_hops):
                if hop.ip_address:
                    try:
                        record = reader.get(hop.ip_address)
                        if record and 'country' in record:
                            country_iso = record['country'].get('iso_code', 'UNKNOWN')
                            country_name = record['country']['names'].get('en', 'Unknown')
                            
                            detail = f"Hop {i} IP ({hop.ip_address}) physically located in {country_name} ({country_iso})"
                            fact_geo = _fact(f"fact_geo_hop_{i}", "ip_geolocation", SignalState.PRESENT, f"{hop.ip_address}:{country_iso}", detail)
                            facts.append(fact_geo)

                            # High-risk countries could be flagged here (example list)
                            HIGH_RISK_COUNTRIES = {"RU", "KP", "IR", "CN", "BY", "SY"}
                            if country_iso in HIGH_RISK_COUNTRIES:
                                candidates.append(
                                    _candidate(
                                        "HIGH_RISK_GEOLOCATION",
                                        "High",
                                        f"hop_{i}_ip",
                                        hop.ip_address,
                                        [fact_geo.fact_id],
                                        f"IP originates from high-risk geopolitical region: {country_name}"
                                    )
                                )
                    except Exception as e:
                        logger.warning(f"Failed to lookup IP {hop.ip_address}: {e}")

    except Exception as exc:
        logger.error(f"GeoLocation analyzer error: {exc}")

    return AnalyzerOutput(
        analyzer_name=ANALYZER_NAME,
        analyzer_version=ANALYZER_VERSION,
        facts=facts,
        candidates=candidates,
    )
