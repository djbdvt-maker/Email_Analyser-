import os
import logging
from typing import List
try:
    import maxminddb
except ImportError:
    maxminddb = None

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

def _fact(f_id: str, key: str, state: SignalState, val: str, detail: str) -> Fact:
    return Fact(
        fact_id=f_id,
        category="routing",
        key=key,
        state=state,
        value=val,
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
        detail=detail,
    )

def _candidate(
    q_code: str, strength: str, claim: str, s_text: str, fact_ids: List[str], detail: str
) -> FindingCandidate:
    return FindingCandidate(
        category="routing",
        qualification_code=q_code,
        qualification_version="1.0",
        strength=strength,
        normalized_subject=None,
        normalized_target=None,
        claim_signature=claim,
        supporting_fact_ids=fact_ids,
        supporting_text=s_text,
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
    )

def analyze_geolocation(email: CanonicalEmail, normalized_evidence=None) -> AnalyzerOutput:
    facts: List[Fact] = []
    candidates: List[FindingCandidate] = []

    if not maxminddb or not os.path.exists(DB_PATH):
        if not maxminddb:
            logger.warning("maxminddb module not available, skipping geolocation analysis")
        else:
            logger.warning(f"GeoLite2 DB not found at {DB_PATH}")
        return AnalyzerOutput(analyzer_name=ANALYZER_NAME, analyzer_version=ANALYZER_VERSION, facts=[], candidates=[])

    try:
        with maxminddb.open_database(DB_PATH) as reader:
            for i, hop in enumerate(email.received_chain_raw):
                if hop.observed_ip:
                    try:
                        record = reader.get(hop.observed_ip)
                        if record and 'country' in record:
                            country_iso = record['country'].get('iso_code', 'UNKNOWN')
                            country_name = record['country']['names'].get('en', 'Unknown')
                            
                            detail = f"Hop {i} IP ({hop.observed_ip}) physically located in {country_name} ({country_iso})"
                            fact_geo = _fact(f"fact_geo_hop_{i}", "ip_geolocation", SignalState.PRESENT, f"{hop.observed_ip}:{country_iso}", detail)
                            facts.append(fact_geo)

                            # High-risk countries could be flagged here (example list)
                            HIGH_RISK_COUNTRIES = {"RU", "KP", "IR", "CN", "BY", "SY"}
                            if country_iso in HIGH_RISK_COUNTRIES:
                                candidates.append(
                                    _candidate(
                                        "HIGH_RISK_GEOLOCATION",
                                        "High",
                                        f"hop_{i}_ip",
                                        hop.observed_ip,
                                        [fact_geo.fact_id],
                                        f"IP originates from high-risk geopolitical region: {country_name}"
                                    )
                                )
                    except Exception as e:
                        logger.warning(f"Failed to lookup IP {hop.observed_ip}: {e}")

    except Exception as exc:
        logger.error(f"GeoLocation analyzer error: {exc}")

    return AnalyzerOutput(
        analyzer_name=ANALYZER_NAME,
        analyzer_version=ANALYZER_VERSION,
        facts=facts,
        candidates=candidates,
    )
