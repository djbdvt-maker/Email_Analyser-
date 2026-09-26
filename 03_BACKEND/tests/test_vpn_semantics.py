import pytest
from unittest.mock import patch, MagicMock
from hopzero_forensics.analyzers.infrastructure import analyze_infrastructure
from hopzero_forensics.interfaces import CanonicalEmail, ReceivedHopRaw

def test_vpn_is_not_malicious_and_not_bulletproof():
    email = MagicMock()
    email.received_chain_raw=[ReceivedHopRaw(sequence_index=0, raw_line="dummy", from_claim=None, by_claim=None, with_claim=None, for_claim=None, observed_ip="198.51.100.42", timestamp_raw=None, timestamp_parsed=None, parse_state=None, malformed_reason=None)]
    
    # Mock RapidAPI to return is_vpn=True but malicious=False
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"is_vpn": true, "malicious": false, "risk_score": 10}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        # Must have key to hit API
        with patch.dict("os.environ", {"HOPZERO_RAPIDAPI_KEY": "test-key"}):
            output = analyze_infrastructure(email, probable_origin_ip="198.51.100.42")
            
    # Check that VPN fact was created
    vpn_facts = [f for f in output.facts if f.key == "network_type" and f.value == "VPN"]
    assert len(vpn_facts) == 1, "VPN fact must be present"
    
    # Check that BULLETPROOF_HOSTING_MATCH is NOT created
    bp_cands = [c for c in output.candidates if c.qualification_code == "BULLETPROOF_HOSTING_MATCH"]
    assert len(bp_cands) == 0, "VPN alone must NOT trigger bulletproof hosting"
    
    # Check that CONFIRMED_MALICIOUS_INDICATOR is NOT created
    mal_cands = [c for c in output.candidates if c.qualification_code == "CONFIRMED_MALICIOUS_INDICATOR"]
    assert len(mal_cands) == 0, "VPN alone must NOT trigger confirmed malicious indicator"

def test_api_unavailable_handled_safely():
    email = MagicMock()
    email.received_chain_raw=[ReceivedHopRaw(sequence_index=0, raw_line="dummy", from_claim=None, by_claim=None, with_claim=None, for_claim=None, observed_ip="198.51.100.42", timestamp_raw=None, timestamp_parsed=None, parse_state=None, malformed_reason=None)]
    
    # Force API failure
    with patch("urllib.request.urlopen", side_effect=Exception("Timeout")):
        with patch.dict("os.environ", {"HOPZERO_RAPIDAPI_KEY": "test-key"}):
            output = analyze_infrastructure(email, probable_origin_ip="198.51.100.42")
            
    # Check unavailable fact
    unavail_facts = [f for f in output.facts if f.key == "external_intelligence_provider" and f.state.name == "UNAVAILABLE"]
    assert len(unavail_facts) == 1, "Must record unavailable state"
    
    # Check no malicious or BP triggered by accident
    assert len(output.candidates) == 0





