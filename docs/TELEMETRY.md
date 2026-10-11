# HopZero Zero-Telemetry & Privacy Guarantee

## 1. Absolute Privacy by Default
HopZero is engineered specifically for sensitive digital forensics, cyber investigation, and SOC triage environments.

As a core architectural policy:
- **NO Cloud Telemetry**: HopZero does **NOT** contain any telemetry beacons, Google Analytics, Mixpanel, Sentry, or third-party phone-home tracking.
- **NO Data Exfiltration**: Email headers, message bodies, IP addresses, attachments, IOCs, and analyst notes **NEVER** leave your host environment.
- **NO Cloud AI Dependency**: AI reasoning is powered strictly by a local resident Ollama instance (`hermes3:3b`, Q4_K_M) or local deterministic fallback.

---

## 2. Air-Gapped Verification
You can independently verify HopZero's zero-network invariant using the air-gapped isolation test:
```bash
python scripts/test_network_isolation.py
```
This test monkeypatches the system socket interface, blocks all non-localhost outbound traffic, and verifies that the complete forensic analysis pipeline executes with zero network leaks.

---

## 3. Redacted Support Diagnostics
When exporting diagnostics for troubleshooting via:
```bash
python scripts/diagnostics.py --export
```
The diagnostics engine automatically scrubs and redacts all:
- Personal email addresses -> `[REDACTED_EMAIL]`
- Non-loopback IP addresses -> `[REDACTED_IP]`
- Bearer tokens and JWTs -> `[REDACTED_JWT_TOKEN]`
- Secrets, passwords, and private API keys -> `[REDACTED_CREDENTIAL]`
