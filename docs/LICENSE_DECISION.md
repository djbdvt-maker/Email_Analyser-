# HopZero Licensing Architectural Decision Record

**Status:** Approved  
**Date:** 2026-10-12  
**Applies to:** HopZero v4.2.0+  
**License:** Apache License, Version 2.0  

---

## 1. Context and Problem Statement

The HopZero repository previously had contradictory licensing signals:
- `pyproject.toml` declared `license = "Proprietary"`
- The root `LICENSE` was Apache-2.0
- README contained an Apache 2.0 badge
- Symmetric HMAC keys were embedded in open-source code for "commercial licensing" and release verification

This ambiguity created legal uncertainty for open-source users and maintainers.

## 2. Decision: Apache-2.0 Open Source Core with Asymmetric Verification

1. **Unified License Definition**: The entire codebase in this repository is licensed under the **Apache License, Version 2.0**.
   - `pyproject.toml` defines `license = { text = "Apache-2.0" }`.
   - Root `LICENSE` contains the standard Apache-2.0 text.
   - `NOTICE` provides third-party copyright and attribution notices.
   - `README.md` links to Apache 2.0.

2. **Commercial vs. Community Architecture**:
   - Community edition functionality is completely open source and unencumbered under Apache 2.0.
   - Commercial/Enterprise features, if distributed as separate modules or certified support packages, are gated strictly by asymmetric Ed25519 signatures (as implemented in F2).
   - The application binary only embeds trusted public verification keys (`OFFICIAL_LICENSE_PUBLIC_KEYS`, `OFFICIAL_RELEASE_PUBLIC_KEYS`).
   - Private signing keys are held strictly offline by the maintainer.
   - No proprietary restrictions or non-compete clauses are injected into the open-source Apache-2.0 codebase.

3. **External Network and Threat Intelligence Dependencies**:
   - Core forensic analysis is 100% on-premises and does not transmit data externally.
   - Optional network lookups (e.g. AbuseIPDB, sandbox screenshots) require explicit user configuration and consent.
