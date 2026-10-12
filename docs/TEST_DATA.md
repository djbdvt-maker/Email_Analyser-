# Test Data Provenance & Privacy Documentation

This document records the provenance, synthesis rules, and privacy compliance of all test data included in the HopZero Email Forensics & BotChain Tool Suite.

---

## 1. Ground Rules & Privacy Invariants

1. **Zero Real Personal Data**: No real names, personal email addresses, phone numbers, employee IDs, private credentials, or internal corporate domain names of real individuals or companies are retained in tracked repository fixtures.
2. **RFC 2606 & RFC 6761 Compliance**: All domain names used in synthetic test cases and regression fixtures leverage reserved testing Top-Level Domains (`.example`, `.test`, `.invalid`, `.localhost`) or reserved second-level domains (`example.com`, `example.org`, `example.net`), or controlled mock domains (e.g., `legit-bank-support.com`, `legit-corporate.com`).
3. **No Confidential Message Content**: All synthetic email fixture bodies and headers are fabricated solely to test parsing edge cases, forensic qualifiers, and adversarial evasion techniques.

---

## 2. Test Datasets Inventory

### 2.1 Tracked Fixtures (`07_TEST_DATA/`)
These fixtures form the golden regression test suite (`scripts/check_golden.py`) and are tracked in version control:

| Dataset / Fixture | Provenance | Purpose | Privacy Treatment |
|---|---|---|---|
| `clean/clean_legit_corporate.eml` | Synthetic hand-crafted | Baseline legitimate corporate communication (SPF/DKIM/DMARC pass) | Uses `example.com` domains; synthetic names and IPs |
| `phishing/credential_harvesting_portal.eml` | Synthetic hand-crafted | Tests credential harvesting link detection | Synthetic phishing URL targeting fictional service |
| `attachments/double_extension_macro.eml` | Synthetic hand-crafted | Tests dangerous double extension attachment detection (`.pdf.exe`) | Benign mock macro content |
| `BEC/bec_ceo_wire_transfer.eml` | Synthetic hand-crafted | Tests display name spoofing & urgent financial requests | Synthetic CEO/CFO personas on `example.org` |
| `lookalike/protected_brand_lookalike.eml` | Synthetic hand-crafted | Tests homoglyph/typosquatting protected brand detection | Synthetic lookalike domain variation |
| `routing/*.eml` (10 fixtures) | Synthetic & Anonymized captures | Tests Hop-0 routing trust walk and multi-hop relay trace headers | Anonymized IP addresses and scrubbed user accounts |

### 2.2 Bulk Test Datasets (`07_TEST_DATA/test_emails/`)
The bulk dataset directory contains the Apache SpamAssassin public benchmark corpus (2002/2003 public research dataset):
- **Source**: Publicly available Apache SpamAssassin corpus (`ham_zipped` / `spam_zipped`).
- **Tracking**: Strictly **excluded** from version control (`.gitignore` specifies `test_emails/`).
- **Distribution Policy**: Never packaged into production distribution archives or GitHub releases. For local benchmark stress-testing, automated download scripts with SHA-256 verification can provision the public corpus into scratch storage.

### 2.3 Transient Execution Artifacts (`storage/artifacts/`)
- During local analysis runs and testing, parsed RFC822 headers and attachments are written to `storage/artifacts/`.
- This directory is strictly ignored by git (except `.gitkeep`).
- Released builds and packages exclude all files under `storage/artifacts/`.

---

## 3. Privacy & Secret Scanner Verification

Every CI run and release packaging workflow executes `scripts/scan_secrets_and_pii.py`:
- Scans all files across the repository against private key blocks, API tokens, cloud credentials, and unredacted PII patterns.
- Verifies that all test fixtures adhere to RFC 2606 synthetic standards.
