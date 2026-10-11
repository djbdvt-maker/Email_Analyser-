# Responsible Use & Forensic Ethics Policy

## 1. Defensive Positioning

HopZero is strictly engineered and licensed as a **defensive digital forensics and incident response (DFIR) platform**. Its primary functions are:
- Auditing raw email headers, transit hops, and MIME structures (`.eml`, `.msg`).
- Detecting spoofing, lookalike domains, credential harvesting, and deceptive payload techniques.
- Providing deterministic forensic evidence preservation and chain-of-custody tracking.

HopZero is **not** an offensive testing tool, spear-phishing generator, or mass mailer. Any use of HopZero code, tools, or models to conduct offensive surveillance, unauthorized network penetration, automated harassment, or spam campaigns is strictly prohibited.

---

## 2. Ethical Incident Triage

Forensic investigators and SOC analysts operating HopZero must adhere to accepted DFIR ethics:
1. **Authorization & Scope**: Analyze only electronic communications and mail artifacts that you are legally authorized to examine under organizational security policies or warrant authority.
2. **Chain of Custody**: Do not alter original forensic evidence files. HopZero enforces read-only parsing and cryptographic SHA-256 fingerprinting on ingested evidence artifacts.
3. **Data Minimization & Confidentiality**: Electronic messages often contain confidential, financial, or personal information. Forensic artifacts should be retained strictly in accordance with statutory privacy requirements and internal data retention policies. HopZero operates 100% on-premises with zero telemetry to protect sensitive data from external transmission.
4. **Draft-Only Remediation**: To prevent disruption of legitimate operations, HopZero enforces `ActionDrafts` governance. All remediation proposals (quarantine, domain blocking) must be reviewed by human operators before activation.

---

## 3. Evidence Integrity & Legal Admissibility

HopZero generates structured evidence exports and audit trails designed to support formal legal proceedings and compliance frameworks.
- **Section 63 Bharatiya Sakshya Adhiniyam (BSA) / Section 65B Indian Evidence Act**:
  HopZero provides a hash-verified, auditable evidence package structured to support the applicable Section 63 Bharatiya Sakshya Adhiniyam (BSA) certification process; HopZero does not certify legal admissibility.
  *Important Legal Notice*: HopZero generates technical evidence verification packages; HopZero does not itself certify legal admissibility in court. Legal certification of electronic records must be executed by authorized human custodians and forensic experts in compliance with local court rules and evidentiary standards.
