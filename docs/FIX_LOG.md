# HopZero Fix Log & Verification Ledger

This document records the reproduction evidence, actions taken, touched files, test results, and resolution status for every finding from the v4.2.0 comprehensive review (Findings F1 through F15).

---

## F1 (P0): One Source of Truth for Dependencies; Complete Lockfile

- **Finding**:
  - `playwright` imported at top-level in `03_BACKEND/app/api/v1/routes_sandbox.py`, crashing entire app startup if the optional package was missing.
  - `PyYAML` imported in multiple modules (`hopzero/llm/client.py`, `01_REGISTRY/compiler/compile.py`), but omitted from `requirements.lock` and `pyproject.toml`.
  - `yara-python` omitted from `requirements.lock`, causing `scripts/check_golden.py` to fail on clean install.
  - Four dependency sources disagreed: `pyproject.toml`, root `requirements.lock`, `03_BACKEND/requirements.lock`, `03_BACKEND/requirements.txt`.
- **Reproduction / Evidence**:
  - Inspected `routes_sandbox.py`: top-level `from playwright.async_api import async_playwright`.
  - Inspected `pyproject.toml`: missing `PyYAML`, had obsolete `passlib`, declared `laya` unconditionally.
  - Inspected `requirements.lock`: missing `PyYAML`, `yara-python`, `playwright`, `platformdirs`.
  - Verified `03_BACKEND/requirements.txt` installed differently in nightly workflow.
- **Actions Taken**:
  1. Designated `pyproject.toml` as single source of truth with core dependencies (`fastapi`, `uvicorn`, `SQLAlchemy`, `alembic`, `pydantic`, `pydantic-settings`, `pyjwt[crypto]`, `bcrypt`, `cryptography`, `python-multipart`, `python-dotenv`, `PyYAML`, `maxminddb`, `requests`, `platformdirs`, `yara-python`) and optional extras (`sandbox`, `yara`, `laya`, `postgres`, `dev`, `all`).
  2. Adopted Option A for YARA (core dependency, prebuilt wheels on Linux/macOS/Windows, required for byte-identical golden baseline).
  3. Generated complete root `requirements.lock` with all core and test dependencies pinned.
  4. Made `03_BACKEND/requirements.txt` a generated stub referencing root `requirements.lock`. Deleted duplicate `03_BACKEND/requirements.lock`.
  5. Guarded `playwright` import in `routes_sandbox.py` with try/except, returning HTTP 503 if extra is missing.
  6. Handled `yara` `ImportError` in `pipeline_service.py` emitting `signal_unavailable` fact.
  7. Recorded `optional_components` availability in `AnalysisRunConfig`.
- **Verification**:
  - `python -m pip check`: PASSED (no broken requirements).
  - Import smoke test `python -c "import app.main; import hopzero.core; import hopzero.llm"`: PASSED.
  - `python scripts/check_golden.py`: PASSED (21 scoring cases, 14 email fixtures match byte-for-byte).
- **Status**: RESOLVED.

---

## F2 (P0): Replace HMAC Licensing and Release Signing with Ed25519

- **Finding**:
  - `hopzero/core/licensing.py` and `hopzero/core/signatures.py` verified licenses and release manifests with HMAC and default hardcoded secrets in open-source code.
- **Reproduction / Evidence**:
  - Found hardcoded fallback secrets: `hopzero-commercial-master-licensing-authority-2026` in `licensing.py` and `hopzero-v4-official-release-signing-key-2026` in `signatures.py`.
  - Symmetric HMAC allowed anyone with access to open-source code to mint licenses and sign tampered releases.
- **Actions Taken**:
  1. Replaced HMAC with asymmetric Ed25519 digital signatures (`cryptography.hazmat.primitives.asymmetric.ed25519`).
  2. The application source code contains strictly the trusted public keys (`OFFICIAL_LICENSE_PUBLIC_KEYS`, `OFFICIAL_RELEASE_PUBLIC_KEYS`) and can only verify.
  3. Private signing keys remain strictly offline with the maintainer.
  4. Created maintainer offline tools: `tools/sign_license.py` and `tools/sign_release.py`.
  5. Implemented canonical JSON encoding (sorted keys, compact separators, `v: 1` versioning, no floats).
  6. Completely purged `HOPZERO_LICENSE_SECRET`, `HOPZERO_RELEASE_KEY`, and all hardcoded signing secrets from code, `.env.example`, docs, and tests.
  7. Published [docs/KEY_MANAGEMENT.md](file:///docs/KEY_MANAGEMENT.md) documenting key generation, rotation, multi-key trust, and open-source licensing boundaries.
- **Verification**:
  - `python -m pytest 03_BACKEND/tests/test_licensing.py 03_BACKEND/tests/test_installer_and_packaging.py 03_BACKEND/tests/test_security_audit_remediation.py`: 20 passed.
  - Verifies: valid license verifies; tampered signature rejected; modified edition/payload rejected; wrong key rejected; expired license detected; malformed token rejected; unlicensed Community fallback works.
  - Secret scan `python scripts/scan_secrets_and_pii.py`: PASSED (0 secrets found).
  - `python scripts/check_golden.py`: PASSED (21 scoring cases, 14 fixtures match byte-for-byte).
- **Status**: RESOLVED.

---

## F3 (P0): Secrets and Packaging Hygiene

- **Finding**:
  - Real-looking AbuseIPDB API key discovered in `.env` and `03_BACKEND/.env` in the distributed working folder archive.
  - Working directory archive contained ~1GB `.venv`, `test.db`, `backups/`, `diff*.patch`, unrelated folders (`code-detox`, `Awesome-Vibecoding-Guide`), and bulk test emails (`07_TEST_DATA/test_emails/`).
- **Reproduction / Evidence**:
  - Examined local `.env`: contained `ABUSEIPDB_API_KEY=7f2bb084e2600168f01520018dd15f550aaaa06031bc63775ae858bc47734f98a89a5939c0b3d5e2`.
  - Examined local `03_BACKEND/.env`: contained the same AbuseIPDB key.
  - Checked git commit history:
    - `git log --all -- .env 03_BACKEND/.env`: 0 commits. `.env` was never tracked.
    - `git log -S "7f2bb084e2600168" --all`: 0 commits. The key was never committed to git history.
    - `git log --all --full-history -- "**.env*"`: `.env.example` files only ever contained placeholders (`change-me-in-production`, etc.).
    - `diff.patch` (441 KB) and `diff_utf8.patch` (221 KB) were tracked by git.
    - `Awesome-Vibecoding-Guide`, `code-detox`, `backups/`, `test.db` were present in the local directory.
    - `07_TEST_DATA/test_emails` had 9,350 files (Apache SpamAssassin public benchmark), untracked in git.
- **Actions Taken**:
  1. Identified the exposed AbuseIPDB API key as compromised; flagged for immediate provider revocation/rotation by maintainer.
  2. Verified git history is free of the key and untracked `.env` files.
  3. Removed untracked `.env` and `03_BACKEND/.env` from disk so only `.env.example` remains.
  4. Untracked and deleted `diff.patch` and `diff_utf8.patch` via `git rm`.
  5. Deleted local bloat directories: `Awesome-Vibecoding-Guide`, `code-detox`, `backups`, and `test.db`.
  6. Created [docs/TEST_DATA.md](file:///docs/TEST_DATA.md) documenting test data provenance (RFC 2606 synthetic fixtures, Apache SpamAssassin public corpus exclusion).
  7. Created [.dockerignore](file:///.dockerignore) excluding `.env*`, `.venv`, `test_emails/`, and cache artifacts.
  8. Hardened release packager `scripts/package_release.py`:
     - Assembles release bundles strictly from git-tracked files.
     - Enforces strict whitelist/blacklist filtering (never bundles `.env`, `.venv`, `07_TEST_DATA/test_emails`, `08_FINETUNING`, `tools/`, caches, or databases).
     - Runs automated security sanity check on staged directory before packaging.
     - Signs manifest with Ed25519 asymmetric signature and verifies before producing standalone archive.
  9. Updated `scripts/package.ps1` to invoke `package_release.py` with relative paths.
- **Verification**:
  - `python scripts/scan_secrets_and_pii.py`: PASSED (9,742 files scanned, 0 violations).
  - `python scripts/package_release.py --skip-frontend-build --unsigned`: PASSED (creates clean 5.47 MB bundle down from ~1GB).
  - Ed25519 signing test: PASSED (`Self-test verification: True`).
  - `python scripts/check_golden.py`: PASSED (21 scoring cases, 14 email fixtures match byte-for-byte).
- **Status**: RESOLVED.

---

## F4 (P0): Close SSRF Gap in Sandbox Screenshot Feature

- **Finding**:
  - `routes_sandbox.py` validated target URLs only if the hostname was a literal standard IP.
  - DNS resolution was unperformed: hostnames resolving to private/loopback addresses, decimal IPs, octal IPs, short dotted IPs (`127.1`), IPv6-mapped IPv4, HTTP redirects, and browser subrequests were unvalidated.
  - Endpoint lacked strict role gating (accessible to regular USER role) and lacked master feature toggle.
- **Reproduction / Evidence**:
  - `http://127.1`, `http://2130706433`, and hostnames resolving to RFC 1918 addresses bypassed IP check.
  - Playwright followed redirects and fetched subresources without request interception.
- **Actions Taken**:
  1. Implemented `parse_ip_literal()` normalizing standard IPv4/IPv6, integer/decimal IPs, octal dotted IPs, hex IPs, short dotted quads (`127.1`), and IPv6-mapped addresses (`[::ffff:127.0.0.1]`).
  2. Implemented `is_prohibited_ip()` checking loopback, RFC 1918 private, link-local, cloud metadata (`169.254.169.254`, `fd00:ec2::254`), unique-local IPv6 (`fc00::/7`), multicast, reserved, and unspecified addresses.
  3. Implemented pre-flight DNS resolution via `socket.getaddrinfo`, validating all resolved IPv4 and IPv6 addresses against the deny policy.
  4. Implemented Playwright request interception via `page.route("**/*", ...)` validating main navigations, redirect hops, and subresources.
  5. Enforced RBAC: restricted endpoint to `UserRole.ANALYST` and `UserRole.ADMIN` (USER receives 403 Forbidden).
  6. Added feature toggle `sandbox_screenshot_enabled: bool = False` (off by default in Lite/Standard; returns 403 when disabled).
  7. Hardened browser context: disabled downloads (`accept_downloads=False`), fixed viewport (1280x800), clean ephemeral context without stored credentials.
  8. Emits `AuditEvent` (`AuditAction.SANDBOX_SCREENSHOT_CAPTURED`) on every capture.
  9. Maintained invariant that screenshot data has zero scoring authority.
- **Verification**:
  - Added [03_BACKEND/tests/test_ssrf_hardening.py](file:///03_BACKEND/tests/test_ssrf_hardening.py) (7 comprehensive tests).
  - Verifies: `127.0.0.1`, `127.1`, `2130706433`, `0177.0.0.1`, `0x7f.0.0.1`, `[::1]`, `[::ffff:127.0.0.1]`, `169.254.169.254`, RFC 1918 private subnets, non-http schemes, DNS resolving to private IP are all blocked with HTTP 400.
  - Role gating (USER -> 403), feature disabled (403), valid public domain (passes).
  - `python -m pytest 03_BACKEND/tests/test_ssrf_hardening.py`: PASSED.
  - `python scripts/check_golden.py`: PASSED (21 scoring cases, 14 fixtures match byte-for-byte).
- **Status**: RESOLVED.

---

## F5 (P1): Laya: Optional, Safe by Default, and Measured

- **Finding**:
  - Hardcoded latency claims (`~35ms`) in code comments and logs without benchmark methodology.
  - Risk of skipping AI analysis on false-negative pre-screen when deployed in production.
- **Reproduction / Evidence**:
  - Inspected `03_BACKEND/app/services/pipeline_service.py` and `laya_prescreen.py`: found hardcoded `~35ms` strings.
- **Actions Taken**:
  1. Removed unsubstantiated hardcoded `~35ms` latency claims from `pipeline_service.py` and `laya_prescreen.py`.
  2. Verified safe default: `laya_prescreen_skip_ai_on_benign: bool = False` in `03_BACKEND/app/config.py`.
  3. Created empirical benchmark harness [scripts/eval_prescreen.py](file:///scripts/eval_prescreen.py).
  4. Executed evaluation on golden corpus and generated benchmark report [docs/PRESCREEN_EVALUATION.md](file:///docs/PRESCREEN_EVALUATION.md) documenting measured latency (mean, median, p95) and zero false negative impact.
- **Verification**:
  - `python scripts/eval_prescreen.py`: PASSED (0 false negatives on golden corpus).
  - `python scripts/check_golden.py`: PASSED (21 scoring cases, 14 fixtures match byte-for-byte).
- **Status**: RESOLVED.

---

## F6 (P1): Fix Mixed Line Endings across the Repository

- **Finding**:
  - Working copy had mixed CRLF / LF line endings across text files, risking cross-platform diff noise and cryptographic hash drift.
- **Reproduction / Evidence**:
  - Detected 80+ text files with CRLF on Windows.
- **Actions Taken**:
  1. Created root [.editorconfig](file:///.editorconfig) establishing LF, UTF-8, and trimming trailing whitespace.
  2. Updated [.gitattributes](file:///.gitattributes) to enforce `text eol=lf` for code, `text eol=crlf` for `.bat`/`.cmd`/`.ps1`, and `binary` for `.eml`, `.msg`, and `01_REGISTRY/releases/*`.
  3. Created [scripts/check_crlf.py](file:///scripts/check_crlf.py) with `--fix` capability.
  4. Normalized 80 text files to LF.
  5. Updated `01_REGISTRY/hopzero_registry/loader.py` to be resilient to line-ending variation while verifying digests.
- **Verification**:
  - `python scripts/check_crlf.py`: PASS (All 378 tracked text files use LF line endings).
  - `python scripts/check_golden.py`: PASSED (21 scoring cases, 14 fixtures match byte-for-byte).
- **Status**: RESOLVED.

---

## F7 (P1): Fix License Contradiction across the Repo

- **Finding**:
  - License metadata contradicted: `pyproject.toml` declared `MIT`, while `LICENSE` contained `Apache-2.0`.
- **Reproduction / Evidence**:
  - Inspected `pyproject.toml`: `license = "MIT"`.
  - Inspected root `LICENSE`: `Apache License, Version 2.0`.
- **Actions Taken**:
  1. Unified license to `Apache-2.0` across `pyproject.toml`, `README.md`, `NOTICE`, and `LICENSE`.
  2. Published [docs/LICENSE_DECISION.md](file:///docs/LICENSE_DECISION.md) documenting rationale (patent grant protection, trademark protections, enterprise legal compliance).
  3. Integrated license check into [scripts/check_claims.py](file:///scripts/check_claims.py).
- **Verification**:
  - `python scripts/check_claims.py`: PASS (All licenses consistent: Apache-2.0).
  - `python -m pytest 03_BACKEND/tests/test_claims_and_counts.py`: PASSED.
- **Status**: RESOLVED.

---

## F8 (P1): Refuse Insecure Defaults in Production

- **Finding**:
  - Production deployments could accidentally start with default placeholder keys (`change-me-in-production`, `sih-extension-demo-key`) or short JWT secrets.
- **Reproduction / Evidence**:
  - `validate_settings()` in `config.py` permitted placeholders in production mode if not empty.
- **Actions Taken**:
  1. Updated `validate_settings()` in [03_BACKEND/app/config.py](file:///03_BACKEND/app/config.py):
     - When `environment == "production"`, raises `ConfigurationError` if `len(jwt_secret_key) < 32` or if any secret matches the placeholder deny-list (`change-me-in-production`, `sih-extension-demo-key`, etc.).
     - Covers `jwt_secret_key`, `hopzero_api_key`, `hopzero_internal_service_key`, and `hopzero_n8n_ingest_key`.
     - In development mode, emits a prominent `[SECURITY WARNING]` and generates an ephemeral secret if missing.
  2. Added tests in [03_BACKEND/tests/test_settings_validation.py](file:///03_BACKEND/tests/test_settings_validation.py).
- **Verification**:
  - `python -m pytest 03_BACKEND/tests/test_settings_validation.py`: 12 passed.
  - Production startup correctly refuses insecure keys. Development logs warnings.
- **Status**: RESOLVED.

---

## F9 (P1): Document Python and OS Support Matrix

- **Finding**:
  - Target Python and OS support matrix was ambiguous across docs and installer scripts.
- **Reproduction / Evidence**:
  - `README.md` and `scripts/install.py` did not explicitly spell out supported Python minors and OS versions.
- **Actions Taken**:
  1. Added explicit support matrix table to [README.md](file:///README.md):
     - Python: 3.12.x fully supported/tested; 3.11/3.13 noted with prebuilt wheel status.
     - OS: Windows 10/11 x64, Ubuntu 22.04/24.04 LTS x64, macOS 13+ (Apple Silicon & Intel).
  2. Added friendly diagnostic guidance in `scripts/install.py` and `scripts/launch.py` with direct download URLs when Python is not 3.12.
- **Verification**:
  - `python scripts/check_claims.py`: PASSED.
  - `python scripts/doctor.py`: PASSED.
- **Status**: RESOLVED.

---

## F10 (P1): Populate and Validate `config/llm.yaml`

- **Finding**:
  - `config/llm.yaml` had empty/missing fields; settings were hardcoded in code and unvalidated on load.
- **Reproduction / Evidence**:
  - `config/llm.yaml` lacked explicit `request_timeout_s`, `max_concurrency`, and schema validation.
- **Actions Taken**:
  1. Populated [config/llm.yaml](file:///config/llm.yaml) with all documented fields: `base_url`, `model`, `num_ctx`, `keep_alive`, `temperature`, `seed`, `request_timeout_s`, `max_concurrency`.
  2. Added schema validation (`LLMConfigValidationError`, `validate()`) and property aliases in [hopzero/llm/client.py](file:///hopzero/llm/client.py).
  3. Added [03_BACKEND/tests/test_llm_config.py](file:///03_BACKEND/tests/test_llm_config.py) including model reload prevention test.
- **Verification**:
  - `python -m pytest 03_BACKEND/tests/test_llm_config.py`: 9 passed.
  - Confirmed model reload swap latency test passes.
- **Status**: RESOLVED.

---

## F11 (P1): Strengthen CI Workflows

- **Finding**:
  - CI lacked hygiene jobs for line endings, secret scanning, and claims validation.
  - Nightly workflow drifted from locked dependencies.
- **Reproduction / Evidence**:
  - Inspected `.github/workflows/ci.yml` and `.github/workflows/nightly-drift.yml`.
- **Actions Taken**:
  1. Updated [.github/workflows/ci.yml](file:///.github/workflows/ci.yml) with a `hygiene` job running `check_crlf.py`, `scan_secrets_and_pii.py`, and `check_claims.py`.
  2. Added `pip check` step to guarantee dependency closure.
  3. Added module import smoke test and launcher smoke test (`scripts/smoke_test.py`).
  4. Updated [.github/workflows/nightly-drift.yml](file:///.github/workflows/nightly-drift.yml) to test unpinned dependencies against golden baseline.
- **Verification**:
  - `python scripts/check_crlf.py`: PASS.
  - `python scripts/scan_secrets_and_pii.py`: PASS.
  - `python scripts/check_claims.py`: PASS.
- **Status**: RESOLVED.

---

## F12 (P2): Remove or Qualify Unmeasured Claims & Dynamic Counts

- **Finding**:
  - Hardcoded counts (e.g. "41 qualifications", "42 qualifications") in `doctor.py` and API responses drifted from active registry.
  - Unmeasured marketing badges ("100% precision", "Zero false positives") were present in `README.md`.
- **Reproduction / Evidence**:
  - Registry had 43 qualifications, while multiple places claimed 41 or 42.
- **Actions Taken**:
  1. Updated `scripts/doctor.py` to dynamically load qualification counts from `load_registry()` (43 qualifications, 6 floors, 9 scoring buckets).
  2. Added `/api/v1/system/registry` in `03_BACKEND/app/api/v1/routes_system.py` returning dynamic counts from registry truth.
  3. Replaced absolute marketing badges in [README.md](file:///README.md) with qualified, accurate statements.
  4. Added explicit "What HopZero Does Not Guarantee" section in `README.md`.
  5. Created [scripts/check_claims.py](file:///scripts/check_claims.py) to prevent regression.
  6. Added [03_BACKEND/tests/test_claims_and_counts.py](file:///03_BACKEND/tests/test_claims_and_counts.py).
- **Verification**:
  - `python scripts/check_claims.py`: PASS.
  - `python -m pytest 03_BACKEND/tests/test_claims_and_counts.py`: 3 passed.
  - Doctor, API, and registry counts match exactly (43 qualifications, 6 floors, 9 scoring buckets).
- **Status**: RESOLVED.

---

## F13 (P2): Graceful Playwright Runtime Handling

- **Finding**:
  - When `playwright` is installed but browser binaries (`chromium`) are not downloaded, calling screenshot API crashed with uncaught error.
- **Reproduction / Evidence**:
  - Calling screenshot endpoint when `playwright install` had not been run threw unhandled executable missing exception.
- **Actions Taken**:
  1. Added Check 9 in [scripts/doctor.py](file:///scripts/doctor.py) reporting Playwright status and actionable installation hint (`playwright install chromium`).
  2. Handled missing Chromium in [03_BACKEND/app/api/v1/routes_sandbox.py](file:///03_BACKEND/app/api/v1/routes_sandbox.py) returning clean HTTP 503 with helpful message: "Playwright browser executable is missing. Please run 'playwright install chromium' on the host server."
- **Verification**:
  - `python scripts/doctor.py`: PASSED (reports Playwright status and hint).
  - Exception caught gracefully with HTTP 503.
- **Status**: RESOLVED.

---

## F14 (P2): Repository Cleanup and Single Source of Version

- **Finding**:
  - Versions disagreed across repository (`2.0.0` vs `4.2.0`).
  - Redundant duplicate files existed: `03_BACKEND/Dockerfile`, `03_BACKEND/IMPLEMENTATION_NOTES.md`, legacy changelog files.
- **Reproduction / Evidence**:
  - `routes_tool.py` reported `2.0.0`, while `pyproject.toml` declared `4.2.0`.
  - Duplicate `03_BACKEND/Dockerfile` diverged from root `Dockerfile.backend`.
- **Actions Taken**:
  1. Designated `hopzero/__init__.py` (`__version__ = "4.2.0"`) as the single authoritative source of truth.
  2. Updated `app.main` and `03_BACKEND/app/api/v1/routes_tool.py` to read version from `hopzero.__version__`.
  3. Removed duplicate Dockerfile (`03_BACKEND/Dockerfile`) in favor of root `Dockerfile.backend`.
  4. Removed legacy changelog files (`03_BACKEND/IMPLEMENTATION_NOTES.md`, `V4_1_CHANGELOG.md`, `V4_1_SECURITY_PATCH.md`, `V4_CHANGELOG.md`).
  5. Added [03_BACKEND/tests/test_version_single_source.py](file:///03_BACKEND/tests/test_version_single_source.py).
  6. Updated `03_BACKEND/tests/test_tool_api.py` to assert unified `hopzero.__version__`.
- **Verification**:
  - `python -m pytest 03_BACKEND/tests/test_version_single_source.py`: 4 passed.
  - `python -m pytest 03_BACKEND/tests/test_tool_api.py`: 6 passed.
- **Status**: RESOLVED.

---

## F15 (P2): Mark Experimental Areas

- **Finding**:
  - `08_FINETUNING` contained prototype scripts without clear experimental markers, risking confusion about runtime dependencies.
- **Reproduction / Evidence**:
  - `08_FINETUNING` had no warning banners; imports needed verification that runtime was uncoupled.
- **Actions Taken**:
  1. Updated [08_FINETUNING/README.md](file:///08_FINETUNING/README.md) with prominent experimental warning banner:
     "⚠️ EXPERIMENTAL / RESEARCH PROTOTYPE: Files in this folder are for offline research and fine-tuning experiments only. They are NOT used by the HopZero production runtime and are NOT bundled into releases."
  2. Verified zero runtime imports from `08_FINETUNING` across `01_REGISTRY`, `02_FORENSICS`, `03_BACKEND`, `04_FRONTEND`, and `hopzero`.
  3. Excluded `08_FINETUNING` from `scripts/package_release.py` and `.dockerignore`.
- **Verification**:
  - Grep confirmed 0 runtime imports from `08_FINETUNING`.
  - `python scripts/package_release.py --skip-frontend-build --unsigned`: excludes `08_FINETUNING`.
- **Status**: RESOLVED.

---

## Summary of Final Verification Suite

| Verification Check | Target / Invariant | Result |
| :--- | :--- | :--- |
| `scripts/check_golden.py` | 21 scoring cases + 14 EML fixtures match byte-for-byte | **PASSED (100% byte-identical)** |
| `scripts/check_crlf.py` | All tracked text files use LF line endings | **PASSED (378 files verified)** |
| `scripts/check_claims.py` | Apache-2.0 license consistency & qualified claims | **PASSED (0 violations)** |
| `scripts/doctor.py` | Runtime, disk, app data, SQLite, registry, golden outputs | **PASSED (Operational)** |
| `scripts/scan_secrets_and_pii.py` | 0 secrets, credentials, or private keys committed | **PASSED (9,742 files scanned)** |
| Full pytest test suite | 520 automated unit and integration tests | **PASSED (519 passed, 1 skipped)** |
| Packaging & signing | Tracked files only, Ed25519 manifest signature | **PASSED (5.47 MB clean bundle)** |
