# Security Patch — Internal Service Key for Direct Finding Creation

## What was wrong

`app/services/finding_service.py` had a `DETERMINISTIC_PRODUCERS`
allow-list that checked the request body's own `produced_by` field
against a fixed set of strings (`"deterministic_analyzer"`,
`"forensics_analyzer_v1"`, `"forensics_analyzer_v2"`). This was
presented in `V4_CHANGELOG.md` as a fix, but it wasn't a real
authorization control -- it inspected a value the caller supplies
themselves, with no credential behind it. Any authenticated HopZero
user could POST:

```json
{"produced_by": "deterministic_analyzer", ...}
```

and the backend would treat it as if it came from a trusted
deterministic analyzer. I should have flagged this myself when I
introduced it; I didn't, and it took an external review to catch it.
Noting that plainly rather than glossing over it.

## What changed

- **`app/config.py`**: added `hopzero_internal_service_key: str | None = None`.
  No default value. Sourced only from the `HOPZERO_INTERNAL_SERVICE_KEY`
  environment variable.
- **`app/security.py`**: added `require_internal_service_producer`, a
  FastAPI dependency that checks the `X-Internal-Service-Key` header
  against `settings.hopzero_internal_service_key` using
  `secrets.compare_digest` (constant-time comparison). Implements the
  locked Option-B behavior exactly:
  - Key not configured on the server → path unavailable, logged
    internally as a server-configuration state (`logger.warning(...)`),
    externally just a plain `403 Forbidden`.
  - Key configured but caller's header is missing/wrong → `403 Forbidden`,
    same response shape as the above -- the two cases are
    indistinguishable from the outside.
- **`app/api/v1/routes_findings.py`**: `POST /findings` now requires
  `Depends(require_internal_service_producer)` in addition to the
  existing `get_current_user` JWT dependency. Both are required: the
  JWT for organization scoping and audit-actor attribution, the
  internal key for the producer-trust claim itself.
- **`app/services/finding_service.py`**: removed `DETERMINISTIC_PRODUCERS`
  and the check that used it. `produced_by` is now purely descriptive
  metadata on the Finding row, not a security boundary -- the route
  layer's dependency is the actual boundary now.
- **Tests**: new `tests/test_internal_service_key.py` (8 tests) covering
  correct-key success, missing-header rejection, wrong-key rejection,
  the "self-declared produced_by alone is not enough" regression case,
  missing-server-configuration rejection, and that missing-config vs.
  wrong-key produce byte-identical responses. Updated
  `tests/test_findings_dedup.py` and `tests/test_score_engine.py` to
  send the header (via a new `internal_service_headers()` test helper
  in `conftest.py`) since those tests legitimately need the
  deterministic-producer path to work; added one explicit
  403-without-the-header regression test to `test_findings_dedup.py`.
- **Also fixed while in this file**: a Pydantic v2 warning about
  `model_suggested_strength`/`model_confidence`/`model_identifier`/
  `model_version_or_digest` colliding with BaseModel's protected
  `model_` namespace, by adding `protected_namespaces=()` to the
  relevant schemas. Unrelated to the security fix, but it was visible
  in your test output and was quick to clean up.
- **`.env.example`**, **`docker-compose.yml`**, **`README.md`**: updated
  to reflect the new header/env var; docker-compose deliberately leaves
  the key unset by default (commented out) so the Option-B "path
  disabled until configured" behavior is what you get out of the box,
  not an accidental convenience default.

## What I still have not verified (same caveat as always)

I have not run this. Same sandbox, still no network, confirmed again
before making these changes. `python -m py_compile` passes on every
changed file. Please run:

```bash
pytest tests/test_internal_service_key.py tests/test_findings_dedup.py tests/test_score_engine.py -v
```

and paste the result. If `test_missing_server_configuration_rejects_even_with_a_key_supplied`
or `test_missing_config_and_wrong_key_are_externally_indistinguishable`
fail, the most likely cause is `monkeypatch.setattr` on the cached
`Settings` instance not behaving the way I expect with
`lru_cache`-wrapped `get_settings()` -- worth checking first if
something's off there.

## Note on the earlier open 403 mystery

I never got the full diagnostic output for the original
`test_findings_dedup.py` 403 failures from a few turns back. Since
this patch replaces the entire mechanism that was causing that 403
(the `DETERMINISTIC_PRODUCERS` check no longer exists), that specific
investigation is moot going forward -- but I want to be upfront that I
never actually root-caused it. If the same class of "check looks
correct by reading it, fails in practice" issue shows up again with
this new code, that's a pattern worth taking seriously rather than
re-explaining away.
