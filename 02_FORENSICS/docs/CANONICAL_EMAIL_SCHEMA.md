# CanonicalEmail Schema — v1 (Proposed, for review)

**Owner:** Email Forensics (Person 3)
**Status:** Draft — circulating for sign-off before freezing. Please review
against your own component's needs before this is treated as stable.
**Source of truth:** `hopzero_forensics/interfaces.py`

## Purpose

`CanonicalEmail` is the single normalized representation produced by the
parser from a raw `.eml` file. Every downstream stage — all forensic
analyzers, the optional semantic AI step, finding normalization/dedup, and
the Score Engine — consumes this instead of re-parsing raw bytes.

## Hard constraints (do not violate when extending this schema)

1. **Purely descriptive.** No score, severity, verdict, "malicious" flag,
   or LLM-derived conclusion may ever be added to this structure. If you
   need to attach a derived judgment to an email, it belongs in a
   different structure (Finding, Score Engine output, etc.), not here.
2. **Nothing is destroyed.** The original raw artifact is referenced via
   `artifact_id`, never inlined-and-discarded. Header `raw_line` values
   are preserved verbatim even when `value` is decoded/normalized.
3. **Order is preserved.** Headers and the Received chain keep their
   original sequence via `sequence_index`; nothing is silently reordered.
4. **Missing ≠ clean.** Every optional/nullable field that represents a
   security-relevant signal is paired with a `parse_state` /
   `SignalState` (`present` / `absent` / `unavailable`). `unavailable`
   must never be interpreted downstream as a negative or "passed" result.
5. **`analysis_run_id` is NOT part of this schema.** Backend/orchestration
   owns the AnalysisRun identity and associates it with this output
   after the fact — CanonicalEmail is run-agnostic by design.
6. **`id` vs `artifact_id` — only one is a real identity.** `artifact_id`
   is the STABLE identity of the underlying raw email artifact, assigned
   and owned by backend persistence — this module only carries whatever
   `artifact_id` it's given. `id` is **not** a competing identity concept:
   it is a parse-instance handle (freshly generated per call to
   `parse_eml()` unless explicitly supplied) and will differ across two
   parses of the exact same `artifact_id`. Never use `id` as a dedup,
   cache, or cross-run correlation key — use `artifact_id` for that.

   *(This was previously ambiguous — an earlier draft generated `id` via
   `uuid4()` in a way that could be mistaken for a stable artifact
   identity. Corrected post-review; see `interfaces.py` docstring on
   `CanonicalEmail` for the authoritative statement.)*

## Top-level fields

| Field | Type | Notes |
|---|---|---|
| `id` | `str` | **Parse-instance identifier, not an artifact identity.** Generated fresh per `parse_eml()` call unless a `parse_instance_id` is explicitly supplied. Two parses of the same `artifact_id` will normally get two different `id` values. Do not use for dedup/correlation. |
| `artifact_id` | `str` | **The stable identity of the underlying raw artifact.** Owned/assigned by backend persistence — the forensics module accepts whatever id it's given and does not generate storage identifiers itself. Use this for dedup/correlation/re-run association. |
| `message_id` | `str \| None` | From the `Message-ID` header, if present. |
| `parsed_at` | `datetime` (UTC) | When parsing occurred. |
| `headers` | `list[RawHeader]` | Every header, order-preserved, see below. |
| `from_addresses` / `reply_to_addresses` / `to_addresses` / `cc_addresses` | `list[EmailAddress]` | Lists because these headers can legally contain multiple addresses. |
| `return_path` | `EmailAddress \| None` | Single value — `Return-Path` is not a list header. |
| `received_chain_raw` | `list[ReceivedHopRaw]` | Ordered as they appeared (index 0 = newest/topmost). **Not yet trust-evaluated** — that's the routing analyzer's job. |
| `body` | `EmailBody` | Plaintext, sanitized HTML, and extracted links. |
| `attachments` | `list[ExtractedAttachment]` | Structural facts only — no execution. |
| `subject` / `date_raw` / `date_parsed` | — | Self-explanatory. |
| `parse_warnings` | `list[str]` | Structural parse issues, not security findings. |
| `is_truncated` | `bool` | Set when the parser could not process the message at all. |

## Substructures

### `RawHeader`
```
name: str              # lower-cased header name
value: str             # decoded value
raw_line: str          # original, undecoded line(s), verbatim
sequence_index: int    # 0-based position in original header block
```

### `EmailAddress`
```
display_name: str | None
address: str | None       # local@domain, domain lower-cased; None if unparsable
raw_value: str             # original header value this came from
parse_state: SignalState
```

### `ReceivedHopRaw`
Structural extraction only — **not trust-evaluated here**.
```
sequence_index: int
raw_line: str
from_claim / by_claim / with_claim / for_claim: str | None   # unverified, as claimed
observed_ip: str | None        # IP literal found in the from-clause, if any
timestamp_raw: str | None
timestamp_parsed: datetime | None
parse_state: SignalState
malformed_reason: str | None    # populated only when parse_state != PRESENT
```

### `EmailBody`
```
text_plain: str | None
html_sanitized: str | None   # scripts/event-handlers/iframes stripped, for safe display only
html_available: bool          # true if an HTML part existed, independent of sanitization success
links: list[ExtractedLink]
```

### `ExtractedLink`
```
link_id: str
href: str                  # literal target as written
display_text: str | None
source: "html" | "plaintext"
context_snippet: str | None
```

### `ExtractedAttachment`
```
attachment_id: str
filename: str | None
declared_mime_type: str | None
size_bytes: int | None
sha256: str | None
content_disposition: str | None
is_inline: bool
within_archive: bool      # reserved for archive analyzer; parser sets False
parse_state: SignalState
```

## Known open items / questions for the team

1. **Storage of raw bytes.** This module does not persist the raw `.eml`
   itself — it expects an `artifact_id` to be supplied by whoever calls
   `parse_eml()`. Please confirm this is how backend intends to integrate
   (i.e. backend stores bytes first, then invokes the parser with the id
   it assigned).
2. **Archive/attachment recursion fields.** `within_archive` exists on
   `ExtractedAttachment` but is always `False` from the base parser —
   this is reserved for the attachment analyzer (fixed-depth, bounded
   archive extraction), which is not yet implemented.
3. **UI consumption.** If the frontend needs a lighter-weight/flattened
   view of this structure for display, that transform should happen in
   the UI or an API layer — please don't ask analyzers to shape output
   for display purposes.

Please raise objections or requested changes before this is frozen —
once analyzers are built against it, changes become more expensive.
