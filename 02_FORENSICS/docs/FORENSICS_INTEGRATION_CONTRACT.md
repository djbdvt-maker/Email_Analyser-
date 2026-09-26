# Forensics Integration Contract

**Owner:** Email Forensics (Person 3)
**Audience:** anyone integrating with, or building the next layer on
top of, this module — Score Engine, semantic AI, backend/orchestration,
frontend.
**Status:** describes the frozen `team3-baseline-v1` surface (see
`docs/BASELINE_FREEZE.md`).

## 1. The two representations, and why there are two

```
raw .eml bytes  (stored by backend; artifact_id refers to this)
      |
      v
  CanonicalEmail          <-- parser output, IMMUTABLE once produced
      |
      v
  Evidence Normalizer
      |
      v
  NormalizedEvidence       <-- SEPARATE, analysis-facing representation
      |
      v
  (future) Analyzers, Semantic AI, deterministic semantic predicates
```

**`CanonicalEmail` is the immutable parser output.** It is produced once
per parse by `parser.parse_eml()` / `parse_eml_file()` and is never
mutated afterward by anything downstream — not by the Evidence
Normalizer, not by any analyzer, not by the semantic AI step. Every
consumer receives it by reference and treats it as read-only. This is
enforced today by a regression test
(`test_normalize_email_does_not_mutate_canonical_email`) that
deep-compares a `CanonicalEmail` before and after normalization.

**`NormalizedEvidence` is a separate, additive, analysis-facing
representation.** It is derived FROM a `CanonicalEmail` by
`evidence_normalizer.normalize_email()`, but it is a different object
with a different shape — it is not "CanonicalEmail with some fields
overwritten." Consumers that need obfuscation-resistant text (see §3)
use `NormalizedEvidence`; consumers that need the exact original text,
or fields not in `NormalizedEvidence`'s scope, use `CanonicalEmail`
directly. Both can coexist in memory for the same email at the same
time; neither is "the current state" that replaces the other.

Neither structure ever carries a score, severity, verdict, or LLM
conclusion. That is out of scope for both, at every layer of this
module — see §5.

## 2. Which CanonicalEmail fields each future analyzer will consume

This reflects the currently-planned scope documented in each stub's
docstring (`analyzers/*.py`) — it will be refined as each analyzer is
actually built and unblocked, but this is the current intent so
teammates can plan around it.

| Analyzer | CanonicalEmail fields it will read | Notes |
|---|---|---|
| **Routing** (built, not a stub) | `received_chain_raw` | Already implemented — see `docs/ANALYZER_CONTRACT.md`. |
| **Authentication** (stub) | `headers` (filtered for `authentication-results`, `received-spf`, `dkim-signature`), `from_addresses`, `return_path` | Needs raw header values, not normalized text — protocol results are structured tokens, not human-readable prose. |
| **Identity** (stub) | `from_addresses`, `reply_to_addresses`, `return_path`, `to_addresses` (raw, for address-level structural comparison) | Display-name *text* comparison should use `NormalizedEvidence` instead (see §3) — address comparison itself must stay on raw data. |
| **Domain** (stub) | `from_addresses` / `reply_to_addresses` / `return_path` (raw domain portions), `body.links` (raw hrefs) | Deliberately does **not** consume `NormalizedEvidence` — see §4. |
| **Links** (stub) | `body.links` (raw hrefs) | Same reasoning as Domain — hrefs stay raw. |
| **Attachments** (stub) | `attachments` (filename, declared_mime_type, size_bytes, sha256, content_disposition) | Raw fields for evidence display + hashing; filename *text* comparison (for obfuscated extensions) should use `NormalizedEvidence`. |
| **Infrastructure** (stub) | Not yet defined — this category's scope itself is an open blocker, not just its codes. | See `docs/ANALYZER_CONTRACT.md` registry-blockers list. |

## 3. Which normalized text fields are available to semantic analyzers

`NormalizedEvidence.fields` (v1 scope, produced by
`evidence_normalizer.normalize_email()`):

- `subject`
- `body.text_plain`
- `from_addresses[i].display_name`, `reply_to_addresses[i].display_name`,
  `to_addresses[i].display_name`, `cc_addresses[i].display_name`,
  `return_path.display_name` (only present when the underlying display
  name text exists)
- `attachments[i].filename` (only present when a filename exists)

Each `NormalizedField` carries `original_text`, `normalized_text`,
`policy_version`, and a fully traceable `events` list (see
`docs/NORMALIZATION_DESIGN.md` for the full mechanism). Semantic
predicates and the semantic AI step should read `normalized_text` for
keyword/pattern/semantic matching, since that's what resists zero-width
insertion, unusual whitespace, and full-width character substitution —
but should treat `original_text` as the evidentiary record when
displaying "what the email actually said" to a human reviewer.

## 4. Which fields intentionally remain raw / domain-specific

**Link hrefs / URLs are never normalized by the Evidence Normalizer, and
this is deliberate, not an oversight.** A URL's exact bytes are what
would actually be requested if followed, and IDN/punycode-based
domain trickery is precisely the kind of signal a blind text-normalization
pass could mask or corrupt. Any URL-specific normalization (IDNA
decoding, punycode handling, confusable/homoglyph comparison against a
protected-brand list) belongs to the future Domain/Links analyzers,
operating directly on `CanonicalEmail.body.links[].href` — never on a
`NormalizedEvidence` version of it, because none exists and none is
planned for hrefs.

Other fields that remain raw/domain-specific for their own reasons:

- **`body.html_sanitized`** (raw HTML markup with tags) — not covered by
  the Evidence Normalizer at all yet, because normalizing text still
  embedded in HTML tags risks corrupting tag/attribute syntax. A
  dedicated visible-text-extraction-from-HTML step would need to exist
  first; it doesn't yet.
- **Raw header values in general** — only `authentication-results`,
  `received-spf`, `dkim-signature` (for Authentication) and the
  `received` chain (already handled by Routing) have identified
  consumers so far. Nothing else is normalized or has a planned
  consumer yet.
- **Email addresses themselves** (the `local@domain` part, as opposed to
  display names) — never text-normalized. Address comparison for
  Identity/Domain purposes must operate on the exact, raw address
  string; NFKC or whitespace normalization of an address could change
  its actual deliverability semantics, which display-name prose does
  not have.

## 5. Analyzer input/output boundaries

Every analyzer (built or stub) follows the same boundary, unconditionally:

- **Input:** `CanonicalEmail` (read-only) and, where its docstring says
  so, `NormalizedEvidence` (also read-only). Analyzers never mutate
  either.
- **Output:** `AnalyzerOutput` — `facts: list[Fact]` and
  `candidates: list[FindingCandidate]` only.
- **Never in an analyzer's output, at any point, for any category:** a
  score, a severity, a verdict, an LLM-generated conclusion, or a
  qualification code that isn't already confirmed in
  `qualification_vocab.py`. This is not a style preference — it's the
  reason the six analyzers below Routing remain stubs rather than
  best-effort implementations: without a confirmed code, there is
  nothing valid to put in `FindingCandidate.qualification_code`, so no
  `FindingCandidate` can correctly be produced for those categories yet.
- Deterministic analyzers assign `FindingCandidate.strength` directly
  from the qualification's own registered default (see
  `qualification_vocab.QualificationDefinition.default_strength`) — they
  never compute a number.

## 6. Unavailable signals remain Facts, never silently-converted findings

This is a project-wide rule, not specific to Routing, and every future
analyzer must follow it identically:

- If a signal cannot be determined (a header is missing, a value is
  unparsable, a chain doesn't exist, an archive is truncated, whatever
  the future category-specific case is), the analyzer records exactly
  one thing: a `Fact` with `state=SignalState.UNAVAILABLE` and an
  explanatory `detail`.
- **No `FindingCandidate` is emitted for an unavailable signal.** Not a
  placeholder one, not a "weak strength, just in case" one. This was
  corrected in this module once already — a previous draft of the
  Routing analyzer emitted a `CF-01:ORIGIN_INDETERMINATE` candidate for
  "no chain / no trusted boundary," and that candidate was removed on
  review specifically because its qualification code was never
  confirmed against the registry (see `docs/ANALYZER_CONTRACT.md`
  changelog). The corrected, permanent rule: unavailability is
  represented in `SignalState`, full stop — never promoted into a
  `FindingCandidate` of any kind, confirmed-code or otherwise.
- Unavailable must never be interpreted downstream (by the Score
  Engine, by a human reviewer, by anything) as "checked and clean." The
  distinction between "absent/failed" and "unavailable" lives entirely
  in `SignalState`, and every future analyzer must preserve that
  distinction rather than collapsing it.

## 7. How the identifiers/versions relate

Five independent axes exist. None of them are interchangeable, and a
complete audit trail for one investigation needs all five recorded
together (this module produces the first three; backend/orchestration
is responsible for capturing the association with the last two):

| Identifier / version | Owned by | What it identifies | Stability |
|---|---|---|---|
| `artifact_id` | Backend persistence | The stable identity of the underlying raw `.eml` artifact | Same value every time the same stored email is referenced, forever. |
| `CanonicalEmail.id` | This module (generated per parse) | One specific **parse instance/invocation** | Different every time the same `artifact_id` is parsed again, unless a caller explicitly supplies `parse_instance_id`. Never use as a dedup/correlation key. |
| `analyzer_version` (e.g. `routing_analyzer@1.0`, in `Fact.produced_by` / `FindingCandidate.produced_by`) | Each analyzer module | Which version of the analyzer's **code/logic** produced a given Fact/Candidate | Changes when the analyzer's detection logic changes (e.g. if CF-06's temporal tolerance were adjusted). |
| `qualification_version` (`VOCABULARY_VERSION` in `qualification_vocab.py`, currently `"v1"`) | Architecture-owned registry (this module currently substitutes a locked subset) | Which version of the **qualification code definitions** (codes, default strengths) was in effect | Changes when the registry itself is revised — independent of any single analyzer's code changing. |
| `NORMALIZATION_POLICY_VERSION` (`"v1"`, in `config/normalization_policy_v1.py`) | This module | Which version of the **mechanical normalization rules** (zero-width codepoint set, whitespace map) produced a given `NormalizedField` | Changes when the curated codepoint sets are revised — independent of parser or analyzer versions. |

**Why this matters in practice:** re-running the same stored artifact
(`artifact_id` unchanged) through an updated Routing analyzer
(`analyzer_version` bumped) six months from now, against a possibly-revised
registry (`qualification_version` bumped) and a possibly-revised
normalization policy (`NORMALIZATION_POLICY_VERSION` bumped), is a
**new investigation run** that must be preserved alongside the original
— never overwriting it — per the project's "preserve history, derive
current state" rule. Every one of the five identifiers above should be
captured on that run's stored record so it's fully reconstructible later
which exact code, vocabulary, and policy versions produced which
specific Facts/Candidates. `analysis_run_id` itself (tying a specific
run together) is explicitly **not** generated by this module — that's
backend/orchestration's identifier, associated with this module's output
after the fact (see `docs/CANONICAL_EMAIL_SCHEMA.md`).

## 8. Summary table: what's built vs. stubbed vs. undefined

| Component | Status |
|---|---|
| Parser → CanonicalEmail | **Built, frozen** |
| Routing / Hop-0 (CF-06) | **Built, frozen** |
| Evidence Normalizer | **Built, frozen** |
| Authentication | Stub — raises `NotImplementedError`; blocked on registry codes |
| Identity | Stub — raises `NotImplementedError`; blocked on registry codes |
| Domain | Stub — raises `NotImplementedError`; blocked on registry codes + protected-brand dataset |
| Links | Stub — raises `NotImplementedError`; blocked on registry codes |
| Attachments | Stub — raises `NotImplementedError`; blocked on registry codes |
| Infrastructure | Stub — raises `NotImplementedError`; blocked on **undefined category scope**, not just codes |

Every stub is covered by a test (`test_blocked_analyzer_stubs.py`)
asserting it raises rather than silently returning an empty, misleadingly
"clean" `AnalyzerOutput`.
