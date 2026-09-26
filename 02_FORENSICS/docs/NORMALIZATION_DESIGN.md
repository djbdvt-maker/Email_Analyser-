# Evidence Normalizer — Design Document

**Owner:** Email Forensics (Person 3)
**Status:** New component, for review — not merged to main.
**Depends on:** `CanonicalEmail` (parser output). Runs strictly after
parsing/CanonicalEmail and strictly before semantic AI / deterministic
semantic predicates in the pipeline.

## Why this exists

Deterministic semantic predicates and the semantic AI step both need to
read email text (subject, body, display names, filenames) to look for
things like phishing phrasing, impersonation cues, or suspicious
attachment names. Plain Unicode text offers several cheap, well-known
ways to defeat naive keyword/pattern matching while looking identical or
nearly identical to a human reader:

- Inserting zero-width characters between letters of a sensitive word
  (`V​e​r​i​f​y` — invisible joiners between every letter).
- Using visually-identical Unicode whitespace instead of a normal space.
- Using full-width/compatibility character forms instead of standard
  ASCII (`ｐａｙｐａｌ．ｃｏｍ` instead of `paypal.com`).
- Using bidi control characters to make a filename *display* differently
  than its actual byte content.

The Evidence Normalizer removes this class of evasion **mechanically**,
before any semantic judgment happens, while leaving the original
evidence completely untouched and fully recoverable.

## What it is NOT

- It is not a security analyzer. It produces no Facts, no
  FindingCandidates, no qualification codes, no scores, no verdicts.
- It does not call an LLM or make any network request.
- It does not interpret meaning. It applies a fixed, versioned,
  mechanical transformation pipeline and nothing else.
- It does not perform confusable/homoglyph folding of arbitrary text
  (see the dedicated section below — this is the single most important
  scoping decision in this design and is deliberately NOT implemented
  here).

## Architecture placement

```
CanonicalEmail
      |
      v
Evidence Normalizer   <-- NEW, this document
      |
      v
NormalizedEvidence  (separate structure, alongside CanonicalEmail)
      |
      v
Semantic AI / deterministic semantic predicates
```

`NormalizedEvidence` is additive. `CanonicalEmail` is never mutated, and
the raw `.eml` artifact (referenced by `artifact_id`, stored by backend
persistence) is never touched at any point in this pipeline stage.
Downstream consumers that want obfuscation-resistant text use
`NormalizedEvidence`; anything that needs the exact original (e.g. for
evidence export, chain-of-custody display, or re-deriving a different
normalization policy later) uses `CanonicalEmail` unchanged.

## Data model

```
NormalizationEvent:
  transformation: str        # best-effort classification (see below)
  position: int                # index into the ORIGINAL text
  original_span: str
  replacement_span: str | None   # None if the span was removed entirely
  codepoints: str                 # "U+XXXX,U+YYYY,..." of original_span
  detail: str | None

NormalizedField:
  field_path: str             # e.g. "subject", "body.text_plain"
  original_text: str           # verbatim source text, copied for traceability
  normalized_text: str
  policy_version: str
  events: list[NormalizationEvent]
  unchanged: bool

NormalizedEvidence:
  source_canonical_email_id: str   # CanonicalEmail.id (parse-instance handle)
  source_artifact_id: str            # CanonicalEmail.artifact_id (stable identity)
  policy_version: str
  produced_by: str
  fields: list[NormalizedField]
```

Every `NormalizedField` carries both `original_text` and
`normalized_text` side by side, so no downstream consumer ever has to
guess what changed or go back to the raw artifact to check — but the
raw artifact and `CanonicalEmail` remain the actual source of truth and
are never superseded.

## Requirement-by-requirement mapping

| # | Requirement | How it's met |
|---|---|---|
| 1 | Preserve original raw `.eml` artifact unchanged | Normalizer never touches `artifact_id`-referenced bytes; it only reads `CanonicalEmail` fields (already-parsed text), never re-touches storage. |
| 2 | Produce a separate canonical analysis representation | `NormalizedEvidence` is a new, additive structure — `CanonicalEmail` is passed by reference and never mutated (verified by a regression test that deep-compares before/after). |
| 3 | Apply NFKC normalization | Final pass of the pipeline, via stdlib `unicodedata.normalize("NFKC", ...)`. |
| 4 | Handle zero-width/invisible Unicode characters deterministically | Explicit, curated, versioned codepoint set (`ZERO_WIDTH_AND_INVISIBLE_CODEPOINTS`) — characters are removed, every removal logged as an event with position and codepoint. |
| 5 | Make the normalization policy versioned | `NORMALIZATION_POLICY_VERSION = "v1"` in `config/normalization_policy_v1.py`, stamped onto every `NormalizedField`/`NormalizedEvidence`. Future changes require a version bump, not an in-place edit. |
| 6 | Make the normalized representation traceable back to the original | Every field carries `original_text` verbatim, plus a full diff-derived event list with `position`/`original_span`/`replacement_span`/`codepoints`. `NormalizedEvidence` carries `source_canonical_email_id` and `source_artifact_id`. |
| 7 | Do not silently modify the evidentiary raw artifact | Same as #1/#2 — enforced structurally (the normalizer's only inputs are already-parsed `str` values; it has no access to raw bytes or storage) and by regression test. |
| 8 | Do not add scores/findings/verdicts/LLM conclusions to CanonicalEmail | `CanonicalEmail` is untouched; `NormalizedEvidence` itself also carries none of these — only text and mechanical event metadata. |
| 9 | Do not invent qualification codes | The normalizer does not reference `qualification_vocab.py` at all and produces no `FindingCandidate`. |
| 10 | Do not use an LLM or network call | Only `unicodedata` (stdlib) and `difflib` (stdlib) are used. |
| 11 | No blind confusable folding on arbitrary body text | Not implemented — see dedicated section below. |

## Pipeline (fixed, deterministic order)

1. **Remove zero-width / invisible characters** — filter out any
   character in the curated `ZERO_WIDTH_AND_INVISIBLE_CODEPOINTS` set.
2. **Normalize unusual Unicode whitespace** — replace any character in
   the curated `UNICODE_WHITESPACE_MAP` with its canonical ASCII space
   or newline. Standard ASCII space/tab/CR/LF are left untouched.
3. **Apply NFKC** to the result of steps 1–2 — this is what folds
   full-width/half-width forms, ligatures, and other compatibility
   variants into their canonical form.

A diff (`difflib.SequenceMatcher`) between the **original** text and the
**final** normalized text is then computed to produce the traceable
`NormalizationEvent` list, with each changed span best-effort classified
as `zero_width_removed`, `unicode_whitespace_normalized`, or
`nfkc_compatibility_normalization` (fallback label when a span mixes
causes or doesn't cleanly match either curated set).

## Fields in scope (v1)

- `subject`
- `body.text_plain`
- `display_name` of every parsed address (`from`/`reply_to`/
  `return_path`/`to`/`cc`)
- attachment `filename`s

Fields are only included if the underlying text is actually present
(not `None`). Absent fields are not fabricated as empty
`NormalizedField`s — that would conflate "no text existed" with "text
existed and happened to normalize to something," which is a
signal-availability concern that belongs to `SignalState` in
`CanonicalEmail`/analyzers, not to this module.

## Fields deliberately OUT of scope (v1) and why

- **`body.html_sanitized` (raw HTML markup).** Running NFKC/zero-width
  stripping on a string that still contains HTML tags risks corrupting
  tag/attribute syntax (e.g. if an invisible character sits inside a
  tag name via malformed markup). A correct implementation would need a
  dedicated "extract visible text from sanitized HTML" step first, which
  doesn't exist yet. Normalizing raw markup is explicitly deferred
  rather than done unsafely.
- **Link `href` values / URLs.** A URL's exact bytes are what actually
  gets requested if the link is followed — normalizing it here (e.g.
  folding full-width characters in a punycode-adjacent domain) could
  produce a normalized string that no longer corresponds to the real
  target, or could mask exactly the IDN/punycode trickery the Domain/
  Links analyzer needs to see in its raw form. Any URL-specific
  normalization belongs in the Domain/Links analyzer, using
  domain-specific IDNA/punycode handling — not generic text
  normalization.
- **Raw header values in general** (beyond the specific address
  display-name and filename surfaces above). Not yet a demonstrated need
  for v1; can be added field-by-field as later analyzers require it.

## Confusable/homoglyph folding — explicitly NOT implemented here

This is the most important scoping decision in this design, so it gets
its own section rather than a bullet point.

**What confusable folding is:** mapping visually-similar characters from
different scripts to a single "skeleton" form for comparison — e.g.
Cyrillic `а` (U+0430) and Latin `a` (U+0061) are visually indistinguishable
in most fonts and could be mapped to the same skeleton so that
`аpple.com` (Cyrillic а) and `apple.com` (Latin a) compare as
"confusable."

**Why it is not applied here, to arbitrary text:**

1. **It would corrupt genuine multilingual content.** Russian, Ukrainian,
   Serbian, Bulgarian, Greek, and other scripts contain many characters
   that are "confusable" with Latin letters by design (shared Greek/
   Cyrillic ancestry with Latin). A Russian-language email body,
   subject, or display name folded through confusable mapping would
   have letters silently replaced with Latin look-alikes, destroying
   the actual text for a native reader and for any legitimate
   downstream use (e.g. the AI trying to understand what the email
   actually says).
2. **It would destroy the exact signal a security analyst needs.**
   Mixed-script substitution (a Cyrillic letter hiding inside an
   otherwise-Latin word) is itself the indicator of interest for
   impersonation detection. If this normalizer silently folded it away,
   the Domain analyzer (or a human reviewing evidence) would never see
   that the substitution happened at all — the exact opposite of
   "evidence preservation."
3. **It is a narrow, comparison-specific technique, not a general text
   operation.** Confusable/skeleton computation (per Unicode TR39) is
   meaningful when comparing one specific string against a **known
   reference** (e.g. "does this candidate domain label skeleton-match a
   protected brand name?"). It is not meaningful as a blanket
   transformation applied to arbitrary running text with no reference
   to compare against.

**Where this belongs instead:** the Domain analyzer (not yet
implemented, blocked on registry codes per current instruction) is the
correct owner of any confusable/skeleton comparison, and even there it
should be scoped strictly to comparing a candidate domain label against
the protected-brand dataset — never applied to reshape body text,
subject lines, or display names that a human or the LLM will read as
"the text of the email."

**What IS safe and is implemented:** NFKC folding of full-width/
half-width **compatibility variants of ASCII characters** (e.g.
fullwidth Latin letters, fullwidth digits, fullwidth punctuation). This
is meaningfully different from confusable folding:
- It only maps a character to its own explicitly-designated Unicode
  compatibility decomposition (a 1:1, script-owned relationship defined
  by the Unicode Standard itself), not a cross-script visual-similarity
  judgment.
- It does not touch native-script characters (kana, kanji, Cyrillic,
  Greek, Arabic, etc.) at all, unless that specific character itself
  has a compatibility decomposition (which the CJK/Cyrillic/Greek/
  Arabic *letters* generally do not — only some *ASCII-derived
  punctuation* commonly used alongside them does, e.g. fullwidth `？`).
  See the dedicated Japanese-text test case in
  `tests/test_evidence_normalizer.py` for a concrete demonstration of
  this exact boundary.

## Transformations implemented (v1)

1. **Zero-width / invisible character removal** — explicit curated
   codepoint set (soft hyphen, ZWSP/ZWNJ/ZWJ, word joiner, BOM/ZWNBSP,
   bidi embedding/override/isolate controls, LRM/RLM, Mongolian
   free-variation selectors, invisible math operators, Hangul/Khmer
   fillers, variation selectors VS1–VS16). See
   `config/normalization_policy_v1.py` for the full list with
   per-character comments.
2. **Unusual Unicode whitespace normalization** — explicit curated
   mapping (NBSP, various en/em/thin/hair spaces, ideographic space,
   Ogham space mark, narrow/medium math spaces → ASCII space; line/
   paragraph separators → `\n`). Standard ASCII whitespace is untouched.
3. **NFKC compatibility normalization** — applied via stdlib
   `unicodedata`, folding full-width/half-width forms and other
   Unicode-defined compatibility variants to their canonical form.

## Transformations deliberately NOT implemented (v1) and why

1. **Confusable/homoglyph skeleton folding of arbitrary text** — see
   dedicated section above. Belongs (if at all) to the Domain analyzer,
   scoped to domain-label comparison only.
2. **Case-folding / lowercasing** — not a "mechanical normalization"
   concern in the same sense as the above; case carries information
   (e.g. distinguishing acronyms) that shouldn't be silently erased at
   this layer. If a specific downstream semantic predicate needs
   case-insensitive comparison, it can lowercase its own inputs locally.
3. **Diacritic/accent stripping** (e.g. `é` → `e`) — semantically
   meaningful in normal multilingual text; stripping it would degrade
   legitimate content the same way confusable folding would, and NFKC
   deliberately does not do this either (NFKC ≠ NFKD-then-strip-marks).
4. **Any transformation of link hrefs/URLs** — see "out of scope"
   fields above; reserved for domain-specific IDNA/punycode logic in a
   future analyzer.
5. **Normalization of raw HTML markup** — see "out of scope" fields
   above; needs a dedicated visible-text-extraction step first.
6. **Dynamic Unicode-category-based invisible-character detection**
   (e.g. filtering by General Category `Cf` at runtime) — deliberately
   avoided in favor of an explicit, curated, versioned list, so behavior
   doesn't silently shift if the Python runtime's bundled Unicode
   Character Database version changes between environments. Extending
   the curated list requires an explicit policy version bump.

## Test coverage

`tests/test_evidence_normalizer.py` — 30 tests, all passing, covering:

- Zero-width character insertion (ZWSP between every letter, ZWJ/ZWNJ,
  BOM).
- Unusual Unicode whitespace (NBSP, ideographic space, line/paragraph
  separators, a mix of several space variants in one string).
- Full-width characters (fullwidth Latin letters, a fullwidth
  domain-like string, fullwidth digits).
- Benign multilingual text (Spanish with accents, Japanese, Russian,
  Arabic) — including the precise Japanese fullwidth-punctuation
  boundary case described above.
- Mixed-script text (Cyrillic `А` substituted into "Apple", Greek `Ο`
  substituted into "Official") — asserted to remain **byte-for-byte
  unchanged**, proving no confusable folding occurs.
- Obfuscated security/phishing-style text (a keyword split by zero-width
  joiners, a mixed fullwidth+zero-width case, bidi-override filename
  obfuscation).
- Text that should remain unchanged (plain ASCII, empty string).
- Preservation/traceability of the original text (verbatim
  `original_text`, event positions verified against the original
  string, policy version stamped, `CanonicalEmail` proven unmutated via
  deep-equality check before/after, `NormalizedEvidence` correctly
  carrying `source_artifact_id`/`source_canonical_email_id`, absent
  fields correctly not fabricated, display-name and attachment-filename
  coverage).

## Full test suite status

**71/71 passing** (`python3 -m pytest tests/ -v`):
- Pre-existing baseline (parser, parser-security, routing): 41/41,
  unchanged.
- New Evidence Normalizer tests: 30/30.

## Open items for the team

1. As with the routing analyzer, this module produces no qualification
   codes and needs none — it's purely mechanical. No registry
   dependency exists for this component specifically.
2. If/when a text-extraction-from-HTML capability is added (for the
   `body.html_sanitized` gap noted above), it should feed into this same
   normalizer rather than spawning a parallel normalization path.
3. If the Domain analyzer (once unblocked) implements confusable/
   skeleton comparison, it should import the curated datasets/approach
   independently — this module intentionally does not expose any
   confusable-folding primitive for it to reuse, to keep the two
   concerns (mechanical text normalization vs. domain-specific
   comparison) cleanly separated.
