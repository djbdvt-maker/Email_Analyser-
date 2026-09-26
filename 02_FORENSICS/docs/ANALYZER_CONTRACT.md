# Analyzer Contract & Routing/Hop-0 Notes

**Owner:** Email Forensics (Person 3)
**Status:** Updated post-review (fixes applied — see changelog at bottom).

## Analyzer output contract

Every analyzer takes a `CanonicalEmail` and returns an `AnalyzerOutput`:

```
AnalyzerOutput:
  analyzer_name: str
  analyzer_version: str
  facts: list[Fact]
  candidates: list[FindingCandidate]
```

```
Fact:
  fact_id: str
  category: str
  key: str
  state: SignalState        # present | absent | unavailable
  value: str | None
  produced_by: str            # "{analyzer_name}@{analyzer_version}"
  detail: str | None

FindingCandidate:
  category: str
  qualification_code: str        # MUST come from the locked vocabulary — never invented
  qualification_version: str
  strength: str                   # weak | moderate | strong — registered enum, NOT a number
  normalized_subject: str | None
  normalized_target: str | None
  claim_signature: str              # stable dedup key
  supporting_fact_ids: list[str]
  supporting_text: str | None
  produced_by: str
```

**Rules enforced by every analyzer in this module:**
- No scoring, no points, no severity, no verdict.
- No new qualification codes — only codes present in
  `qualification_vocab.py` (which itself is a locked subset pending the
  full architecture-owned registry file — see blockers below).
- **A signal that is `unavailable` is represented ONLY as a `Fact`. It
  never produces a `FindingCandidate` of any kind** — not even a
  placeholder/"indeterminate" one — because doing so would require a
  qualification code, and no code may be emitted unless it is confirmed
  in the locked registry. (This was corrected post-review: an earlier
  draft emitted a `CF-01:ORIGIN_INDETERMINATE` candidate for this case;
  that code was never confirmed and has been removed. See changelog.)
- Deterministic analyzers assign `strength` directly from the
  qualification's registered default — they don't compute it.

## ⚠️ Remaining registry blockers

A single machine-readable registry file for the full v1 vocabulary is
still not in the repo. `qualification_vocab.py` hard-codes **only** the
three codes explicitly validated for the routing analyzer:

- `CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE`
- `CF-06:INDEPENDENT_TRUSTED_CONTRADICTION`
- `CF-06:STRUCTURAL_IMPLAUSIBILITY`

**Blocked pending architecture-owned registry entries:**

1. **No confirmed code for "origin indeterminate."** No Received chain,
   or no trusted boundary at hop 0, is currently represented as a
   `Fact` only (`hop0_candidate_ip`, `state=unavailable`) with **no
   FindingCandidate**. If the architecture registry defines a real code
   for this condition, it should be added to `qualification_vocab.py`
   under that confirmed name — do not reintroduce speculatively.
2. **Authentication analyzer** — blocked on SPF/DKIM/DMARC-alignment
   qualification codes.
3. **Identity analyzer** — blocked on display-name/Reply-To/Return-Path
   mismatch and impersonation qualification codes.
4. **Domain analyzer** — blocked on Punycode/IDN/mixed-script/confusable
   and protected-brand qualification codes.
5. **Links analyzer** — blocked on domain-mismatch, shortener, auth-like
   path, and lookalike qualification codes.
6. **Attachments analyzer** — blocked on extension/MIME-mismatch,
   macro-presence, and archive-related qualification codes.
7. **Infrastructure analyzer** — blocked on whatever codes architecture
   defines for this category (not yet specified anywhere I've seen).

Per direction: fact extraction may proceed ahead of the registry landing
where useful (e.g. computing SPF/DKIM/DMARC pass/fail/none as Facts),
but candidate emission for these categories will not be written until
their codes are confirmed. **Next analyzers are not being built yet per
current instruction** — this list is for when that resumes.

## Routing / Hop-0 analyzer — behavior summary

**Terminology:** the analyzer never says "attacker IP." The result is
always **candidate probable-origin IP** — an inference from the trusted
portion of the chain, not an attribution claim.

**Algorithm:**
1. Walk `received_chain_raw` from index 0 (newest) toward older hops.
2. At each hop, check whether its `by` claim matches the v1
   trusted-receiver configuration (`config/trusted_receivers_v1.py`).
3. Continue while hops match; stop at the first hop that doesn't.
4. The **candidate probable-origin IP** is the observed IP from the
   `from`-clause of the **last trusted hop** (the boundary hop) — i.e.
   the IP that trusted infrastructure itself recorded as its sender,
   not a claim made by an untrusted party.
5. If no Received chain exists at all, or hop 0 itself isn't trusted,
   origin is **indeterminate** — represented as `SignalState.UNAVAILABLE`
   on the `hop0_candidate_ip` Fact, with **no FindingCandidate emitted**
   (see registry blockers above). This must never be interpreted as a
   clean/negative result — the distinction lives entirely in the Fact's
   `SignalState`, not in candidate presence/absence.

**v1 trusted-receiver config** (versioned, in
`config/trusted_receivers_v1.py`):
- Gmail: documented MX/relay hostname suffixes (`mx.google.com`,
  `google.com`, `gmail.com`) **plus** Gmail's internal final-delivery
  hextet token pattern (e.g. `2002:a05:6902:...`), matched via a strict
  hex/colon-only regex so it cannot be satisfied by an adversarial string.
- Microsoft 365: documented EOP/relay hostname suffixes
  (`protection.outlook.com`, `prod.outlook.com`, `outlook.com`).
- Deliberately small. Do not extend this list to make a specific test
  pass — extensions require a documented justification tied to a real,
  published provider pattern.

**Both extracted IPs (from `from`-clauses) and addresses (from
`From`/`To`/`Reply-To`/`Return-Path`) are validated before being
reported as `PRESENT`:**
- IPs are validated with Python's `ipaddress` module. An out-of-range
  IPv4-looking string (e.g. `999.999.999.999`) or malformed IPv6 is
  rejected — `observed_ip` is left `None` rather than passed through.
- Addresses without an `@` are reported as `SignalState.UNAVAILABLE`
  with `address=None`, not silently treated as a valid, present address.
  (Both of these were tightened post-review — see changelog.)

**CF-06 (routing fabrication) — only these three validated conditions,
per explicit team decision. Generic malformedness never auto-promotes:**

| Condition | What it detects | Where it applies |
|---|---|---|
| `TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE` | An older hop's timestamp is later than a newer hop's timestamp by more than a 5-minute tolerance, given the chain is walked newest→oldest. | Across the whole chain (any two adjacent timestamped hops), not just the trusted segment. |
| `STRUCTURAL_IMPLAUSIBILITY` | Within the **trusted boundary segment only**, an adjacent hop's `from`/`by` claim resolves to a **different trusted-provider family** (e.g. one hop is Google infra, the adjacent hop is Microsoft infra) — a genuine cross-provider identity break. | Trusted segment only (hops 0..boundary_index). |
| `INDEPENDENT_TRUSTED_CONTRADICTION` | An **untrusted, non-adjacent** hop's `from` claim exactly matches a `by` host that was independently recorded by a trusted hop elsewhere in the chain — i.e. it's trying to "borrow" a trusted identity out of position. | Untrusted hops beyond the boundary. |

**Deliberate calibration note (do not revert):** structural
implausibility compares *provider family*, not exact hostname string
equality, and this is intentional and must be kept. Real Gmail/M365
chains legitimately hand off between many differently-named internal
nodes of the *same* provider — exact-hostname comparison produced false
positives on a real M365 fixture during initial testing and was
corrected to compare provider family instead. Reverting to exact-hostname
equality would reintroduce that false-positive class.

**Generic malformedness** (e.g. a Received header that doesn't even
start with `from`/`by`) is recorded as a `Fact` (`hop_malformed`,
`state=unavailable`) only. It is explicitly asserted by unit test that
this never produces a CF-06 candidate on its own.

## Fixture coverage (`tests/fixtures/`)

| Fixture | Purpose |
|---|---|
| `legit_gmail_to_gmail.eml` | Real Gmail→Gmail multi-hop chain (including the internal hextet delivery hop) — must produce zero CF-06 candidates and a present Hop-0 IP. |
| `legit_m365.eml` | Real M365/EOP chain — must produce zero CF-06 candidates and a present Hop-0 IP. |
| `legit_forwarded_via_unknown_relay.eml` | **See exact hop-by-hop breakdown in the fixture's own `X-Fixture-Note` headers.** Hop 0 and Hop 1 are Google-trusted; Hop 2's `by` clause (`smtp-relay.corporate-forwarder.example`) does **not** match any v1 trusted pattern, so the boundary walk stops there. The candidate probable-origin IP is Hop 1's own from-claim IP (`209.85.220.52` — Google's own record of who it received from), **not** the untrusted relay's self-reported IP (`198.51.100.77`). This demonstrates the boundary correctly stopping mid-chain at an unrecognized *receiving* relay, as opposed to just an unverified sender claim. |
| `no_received_chain.eml` | No Received headers at all — Hop-0 Fact is `unavailable`, **no candidate emitted** (not "clean"). |
| `no_trusted_boundary_at_hop0.eml` | A Received chain exists, but hop 0's `by` claim matches no trusted pattern at all — distinct from the no-chain case. Also Fact-only, `unavailable`, no candidate. |
| `generic_malformed_header.eml` | One nonsense Received line alongside a legitimate one — must NOT produce CF-06. |
| `adversarial_temporal_contradiction.eml` | Triggers `TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE`. |
| `adversarial_structural_implausibility.eml` | Triggers `STRUCTURAL_IMPLAUSIBILITY` (cross-provider break: Google hop adjacent to a Microsoft-hostname hop within the trusted segment). |
| `adversarial_independent_trusted_contradiction.eml` | Triggers `INDEPENDENT_TRUSTED_CONTRADICTION`. |

## Parser security regression coverage (`tests/test_parser_security.py`)

23 tests covering: folded headers, duplicate headers (including
duplicate `Received`), malformed/`@`-less addresses, empty address
headers, malformed dates, out-of-range IPv4-looking values, valid/invalid
IPv6, RFC 2231 and RFC 2047 encoded attachment filenames, nested MIME
(`multipart/alternative` inside `multipart/mixed` plus a sibling
attachment), dangerous HTML (`<script>`, `onclick`, `<iframe>`,
`javascript:` hrefs — stripped/never executed, but hrefs preserved as
inert evidence data), malformed/mismatched MIME boundaries (must not
crash), non-UTF-8 body and header bytes (must not crash), and two
non-execution assertions: embedded prompt-injection-style body text is
extracted as inert text only (`CanonicalEmail` has no `verdict`/
`severity`/`score` attribute for such content to influence), and a
remote `<img src>` reference is captured as inert data, never fetched.

## Test results

**41/41 passing** (`python3 -m pytest tests/ -v`):
- `tests/test_parser.py` — 8
- `tests/test_parser_security.py` — 23
- `tests/test_routing_analyzer.py` — 10

## Changelog (post-review fixes)

1. Removed `CF-01:ORIGIN_INDETERMINATE` entirely — it was never
   confirmed against the architecture registry. No-chain / no-boundary
   cases now emit Facts only, never a candidate.
2. Clarified `CanonicalEmail.id` as a parse-instance handle, not a
   competing artifact identity; `artifact_id` remains the sole stable
   identity, backend-owned. Renamed the `parse_eml`/`parse_eml_file`
   optional id parameter from `email_id` to `parse_instance_id` to match.
3. Added 23 parser security/regression tests (see above); this surfaced
   and fixed two latent gaps: addresses without `@` were being reported
   as `PRESENT`/valid, and out-of-range/malformed IP-looking strings
   were being accepted as real IPs. Both now validate properly and
   report `UNAVAILABLE` when invalid.
4. Kept provider-family structural CF-06 logic unchanged (confirmed
   correct, not reverted).
5. Rebuilt `legit_forwarded_via_unknown_relay.eml` and its test: the
   previous version had no untrusted hop in the trust-boundary sense at
   all (the "unknown relay" only ever appeared as a sender claim, never
   as a `by` claim), and its docstring claimed an "indeterminate" result
   while the assertions actually checked for a present IP — an internal
   contradiction. The fixture now has a genuinely unrecognized `by`
   clause at hop 2, and the test/docs accurately describe the resulting
   boundary-stop behavior.
6. No new qualification codes introduced for Authentication / Identity /
   Domain / Links / Attachments / Infrastructure. Those analyzers are
   not yet implemented.

## Not yet implemented

Authentication → Identity → Domain → Links → Attachments →
Infrastructure — **on hold per current instruction**, pending the
registry blockers listed above.
