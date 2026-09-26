# ===========================================================================
# FAMILY G - ATTACHMENTS (7 cases, 41-47), STATIC ANALYSIS ONLY
# ===========================================================================

case("SEC-041", "Normal benign attachment", "G. Attachments",
     "Ordinary attachment (e.g. PDF, docx) with matching extension/MIME type, no double extension, no macro, no archive.",
     ["Must be reported as clean/no-anomaly at the attachment-analysis level.",
      "Negative control for the whole attachment family."],
     ["benign attachment - negative control"],
     [SRC_TASK_BRIEF, SRC_PHASE1("02_legit_m365")],
     notes="Corresponds to Phase 1 fixture 02's attachment.")

case("SEC-042", "Extension/MIME mismatch", "G. Attachments",
     "Attachment's file extension does not match its actual declared MIME type or magic-byte signature (statically inspectable), independent of any double-extension pattern.",
     ["Extension/MIME mismatch must be reported as a distinct static observation from the double-extension pattern (SEC-045).",
      "Static-only: inspects declared Content-Type and, where feasible, file signature/magic bytes without executing anything."],
     ["extension/declared-type mismatch, static only"],
     [SRC_TASK_BRIEF],
     notes="")

case("SEC-043", "Macro-enabled document", "G. Attachments",
     "Attachment is a macro-enabled document format (e.g. .docm/.xlsm) or an ordinary document format containing embedded macro content, detected via static structural inspection only (no macro execution).",
     ["Presence of macro-capable format/content must be reported as a distinct static observation.",
      "No macro execution, sandboxing, or dynamic analysis - detection must be purely structural/static, per the explicit constraint on this family."],
     ["macro-enabled document format, detected statically, never executed"],
     [SRC_TASK_BRIEF],
     notes="")

case("SEC-044", "Archive containing executable", "G. Attachments",
     "Attachment is a compressed archive (zip/rar/etc.) whose statically-inspectable directory listing shows an executable file inside, without extracting/running it.",
     ["Archive contents must be inspected only via static listing (e.g. central-directory metadata), never by extraction or execution.",
      "Presence of an executable inside an archive should be reported as a distinct, likely-elevated observation compared to a bare double-extension case (SEC-045)."],
     ["archive-contained executable, detected via static listing only, never extracted"],
     [SRC_TASK_BRIEF],
     notes="")

case("SEC-045", "Double/compound extension", "G. Attachments",
     "Filename uses a double/compound extension masking an executable as a document (e.g. Invoice.pdf.exe), matching Phase 1 fixture 06's pattern.",
     ["Double-extension pattern must be reported as a distinct, well-established static observation.",
      "As established in Phase 1: this alone is CF-04 Group 1; CF-04 also requires a Group 2 'qualifying sender/security-context anomaly' whose locked predicate is UNKNOWN to QA (open question carried over from Phase 1 fixture 06)."],
     ["double/compound extension masking an executable (CF-04 Group 1)"],
     [SRC_FLOOR_REVIEW, SRC_PHASE1("06_suspicious_attachment")],
     severity="CF-04 Group 1 present; overall floor status AMBIGUOUS pending Group 2 predicate (see Phase 1 open question)",
     notes="Directly reuses Phase 1 fixture 06 and its still-open CF-04 Group 2 question.",
     confirmation=("A",))

case("SEC-046", "Urgency/authority filename", "G. Attachments",
     "Attachment filename itself uses urgency/authority language (e.g. 'URGENT_Invoice_OVERDUE_FinalNotice.pdf') independent of the file's actual type/structure.",
     ["Filename-level social-engineering language should be reported as a distinct, weaker static observation from structural attachment anomalies (extension mismatch, macros, archives).",
      "Must not by itself be escalated to a confirmed-suspicious-attachment finding absent an actual structural anomaly."],
     ["urgency/authority language in filename text, a weak standalone signal"],
     [SRC_TASK_BRIEF],
     notes="")

case("SEC-047", "Truncated archive", "G. Attachments",
     "Attachment is an archive file whose structure is truncated/corrupted such that its directory listing cannot be fully read.",
     ["Must be represented as 'attachment contents unavailable/undetermined', not as 'clean' and not as 'confirmed malicious' (rule 7 applied to attachment evidence).",
      "No unbounded recursive extraction or decompression attempts, per the explicit constraint on this family - a truncated/corrupted archive must degrade gracefully to an unavailable state, not trigger unbounded processing."],
     ["truncated archive - contents unavailable, not clean, and not a decompression-bomb attempt"],
     [SRC_TASK_BRIEF, SRC_BRIEF],
     notes="Rule 7 (missing signals unavailable, not clean) applied specifically to the attachment-analysis category. Also implicitly tests the 'no unbounded recursive extraction' static-only constraint.")

# ===========================================================================
# FAMILY H - AUTHENTICATION (10 cases, 48-57)
# ===========================================================================

case("SEC-048", "SPF pass", "H. Authentication",
     "SPF check result is 'pass'.",
     ["SPF pass must be reported factually as pass.",
      "SPF pass must NOT be treated as general evidence of legitimacy/trustworthiness beyond the authentication category itself (authentication pass is not evidence of non-maliciousness at the brand/identity level, per the explicit warning) - see Phase 1 fixtures 04/05 where SPF pass co-occurs with a confirmed-malicious floor."],
     ["auth pass is not a general trust signal"],
     [SRC_TASK_BRIEF, SRC_PHASE1("05_lookalike_domain")],
     notes="")

case("SEC-049", "SPF fail", "H. Authentication",
     "SPF check result is 'fail'.",
     ["SPF fail must be reported factually as fail.",
      "SPF fail is an OBSERVATION; its severity interpretation belongs to the scoring/registry architecture, not to QA. Per the review: authentication alone (max 18 points) cannot independently produce High severity - SPF fail by itself, with no other independent category evidence, must not be assumed to reach High."],
     ["auth fail is an observation, not an automatic high-severity verdict"],
     [SRC_FLOOR_REVIEW, SRC_PHASE1("07_auth_failure")],
     severity="Cannot independently reach High severity from SPF fail alone",
     notes="Directly reflects the corrected Phase 1 fixture 07 finding.",
     confirmation=("A", "E"))

case("SEC-050", "SPF unavailable/none", "H. Authentication",
     "No SPF record/result is present at all (distinct from an explicit 'fail' or 'neutral' result).",
     ["Must be represented as 'unavailable', distinct from 'fail', 'neutral', and 'pass' - four distinct states, not collapsed.",
      "Unavailable must not be treated as clean (rule 7)."],
     ["SPF unavailable is a fourth distinct state, not folded into fail/neutral/pass"],
     [SRC_BRIEF],
     notes="")

case("SEC-051", "DKIM pass", "H. Authentication",
     "DKIM signature verification result is 'pass'.",
     ["DKIM pass reported factually.",
      "Same non-general-trust-signal caveat as SEC-048 applies."],
     ["auth pass is not a general trust signal (DKIM)"],
     [SRC_TASK_BRIEF],
     notes="")

case("SEC-052", "DKIM fail", "H. Authentication",
     "DKIM signature verification result is 'fail' (present but invalid, e.g. bad signature).",
     ["DKIM fail reported factually, distinct from DKIM absent/unsigned (SEC-053).",
      "Same 18-point-cap caveat as SEC-049 applies - cannot independently reach High from this alone."],
     ["DKIM fail (present but invalid) distinct from DKIM absent"],
     [SRC_FLOOR_REVIEW],
     severity="Cannot independently reach High severity from DKIM fail alone",
     confirmation=("A", "E"),
     notes="")

case("SEC-053", "DKIM unavailable/none", "H. Authentication",
     "Message is entirely unsigned - no DKIM-Signature header present at all.",
     ["Must be represented as 'unavailable/unsigned', distinct from 'fail' (SEC-052) - an invalid signature is a different fact from no signature at all.",
      "Unavailable must not be treated as clean (rule 7)."],
     ["DKIM unsigned is a distinct state from DKIM invalid"],
     [SRC_BRIEF, SRC_PHASE1("03_credential_phishing")],
     notes="Phase 1 fixture 03 is a concrete instance (dkim=none, message not signed).")

case("SEC-054", "DMARC pass", "H. Authentication",
     "DMARC evaluation result is 'pass'.",
     ["DMARC pass reported factually.",
      "Same non-general-trust-signal caveat applies."],
     ["auth pass is not a general trust signal (DMARC)"],
     [SRC_TASK_BRIEF],
     notes="")

case("SEC-055", "DMARC fail", "H. Authentication",
     "DMARC evaluation result is 'fail', independent of policy strength (p=none/quarantine/reject).",
     ["DMARC fail reported factually, WITH its policy value preserved (p=none vs p=quarantine vs p=reject are materially different facts, not collapsed into one 'fail' state).",
      "Same 18-point-cap caveat applies - fail alone does not guarantee High."],
     ["DMARC fail with policy value preserved as a distinct sub-fact"],
     [SRC_FLOOR_REVIEW, SRC_PHASE1("07_auth_failure")],
     severity="Cannot independently reach High severity from DMARC fail alone, regardless of policy value",
     notes="Phase 1 fixture 07 specifically used p=reject to test whether policy strength alone elevates severity - per the correction, it does not, absent a separately-confirmed floor.",
     confirmation=("A", "E"))

case("SEC-056", "DMARC unavailable/none result", "H. Authentication",
     "No DMARC record exists for the domain / no DMARC evaluation could be performed (distinct from an explicit dmarc=fail or dmarc=none-as-policy-result - see notes).",
     ["Must distinguish 'no DMARC record exists at all' (truly unavailable) from 'DMARC record exists with p=none policy, evaluated, result token literally none' (Phase 1 fixture 04's case) - these are different facts that both surface a 'none'-shaped token but mean different things.",
      "Whichever state applies must not be silently treated as clean."],
     ["true DMARC unavailability vs. an explicit p=none policy evaluation result - a naming/parsing ambiguity worth testing explicitly"],
     [SRC_BRIEF, SRC_PHASE1("04_bec_ceo_impersonation")],
     notes="Raised because Phase 1 fixture 04 already surfaced exactly this ambiguity during the correction pass (see that fixture's expected-result notes).")

case("SEC-057", "Identifier alignment failure", "H. Authentication",
     "SPF and/or DKIM individually pass, but DMARC identifier alignment fails (the authenticated domain does not match the visible From domain) - a distinct sub-case from a bare DMARC pass/fail token.",
     ["Alignment failure must be reported as its own distinct fact, separate from the underlying SPF/DKIM pass/fail results.",
      "This is the exact mechanism by which Phase 1 fixture 04's pattern works (SPF/DKIM pass for the SENDING domain, but that domain is not the claimed executive's organization) - stated here explicitly as its own authentication-category case rather than only implicit in the BEC family."],
     ["alignment failure as a distinct fact from raw SPF/DKIM pass/fail"],
     [SRC_BRIEF, SRC_PHASE1("04_bec_ceo_impersonation")],
     notes="")

# ===========================================================================
# FAMILY I - INFRASTRUCTURE (5 cases, 58-62)
# ===========================================================================
# Per instruction: do not invent additional infrastructure qualifications
# beyond what the architecture already defines. QA does not have the exact
# list of confirmed infrastructure qualification concepts beyond what is
# named in the task brief itself (known-bad ASN, bulletproof hosting,
# unresolvable rDNS, newly-observed infrastructure, ordinary legitimate
# infrastructure) - those five names come directly from the task brief and
# are used here at the concept level only; no code is invented.

case("SEC-058", "Known-bad ASN", "I. Infrastructure",
     "Candidate probable-origin IP belongs to an Autonomous System (ASN) present on a locally-maintained known-bad list.",
     ["Must be reported as a distinct infrastructure-category observation.",
      "Consistent with rule 8 (external threat-intel optional, never required for MVP): assumes a LOCAL/offline-maintained ASN reputation list, not a live external lookup.",
      "Whether this alone satisfies CF-05 ('exact confirmed malicious indicator') or is a weaker supporting signal is UNKNOWN to QA - not assumed."],
     ["known-bad ASN match against a local list"],
     [SRC_TASK_BRIEF, SRC_BRIEF],
     notes="")

case("SEC-059", "Bulletproof-hosting match", "I. Infrastructure",
     "Candidate probable-origin IP/netblock matches a locally-maintained list of infrastructure known for hosting abuse-tolerant ('bulletproof') services.",
     ["Must be reported as a distinct infrastructure-category observation, separate from SEC-058 (ASN-level) even though related in spirit.",
      "Same local-list, MVP-appropriate framing as SEC-058."],
     ["bulletproof-hosting match against a local list, distinct from ASN-level matching"],
     [SRC_TASK_BRIEF, SRC_BRIEF],
     notes="")

case("SEC-060", "Unresolvable reverse DNS", "I. Infrastructure",
     "Candidate probable-origin IP has no resolvable reverse-DNS (PTR) record.",
     ["Must be represented as 'unresolvable/unavailable', not as 'clean' and not as 'confirmed malicious' - rule 7 applied to infrastructure evidence.",
      "Many legitimate mail servers also lack clean rDNS in some configurations - must not be treated as a strong standalone signal without corroboration."],
     ["unresolvable rDNS is an unavailable-state observation, not a confirmed-bad signal by itself"],
     [SRC_TASK_BRIEF, SRC_BRIEF],
     notes="")

case("SEC-061", "Newly observed infrastructure", "I. Infrastructure",
     "Candidate probable-origin IP/netblock has no prior observation history in the system (first time seen), assuming a local observation-history store rather than any external service.",
     ["'Newly observed' is a distinct historical/temporal fact, separate from reputation-list matching (SEC-058/059) and separate from rDNS resolvability (SEC-060).",
      "Must not be treated as inherently malicious - legitimate new infrastructure is observed for the first time constantly."],
     ["newly-observed infrastructure is a distinct, weak, non-malicious-by-default signal"],
     [SRC_TASK_BRIEF, SRC_BRIEF],
     notes="Relates to rule 10 (preserve history; derive current state) - 'newly observed' only has meaning relative to the system's own accumulated history.")

case("SEC-062", "Ordinary legitimate infrastructure", "I. Infrastructure",
     "Candidate probable-origin IP belongs to well-established, widely-recognized legitimate mail infrastructure (e.g. a major ESP's known outbound ranges).",
     ["Negative control for the whole infrastructure family - no infrastructure-level finding should be generated.",
      "Recognized-legitimate infrastructure status must still be represented as 'candidate probable-origin', per rule 6, never as a positive trust assertion about the message's overall legitimacy on its own."],
     ["ordinary legitimate infrastructure - negative control"],
     [SRC_TASK_BRIEF, SRC_BRIEF, SRC_PHASE1("01_legit_gmail")],
     notes="")
