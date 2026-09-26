# ===========================================================================
# FAMILY C - IDENTITY / IMPERSONATION (6 cases, 15-20)
# ===========================================================================

case("SEC-015", "Display-name mismatch", "C. Identity/Impersonation",
     "From display name claims one identity (e.g. a known contact's name) while the underlying email address belongs to an unrelated/unknown domain, with no further corroborating anomaly.",
     ["A display-name mismatch alone is EXPLICITLY confirmed as insufficient to satisfy CF-03's 'qualifying identity anomaly' condition (per the architecture review: 'a generic display-name mismatch alone is not sufficient').",
      "The observation itself (mismatch exists) should still be reported as a deterministic finding at the concept level.",
      "Must not, by itself, guarantee any CF-0x floor."],
     ["display-name/address mismatch, by itself insufficient for CF-03"],
     [SRC_FLOOR_REVIEW, SRC_TASK_BRIEF],
     severity="Explicitly NOT sufficient alone to guarantee CF-03 minimum-High",
     notes="This is a confirmed NEGATIVE case - useful as a boundary test against over-triggering.",
     confirmation=("A", "E"))

case("SEC-016", "Reply-To mismatch", "C. Identity/Impersonation",
     "Reply-To header points to a domain/address different from the From address, with no other anomaly present.",
     ["Reply-To/From mismatch should be reported as a deterministic identity-consistency observation.",
      "Whether this qualifies toward any locked floor's second-condition predicate (e.g. CF-03's identity anomaly) is UNKNOWN to QA and not assumed."],
     ["Reply-To/From inconsistency as a standalone observation"],
     [SRC_BRIEF, SRC_TASK_BRIEF],
     notes="Legitimate mailing lists and some legitimate business tools also produce Reply-To/From differences - this case does not assume malicious intent.")

case("SEC-017", "Return-Path mismatch", "C. Identity/Impersonation",
     "Return-Path (envelope sender) domain differs from the visible From domain, with no other anomaly present.",
     ["Return-Path/From mismatch should be reported as a deterministic identity-consistency observation, distinct from Reply-To/From mismatch (SEC-016).",
      "Whether this alone qualifies toward any locked floor predicate is UNKNOWN to QA."],
     ["Return-Path/From inconsistency as a standalone observation, distinct from Reply-To mismatch"],
     [SRC_BRIEF, SRC_TASK_BRIEF],
     notes="Also common in legitimate bulk-mail/ESP setups (SPF alignment can differ from visible From) - not assumed malicious by itself.")

case("SEC-018", "Executive impersonation", "C. Identity/Impersonation",
     "Display name and/or body content claims to be a specific executive (e.g. CEO/CFO) of the recipient's organization, sent from an address that does not belong to that organization, with NO financial/payment request present.",
     ["This satisfies CF-02 Group 1 (executive identity claim) alone. CF-02 requires BOTH Group 1 AND Group 2 (financial/payment request) - Group 2 is absent here, so CF-02 must NOT trigger from this case alone.",
      "The executive-identity-claim observation itself should still be reported as a finding."],
     ["executive identity claim present, financial-request group absent"],
     [SRC_FLOOR_REVIEW],
     severity="CF-02 explicitly NOT met (Group 2 absent)",
     notes="Direct negative-control pair with SEC-022 (both groups present) and identical in spirit to SEC-020 below - see SEC-020 for the version drawn directly from the task brief's numbered list.",
     confirmation=("A", "E"))

case("SEC-019", "Multiple mutually reinforcing identity anomalies", "C. Identity/Impersonation",
     "A single email exhibits several independent identity-consistency issues at once (e.g. display-name mismatch + Reply-To mismatch + Return-Path mismatch + domain freshly registered), none individually confirmed sufficient for a locked floor, but co-occurring.",
     ["Tests whether/how multiple independently-weak identity signals combine.",
      "Per the corpus's contradiction/aggregation principles (section 6 of the task brief): dedup must preserve independently earned strength; the corpus does not assume that combining multiple weak signals automatically equals one strong CF-03-qualifying signal - that combination rule is scoring-architecture-owned and UNKNOWN to QA.",
      "Whether the CF-03 'qualifying identity anomaly' locked predicate can be satisfied BY a combination of otherwise-individually-insufficient signals, or requires one specific single anomaly type, is an OPEN QUESTION."],
     ["multiple weak identity signals co-occurring", "combination rule is scoring-owned and unconfirmed"],
     [SRC_TASK_BRIEF, SRC_FLOOR_REVIEW],
     notes="Flagged open question: does the CF-03 'qualifying identity anomaly' predicate accept an aggregate of weak signals, or only a specific single strong one?")

case("SEC-020", "Executive impersonation without financial request", "C. Identity/Impersonation",
     "Same shape as SEC-018 - executive identity claim from an unrelated domain, but the email's purpose is something else entirely (e.g. asking for a document, praising work, scheduling), with explicitly no financial/payment ask.",
     ["CF-02 Group 1 present, Group 2 explicitly absent -> CF-02 must NOT trigger.",
      "Must be distinguishable in the expected result from SEC-022 (both groups present) and from SEC-004/SEC-002-style ordinary urgency cases."],
     ["executive identity claim without financial request - CF-02 Group 2 explicitly absent"],
     [SRC_FLOOR_REVIEW, SRC_TASK_BRIEF],
     severity="CF-02 explicitly NOT met (Group 2 absent)",
     notes="Listed explicitly by number in the task brief (item 20) as distinct from SEC-018 - kept as a separate case for direct traceability to the brief's numbering, even though behaviorally identical to SEC-018 as specified to QA.",
     confirmation=("A", "E"))

# ===========================================================================
# FAMILY D - BEC / CONTENT (7 cases, 21-27)
# ===========================================================================

case("SEC-021", "Explicit payment/transfer request", "D. BEC/Content",
     "Body explicitly requests a payment, wire transfer, or gift-card purchase, WITHOUT an accompanying executive-identity claim (e.g. from a generic 'vendor' or 'accounting' persona).",
     ["This is CF-02 Group 2 alone (financial/payment request) without Group 1 (executive identity claim) - CF-02 requires BOTH, so it must NOT trigger from this alone.",
      "The financial-request observation itself should still be reported as a content/BEC-relevant finding."],
     ["financial/payment request present, executive-identity-claim group absent"],
     [SRC_FLOOR_REVIEW],
     severity="CF-02 explicitly NOT met (Group 1 absent)",
     notes="Negative-control counterpart to SEC-018/SEC-020 (Group 1 present, Group 2 absent).",
     confirmation=("A", "E"))

case("SEC-022", "Executive impersonation + financial request", "D. BEC/Content",
     "Both CF-02 groups present: executive-identity claim AND a financial/payment request in the same email.",
     ["CF-02 Group 1 AND Group 2 both present -> CF-02 confirmed to trigger -> minimum High severity, per the locked floor definition.",
      "Authentication passing for the sending domain (if applicable) must NOT suppress this finding - auth and identity/content evidence are separate categories."],
     ["executive identity claim + financial request (CF-02, both groups present)"],
     [SRC_FLOOR_REVIEW, SRC_PHASE1("04_bec_ceo_impersonation")],
     severity="minimum High (CF-02 confirmed)",
     notes="Directly corresponds to Phase 1 fixture 04, restated here as the canonical positive CF-02 case in the security-evaluation corpus.",
     confirmation=("A", "E"))

case("SEC-023", "Urgency without malicious intent", "D. BEC/Content",
     "Body conveys genuine time pressure but contains neither a financial/payment request nor an identity claim (see SEC-002 for the paired baseline fixture).",
     ["Urgency alone, without either CF-02 group present, must not trigger CF-02 or any other floor.",
      "Must not be scored higher purely for tone/urgency language."],
     ["urgency alone is not a floor-qualifying signal"],
     [SRC_FLOOR_REVIEW, SRC_PHASE1("08_legit_urgent_business")],
     severity="No floor triggered from urgency alone",
     notes="Behaviorally identical in spirit to SEC-002 - kept separate for direct traceability to the task brief's family-D numbering.",
     confirmation=("A", "E"))

case("SEC-024", "Authority/secrecy language without financial request", "D. BEC/Content",
     "Body invokes authority and/or requests secrecy/bypassing normal process (classic BEC social-engineering markers) but does NOT contain an explicit financial/payment request.",
     ["Neither CF-02 group is unambiguously both present (Group 2 specifically requires a financial/payment request, which is absent here) - CF-02 should NOT be assumed to trigger from authority/secrecy language alone.",
      "The authority/secrecy language itself should still be reported as a content-level observation, since it may be relevant to a different, currently-unconfirmed qualification concept.",
      "Whether authority/secrecy language alone maps to ANY confirmed floor is UNKNOWN - not assumed either way."],
     ["authority/secrecy social-engineering markers without a financial ask"],
     [SRC_TASK_BRIEF, SRC_FLOOR_REVIEW],
     notes="Important boundary case: distinguishes 'classic BEC tone' from the specific CF-02 predicate, which requires an actual financial/payment request, not just manipulative tone.")

case("SEC-025", "Legitimate discussion ABOUT financial requests", "D. BEC/Content",
     "Body discusses the topic of a financial/payment request in a meta sense (e.g. 'FYI, finance flagged a wire-transfer scam attempt last week, be careful') without the email itself making any request of the recipient.",
     ["The email must NOT be treated as itself making a financial request merely because the words 'wire transfer' or similar appear.",
      "Tests that content analysis distinguishes an email ABOUT a financial-request topic from an email THAT IS a financial request.",
      "H2-adjacent: this is the semantic-context-matters class of case, related to family J's H2a concern (grounded text whose surrounding context reverses meaning), applied here at the deterministic/content-analysis level rather than the AI-validator level."],
     ["email discussing a topic is not the same as an email making that request - context must be evaluated, not keyword-matched"],
     [SRC_TASK_BRIEF],
     notes="Flagged by the task brief as 'especially important for H2 validity testing' alongside SEC-026 and SEC-027.")

case("SEC-026", "Conditional discussion that mentions financial transfer", "D. BEC/Content",
     "Body mentions a financial transfer only inside a conditional/hypothetical framing (e.g. 'if the board approves the transfer next quarter, I'll send details then') - no request is being made now.",
     ["Must not be treated as an active/current financial request.",
      "Tests that conditional/future-tense framing is not conflated with an immediate actionable request."],
     ["conditional/hypothetical mention of a financial transfer is not an active request"],
     [SRC_TASK_BRIEF],
     notes="Same H2-validity importance as SEC-025/SEC-027, per the task brief.")

case("SEC-027", "Quoted text containing a financial request but not making one", "D. BEC/Content",
     "Body quotes/forwards a prior email that itself contained a financial request (e.g. '>> Please wire $5,000 to...' inside a quoted reply chain), while the current sender's own message is only commentary (e.g. 'See below, does this look legit to you?').",
     ["The CURRENT message's own claim/request must be evaluated separately from quoted/forwarded content.",
      "A finding attributed to the current sender must not be generated purely from text that is grounded in a QUOTED prior message rather than the sender's own words.",
      "This is the clearest test of grounding discipline: text that exists in the raw email (in the quoted block) but does not represent the current sender's own assertion."],
     ["quoted/forwarded content must not be misattributed as the current sender's own claim"],
     [SRC_TASK_BRIEF],
     notes="Explicitly flagged by the task brief as important for H2 validity testing; also directly relevant to family J's grounding-vs-attribution distinction.")

# ===========================================================================
# FAMILY E - LINKS (7 cases, 28-34), STATIC ANALYSIS ONLY
# ===========================================================================

case("SEC-028", "Display text differs from href", "E. Links",
     "Anchor text shows one URL/domain (e.g. 'https://paypal.com/login') while the actual href target is a different domain, evaluated via static parsing only (no fetching).",
     ["Display-text/href mismatch must be reported as a deterministic, statically-derivable finding.",
      "Must not require fetching or resolving the URL - static text comparison only."],
     ["display-text-vs-href mismatch, static only"],
     [SRC_TASK_BRIEF],
     notes="")

case("SEC-029", "Brand claim pointing to unrelated domain", "E. Links",
     "Anchor text or surrounding body text names a specific brand (e.g. 'Click here to verify your Microsoft account') while the href target domain has no relationship to that brand.",
     ["Brand-name claim + unrelated href target domain must be reported as a distinct, stronger signal than a generic display/href mismatch (SEC-028) - a brand is being explicitly invoked.",
      "Whether this satisfies any CF-0x locked predicate on its own (it resembles CF-01's 'explicit claim representing that protected brand' Group 2, but CF-01's Group 1 is specifically about the SENDER domain being a lookalike, not the link target) is UNKNOWN and not assumed."],
     ["explicit brand claim + unrelated link target"],
     [SRC_TASK_BRIEF, SRC_FLOOR_REVIEW],
     notes="Flagged ambiguity: CF-01 as defined pairs a lookalike SENDER domain with a brand claim; whether an analogous link-level pairing (brand claim + unrelated/lookalike LINK domain) falls under CF-01, under CF-03, or under neither, is unresolved.")

case("SEC-030", "URL shortener", "E. Links",
     "Link uses a known URL-shortener domain (e.g. bit.ly-style), obscuring the true destination from static inspection alone.",
     ["Must be reported as a distinct 'destination obscured by shortener' observation - a DIFFERENT concept from 'malicious destination confirmed', since static analysis alone cannot resolve the true target.",
      "Must not be escalated to a confirmed-malicious finding (CF-05 requires an EXACT confirmed malicious indicator) purely because a shortener is present - a shortener obscures, it does not by itself confirm."],
     ["obscured destination is a distinct, weaker observation than a confirmed-malicious link"],
     [SRC_TASK_BRIEF, SRC_FLOOR_REVIEW],
     notes="Static-only constraint means the corpus cannot test actual shortener-resolution behavior - only the 'obscured, not confirmed' distinction.")

case("SEC-031", "Authentication-like path on unrelated domain", "E. Links",
     "URL path contains authentication-suggestive segments (e.g. '/login', '/verify-account', '/secure/session') on a domain unrelated to any brand claimed in the email.",
     ["Path semantics ('looks like a login flow') should be reported as a distinct static-content observation from domain-level findings.",
      "Must not be conflated with a confirmed credential-phishing-link finding (CF-03) without the CF-03 'qualifying identity anomaly' second condition also being satisfied."],
     ["login-like path semantics as a standalone static observation"],
     [SRC_TASK_BRIEF, SRC_FLOOR_REVIEW],
     notes="")

case("SEC-032", "Qualified protected-brand lookalike link", "E. Links",
     "Href target domain is itself a character-substitution/typosquat lookalike of a protected brand (distinct from SEC-029, where the link target was merely unrelated, not a lookalike), combined with an explicit brand claim in the surrounding text.",
     ["Structurally resembles CF-01's two-group pattern (lookalike + explicit brand claim), but applied to the LINK domain rather than the SENDER domain.",
      "Whether CF-01 as locked is scoped to sender-domain-only or also covers link-domain lookalikes is an OPEN QUESTION - not assumed either way.",
      "The lookalike-domain observation itself (distance/substitution pattern) should be reported regardless of the floor-scope question."],
     ["link-domain lookalike + explicit brand claim - CF-01 scope to link domains is unconfirmed"],
     [SRC_FLOOR_REVIEW, SRC_TASK_BRIEF],
     notes="Same open question as SEC-029/SEC-036 - flagged once here as the clearest instance, referenced from the other two.")

case("SEC-033", "Exact offline malicious blocklist match", "E. Links",
     "Href target domain/URL exactly matches an entry in a LOCAL, offline-maintained known-malicious indicator list (no live external threat-intel lookup - consistent with rule 8's local-first requirement).",
     ["An exact match against a maintained local indicator list is the clearest fit for CF-05 ('exact confirmed malicious indicator') -> minimum High severity.",
      "Must be clearly distinguished from heuristic/pattern-based suspicion (e.g. SEC-030's shortener case, SEC-031's login-path case) - CF-05 requires an EXACT, CONFIRMED match, not a resemblance."],
     ["exact local-blocklist match (CF-05 pattern)"],
     [SRC_FLOOR_REVIEW, SRC_BRIEF],
     severity="minimum High (IF an exact local-list match is confirmed - the existence/contents of such a list are outside QA's scope)",
     notes="Rule 8 requires external threat-intel to be OPTIONAL, never required for MVP - this case assumes a local/offline list only, consistent with that constraint.",
     confirmation=("A", "E"))

case("SEC-034", "Benign link whose display text and target legitimately differ in presentation", "E. Links",
     "Legitimate case where display text and href differ for an ordinary, non-deceptive reason (e.g. tracking-pixel redirect used by a legitimate ESP, a link-shortening service used by the sender's own legitimate marketing platform, display text is a friendly label like 'View invoice' rather than the raw URL).",
     ["Must NOT be treated identically to SEC-028 (deceptive display/href mismatch) - the negative control specifically distinguishes 'friendly label, benign redirect infrastructure' from 'deceptive mismatch'.",
      "Tests that the display/href-mismatch detector does not produce a false positive on ordinary legitimate email-marketing/ESP redirect patterns."],
     ["benign, ordinary display/href difference vs. deceptive mismatch (negative control for SEC-028)"],
     [SRC_TASK_BRIEF],
     notes="Explicitly listed by the task brief (item 34) as a benign case within family E - the negative control for SEC-028/SEC-029.")

# ===========================================================================
# FAMILY F - DOMAIN / LOOKALIKE (6 cases, 35-40)
# ===========================================================================

case("SEC-035", "Exact legitimate protected domain", "F. Domain/Lookalike",
     "Sender/link domain is an EXACT match to a known, legitimate protected-brand domain (e.g. the real microsoft.com).",
     ["Exact match to a known-legitimate domain must not trigger any lookalike finding.",
      "Negative control for the entire domain/lookalike family."],
     ["exact legitimate domain match - negative control"],
     [SRC_TASK_BRIEF],
     notes="")

case("SEC-036", "Protected-brand lookalike (domain only, no accompanying brand claim in body)", "F. Domain/Lookalike",
     "Sender domain is a character-substitution/typosquat lookalike of a protected brand, but the email body/display-name makes NO explicit claim to represent that brand (e.g. sender domain is 'micros0ft-billing.net' but the email is signed generically, 'The Team', with no explicit Microsoft brand claim).",
     ["CF-01 Group 1 (lookalike domain) present; Group 2 (explicit brand claim) explicitly absent here -> CF-01 must NOT be assumed to trigger from the domain alone.",
      "The lookalike-domain observation itself should still be reported as a finding, distinct from the CF-01 floor question."],
     ["domain-level lookalike without an accompanying explicit brand claim - CF-01 Group 2 absent"],
     [SRC_FLOOR_REVIEW],
     severity="CF-01 explicitly NOT met on domain evidence alone (Group 2 absent)",
     notes="Important negative-control pair with Phase 1 fixtures 03/05, where BOTH groups were present.",
     confirmation=("A", "E"))

case("SEC-037", "Punycode/IDN domain", "F. Domain/Lookalike",
     "Sender/link domain uses Punycode (xn--) encoding representing an internationalized domain name, which may render visually similar to a protected-brand domain in some mail clients.",
     ["Punycode presence itself should be reported as a distinct observation from a confirmed visual lookalike.",
      "Whether the decoded IDN form is confusable with a specific protected brand should be evaluated via domain-specific confusable/skeleton comparison, consistent with the task brief's explicit rule that this comparison is domain-scoped."],
     ["punycode/IDN domain as a distinct static observation, subject to domain-scoped confusable analysis"],
     [SRC_TASK_BRIEF],
     notes="")

case("SEC-038", "Mixed-script domain", "F. Domain/Lookalike",
     "Domain mixes characters from multiple Unicode scripts (e.g. Latin + Cyrillic look-alike characters) within a single label, a classic confusable-domain technique.",
     ["Mixed-script composition within a domain label should be reported as a distinct static observation.",
      "Confusable/skeleton comparison applies here (domain-specific, per the task brief), not to body text."],
     ["mixed-script domain label as a distinct confusability signal"],
     [SRC_TASK_BRIEF],
     evasion_class="mixed-script domain")

case("SEC-039", "Generic similar-looking domain with no explicit brand claim", "F. Domain/Lookalike",
     "Domain is generically similar in style/naming convention to a category of business (e.g. 'secure-billing-notice.com') but is NOT a lookalike of any SPECIFIC identifiable protected brand, and no explicit brand claim is made.",
     ["Must be distinguished from a qualified protected-brand lookalike (SEC-036, Phase 1 fixtures 03/05) - this is generic 'sounds official' naming, not typosquatting a specific brand.",
      "Must not trigger CF-01, which requires a QUALIFIED lookalike of an actual protected brand, not a generic impression."],
     ["generic 'official-sounding' domain naming is distinct from a qualified brand-specific lookalike"],
     [SRC_FLOOR_REVIEW, SRC_PHASE1("06_suspicious_attachment")],
     severity="CF-01 not met - no specific protected brand being impersonated",
     notes="Phase 1 fixture 06's sender domain (vendorbilling-group.net) is a real-world instance of this pattern - reused here as the reference example.",
     confirmation=("A", "E"))

case("SEC-040", "Legitimate non-Latin domain", "F. Domain/Lookalike",
     "Entirely legitimate business domain that happens to use a non-Latin script natively (not an IDN spoofing attempt, not mixed-script confusables - a genuinely non-English-market legitimate business).",
     ["Must not be treated as suspicious purely for using a non-Latin script.",
      "Negative control distinguishing SEC-037/SEC-038 (spoofing techniques) from ordinary legitimate non-Latin-script business domains."],
     ["non-Latin script alone is not a security signal - negative control for SEC-037/038"],
     [SRC_TASK_BRIEF],
     notes="Directly parallels SEC-005 (legitimate multilingual email) at the domain level.")
