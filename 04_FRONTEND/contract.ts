/**
 * HopZero — Frontend API Contract (MVP)
 * STATUS: FROZEN — approved by team review. Change only on a concrete
 * contract conflict discovered during implementation, not on preference.
 *
 * The frontend's view of backend-provided data. Nothing here is computed
 * or derived client-side: analysis results, status, and explanations are
 * read-only fields the frontend renders, never calculates.
 *
 * Investigation and AnalysisRun are separate lifecycles — an Investigation
 * can exist with no completed analysis yet, and analysis results only
 * appear once a run reaches COMPLETED. A missing/failed run must never be
 * treated as a clean result (shared rule 7).
 */

// ============================================================
// Shared primitives
// ============================================================

export type SHA256Hex = string; // 64 hex chars

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'low' | 'medium' | 'high' | 'critical' | 'clean';

/**
 * Authoritative backend verdict vocabulary (Phase 7 locked specification):
 * Exactly: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'INDETERMINATE'
 */
export type Verdict = 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'INDETERMINATE' | string;

/** Categorical only, never numeric (contract correction round 1, #4). */
export type ConfidenceLevel = 'verified' | 'unverified' | 'low_confidence' | 'indeterminate';

export type AuthResult = 'pass' | 'fail' | 'neutral' | 'unavailable';

/**
 * Locked Investigation status enum (contract correction round 2, #2) — use
 * exactly these seven values. REOPENED is deliberately absent: reopen is
 * an action (see AnalystActionType), not a lifecycle status. If the UI
 * needs to show "this was reopened", read it from analystActions /
 * auditTrail history — never invent an eighth status value.
 */
export type InvestigationStatus =
  | 'AWAITING_ANALYSIS'
  | 'UNDER_REVIEW'
  | 'CONFIRMED'
  | 'FALSE_POSITIVE'
  | 'ESCALATED'
  | 'CLOSED';

/**
 * AnalysisRun lifecycle — separate from InvestigationStatus above (contract
 * correction round 2, #1).
 */
export type AnalysisRunStatus =
  | 'QUEUED'
  | 'PARSING'
  | 'ANALYZING'
  | 'SCORING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

// ============================================================
// Upload
// ============================================================

export interface UploadResult {
  investigationId: string;
  filename: string;
  fileSizeBytes: number;
  /** Returned by the backend after ingestion — never computed client-side. */
  sha256: SHA256Hex;
  // Upload completion is ingestion only, not analysis completion (contract
  // correction round 2, #6). The UI navigates to the investigation detail
  // page and polls it until the current run reaches a terminal status.
}

// ============================================================
// Investigation list
// ============================================================

export interface InvestigationSummary {
  investigationId: string;
  createdAt: string; // ISO 8601
  status: InvestigationStatus;
  /** Mirrors the current run's status so the list can show "Analyzing…" without fetching full detail. */
  currentRunStatus: AnalysisRunStatus;
  /** Null until the current run is COMPLETED. Never render as 0/clean. */
  score: number | null;
  severity: Severity | null;
  verdict: Verdict | null;
  lastAnalysisAt: string | null; // ISO 8601
}

// ============================================================
// Routing / Hop-0
// ============================================================

export interface RoutingHop {
  hopIndex: number;
  receivingServer: string | null;
  observedIp: string | null;
  timestamp: string | null; // ISO 8601
  trustStatus: 'trusted' | 'untrusted' | 'unknown';
}

export interface RoutingInfo {
  hops: RoutingHop[];
  /** Candidate probable-origin only — never labeled "attacker IP" (rule 6). */
  candidateProbableOriginIp: string | null;
  candidateOriginConfidence: ConfidenceLevel;
  anomalies: string[];
}

// ============================================================
// Authentication
// ============================================================

export interface AuthCheck {
  result: AuthResult;
  /** Backend-authored — never generated in the UI. */
  explanation: string;
  technicalDetails: string;
}

export interface AuthenticationInfo {
  spf: AuthCheck;
  dkim: AuthCheck;
  dmarc: AuthCheck;
  alignment: AuthCheck;
}

// ============================================================
// Identity
// ============================================================

export interface IdentityInfo {
  from: string;
  displayName: string | null;
  replyTo: string | null;
  returnPath: string | null;
  mismatches: string[];
  impersonationEvidence: string[];
}

// ============================================================
// Domain
// ============================================================

export interface DomainInfo {
  senderDomain: string;
  domainAgeDays: number | null;
  protectedBrandMatch: string | null;
  isPunycode: boolean;
  homoglyphIndicators: string[];
}

// ============================================================
// Links
// ============================================================

export interface LinkInfo {
  visibleText: string;
  actualHref: string;
  actualDomain: string;
  suspiciousIndicators: string[];
  /** Blocklist checks are an optional external service (rule 8) — "unavailable" is honest, not "no_match". */
  blocklistMatch: 'match' | 'no_match' | 'unavailable';
  // MVP is static analysis only: never imply the URL was visited, never
  // render this as a clickable link.
}

// ============================================================
// Attachments
// ============================================================

export interface AttachmentInfo {
  filename: string;
  mimeType: string;
  sizeBytes: number;
  sha256: SHA256Hex;
  suspiciousIndicators: string[];
  archiveStatus: 'not_archive' | 'archive_ok' | 'archive_truncated' | 'unavailable';
  // No malwareScanStatus — MVP does static analysis only and never claims
  // malware detection. No raw bytes / download field — attachments are
  // never opened or downloaded from the investigation UI.
}

// ============================================================
// Findings
// ============================================================

/**
 * Canonical, backend-authoritative — exactly these ten fields, nothing
 * added, nothing removed. Notably no `title`: a human-readable label is
 * presentation data, not part of the canonical Finding — see
 * FindingPresentation below.
 *
 * qualification_code and qualification_version values come entirely from
 * the architecture-owned qualification registry. The frontend never
 * defines, proposes, or confirms vocabulary — including in its own mock
 * fixtures, where every code is illustrative only (see mockFixtures.ts).
 */
export interface Finding {
  analysis_run_id?: string;
  category: string;
  qualification_code: string;
  qualification_version: string;
  /** Open vocabulary, like qualification_code — not assumed to be a fixed 3-value set. */
  strength: string;
  mitre_id?: string;
  normalized_subject: string;
  normalized_target: string;
  claim_signature: string;
  supporting_fact_ids: string[];
  supporting_text: string;
  produced_by: string;
}

/**
 * What the UI actually renders a finding as. display_label comes from the
 * backend/API presentation layer, sourced from the versioned qualification
 * vocabulary — the frontend must never hardcode a qualification_code →
 * label mapping itself (contract correction round 2, #4).
 */
export interface FindingPresentation extends Finding {
  display_label: string;
}

/**
 * Resolves Finding.supporting_fact_ids, by id, within one InvestigationDetail
 * (contract correction round 2, #5). Treat resolution as best-effort: a
 * referenced id is not guaranteed to be present unless the API contract
 * guarantees it — look it up defensively and show "evidence unavailable"
 * rather than assuming a match.
 */
export interface EvidenceFact {
  factId: string;
  description: string;
  source: string;
}

// ============================================================
// Explanation / Conclusion
// ============================================================

export interface Conclusion {
  /** Shown at progressive-disclosure Level 1/2 — backend-authored. */
  oneLineExplanation: string;
  /** The fuller "Why?" narrative — backend-authored. */
  whyExplanation: string;
}

// ============================================================
// Analysis run + result
// ============================================================

/**
 * Everything the pipeline produces. Only present once a run is COMPLETED —
 * absence must render as "analysis in progress" / "analysis failed", never
 * as zero, safe, or benign (contract correction round 2, #1).
 */
export interface AnalysisResult {
  score: number; // 0-100
  severity: Severity;
  verdict: Verdict;
  conclusion: Conclusion;
  triggered_floor_codes?: string[];
  routing: RoutingInfo;
  authentication: AuthenticationInfo;
  identity: IdentityInfo;
  domain: DomainInfo;
  links: LinkInfo[];
  attachments: AttachmentInfo[];
  findings: FindingPresentation[];
  evidenceFacts: EvidenceFact[];
}

export interface AnalysisRun {
  runId: string;
  status: AnalysisRunStatus;
  startedAt: string; // ISO 8601
  completedAt: string | null;
  /** Present only when status === 'COMPLETED'. */
  result: AnalysisResult | null;
  /** Present only when status === 'FAILED' — backend-authored, human-readable. */
  failureReason: string | null;
}

// ============================================================
// Analyst actions
// ============================================================

export type AnalystActionType =
  | 'confirm_malicious'
  | 'false_positive'
  | 'needs_escalation'
  | 'add_note'
  | 'reopen'
  | 'close';

/**
 * Sent BY the frontend. No actor/analyst identity field — actor identity
 * is attached server-side.
 */
export interface AnalystActionRequest {
  investigationId: string;
  action: AnalystActionType;
  note?: string;
  /** Required by the UI when action === 'false_positive'. */
  falsePositiveReason?: string;
}

/** Returned BY the backend — actor identity lives here, never on the request. */
export interface AnalystActionRecord {
  actionId: string;
  action: AnalystActionType;
  actor: string;
  note?: string;
  falsePositiveReason?: string;
  timestamp: string; // ISO 8601
}

// ============================================================
// Audit
// ============================================================

export interface AuditEntry {
  entryId: string;
  type: 'ingestion' | 'analysis' | 'review' | 'confirmation' | 'note' | 'escalation' | 'export' | 'reopen' | 'close';
  /** null for system-generated entries (ingestion, analysis). */
  actor: string | null;
  timestamp: string; // ISO 8601
  detail: string;
}

// ============================================================
// Evidence export
// ============================================================

export interface EvidenceExportInfo {
  /** Hash of the original ingested .eml artifact — always available once the investigation exists. */
  original_artifact_sha256: SHA256Hex;
  /**
   * Hash of the generated export package itself. Null until the backend
   * computes it — never fabricated client-side. May stay null indefinitely
   * if bundle hashing isn't implemented yet; that's a valid, honest state,
   * not an error.
   */
  export_bundle_sha256: SHA256Hex | null;
  investigationId: string;
  analysisVersion: string;
  packageStatus: 'not_generated' | 'generating' | 'ready' | 'failed';
  /**
   * Present only once packageStatus === 'ready'. Downloads the forensic
   * export package — unrelated to, and not a loophole around, the
   * no-attachment-download rule above (that rule covers raw attachment
   * bytes, not the evidence bundle).
   */
  downloadUrl?: string;
}

// ============================================================
// Full investigation detail (composed)
// ============================================================

export interface InvestigationDetail {
  investigationId: string;
  createdAt: string; // ISO 8601
  /**
   * Current lifecycle status, backend-supplied. A later CLOSED (or
   * ESCALATED) status does not erase a prior confirmation determination —
   * that history lives in auditTrail / analystActions. If the UI needs to
   * show "this was confirmed before it was closed", read it from there;
   * never re-derive or infer a confirmation state from `status` alone.
   */
  status: InvestigationStatus;

  /** Full run history — preserved, never overwritten (shared rule 10). */
  runs: AnalysisRun[];
  /**
   * The run the UI should render right now. Backend-supplied, not
   * frontend-derived (e.g. "last in the array") — per contract correction
   * round 2, #3, the frontend does not derive backend-owned facts.
   */
  currentRun: AnalysisRun;

  auditTrail: AuditEntry[];
  analystActions: AnalystActionRecord[];
  evidenceExport: EvidenceExportInfo;
  userFeedbacks?: UserFeedbackRecord[];
  enforcementActions?: EnforcementActionRecord[];
  enforcementOptions?: GroundedEnforcementOption[];
}

// ============================================================
// User Feedback & Re-Analysis
// ============================================================

export type FeedbackType = 'SPAM_REPORTED' | 'PHISHING_REPORTED' | 'ANALYSIS_DISPUTED';

export interface UserFeedbackRecord {
  id: string;
  organization_id: string;
  investigation_id: string;
  source_analysis_run_id: string;
  actor_user_id: string;
  feedback_type: FeedbackType;
  note?: string | null;
  resulting_analysis_run_id?: string | null;
  created_at: string;
}

export interface RunComparison {
  investigation_id: string;
  run_1_id: string;
  run_2_id: string;
  run_1_score: number | null;
  run_2_score: number | null;
  score_delta: number | null;
  run_1_severity: string | null;
  run_2_severity: string | null;
  severity_changed: boolean;
  run_1_verdict: string | null;
  run_2_verdict: string | null;
  verdict_changed: boolean;
  new_findings: any[];
  unchanged_findings: any[];
  resolved_findings: any[];
  summary: string;
}

// ============================================================
// Threat Enforcement
// ============================================================

export type EnforcementType = 'BLOCK_SENDER' | 'BLOCK_DOMAIN' | 'BLOCK_IP' | 'QUARANTINE';

export type EnforcementResultStatus = 'REQUESTED' | 'AUTHORIZED' | 'EXECUTED' | 'FAILED' | 'REJECTED';

export interface GroundedEnforcementOption {
  action_type: EnforcementType;
  target: string;
  grounded_source: string;
  description: string;
}

export interface EnforcementActionRecord {
  id: string;
  organization_id: string;
  investigation_id: string;
  action_type: EnforcementType;
  target: string;
  status: EnforcementResultStatus;
  provider: string;
  is_demo: boolean;
  requested_by_user_id: string;
  authorized_by_user_id?: string | null;
  executed_by_user_id?: string | null;
  rejection_reason?: string | null;
  failure_reason?: string | null;
  execution_details: any;
  created_at: string;
  updated_at: string;
}

