import {
  InvestigationDetail,
  InvestigationSummary,
  UploadResult,
  AnalystActionRequest,
  AnalystActionRecord,
  EvidenceExportInfo,
  AnalysisRunStatus,
  AuditEntry,
  UserFeedbackRecord,
  RunComparison,
  GroundedEnforcementOption,
  EnforcementActionRecord,
  EnforcementType,
  FeedbackType,
} from '../../contract';

const API_BASE = '/api/v1';

async function getExtensionToken(): Promise<string> {
  // Innovative Extension Authentication:
  // Instead of a hardcoded username/password, extensions authenticate via an Integration API Key.
  const apiKey = (import.meta as any).env.VITE_HOPZERO_API_KEY || 'sih-extension-demo-key';
  localStorage.setItem('token', apiKey);
  return apiKey;
}

async function apiFetch(url: string, options: RequestInit = {}): Promise<Response> {
  let token = localStorage.getItem('token');
  if (!token) {
    token = await getExtensionToken();
  }
  
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${token}`);
  
  let res = await window.fetch(url, { ...options, headers });
  
  if (res.status === 401) {
    token = await getExtensionToken();
    headers.set('Authorization', `Bearer ${token}`);
    res = await window.fetch(url, { ...options, headers });
  }
  
  return res;
}


export async function fetchInvestigationSummaries(): Promise<InvestigationSummary[]> {
  const token = localStorage.getItem('token');
  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await apiFetch(`${API_BASE}/investigations`, { headers });
  if (!res.ok) {
    throw new Error(`Failed to fetch investigations: ${res.status} ${res.statusText}`);
  }
  const data = await res.json();
  return data.map((inv: any) => ({
    investigationId: inv.id,
    createdAt: inv.created_at,
    status: inv.status,
    currentRunStatus: inv.current_run_status as AnalysisRunStatus,
    score: inv.score ?? null,
    severity: inv.severity ?? null,
    verdict: inv.verdict ?? null,
    lastAnalysisAt: inv.updated_at,
  }));
}

export async function fetchInvestigationDetail(id: string): Promise<InvestigationDetail> {
  

  const headers: Record<string, string> = {};
  const token = localStorage.getItem('token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // 1. Query strictly canonical endpoints (zero calls to deprecated /details)
  const [
    invRes,
    runsRes,
    auditRes,
    evidenceRes,
    factsRes,
    feedbacksRes,
    enforcementsRes,
    enforcementOptionsRes,
  ] = await Promise.all([
    apiFetch(`${API_BASE}/investigations/${id}`, { headers }),
    apiFetch(`${API_BASE}/investigations/${id}/analysis-runs`, { headers }).catch(() => null),
    apiFetch(`${API_BASE}/investigations/${id}/audit`, { headers }).catch(() => null),
    apiFetch(`${API_BASE}/investigations/${id}/evidence`, { headers }).catch(() => null),
    apiFetch(`${API_BASE}/investigations/${id}/facts`, { headers }).catch(() => null),
    apiFetch(`${API_BASE}/investigations/${id}/feedback`, { headers }).catch(() => null),
    apiFetch(`${API_BASE}/investigations/${id}/enforcement`, { headers }).catch(() => null),
    apiFetch(`${API_BASE}/investigations/${id}/enforcement/options`, { headers }).catch(() => null),
  ]);

  if (!invRes.ok) {
    throw new Error(`Failed to fetch investigation ${id}: ${invRes.status} ${invRes.statusText}`);
  }

  const inv = await invRes.json();
  const rawRuns = runsRes && runsRes.ok ? await runsRes.json() : [];
  const auditEvents = auditRes && auditRes.ok ? await auditRes.json() : [];
  const artifacts = evidenceRes && evidenceRes.ok ? await evidenceRes.json() : [];
  const factsList = factsRes && factsRes.ok ? await factsRes.json() : [];
  const feedbacksList: UserFeedbackRecord[] = feedbacksRes && feedbacksRes.ok ? await feedbacksRes.json() : [];
  const enforcementList: EnforcementActionRecord[] = enforcementsRes && enforcementsRes.ok ? await enforcementsRes.json() : [];
  const enforcementOptionsList: GroundedEnforcementOption[] = enforcementOptionsRes && enforcementOptionsRes.ok ? await enforcementOptionsRes.json() : [];
  const primaryArtifact = artifacts.length > 0 ? artifacts[0] : null;

  // Determine currentRun strictly from backend data
  let currentRunBackend: any = null;
  if (inv.current_analysis_run_id) {
    currentRunBackend = rawRuns.find((r: any) => r.id === inv.current_analysis_run_id);
  }
  if (!currentRunBackend && rawRuns.length > 0) {
    currentRunBackend = rawRuns[rawRuns.length - 1];
  }

  const currentRunId = currentRunBackend ? currentRunBackend.id : (inv.current_analysis_run_id || 'none');
  const currentRunStatus = currentRunBackend ? (currentRunBackend.status as AnalysisRunStatus) : (inv.current_run_status as AnalysisRunStatus);

  // If a usable completed run exists, query score and findings
  let runResult: any = null;
  if (inv.current_analysis_run_id) {
    try {
      const [scoreRes, findingsRes] = await Promise.all([
        apiFetch(`${API_BASE}/investigations/${id}/analysis-runs/${inv.current_analysis_run_id}/score`, { headers }).catch(() => null),
        apiFetch(`${API_BASE}/investigations/${id}/findings?analysis_run_id=${inv.current_analysis_run_id}`, { headers }).catch(() => null),
      ]);

      if (scoreRes && scoreRes.ok) {
        const scoreData = await scoreRes.json();
        const findingsData = findingsRes && findingsRes.ok ? await findingsRes.json() : [];

        // Build technical evidence breakdown directly from facts
        let candidateIp: string | null = null;
        let fromAddr: string | null = null;
        let fromDisp: string | null = null;
        let fromDom: string | null = null;
        let replyTo: string | null = null;
        let returnPath: string | null = null;
        const hops: any[] = [];
        const extractedLinks: any[] = [];
        const extractedAttachments: any[] = [];

        for (const fact of factsList) {
          const p = fact.payload || {};
          if (fact.fact_type === 'hop0_candidate_ip' && p.value) {
            candidateIp = String(p.value);
          } else if (fact.fact_type === 'envelope_metadata') {
            fromAddr = p.from_address || null;
            fromDisp = p.from_display || null;
            fromDom = p.from_domain || null;
            replyTo = (p.reply_to && p.reply_to.length > 0) ? p.reply_to[0] : null;
            returnPath = p.return_path || null;
          } else if (fact.fact_type === 'received_hops' && p.hops) {
            for (const h of p.hops) {
              hops.push({
                hopIndex: h.sequence_index,
                fromClaim: h.from_claim,
                byClaim: h.by_claim,
                observedIp: h.observed_ip,
                tlsVersion: h.tls ? 'TLS' : null,
                timestamp: h.timestamp,
                trustStatus: 'neutral',
              });
            }
          } else if (fact.fact_type === 'extracted_links' && p.links) {
            for (const l of p.links) {
              extractedLinks.push({
                linkId: l.link_id,
                href: l.href,
                displayText: l.display_text,
                flags: [],
              });
            }
          } else if (fact.fact_type === 'extracted_attachments' && p.attachments) {
            for (const a of p.attachments) {
              extractedAttachments.push({
                attachmentId: a.attachment_id,
                filename: a.filename,
                declaredMime: a.declared_mime_type,
                sizeBytes: a.size_bytes,
                sha256: a.sha256,
                flags: [],
              });
            }
          }
        }

        runResult = {
          score: scoreData.total_score,
          total_score: scoreData.total_score,
          severity: scoreData.severity,
          verdict: scoreData.verdict,
          triggered_floor_codes: scoreData.triggered_floor_codes || [],
          conclusion: {
            oneLineExplanation: scoreData.one_line_explanation || '',
            whyExplanation: scoreData.why_explanation || '',
          },
          routing: {
            hops,
            candidateProbableOriginIp: candidateIp,
            candidateOriginConfidence: candidateIp ? 'verified' : null,
            anomalies: [],
          },
          authentication: {
            spf: { result: 'neutral', explanation: '', technicalDetails: '' },
            dkim: { result: 'neutral', explanation: '', technicalDetails: '' },
            dmarc: { result: 'neutral', explanation: '', technicalDetails: '' },
            alignment: { result: 'neutral', explanation: '', technicalDetails: '' },
          },
          identity: {
            from: fromAddr,
            displayName: fromDisp,
            replyTo,
            returnPath,
            mismatches: [],
            impersonationEvidence: [],
          },
          domain: {
            senderDomain: fromDom,
            domainAgeDays: null,
            protectedBrandMatch: null,
            isPunycode: false,
            homoglyphIndicators: [],
          },
          links: extractedLinks,
          attachments: extractedAttachments,
          findings: findingsData.map((f: any) => ({
            analysis_run_id: f.analysis_run_id,
            category: f.category,
            qualification_code: f.qualification_code,
            qualification_version: f.qualification_version,
            strength: f.strength,
            normalized_subject: f.normalized_subject_or_target,
            normalized_target: f.normalized_subject_or_target,
            claim_signature: f.claim_signature,
            supporting_fact_ids: f.supporting_fact_ids || [],
            supporting_text: f.supporting_text,
            produced_by: f.produced_by,
            display_label: `${f.category}: ${f.qualification_code} (${f.strength})`,
          })),
          evidenceFacts: factsList,
        };
      }
    } catch {
      // Ignore score fetch error if run incomplete
    }
  }

  const composedRuns: any[] = rawRuns.map((r: any) => ({
    runId: r.id,
    status: r.status as AnalysisRunStatus,
    startedAt: r.started_at || r.created_at,
    completedAt: r.completed_at || null,
    result: r.id === inv.current_analysis_run_id ? runResult : null,
    failureReason: r.failure_reason || null,
  }));

  const auditTrail: AuditEntry[] = auditEvents.map((e: any) => {
    const meta = e.metadata_json || {};
    let type: AuditEntry['type'] = 'review';
    if (e.action === 'NOTE_ADDED') {
      type = 'note';
    } else if (e.action === 'INVESTIGATION_REOPENED') {
      type = 'reopen';
    } else if (e.action === 'EVIDENCE_EXPORTED') {
      type = 'export';
    } else if (e.action === 'ARTIFACT_INGESTED' || e.action === 'INVESTIGATION_CREATED') {
      type = 'ingestion';
    } else if (e.action.includes('FEEDBACK')) {
      type = 'review';
    } else if (e.action.includes('ENFORCEMENT')) {
      type = 'escalation';
    } else if (e.action === 'INVESTIGATION_STATUS_CHANGED') {
      const toVal = (meta.to || '').toUpperCase();
      if (toVal === 'CONFIRMED') type = 'confirmation';
      else if (toVal === 'ESCALATED') type = 'escalation';
      else if (toVal === 'CLOSED') type = 'close';
      else type = 'review';
    } else if (e.action.includes('ANALYSIS') || e.action.includes('FINDING') || e.action.includes('SCORE') || e.action.includes('AI_')) {
      type = 'analysis';
    }
    return {
      entryId: e.id,
      type,
      actor: e.actor_user_id || 'system',
      timestamp: e.created_at,
      detail: `${e.action}: ${JSON.stringify(meta)}`,
    };
  });

  const analystActions: AnalystActionRecord[] = auditEvents
    .filter((e: any) => ['INVESTIGATION_STATUS_CHANGED', 'INVESTIGATION_REOPENED', 'NOTE_ADDED'].includes(e.action))
    .map((e: any) => {
      const meta = e.metadata_json || {};
      const actType = meta.action || (e.action === 'NOTE_ADDED' ? 'add_note' : 'confirm_malicious');
      return {
        actionId: `action-${e.id}`,
        action: actType,
        actor: e.actor_user_id || 'analyst',
        note: meta.note,
        falsePositiveReason: meta.falsePositiveReason,
        timestamp: e.created_at,
      };
    });

  return {
    investigationId: inv.id,
    createdAt: inv.created_at,
    status: inv.status,
    runs: composedRuns,
    currentRun: {
      runId: currentRunId,
      status: currentRunStatus,
      startedAt: currentRunBackend?.started_at || inv.created_at,
      completedAt: inv.current_analysis_run_id ? (currentRunBackend?.completed_at || inv.updated_at) : null,
      result: runResult,
      failureReason: currentRunBackend?.failure_reason || null,
    },
    auditTrail,
    analystActions,
    evidenceExport: {
      original_artifact_sha256: primaryArtifact?.original_artifact_sha256 || '',
      export_bundle_sha256: primaryArtifact?.export_bundle_sha256 || null,
      investigationId: inv.id,
      analysisVersion: '1.0.0',
      packageStatus: primaryArtifact?.export_bundle_sha256 ? 'ready' : 'not_generated',
    },
    userFeedbacks: feedbacksList,
    enforcementActions: enforcementList,
    enforcementOptions: enforcementOptionsList,
  };
}

export async function uploadEmlFile(file: File): Promise<UploadResult> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('ingestion_source', 'web_upload');
  formData.append('provider_message_id', `upload-${Date.now()}`);
  formData.append('auto_analyze', 'true');

  const headers: Record<string, string> = {};
  const token = localStorage.getItem('token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await apiFetch(`${API_BASE}/ingest`, {
    method: 'POST',
    headers,
    body: formData,
  });

  if (!res.ok) {
    let errorDetail = `Upload failed with status ${res.status}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) {
        errorDetail = errJson.detail;
      }
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }

  const data = await res.json();
  return {
    investigationId: data.investigation_id,
    filename: file.name,
    fileSizeBytes: file.size,
    sha256: data.artifact_id || 'ingested',
  };
}

export async function performAnalystAction(
  req: AnalystActionRequest
): Promise<AnalystActionRecord> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  const token = localStorage.getItem('token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await apiFetch(`${API_BASE}/investigations/${req.investigationId}/actions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      action: req.action,
      note: req.note,
      falsePositiveReason: req.falsePositiveReason,
    }),
  });

  if (!res.ok) {
    let errorDetail = `Action ${req.action} failed: ${res.status} ${res.statusText}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) {
        errorDetail = errJson.detail;
      }
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }

  const data = await res.json();
  return {
    actionId: data.actionId,
    action: data.action,
    actor: data.actor,
    note: data.note,
    falsePositiveReason: data.falsePositiveReason,
    timestamp: data.timestamp,
  };
}

// ============================================================
// User Feedback & Re-Analysis Client Functions
// ============================================================

export async function submitUserFeedback(
  investigationId: string,
  feedbackType: FeedbackType,
  note?: string,
  sourceRunId?: string
): Promise<any> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  const token = localStorage.getItem('token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await apiFetch(`${API_BASE}/investigations/${investigationId}/feedback`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      feedback_type: feedbackType,
      note: note || null,
      source_analysis_run_id: sourceRunId || null,
    }),
  });

  if (!res.ok) {
    let msg = `Feedback submission failed (${res.status})`;
    try {
      const j = await res.json();
      if (j.message) msg = j.message;
    } catch {}
    throw new Error(msg);
  }

  return await res.json();
}

export async function compareRuns(
  investigationId: string,
  run1Id: string,
  run2Id: string
): Promise<RunComparison> {
  const headers: Record<string, string> = {};
  const token = localStorage.getItem('token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await apiFetch(
    `${API_BASE}/investigations/${investigationId}/compare-runs?run1=${encodeURIComponent(run1Id)}&run2=${encodeURIComponent(run2Id)}`,
    { headers }
  );

  if (!res.ok) {
    throw new Error(`Failed to compare runs: ${res.status}`);
  }

  return await res.json();
}

// ============================================================
// Threat Enforcement Client Functions
// ============================================================

export async function fetchEnforcementOptions(investigationId: string): Promise<GroundedEnforcementOption[]> {
  const headers: Record<string, string> = {};
  const token = localStorage.getItem('token');
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await apiFetch(`${API_BASE}/investigations/${investigationId}/enforcement/options`, { headers });
  if (!res.ok) return [];
  return await res.json();
}

export async function requestEnforcementAction(
  investigationId: string,
  actionType: EnforcementType,
  target: string
): Promise<EnforcementActionRecord> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = localStorage.getItem('token');
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await apiFetch(`${API_BASE}/investigations/${investigationId}/enforcement/request`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ action_type: actionType, target }),
  });

  if (!res.ok) {
    let msg = `Enforcement request failed (${res.status})`;
    try {
      const j = await res.json();
      if (j.message) msg = j.message;
    } catch {}
    throw new Error(msg);
  }

  return await res.json();
}

export async function authorizeEnforcementAction(
  investigationId: string,
  actionId: string
): Promise<EnforcementActionRecord> {
  const headers: Record<string, string> = {};
  const token = localStorage.getItem('token');
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await apiFetch(`${API_BASE}/investigations/${investigationId}/enforcement/${actionId}/authorize`, {
    method: 'POST',
    headers,
  });

  if (!res.ok) {
    let msg = `Enforcement authorization failed (${res.status})`;
    try {
      const j = await res.json();
      if (j.message) msg = j.message;
    } catch {}
    throw new Error(msg);
  }

  return await res.json();
}

export async function executeEnforcementAction(
  investigationId: string,
  actionId: string,
  simulateFailure: boolean = false
): Promise<EnforcementActionRecord> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = localStorage.getItem('token');
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await apiFetch(`${API_BASE}/investigations/${investigationId}/enforcement/${actionId}/execute`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ simulate_failure: simulateFailure }),
  });

  if (!res.ok) {
    let msg = `Enforcement execution failed (${res.status})`;
    try {
      const j = await res.json();
      if (j.message) msg = j.message;
    } catch {}
    throw new Error(msg);
  }

  return await res.json();
}

export async function rejectEnforcementAction(
  investigationId: string,
  actionId: string,
  reason: string
): Promise<EnforcementActionRecord> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = localStorage.getItem('token');
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await apiFetch(`${API_BASE}/investigations/${investigationId}/enforcement/${actionId}/reject`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ reason }),
  });

  if (!res.ok) {
    let msg = `Enforcement rejection failed (${res.status})`;
    try {
      const j = await res.json();
      if (j.message) msg = j.message;
    } catch {}
    throw new Error(msg);
  }

  return await res.json();
}




export async function loginUser(username: string, password: string):Promise<any> {
  const formData = new FormData();
  formData.append('username', username);
  formData.append('password', password);
  const res = await window.fetch('/api/v1/auth/login', {
    method: 'POST',
    body: formData
  });
  if (!res.ok) {
    throw new Error('Login failed');
  }
  const data = await res.json();
  localStorage.setItem('token', data.access_token);
  return data;
}
