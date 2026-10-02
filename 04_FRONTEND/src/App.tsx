import React, { useState, useEffect } from 'react';
import {
  InvestigationSummary,
  InvestigationDetail,
  AnalystActionType,
  FeedbackType,
  EnforcementType,
  RunComparison,
} from '../contract';
import {
  fetchInvestigationSummaries,
  fetchInvestigationDetail,
  performAnalystAction,
  submitUserFeedback,
  compareRuns,
  requestEnforcementAction,
  authorizeEnforcementAction,
  executeEnforcementAction,
  rejectEnforcementAction,
} from './services/api';
import { Navbar } from './components/Navbar';
import { Dashboard } from './components/Dashboard';
import { UploadModal } from './components/UploadModal';
import { Level1ConsumerVerdict } from './components/ProgressiveDisclosure/Level1ConsumerVerdict';
import { Level2WhyAndAction } from './components/ProgressiveDisclosure/Level2WhyAndAction';
import { LiveAnalysisScreen } from './components/LiveAnalysisScreen';
import { Level3TechnicalEvidence } from './components/ProgressiveDisclosure/Level3TechnicalEvidence';
import { Level4FindingsTable } from './components/ProgressiveDisclosure/Level4FindingsTable';
import { Level5AuditAndExport } from './components/ProgressiveDisclosure/Level5AuditAndExport';

export const App: React.FC = () => {
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [showUpload, setShowUpload] = useState(false);
  const [comparison, setComparison] = useState<RunComparison | null>(null);
  const [loadingComparison, setLoadingComparison] = useState(false);

  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadList();
    
    // WebSocket for Real-Time Updates
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = (import.meta as any).env?.VITE_WS_HOST || window.location.host;
    const ws = new WebSocket(`${protocol}//${host}/api/v1/ws`);
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.event === 'investigation_updated') {
          loadList();
          if (selectedId === data.investigation_id) {
            loadDetail(data.investigation_id);
          }
        }
      } catch (e) {}
    };
    return () => { ws.close(); };
  }, [selectedId]);

  useEffect(() => {
    if (selectedId) {
      loadDetail(selectedId);
      setComparison(null);
    } else {
      setDetail(null);
      setComparison(null);
    }
  }, [selectedId]);

  const loadList = async () => {
    const token = localStorage.getItem('token');
    if (!token) {
      setInvestigations([]);
      return;
    }
    try {
      setError(null);
      const list = await fetchInvestigationSummaries();
      setInvestigations(list);
    } catch (err: any) {
      if (err.message && err.message.includes('401')) {
        localStorage.removeItem('token');
        setError("You must be logged in to view investigations. Please click 'SOC Login' in the top right.");
      } else {
        setError(`API Connection Error: ${err.message || 'Unable to fetch investigations from backend'}`);
      }
      setInvestigations([]);
    }
  };

  const loadDetail = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchInvestigationDetail(id);
      setDetail(data);
      // If multiple completed runs exist, automatically load comparison between first and current
      if (data.runs && data.runs.length > 1) {
        const completedRuns = data.runs.filter((r) => r.status === 'COMPLETED');
        if (completedRuns.length >= 2) {
          const run1 = completedRuns[completedRuns.length - 1].runId;
          const run2 = completedRuns[0].runId;
          if (run1 !== run2) {
            handleCompareRuns(id, run1, run2);
          }
        }
      }
    } catch (err: any) {
      setError(`API Error: ${err.message || 'Failed to fetch investigation detail'}`);
      setDetail(null);
    } finally {
      setLoading(false);
    }
  };

  const handleCompareRuns = async (invId: string, run1Id: string, run2Id: string) => {
    setLoadingComparison(true);
    try {
      const comp = await compareRuns(invId, run1Id, run2Id);
      setComparison(comp);
    } catch {
      // ignore comparison failure for demo fixtures
    } finally {
      setLoadingComparison(false);
    }
  };

  const handleUserFeedback = async (feedbackType: FeedbackType, note?: string) => {
    if (!selectedId) return;
    await submitUserFeedback(selectedId, feedbackType, note);
    await loadDetail(selectedId);
    await loadList();
  };

  const handleRequestEnforcement = async (actionType: EnforcementType, target: string) => {
    if (!selectedId) return;
    await requestEnforcementAction(selectedId, actionType, target);
    await loadDetail(selectedId);
  };

  const handleAuthorizeEnforcement = async (actionId: string) => {
    if (!selectedId) return;
    await authorizeEnforcementAction(selectedId, actionId);
    await loadDetail(selectedId);
  };

  const handleExecuteEnforcement = async (actionId: string, simulateFailure?: boolean) => {
    if (!selectedId) return;
    await executeEnforcementAction(selectedId, actionId, simulateFailure);
    await loadDetail(selectedId);
  };

  const handleRejectEnforcement = async (actionId: string, reason: string) => {
    if (!selectedId) return;
    await rejectEnforcementAction(selectedId, actionId, reason);
    await loadDetail(selectedId);
  };

  const handlePerformAction = async (action: AnalystActionType, note?: string, fpReason?: string) => {
    if (!selectedId || !detail) return;
    const rec = await performAnalystAction({
      investigationId: selectedId,
      action,
      note,
      falsePositiveReason: fpReason,
    });

    let auditType: any = 'review';
    if (action === 'confirm_malicious') auditType = 'confirmation';
    else if (action === 'needs_escalation') auditType = 'escalation';
    else if (action === 'close') auditType = 'close';
    else if (action === 'reopen') auditType = 'reopen';
    else if (action === 'add_note') auditType = 'note';

    const newAudit = {
      entryId: `audit-${Date.now()}`,
      type: auditType,
      actor: rec.actor,
      timestamp: rec.timestamp,
      detail: note || fpReason || `Analyst performed ${action}`,
    };

    let nextStatus = detail.status;
    if (action === 'confirm_malicious') nextStatus = 'CONFIRMED';
    else if (action === 'false_positive') nextStatus = 'FALSE_POSITIVE';
    else if (action === 'needs_escalation') nextStatus = 'ESCALATED';
    else if (action === 'reopen') nextStatus = 'UNDER_REVIEW';
    else if (action === 'close') nextStatus = 'CLOSED';

    setDetail({
      ...detail,
      status: nextStatus,
      analystActions: [rec, ...detail.analystActions],
      auditTrail: [newAudit, ...detail.auditTrail],
    });
  };

const userRole = React.useMemo(() => {
    const token = localStorage.getItem('token');
    if (!token) return 'USER';
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.role || 'USER';
    } catch (e) {
      return 'USER';
    }
  }, [investigations]); // update if they log in/out

  return (
    <div className="app-container">
      <Navbar
        selectedId={selectedId}
        onUploadClick={() => setShowUpload(true)}
        onHomeClick={() => setSelectedId(null)}
      />

      <main className="main-content">

        {error && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid var(--color-dangerous)',
            color: 'var(--color-dangerous)',
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-md)',
            marginBottom: '1.25rem',
            fontSize: '0.9rem',
            fontWeight: 500,
          }}>
            ⚠️ {error}
          </div>
        )}

        {selectedId === null ? (
          <div>
            {userRole === 'USER' && (
              <div style={{ padding: '1rem 0', color: 'var(--color-primary)', fontWeight: 600 }}>
                👋 Welcome to the HopZero Employee Portal. Below are the emails you've submitted for security review.
              </div>
            )}
            <Dashboard investigations={investigations} onSelect={(id) => setSelectedId(id)} />
          </div>
        ) : loading || !detail ? (
          <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
            Loading forensic investigation detail...
          </div>
        ) : detail.status === 'AWAITING_ANALYSIS' ? (
          <LiveAnalysisScreen investigationId={detail.investigationId} onComplete={() => loadDetail(detail.investigationId)} />
        ) : (
          <div>
            {/* Header info */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div>
                <h1 style={{ fontSize: '1.5rem', fontWeight: 700, display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                  Investigation: <span className="font-mono" style={{ wordBreak: 'break-all' }}>{detail.investigationId}</span>
                </h1>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                  Ingested at {new Date(detail.createdAt.endsWith('Z') ? detail.createdAt : detail.createdAt + 'Z').toLocaleString()} | Original SHA-256 Verified
                </p>
              </div>

              {userRole !== 'USER' && detail.runs && detail.runs.length > 1 && (
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>
                    Analysis Runs ({detail.runs.length}):
                  </span>
                  {detail.runs.map((r, i) => (
                    <span
                      key={r.runId}
                      style={{
                        padding: '0.2rem 0.5rem',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '0.75rem',
                        background: r.runId === detail.currentRun.runId ? 'var(--color-primary)' : 'var(--bg-secondary)',
                        color: r.runId === detail.currentRun.runId ? '#fff' : 'var(--text-secondary)',
                        border: '1px solid var(--border-color)',
                      }}
                    >
                      Run #{detail.runs.length - i} ({r.status})
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Run Comparison Banner (if comparison exists) */}
            {userRole !== 'USER' && comparison && (
              <div
                style={{
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 'var(--radius-md)',
                  padding: '1rem',
                  marginBottom: '1rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                    📊 Multi-Run Comparative Analysis (Run 1 vs Run 2 after User Feedback)
                  </span>
                  <span style={{ fontSize: '0.8rem', color: 'var(--color-primary)', fontWeight: 600 }}>
                    Delta: {comparison.score_delta !== null && comparison.score_delta > 0 ? `+${comparison.score_delta}` : comparison.score_delta} pts
                  </span>
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                  {comparison.summary}
                </div>
                {comparison.new_findings && comparison.new_findings.length > 0 && (
                  <div style={{ fontSize: '0.8rem', color: 'var(--color-caution)' }}>
                    Newly Discovered Findings: {comparison.new_findings.map((f: any) => `${f.category}: ${f.qualification_code} (${f.strength})`).join(', ')}
                  </div>
                )}
              </div>
            )}

            {/* PROGRESSIVE DISCLOSURE LEVELS */}
            {/* Level 1: Consumer Verdict */}
            <Level1ConsumerVerdict
              status={detail.status}
              result={detail.currentRun?.result || null}
              onSubmitFeedback={handleUserFeedback}
            />

            {detail.currentRun?.result && (
              <>
                {/* Level 2: Why Narrative & Recommended Actions */}
                {userRole === 'USER' ? (
                   <div style={{ padding: '1rem', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)', marginBottom: '1rem' }}>
                     <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem', fontWeight: 600 }}>Why did we flag this?</h3>
                     <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
                       {detail.currentRun.result.conclusion.whyExplanation || 'The AI Reasoner has determined this email is unsafe based on hidden forensic signals.'}
                     </p>
                   </div>
                ) : (
                   <Level2WhyAndAction
                     result={detail.currentRun.result}
                     enforcementOptions={detail.enforcementOptions || []}
                     enforcementActions={detail.enforcementActions || []}
                     onRequestEnforcement={handleRequestEnforcement}
                     onAuthorizeEnforcement={handleAuthorizeEnforcement}
                     onExecuteEnforcement={handleExecuteEnforcement}
                     onRejectEnforcement={handleRejectEnforcement}
                   />
                )}

                {/* Level 3: Technical Forensic Evidence - SOC ONLY */}
                {userRole !== 'USER' && (
                  <Level3TechnicalEvidence
                    result={detail.currentRun.result}
                  />
                )}

                {/* Level 4: Validated Findings Table - SOC ONLY */}
                {userRole !== 'USER' && (
                  <Level4FindingsTable
                    findings={detail.currentRun.result.findings}
                    evidenceFacts={detail.currentRun.result.evidenceFacts}
                  />
                )}
              </>
            )}

            {/* Level 5: Audit Trail, Chain of Custody & SOC Actions - SOC ONLY */}
            {userRole !== 'USER' && (
              <Level5AuditAndExport
                investigationId={detail.investigationId}
                auditTrail={detail.auditTrail}
                analystActions={detail.analystActions}
                evidenceExport={detail.evidenceExport}
                onPerformAction={handlePerformAction}
              />
            )}
          </div>
        )}
      </main>

      {showUpload && (
        <UploadModal
          onClose={() => setShowUpload(false)}
          onSuccess={(id) => {
            loadList();
            setSelectedId(id);
          }}
        />
      )}
    </div>
  );
};




