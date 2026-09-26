import React, { useState } from 'react';
import {
  AnalysisResult,
  GroundedEnforcementOption,
  EnforcementActionRecord,
  EnforcementType,
} from '../../../contract';

interface Props {
  result: AnalysisResult;
  enforcementOptions?: GroundedEnforcementOption[];
  enforcementActions?: EnforcementActionRecord[];
  onRequestEnforcement?: (actionType: EnforcementType, target: string) => Promise<void>;
  onAuthorizeEnforcement?: (actionId: string) => Promise<void>;
  onExecuteEnforcement?: (actionId: string, simulateFailure?: boolean) => Promise<void>;
  onRejectEnforcement?: (actionId: string, reason: string) => Promise<void>;
}

export const Level2WhyAndAction: React.FC<Props> = ({
  result,
  enforcementOptions = [],
  enforcementActions = [],
  onRequestEnforcement,
  onAuthorizeEnforcement,
  onExecuteEnforcement,
  onRejectEnforcement,
}) => {
  const [isOpen, setIsOpen] = useState(true);
  const [selectedTarget, setSelectedTarget] = useState<string>('');
  const [selectedActionType, setSelectedActionType] = useState<EnforcementType>('BLOCK_SENDER');
  const [submitting, setSubmitting] = useState(false);
  const [simulateFailureToggle, setSimulateFailureToggle] = useState(false);
  const [rejectReason, setRejectReason] = useState('');
  const [rejectingActionId, setRejectingActionId] = useState<string | null>(null);

  const { conclusion, severity } = result;

  const getActions = () => {
    switch (severity?.toLowerCase()) {
      case 'critical':
      case 'high':
        return [
          'Do NOT click any links, open attachments, or reply to this message.',
          'If this email claims to be an executive wire or invoice change, verify via an independent voice phone call.',
          'Report this message to your organization\'s Security Operations Center (SOC).',
          'Authorize network blocklist or sender enforcement below via provider-neutral controls.',
        ];
      case 'medium':
        return [
          'Exercise caution: do not enter login credentials or download unexpected files.',
          'Confirm with the sender via a known alternative communication channel.',
          'Check that the sender domain matches legitimate organization branding.',
        ];
      default:
        return [
          'Standard security awareness: verify unexpected requests before taking action.',
          'No immediate malicious indicators or critical risk floors triggered.',
        ];
    }
  };

  const actions = getActions();

  const handleRequest = async () => {
    if (!onRequestEnforcement) return;
    const target = selectedTarget || (enforcementOptions.length > 0 ? enforcementOptions[0].target : '');
    const actType = selectedActionType || (enforcementOptions.length > 0 ? enforcementOptions[0].action_type : 'BLOCK_SENDER');
    if (!target) return;
    setSubmitting(true);
    try {
      await onRequestEnforcement(actType, target);
      setSelectedTarget('');
    } catch (err: any) {
      alert(`Enforcement request failed: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleAuthorize = async (actionId: string) => {
    if (!onAuthorizeEnforcement) return;
    setSubmitting(true);
    try {
      await onAuthorizeEnforcement(actionId);
    } catch (err: any) {
      alert(`Authorization failed: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleExecute = async (actionId: string) => {
    if (!onExecuteEnforcement) return;
    setSubmitting(true);
    try {
      await onExecuteEnforcement(actionId, simulateFailureToggle);
    } catch (err: any) {
      alert(`Execution failed: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleReject = async () => {
    if (!onRejectEnforcement || !rejectingActionId || !rejectReason.trim()) return;
    setSubmitting(true);
    try {
      await onRejectEnforcement(rejectingActionId, rejectReason);
      setRejectingActionId(null);
      setRejectReason('');
    } catch (err: any) {
      alert(`Rejection failed: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'EXECUTED':
        return <span className="badge badge-success" style={{ background: 'rgba(16, 185, 129, 0.2)', color: 'var(--color-safe)' }}>EXECUTED</span>;
      case 'AUTHORIZED':
        return <span className="badge badge-info" style={{ background: 'rgba(59, 130, 246, 0.2)', color: 'var(--color-primary)' }}>AUTHORIZED</span>;
      case 'REQUESTED':
        return <span className="badge badge-warning" style={{ background: 'rgba(245, 158, 11, 0.2)', color: 'var(--color-caution)' }}>REQUESTED</span>;
      case 'FAILED':
        return <span className="badge badge-danger" style={{ background: 'rgba(239, 68, 68, 0.2)', color: 'var(--color-dangerous)' }}>FAILED</span>;
      case 'REJECTED':
        return <span className="badge" style={{ background: 'rgba(107, 114, 128, 0.2)', color: 'var(--text-muted)' }}>REJECTED</span>;
      default:
        return <span className="badge">{status}</span>;
    }
  };

  return (
    <div className="card">
      <div
        className="card-header"
        style={{ cursor: 'pointer', marginBottom: isOpen ? '1rem' : 0 }}
        onClick={() => setIsOpen(!isOpen)}
      >
        <div className="card-title">
          <span>Level 2: Why? & Recommended Threat Response</span>
        </div>
        <span style={{ fontSize: '0.85rem', color: 'var(--color-primary)', fontWeight: 600 }}>
          {isOpen ? '▲ Collapse' : '▼ Expand'}
        </span>
      </div>

      {isOpen && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Critical Floors Alert */}
          {result.triggered_floor_codes && result.triggered_floor_codes.length > 0 && (
            <div style={{
              background: 'rgba(239, 68, 68, 0.1)',
              borderLeft: '4px solid var(--color-dangerous)',
              padding: '1rem',
              borderRadius: '0 8px 8px 0',
            }}>
              <h4 style={{ color: 'var(--color-dangerous)', marginBottom: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                CRITICAL FLOOR TRIGGERED
              </h4>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.4' }}>
                The raw score is overridden by the following critical indicators, which enforce a minimum risk severity regardless of the total point count:
                <br/>
                <strong style={{ color: 'var(--text-primary)' }}>{result.triggered_floor_codes.join(', ')}</strong>
              </p>
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
            {/* Why Narrative */}
            <div style={{ background: 'var(--bg-secondary)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
              <h4 style={{ color: 'var(--text-primary)', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span>🔍</span> Why is this email flagged?
              </h4>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6' }}>
                {conclusion.whyExplanation || conclusion.oneLineExplanation}
              </p>
            </div>

            {/* Action Steps */}
            <div style={{ background: 'var(--bg-secondary)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
              <h4 style={{ color: 'var(--text-primary)', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span>🛡️</span> What should I do?
              </h4>
              <ul style={{ listStylePosition: 'inside', color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6' }}>
                {actions.map((act, i) => (
                  <li key={i} style={{ marginBottom: '0.35rem' }}>{act}</li>
                ))}
              </ul>
            </div>
          </div>

          {/* Threat Response & Enforcement Section */}
          <div style={{ background: 'var(--bg-secondary)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div>
                <h4 style={{ color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem', margin: '0 0 0.25rem 0' }}>
                  <span>🛡️</span> Protect Your Organization
                </h4>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                  Block malicious senders, domains, or IPs to prevent future attacks.
                </div>
              </div>
              <span
                style={{
                  fontSize: '0.75rem',
                  padding: '0.25rem 0.6rem',
                  borderRadius: '4px',
                  background: 'rgba(59, 130, 246, 0.15)',
                  color: 'var(--color-primary)',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.3rem'
                }}
              >
                <span>🧪</span> Demo Mode (Safe Execution)
              </span>
            </div>

            {/* Request Action Bar */}
            {enforcementOptions.length > 0 && (
              <div style={{ background: 'var(--bg-card)', padding: '1rem', borderRadius: '6px', border: '1px solid var(--border-color)', marginBottom: '1rem' }}>
                <div style={{ fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--text-primary)' }}>
                  Create New Block Rule
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <select
                    className="input-field"
                    style={{ flex: 1, minWidth: '250px' }}
                    value={selectedTarget}
                    onChange={(e) => {
                      setSelectedTarget(e.target.value);
                      const opt = enforcementOptions.find(o => o.target === e.target.value);
                      if (opt) setSelectedActionType(opt.action_type);
                    }}
                  >
                    <option value="">-- Select an item to block --</option>
                    {enforcementOptions.map((opt, i) => (
                      <option key={i} value={opt.target}>
                        {opt.action_type.replace('BLOCK_', '')}: {opt.target}
                      </option>
                    ))}
                  </select>

                  <button
                    className="btn-primary"
                    onClick={handleRequest}
                    disabled={submitting || !selectedTarget}
                    style={{ padding: '0.5rem 1rem', background: 'var(--color-dangerous)', border: 'none' }}
                  >
                    Block Threat
                  </button>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: 'auto', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={simulateFailureToggle}
                      onChange={(e) => setSimulateFailureToggle(e.target.checked)}
                    />
                    Test Error Handling
                  </label>
                </div>
              </div>
            )}

            {/* Enforcement Actions Table */}
            {enforcementActions.length > 0 ? (
              <div className="table-container">
                <table style={{ width: '100%', fontSize: '0.85rem', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                      <th style={{ padding: '0.5rem' }}>Action</th>
                      <th style={{ padding: '0.5rem' }}>Target</th>
                      <th style={{ padding: '0.5rem' }}>Status</th>
                      <th style={{ padding: '0.5rem' }}>Details</th>
                      <th style={{ padding: '0.5rem', textAlign: 'right' }}>Controls</th>
                    </tr>
                  </thead>
                  <tbody>
                    {enforcementActions.map((act) => (
                      <tr key={act.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                        <td style={{ padding: '0.5rem', fontWeight: 600 }}>{act.action_type.replace('BLOCK_', 'Block ')}</td>
                        <td style={{ padding: '0.5rem', fontFamily: 'monospace' }}>{act.target}</td>
                        <td style={{ padding: '0.5rem' }}>{getStatusBadge(act.status)}</td>
                        <td style={{ padding: '0.5rem', color: 'var(--text-secondary)' }}>
                          {act.execution_details?.provider_message || act.failure_reason || act.rejection_reason || 'Pending execution'}
                        </td>
                        <td style={{ padding: '0.5rem', textAlign: 'right' }}>
                          <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end' }}>
                            {act.status === 'REQUESTED' && (
                              <>
                                <button
                                  className="btn-primary"
                                  style={{ padding: '0.25rem 0.55rem', fontSize: '0.75rem' }}
                                  onClick={() => handleAuthorize(act.id)}
                                  disabled={submitting}
                                >
                                  Approve
                                </button>
                                <button
                                  className="btn-secondary"
                                  style={{ padding: '0.25rem 0.55rem', fontSize: '0.75rem', borderColor: 'var(--color-dangerous)', color: 'var(--color-dangerous)' }}
                                  onClick={() => setRejectingActionId(act.id)}
                                  disabled={submitting}
                                >
                                  Deny
                                </button>
                              </>
                            )}

                            {act.status === 'AUTHORIZED' && (
                              <>
                                <button
                                  className="btn-primary"
                                  style={{ padding: '0.25rem 0.55rem', fontSize: '0.75rem', background: 'var(--color-safe)', border: 'none' }}
                                  onClick={() => handleExecute(act.id)}
                                  disabled={submitting}
                                >
                                  Apply Block
                                </button>
                                <button
                                  className="btn-secondary"
                                  style={{ padding: '0.25rem 0.55rem', fontSize: '0.75rem' }}
                                  onClick={() => setRejectingActionId(act.id)}
                                  disabled={submitting}
                                >
                                  Cancel
                                </button>
                              </>
                            )}

                            {act.status === 'EXECUTED' && (
                              <span style={{ fontSize: '0.75rem', color: 'var(--color-safe)', fontWeight: 600 }}>
                                ✓ Active
                              </span>
                            )}

                            {act.status === 'FAILED' && (
                              <span style={{ fontSize: '0.75rem', color: 'var(--color-dangerous)', fontWeight: 600 }}>
                                ❌ Failed
                              </span>
                            )}

                            {act.status === 'REJECTED' && (
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                Denied
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontStyle: 'italic', padding: '0.5rem 0' }}>
                No active blocks. You can block senders, domains, and IPs observed in this email above.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Reject Modal */}
      {rejectingActionId && (
        <div
          style={{
            position: 'fixed',
            top: 0, left: 0, right: 0, bottom: 0,
            backgroundColor: 'rgba(0,0,0,0.6)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 9999,
          }}
        >
          <div style={{ background: 'var(--bg-card)', padding: '1.5rem', borderRadius: '8px', width: '90%', maxWidth: '420px', border: '1px solid var(--border-color)' }}>
            <h4 style={{ marginBottom: '0.75rem' }}>Reject Enforcement Action</h4>
            <textarea
              className="input-field"
              rows={3}
              placeholder="Enter mandatory justification for rejection..."
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              style={{ width: '100%', marginBottom: '1rem' }}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              <button className="btn-secondary" onClick={() => setRejectingActionId(null)}>Cancel</button>
              <button className="btn-primary" onClick={handleReject} disabled={!rejectReason.trim() || submitting}>
                Confirm Rejection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
