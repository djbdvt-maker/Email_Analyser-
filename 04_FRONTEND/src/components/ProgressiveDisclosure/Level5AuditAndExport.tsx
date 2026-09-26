import React, { useState } from 'react';
import { AuditEntry, AnalystActionRecord, EvidenceExportInfo, AnalystActionType } from '../../../contract';

interface Props {
  investigationId: string;
  auditTrail: AuditEntry[];
  analystActions: AnalystActionRecord[];
  evidenceExport: EvidenceExportInfo;
  onPerformAction: (action: AnalystActionType, note?: string, fpReason?: string) => Promise<void>;
}

export const Level5AuditAndExport: React.FC<Props> = ({
  investigationId,
  auditTrail,
  analystActions,
  evidenceExport,
  onPerformAction,
}) => {
  const [isOpen, setIsOpen] = useState(true);
  const [noteText, setNoteText] = useState('');
  const [fpReason, setFpReason] = useState('');
  const [showFpModal, setShowFpModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleAction = async (act: AnalystActionType) => {
    if (act === 'false_positive') {
      setShowFpModal(true);
      return;
    }
    setSubmitting(true);
    await onPerformAction(act, noteText);
    setNoteText('');
    setSubmitting(false);
  };

  const submitFalsePositive = async () => {
    if (!fpReason.trim()) return;
    setSubmitting(true);
    await onPerformAction('false_positive', noteText, fpReason);
    setShowFpModal(false);
    setFpReason('');
    setNoteText('');
    setSubmitting(false);
  };

  const handleExport = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/api/v1/investigations/${investigationId}/export`, {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {}
      });
      if (!res.ok) throw new Error('Export failed');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `hopzero_investigation_${investigationId.substring(0, 8)}.zip`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (e) {
      console.error(e);
      alert('Failed to download forensic bundle.');
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
          <span>Level 5: Forensic Audit Trail & Chain of Custody</span>
        </div>
        <span style={{ fontSize: '0.85rem', color: 'var(--color-primary)', fontWeight: 600 }}>
          {isOpen ? '▲ Collapse' : '▼ Expand'}
        </span>
      </div>

      {isOpen && (
        <div>
          {/* Integrity & Export Info */}
          <div style={{ background: 'var(--bg-secondary)', padding: '1rem', borderRadius: '8px', marginBottom: '1.25rem' }}>
            <h4 style={{ fontSize: '0.95rem', marginBottom: '0.5rem' }}>Evidence Chain of Custody</h4>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem' }}>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>ORIGINAL ARTIFACT SHA-256</div>
                <div className="font-mono" style={{ fontSize: '0.8rem', wordBreak: 'break-all', color: 'var(--color-safe)' }}>
                  {evidenceExport.original_artifact_sha256}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>EXPORT BUNDLE SHA-256</div>
                <div className="font-mono" style={{ fontSize: '0.8rem', wordBreak: 'break-all', color: evidenceExport.export_bundle_sha256 ? 'var(--color-accent)' : 'var(--text-muted)' }}>
                  {evidenceExport.export_bundle_sha256 || 'Not yet exported (honest null state)'}
                </div>
              </div>
            </div>
          </div>

          {/* Analyst Actions Workflow Bar */}
          <div style={{ marginBottom: '1.5rem', background: 'var(--bg-secondary)', padding: '1rem', borderRadius: '8px' }}>
            <h4 style={{ fontSize: '0.95rem', marginBottom: '0.5rem' }}>SOC Analyst Determinations</h4>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center', marginBottom: '0.75rem' }}>
              <button
                className="btn-primary"
                style={{ background: 'var(--color-safe)' }}
                onClick={handleExport}
              >
                Download Forensic Bundle
              </button>
              <button
                className="btn-secondary"
                style={{ background: 'rgba(239, 68, 68, 0.2)', color: 'var(--color-dangerous)', borderColor: 'rgba(239, 68, 68, 0.4)' }}
                onClick={() => handleAction('confirm_malicious')}
                disabled={submitting}
              >
                Confirm Malicious
              </button>
              <button
                className="btn-secondary"
                style={{ background: 'rgba(245, 158, 11, 0.2)', color: 'var(--color-caution)', borderColor: 'rgba(245, 158, 11, 0.4)' }}
                onClick={() => handleAction('false_positive')}
                disabled={submitting}
              >
                False Positive
              </button>
              <button
                className="btn-secondary"
                onClick={() => handleAction('needs_escalation')}
                disabled={submitting}
              >
                Escalate
              </button>
              <button
                className="btn-secondary"
                onClick={() => handleAction('close')}
                disabled={submitting}
              >
                Close Case
              </button>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input
                type="text"
                placeholder="Add analyst investigation note..."
                value={noteText}
                onChange={(e) => setNoteText(e.target.value)}
                style={{
                  flex: 1,
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border-color)',
                  color: '#fff',
                  padding: '0.5rem 0.75rem',
                  borderRadius: '6px',
                  fontSize: '0.875rem',
                }}
              />
              <button
                className="btn-primary"
                onClick={() => handleAction('add_note')}
                disabled={!noteText.trim() || submitting}
              >
                Add Note
              </button>
            </div>
          </div>

          {/* Audit Trail Table */}
          <h4 style={{ fontSize: '0.95rem', marginBottom: '0.5rem' }}>Immutable Audit Trail</h4>
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Action Type</th>
                <th>Actor</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {auditTrail.length === 0 ? (
                <tr>
                  <td colSpan={4} style={{ color: 'var(--text-muted)', textAlign: 'center' }}>
                    No audit records recorded yet.
                  </td>
                </tr>
              ) : (
                auditTrail.map((entry, i) => (
                  <tr key={i}>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{entry.timestamp}</td>
                    <td>
                      <span style={{
                        background: 'rgba(59, 130, 246, 0.15)',
                        color: 'var(--color-primary)',
                        padding: '0.15rem 0.45rem',
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        textTransform: 'uppercase',
                      }}>
                        {entry.type}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.85rem' }}>{entry.actor || 'SYSTEM'}</td>
                    <td style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{entry.detail}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* False Positive Reason Modal */}
      {showFpModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3 style={{ marginBottom: '1rem' }}>Mark as False Positive</h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
              A rationale is strictly required by the SOC governance policy before marking an alert as a false positive.
            </p>
            <textarea
              placeholder="Explain why this email is legitimate (e.g. verified vendor, simulated awareness campaign)..."
              value={fpReason}
              onChange={(e) => setFpReason(e.target.value)}
              rows={4}
              style={{
                width: '100%',
                background: 'var(--bg-primary)',
                border: '1px solid var(--border-color)',
                color: '#fff',
                padding: '0.75rem',
                borderRadius: '6px',
                fontSize: '0.875rem',
                marginBottom: '1rem',
                fontFamily: 'inherit',
              }}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              <button className="btn-secondary" onClick={() => setShowFpModal(false)}>
                Cancel
              </button>
              <button className="btn-primary" onClick={submitFalsePositive} disabled={!fpReason.trim()}>
                Confirm False Positive
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
