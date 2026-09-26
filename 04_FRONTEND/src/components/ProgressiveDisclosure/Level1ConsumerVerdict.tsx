import React, { useState } from 'react';
import { AnalysisResult, InvestigationStatus, FeedbackType } from '../../../contract';

interface Props {
  status: InvestigationStatus;
  result: AnalysisResult | null;
  onSubmitFeedback?: (feedbackType: FeedbackType, note?: string) => Promise<void>;
}

export const Level1ConsumerVerdict: React.FC<Props> = ({ status, result, onSubmitFeedback }) => {
  const [showFeedbackModal, setShowFeedbackModal] = useState(false);
  const [selectedType, setSelectedType] = useState<FeedbackType>('SPAM_REPORTED');
  const [feedbackNote, setFeedbackNote] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [feedbackSuccess, setFeedbackSuccess] = useState<string | null>(null);

  if (!result) {
    return (
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div className="score-circle" style={{ borderColor: 'var(--color-primary)' }}>
            <span className="score-value" style={{ fontSize: '1rem' }}>...</span>
            <span className="score-label">STATUS</span>
          </div>
          <div>
            <h3 style={{ fontSize: '1.25rem', marginBottom: '0.25rem' }}>
              Investigation Status: <span style={{ color: 'var(--color-primary)' }}>{status}</span>
            </h3>
            <p style={{ color: 'var(--text-muted)' }}>
              Forensic analysis in progress or awaiting queued processing. Evidence integrity is preserved.
            </p>
          </div>
        </div>
      </div>
    );
  }

  const { score, severity, verdict, conclusion } = result;

  // Visual styling mapped directly from backend-authored severity — never recalculated from score thresholds
  const normSeverity = (severity || 'clean').toLowerCase();
  let verdictClass = 'verdict-safe';
  let scoreColor = 'var(--color-safe)';

  if (normSeverity === 'critical') {
    verdictClass = 'verdict-dangerous';
    scoreColor = 'var(--color-dangerous)';
  } else if (normSeverity === 'high') {
    verdictClass = 'verdict-suspicious';
    scoreColor = 'var(--color-suspicious)';
  } else if (normSeverity === 'medium') {
    verdictClass = 'verdict-caution';
    scoreColor = 'var(--color-caution)';
  } else if (normSeverity === 'low') {
    verdictClass = 'verdict-caution';
    scoreColor = 'var(--color-caution)';
  }

  // Display backend-authored verdict directly — never calculate client-side
  const consumerVerdict = verdict || 'Pending';

  const handleFeedbackSubmit = async () => {
    if (!onSubmitFeedback) return;
    setSubmitting(true);
    try {
      await onSubmitFeedback(selectedType, feedbackNote);
      setFeedbackSuccess('Feedback recorded! New forensic re-analysis run started.');
      setTimeout(() => {
        setShowFeedbackModal(false);
        setFeedbackSuccess(null);
        setFeedbackNote('');
      }, 1500);
    } catch (err: any) {
      alert(`Feedback submission failed: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="card" style={{ borderLeft: `6px solid ${scoreColor}` }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
          <div className="score-circle" style={{ borderColor: scoreColor }}>
            <span className="score-value" style={{ color: scoreColor }}>{score}</span>
            <span className="score-label">SCORE / 100</span>
          </div>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
              <span className={`verdict-badge ${verdictClass}`}>
                {consumerVerdict}
              </span>
              <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontWeight: 600 }}>
                SEVERITY: <span style={{ color: scoreColor, textTransform: 'uppercase' }}>{severity}</span>
              </span>
            </div>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              {conclusion.oneLineExplanation || verdict}
            </h2>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
          {onSubmitFeedback && (
            <button
              className="btn-secondary"
              style={{
                borderColor: 'var(--color-caution)',
                color: 'var(--color-caution)',
                padding: '0.45rem 0.85rem',
                fontSize: '0.85rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
              }}
              onClick={() => setShowFeedbackModal(true)}
            >
              <span>🚩</span> Report as Spam / Phishing
            </button>
          )}

          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Lifecycle Status
            </div>
            <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '1.1rem' }}>
              {status}
            </div>
          </div>
        </div>
      </div>

      {/* User Feedback Modal */}
      {showFeedbackModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0,0,0,0.6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
          }}
        >
          <div
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              padding: '1.5rem',
              maxWidth: '480px',
              width: '90%',
            }}
          >
            <h3 style={{ marginBottom: '0.75rem', color: 'var(--text-primary)' }}>
              User-Guided Feedback & Re-Analysis
            </h3>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem', lineHeight: 1.5 }}>
              Believe this analysis result is inaccurate? Submitting feedback triggers an auditable forensic re-analysis run without directly altering or overwriting historical verdicts.
            </p>

            {feedbackSuccess ? (
              <div style={{ padding: '1rem', background: 'rgba(16, 185, 129, 0.2)', color: 'var(--color-safe)', borderRadius: '6px', textAlign: 'center' }}>
                ✓ {feedbackSuccess}
              </div>
            ) : (
              <>
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                    Feedback Type
                  </label>
                  <select
                    className="input-field"
                    value={selectedType}
                    onChange={(e) => setSelectedType(e.target.value as FeedbackType)}
                    style={{ width: '100%' }}
                  >
                    <option value="SPAM_REPORTED">Report as Spam (SPAM_REPORTED)</option>
                    <option value="PHISHING_REPORTED">Report as Phishing (PHISHING_REPORTED)</option>
                    <option value="ANALYSIS_DISPUTED">Dispute Analysis (ANALYSIS_DISPUTED)</option>
                  </select>
                </div>

                <div style={{ marginBottom: '1.25rem' }}>
                  <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                    Analyst / User Justification Note
                  </label>
                  <textarea
                    className="input-field"
                    rows={3}
                    placeholder="e.g. Sender domain looks like typo of partner, or email requests unusual financial transfer."
                    value={feedbackNote}
                    onChange={(e) => setFeedbackNote(e.target.value)}
                    style={{ width: '100%' }}
                  />
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                  <button
                    className="btn-secondary"
                    onClick={() => setShowFeedbackModal(false)}
                    disabled={submitting}
                  >
                    Cancel
                  </button>
                  <button
                    className="btn-primary"
                    onClick={handleFeedbackSubmit}
                    disabled={submitting}
                  >
                    {submitting ? 'Starting Re-Analysis…' : 'Submit Feedback & Re-Analyze'}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
