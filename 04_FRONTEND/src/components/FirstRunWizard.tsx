import React, { useState, useEffect } from 'react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onOpenUpload?: () => void;
}

export const FirstRunWizard: React.FC<Props> = ({ isOpen, onClose, onOpenUpload }) => {
  const [step, setStep] = useState(1);
  const [dontShowAgain, setDontShowAgain] = useState(true);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        handleDismiss();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, dontShowAgain]);

  if (!isOpen) return null;

  const handleDismiss = () => {
    if (dontShowAgain) {
      localStorage.setItem('hopzero_first_run_completed', 'true');
    }
    onClose();
  };

  const handleCompleteAndUpload = () => {
    handleDismiss();
    if (onOpenUpload) {
      onOpenUpload();
    }
  };

  return (
    <div 
      className="modal-overlay" 
      role="dialog" 
      aria-modal="true" 
      aria-labelledby="wizard-title"
      style={{ zIndex: 1100 }}
    >
      <div 
        className="modal-content" 
        style={{ maxWidth: '640px', width: '92%', padding: '2rem' }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span style={{ 
              background: 'var(--accent-primary, #0ea5e9)', 
              color: '#fff', 
              fontSize: '0.75rem', 
              fontWeight: 700, 
              padding: '0.2rem 0.5rem', 
              borderRadius: '4px' 
            }}>
              v4.2.0
            </span>
            <h3 id="wizard-title" style={{ margin: 0, fontSize: '1.25rem' }}>
              Welcome to HopZero SOC Suite
            </h3>
          </div>
          <button 
            onClick={handleDismiss} 
            aria-label="Close onboarding wizard"
            style={{ 
              background: 'transparent', 
              border: 'none', 
              color: 'var(--text-muted, #94a3b8)', 
              fontSize: '1.25rem', 
              cursor: 'pointer' 
            }}
          >
            ✕
          </button>
        </div>

        {/* Step Indicator */}
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
          {[1, 2, 3].map((s) => (
            <div
              key={s}
              style={{
                flex: 1,
                height: '4px',
                borderRadius: '2px',
                background: s <= step ? 'var(--accent-primary, #0ea5e9)' : 'var(--border-color, #334155)',
                transition: 'background 0.3s ease',
              }}
            />
          ))}
        </div>

        {/* Step 1: Core Architecture */}
        {step === 1 && (
          <div>
            <h4 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: 'var(--text-primary)' }}>
              100% On-Premises & Deterministic Forensics
            </h4>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.5', marginBottom: '1rem' }}>
              HopZero is an enterprise digital email forensics suite built for incident responders and SOC analysts.
              It parses raw RFC 5322 MIME messages in an isolated sandbox and scores attacks through a mathematical 41-rule qualification registry.
            </p>
            <ul style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', lineHeight: '1.6', paddingLeft: '1.25rem', marginBottom: '1.5rem' }}>
              <li><strong>Zero Cloud Telemetry</strong>: No email headers or bodies ever leave your local host.</li>
              <li><strong>Zero LLM Scoring Drift</strong>: Threat scoring is purely deterministic; AI reasoning is strictly advisory.</li>
              <li><strong>Subprocess Parser Wall</strong>: Untrusted inputs are isolated with 100MB RAM, depth &lt;= 2, and 15s execution limits.</li>
            </ul>
          </div>
        )}

        {/* Step 2: 5-Level Progressive Disclosure */}
        {step === 2 && (
          <div>
            <h4 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: 'var(--text-primary)' }}>
              5 Levels of Progressive Disclosure
            </h4>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '1rem' }}>
              HopZero adapts to both tier-1 frontline operators and forensic court witnesses:
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '1.5rem' }}>
              <div style={{ padding: '0.5rem 0.75rem', background: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ color: 'var(--accent-primary)', fontWeight: 600, fontSize: '0.85rem' }}>L1 Consumer Verdict</span>: Instant plain-English safety status.
              </div>
              <div style={{ padding: '0.5rem 0.75rem', background: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ color: 'var(--accent-primary)', fontWeight: 600, fontSize: '0.85rem' }}>L2 Why & Action</span>: Specific threat factors and human-gated ActionDrafts.
              </div>
              <div style={{ padding: '0.5rem 0.75rem', background: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ color: 'var(--accent-primary)', fontWeight: 600, fontSize: '0.85rem' }}>L3 Technical Evidence</span>: Hop lineage, SPF/DKIM/DMARC, lookalike analysis.
              </div>
              <div style={{ padding: '0.5rem 0.75rem', background: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ color: 'var(--accent-primary)', fontWeight: 600, fontSize: '0.85rem' }}>L4 41-Rule Findings</span>: Full breakdown across 9 capped score buckets.
              </div>
              <div style={{ padding: '0.5rem 0.75rem', background: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ color: 'var(--accent-primary)', fontWeight: 600, fontSize: '0.85rem' }}>L5 Audit & Export</span>: SHA-256 reproducibility fingerprint & Section 63 BSA evidence package.
              </div>
            </div>
          </div>
        )}

        {/* Step 3: Getting Started */}
        {step === 3 && (
          <div>
            <h4 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: 'var(--text-primary)' }}>
              Ready to Investigate
            </h4>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.5', marginBottom: '1rem' }}>
              You are all set. You can ingest your first raw <code>.eml</code> file, explore pre-loaded forensic test cases, or inspect BotChain Studio tool integrations.
            </p>
            <div style={{ padding: '0.75rem 1rem', background: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border-color)', marginBottom: '1.5rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              <strong>Tip</strong>: Run <code>python scripts/doctor.py</code> anytime from the terminal to verify local services, database integrity, and Ollama model residency.
            </div>
          </div>
        )}

        {/* Footer Controls */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color)' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.825rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <input 
              type="checkbox" 
              checked={dontShowAgain} 
              onChange={(e) => setDontShowAgain(e.target.checked)} 
              aria-label="Do not show this welcome guide again"
            />
            Don't show this again
          </label>

          <div style={{ display: 'flex', gap: '0.75rem' }}>
            {step > 1 && (
              <button
                type="button"
                onClick={() => setStep(step - 1)}
                className="btn-secondary"
                style={{ padding: '0.4rem 0.85rem', fontSize: '0.85rem' }}
              >
                Back
              </button>
            )}
            {step < 3 ? (
              <button
                type="button"
                onClick={() => setStep(step + 1)}
                className="btn-primary"
                style={{ padding: '0.4rem 1rem', fontSize: '0.85rem' }}
              >
                Next
              </button>
            ) : (
              <button
                type="button"
                onClick={handleCompleteAndUpload}
                className="btn-primary"
                style={{ padding: '0.4rem 1.1rem', fontSize: '0.85rem' }}
              >
                Ingest Evidence
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
