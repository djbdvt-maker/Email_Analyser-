import React, { useState } from 'react';
import { FindingPresentation, EvidenceFact } from '../../../contract';

interface Props {
  findings: FindingPresentation[];
  evidenceFacts: EvidenceFact[];
}

export const Level4FindingsTable: React.FC<Props> = ({ findings, evidenceFacts }) => {
  const [isOpen, setIsOpen] = useState(true);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const getStrengthColor = (str: string) => {
    switch (str.toLowerCase()) {
      case 'strong': return 'var(--color-dangerous)';
      case 'moderate': return 'var(--color-caution)';
      default: return 'var(--color-primary)';
    }
  };

  const getFactDescription = (factId: string) => {
    const fact = evidenceFacts.find(f => f.factId === factId);
    return fact ? fact.description : 'Evidence fact detail unavailable';
  };

  return (
    <div className="card">
      <div
        className="card-header"
        style={{ cursor: 'pointer', marginBottom: isOpen ? '1rem' : 0 }}
        onClick={() => setIsOpen(!isOpen)}
      >
        <div className="card-title">
          <span>Level 4: Validated Security Findings ({findings.length})</span>
        </div>
        <span style={{ fontSize: '0.85rem', color: 'var(--color-primary)', fontWeight: 600 }}>
          {isOpen ? '▲ Collapse' : '▼ Expand'}
        </span>
      </div>

      {isOpen && (
        <div>
          {findings.length === 0 ? (
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>No suspicious findings detected.</p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Category</th>
                  <th>Finding & Description</th>
                  <th>Qualification Code</th>
                  <th>Strength</th>
                  <th>Citations</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f, i) => {
                  const isExp = expandedFinding === f.claim_signature;
                  return (
                    <React.Fragment key={i}>
                      <tr
                        style={{ cursor: 'pointer' }}
                        onClick={() => setExpandedFinding(isExp ? null : f.claim_signature)}
                      >
                        <td>
                          <span style={{
                            background: 'rgba(59, 130, 246, 0.15)',
                            color: 'var(--color-primary)',
                            padding: '0.2rem 0.5rem',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            fontWeight: 600,
                          }}>
                            {f.category}
                          </span>
                        </td>
                        <td>
                          <div style={{ fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            {f.display_label || f.qualification_code}
                            {f.mitre_id && (
                              <span style={{ fontSize: '0.7rem', padding: '0.1rem 0.4rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-strong)', borderRadius: '2px', color: 'var(--text-secondary)' }}>
                                {f.mitre_id}
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                            {f.supporting_text}
                          </div>
                        </td>
                        <td className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                          {f.qualification_code}
                        </td>
                        <td>
                          <span style={{
                            color: getStrengthColor(f.strength),
                            fontWeight: 700,
                            textTransform: 'uppercase',
                            fontSize: '0.8rem',
                          }}>
                            {f.strength}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontSize: '0.75rem', color: 'var(--color-primary)' }}>
                            {f.supporting_fact_ids.length} facts {isExp ? '▲' : '▼'}
                          </span>
                        </td>
                      </tr>

                      {isExp && (
                        <tr>
                          <td colSpan={5} style={{ background: 'var(--bg-secondary)', padding: '1rem' }}>
                            <div style={{ fontSize: '0.8rem', marginBottom: '0.5rem' }}>
                              <strong>Claim Signature:</strong> <span className="font-mono">{f.claim_signature}</span> | <strong>Produced By:</strong> {f.produced_by}
                            </div>
                            <div style={{ fontSize: '0.8rem', marginBottom: '0.25rem' }}><strong>Supporting Facts:</strong></div>
                            <ul style={{ paddingLeft: '1.25rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                              {f.supporting_fact_ids.map((fid, j) => (
                                <li key={j} style={{ marginBottom: '0.2rem' }}>
                                  <span className="font-mono" style={{ color: 'var(--color-accent)' }}>[{fid}]</span> {getFactDescription(fid)}
                                </li>
                              ))}
                            </ul>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
};
