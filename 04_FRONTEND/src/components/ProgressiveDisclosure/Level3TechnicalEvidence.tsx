import React, { useState } from 'react';
import { AnalysisResult } from '../../../contract';

interface Props {
  result: AnalysisResult;
}

export const Level3TechnicalEvidence: React.FC<Props> = ({ result }) => {
  const [activeTab, setActiveTab] = useState<'routing' | 'auth' | 'identity' | 'domain' | 'links' | 'attachments'>('routing');
  const [isOpen, setIsOpen] = useState(true);
  const [sandboxUrl, setSandboxUrl] = useState<string | null>(null);
  const [sandboxLoading, setSandboxLoading] = useState(false);

  const { routing, authentication, identity, domain, links, attachments } = result;

  return (
    <div className="card">
      <div
        className="card-header"
        style={{ cursor: 'pointer', marginBottom: isOpen ? '1rem' : 0 }}
        onClick={() => setIsOpen(!isOpen)}
      >
        <div className="card-title">
          <span>Level 3: Technical Forensic Evidence</span>
        </div>
        <span style={{ fontSize: '0.85rem', color: 'var(--color-primary)', fontWeight: 600 }}>
          {isOpen ? '▲ Collapse' : '▼ Expand'}
        </span>
      </div>

      {isOpen && (
        <div>
          {/* Sub-tabs */}
          <div className="tabs-nav">
            <button
              className={`tab-btn ${activeTab === 'routing' ? 'active' : ''}`}
              onClick={() => setActiveTab('routing')}
            >
              Routing & Origin IP ({routing.hops.length} hops)
            </button>
            <button
              className={`tab-btn ${activeTab === 'auth' ? 'active' : ''}`}
              onClick={() => setActiveTab('auth')}
            >
              Authentication (SPF/DKIM/DMARC)
            </button>
            <button
              className={`tab-btn ${activeTab === 'identity' ? 'active' : ''}`}
              onClick={() => setActiveTab('identity')}
            >
              Identity & Sender
            </button>
            <button
              className={`tab-btn ${activeTab === 'domain' ? 'active' : ''}`}
              onClick={() => setActiveTab('domain')}
            >
              Domain Forensics
            </button>
            <button
              className={`tab-btn ${activeTab === 'links' ? 'active' : ''}`}
              onClick={() => setActiveTab('links')}
            >
              Links ({links.length})
            </button>
            <button
              className={`tab-btn ${activeTab === 'attachments' ? 'active' : ''}`}
              onClick={() => setActiveTab('attachments')}
            >
              Attachments ({attachments.length})
            </button>
          </div>

          {/* TAB 1: Routing */}
          {activeTab === 'routing' && (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
                <div style={{ background: 'var(--bg-secondary)', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>CANDIDATE PROBABLE-ORIGIN IP</div>
                  <div className="font-mono" style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-primary)' }}>
                    {routing.candidateProbableOriginIp || 'Indeterminate'}
                  </div>
                </div>
                <div style={{ background: 'var(--bg-secondary)', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>ORIGIN CONFIDENCE</div>
                  <div style={{ fontSize: '0.95rem', fontWeight: 600, textTransform: 'capitalize' }}>
                    {routing.candidateOriginConfidence}
                  </div>
                </div>
              </div>

              <table className="data-table">
                <thead>
                  <tr>
                    <th>Hop</th>
                    <th>Receiving Server</th>
                    <th>Observed IP</th>
                    <th>Trust Status</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {routing.hops.map((h, i) => (
                    <tr key={i}>
                      <td>#{h.hopIndex}</td>
                      <td className="font-mono">{h.receivingServer || '—'}</td>
                      <td className="font-mono">{h.observedIp || '—'}</td>
                      <td>
                        <span style={{
                          color: h.trustStatus === 'trusted' ? 'var(--color-safe)' : 'var(--color-caution)',
                          fontWeight: 600,
                          fontSize: '0.8rem',
                        }}>
                          {(h.trustStatus || 'neutral').toUpperCase()}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{h.timestamp || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 2: Authentication */}
          {activeTab === 'auth' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
              {(['spf', 'dkim', 'dmarc', 'alignment'] as const).map((proto) => {
                const item = authentication[proto];
                const isPass = item.result === 'pass';
                return (
                  <div key={proto} style={{ background: 'var(--bg-secondary)', padding: '1rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                      <span style={{ fontWeight: 700, textTransform: 'uppercase' }}>{proto}</span>
                      <span style={{
                        fontWeight: 700,
                        color: isPass ? 'var(--color-safe)' : 'var(--color-dangerous)',
                        textTransform: 'uppercase',
                        fontSize: '0.85rem',
                      }}>
                        {item.result}
                      </span>
                    </div>
                    <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                      {item.explanation}
                    </p>
                    <div className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {item.technicalDetails}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* TAB 3: Identity */}
          {activeTab === 'identity' && (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
                <div style={{ background: 'var(--bg-secondary)', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>FROM ADDRESS</div>
                  <div className="font-mono" style={{ fontSize: '0.9rem' }}>{identity.from}</div>
                </div>
                <div style={{ background: 'var(--bg-secondary)', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>DISPLAY NAME</div>
                  <div style={{ fontSize: '0.9rem' }}>{identity.displayName || '—'}</div>
                </div>
                <div style={{ background: 'var(--bg-secondary)', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>REPLY-TO</div>
                  <div className="font-mono" style={{ fontSize: '0.9rem' }}>{identity.replyTo || '—'}</div>
                </div>
              </div>

              {identity.mismatches.length > 0 && (
                <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', padding: '0.75rem', borderRadius: '6px', marginTop: '0.75rem' }}>
                  <h5 style={{ color: 'var(--color-dangerous)', marginBottom: '0.25rem' }}>Identity Mismatches Detected:</h5>
                  <ul style={{ paddingLeft: '1.25rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    {identity.mismatches.map((m, i) => <li key={i}>{m}</li>)}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: Domain */}
          {activeTab === 'domain' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem' }}>
              <div style={{ background: 'var(--bg-secondary)', padding: '0.75rem', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>SENDER DOMAIN</div>
                <div className="font-mono" style={{ fontSize: '0.95rem', fontWeight: 600 }}>{domain.senderDomain}</div>
              </div>
              <div style={{ background: 'var(--bg-secondary)', padding: '0.75rem', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>PROTECTED BRAND MATCH</div>
                <div style={{ fontSize: '0.95rem', color: domain.protectedBrandMatch ? 'var(--color-dangerous)' : 'var(--text-primary)', fontWeight: 600 }}>
                  {domain.protectedBrandMatch || 'None'}
                </div>
              </div>
              <div style={{ background: 'var(--bg-secondary)', padding: '0.75rem', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>PUNYCODE / HOMOGLYPHS</div>
                <div style={{ fontSize: '0.95rem' }}>
                  {domain.isPunycode ? 'Punycode Detected (xn--)' : 'Standard ASCII'}
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: Links */}
          {activeTab === 'links' && (
            <div>
              {links.length === 0 ? (
                <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>No links extracted from message body.</p>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Display Text</th>
                      <th>Target Domain</th>
                      <th>Href Destination</th>
                      <th>Suspicious Indicators</th>
                      <th>Blocklist</th>
                        <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {links.map((lnk, i) => (
                      <tr key={i}>
                        <td style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>{lnk.visibleText}</td>
                        <td className="font-mono">{lnk.actualDomain}</td>
                        <td className="font-mono" style={{ maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', color: 'var(--text-muted)' }}>
                          {lnk.actualHref}
                        </td>
                        <td>
                          {lnk.suspiciousIndicators.map((ind, j) => (
                            <span key={j} style={{ background: 'rgba(239, 68, 68, 0.15)', color: 'var(--color-dangerous)', padding: '0.1rem 0.4rem', borderRadius: '4px', fontSize: '0.75rem', marginRight: '0.25rem' }}>
                              {ind}
                            </span>
                          ))}
                        </td>
                        <td>
                          <span style={{ fontSize: '0.8rem', color: lnk.blocklistMatch === 'match' ? 'var(--color-dangerous)' : 'var(--text-muted)' }}>
                            {lnk.blocklistMatch}
                          </span>
                          </td>
                          <td>
                            <button 
                              className="btn-secondary" 
                              style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem', whiteSpace: 'nowrap' }}
                              onClick={() => {
                                setSandboxUrl(lnk.actualHref);
                                setSandboxLoading(true);
                              }}
                            >
                              View in Sandbox
                            </button>
                          </td>
                        </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* TAB 6: Attachments */}
          {activeTab === 'attachments' && (
            <div>
              {attachments.length === 0 ? (
                <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>No attachments found in this email.</p>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Filename</th>
                      <th>MIME Type</th>
                      <th>Size</th>
                      <th>SHA-256</th>
                      <th>Indicators</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attachments.map((att, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 600 }}>{att.filename}</td>
                        <td className="font-mono">{att.mimeType}</td>
                        <td>{(att.sizeBytes / 1024).toFixed(1)} KB</td>
                        <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{att.sha256}</td>
                        <td>
                          {att.suspiciousIndicators.map((ind, j) => (
                            <span key={j} style={{ background: 'rgba(239, 68, 68, 0.15)', color: 'var(--color-dangerous)', padding: '0.1rem 0.4rem', borderRadius: '4px', fontSize: '0.75rem', marginRight: '0.25rem' }}>
                              {ind}
                            </span>
                          ))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      )}

      {sandboxUrl && (
        <div className="modal-overlay" onClick={() => setSandboxUrl(null)}>
          <div className="modal-content" onClick={e => e.stopPropagation()} style={{ maxWidth: '800px', width: '90%' }}>
            <h3 style={{ marginBottom: '1rem' }}>Defanged Sandbox View</h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1rem', wordBreak: 'break-all' }}>{sandboxUrl}</p>
            <div style={{ background: '#000', borderRadius: '4px', minHeight: '300px', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
              {sandboxLoading && <div style={{ color: '#fff' }}>Loading Sandbox Environment...</div>}
              <img 
                src={`http://localhost:8000/api/v1/sandbox/screenshot?url=${encodeURIComponent(sandboxUrl)}`} 
                alt="Sandbox"
                style={{ maxWidth: '100%', display: sandboxLoading ? 'none' : 'block' }}
                onLoad={() => setSandboxLoading(false)}
                onError={() => setSandboxLoading(false)}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1rem' }}>
              <button className="btn-secondary" onClick={() => setSandboxUrl(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
