import React, { useState, useEffect } from 'react';
import { EmployeeTokenResponse, EmployeeScanResult } from '../../contract';
import {
  verifyEmployeeSecretCode,
  scanEmailAsEmployee,
  reportThreatToSoc,
} from '../services/api';

interface Props {
  onBackToAdmin?: () => void;
}

export const EmployeePortal: React.FC<Props> = ({ onBackToAdmin }) => {
  const [profile, setProfile] = useState<EmployeeTokenResponse | null>(() => {
    try {
      const stored = localStorage.getItem('employee_profile');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  // Secret code login state
  const [code, setCode] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get('code') || '';
  });
  const [isVerifying, setIsVerifying] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);

  // Email scanner state
  const [file, setFile] = useState<File | null>(null);
  const [rawText, setRawText] = useState('');
  const [inputMode, setInputMode] = useState<'upload' | 'paste'>('upload');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<EmployeeScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Reporting state
  const [isReporting, setIsReporting] = useState(false);
  const [reportSuccess, setReportSuccess] = useState(false);
  const [employeeNotes, setEmployeeNotes] = useState('');

  // Auto-verify if code is present in query parameters
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const codeParam = params.get('code');
    if (codeParam && !profile) {
      handleCodeSubmit(codeParam);
    }
  }, []);

  const handleCodeSubmit = async (codeToVerify: string) => {
    if (!codeToVerify.trim()) return;
    try {
      setIsVerifying(true);
      setLoginError(null);
      const data = await verifyEmployeeSecretCode(codeToVerify.trim());
      setProfile(data);
    } catch (err: any) {
      setLoginError(err.message || 'Invalid or revoked secret access code.');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('employee_token');
    localStorage.removeItem('employee_profile');
    setProfile(null);
    setScanResult(null);
    setFile(null);
    setRawText('');
    setReportSuccess(false);
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file && !rawText.trim()) return;
    try {
      setIsScanning(true);
      setScanError(null);
      setScanResult(null);
      setReportSuccess(false);

      const result = await scanEmailAsEmployee(
        inputMode === 'upload' ? (file || undefined) : undefined,
        inputMode === 'paste' ? rawText : undefined,
        file ? file.name : 'Pasted Email'
      );
      setScanResult(result);
    } catch (err: any) {
      setScanError(err.message || 'Failed to scan email.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleReport = async () => {
    if (!scanResult) return;
    try {
      setIsReporting(true);
      await reportThreatToSoc(scanResult.investigation_id, employeeNotes || 'Reported by employee');
      setReportSuccess(true);
    } catch (err: any) {
      alert('Could not report threat: ' + (err.message || 'Error'));
    } finally {
      setIsReporting(false);
    }
  };

  // 1. Code verification view
  if (!profile) {
    return (
      <div style={{
        minHeight: '100vh',
        background: 'linear-gradient(135deg, #090d16 0%, #0f172a 100%)',
        color: '#f8fafc',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
      }}>
        <div style={{
          maxWidth: '480px',
          width: '100%',
          background: '#1e293b',
          borderRadius: '16px',
          padding: '36px 32px',
          border: '1px solid #334155',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
          textAlign: 'center',
        }}>
          <div style={{
            width: '48px',
            height: '48px',
            borderRadius: '12px',
            background: '#2563eb',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '24px',
            fontWeight: 800,
            marginBottom: '16px',
          }}>
            0
          </div>
          <h1 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc' }}>
            HopZero Employee Portal
          </h1>
          <p style={{ margin: '8px 0 24px', fontSize: '0.875rem', color: '#94a3b8' }}>
            Instant email threat detection for company employees. Enter the secret access code sent by your security team.
          </p>

          {loginError && (
            <div style={{
              background: 'rgba(239, 68, 68, 0.15)',
              color: '#fca5a5',
              padding: '10px 14px',
              borderRadius: '8px',
              marginBottom: '16px',
              fontSize: '0.85rem',
              border: '1px solid rgba(239, 68, 68, 0.3)',
            }}>
              ⚠️ {loginError}
            </div>
          )}

          <form onSubmit={(e) => { e.preventDefault(); handleCodeSubmit(code); }}>
            <label style={{
              display: 'block',
              textAlign: 'left',
              fontSize: '0.75rem',
              fontWeight: 700,
              color: '#cbd5e1',
              marginBottom: '6px',
              letterSpacing: '1px',
            }}>
              YOUR SECRET PAIRING CODE
            </label>
            <input
              type="text"
              required
              autoFocus
              placeholder="e.g. HZ-8X42-M9K"
              value={code}
              onChange={(e) => setCode(e.target.value.toUpperCase())}
              style={{
                width: '100%',
                padding: '14px',
                borderRadius: '8px',
                background: '#0f172a',
                border: '2px solid #3b82f6',
                color: '#60a5fa',
                fontFamily: 'monospace',
                fontSize: '1.4rem',
                fontWeight: 800,
                letterSpacing: '3px',
                textAlign: 'center',
                boxSizing: 'border-box',
                marginBottom: '18px',
              }}
            />

            <button
              type="submit"
              className="btn-primary"
              disabled={isVerifying || !code.trim()}
              style={{
                width: '100%',
                padding: '12px',
                fontSize: '1rem',
                fontWeight: 700,
                borderRadius: '8px',
                cursor: 'pointer',
              }}
            >
              {isVerifying ? 'Verifying Code...' : '🔓 Access Threat Scanner'}
            </button>
          </form>

          {onBackToAdmin && (
            <div style={{ marginTop: '24px', borderTop: '1px solid #334155', paddingTop: '16px' }}>
              <button
                onClick={onBackToAdmin}
                className="btn-secondary"
                style={{ fontSize: '0.8rem', padding: '6px 12px' }}
              >
                ← Back to SOC Admin Console
              </button>
            </div>
          )}
        </div>
      </div>
    );
  }

  // 2. Authenticated Employee Scanner view
  return (
    <div style={{ minHeight: '100vh', background: '#090d16', color: '#f8fafc' }}>
      {/* Employee Navbar */}
      <header style={{
        background: '#0f172a',
        padding: '14px 28px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        borderBottom: '1px solid #1e293b',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: '8px',
            background: '#2563eb',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontWeight: 800,
          }}>
            0
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: '1rem', color: '#f8fafc' }}>HopZero Threat Scanner</div>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{profile.organization_name} Defense</div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ textAlign: 'right', fontSize: '0.8rem' }}>
            <div style={{ fontWeight: 600, color: '#f1f5f9' }}>{profile.employee_name || profile.employee_email}</div>
            <div style={{ color: '#64748b', fontSize: '0.75rem' }}>{profile.department || 'Enrolled Employee'}</div>
          </div>
          <button
            onClick={handleLogout}
            className="btn-secondary"
            style={{ padding: '6px 12px', fontSize: '0.8rem' }}
          >
            Sign Out
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main style={{ maxWidth: '800px', margin: '32px auto', padding: '0 20px' }}>
        <div style={{
          background: '#1e293b',
          borderRadius: '12px',
          padding: '24px 28px',
          border: '1px solid #334155',
          boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.4)',
        }}>
          <h2 style={{ margin: '0 0 6px', fontSize: '1.25rem', color: '#f8fafc' }}>
            🔍 Scan Suspicious Email
          </h2>
          <p style={{ margin: '0 0 20px', fontSize: '0.85rem', color: '#94a3b8' }}>
            Suspect an email might be phishing or a scam? Upload the <code>.eml</code> file or paste its content below for an immediate safety verdict.
          </p>

          {/* Toggle upload mode */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
            <button
              className={`btn-${inputMode === 'upload' ? 'primary' : 'secondary'}`}
              onClick={() => setInputMode('upload')}
              style={{ padding: '6px 14px', fontSize: '0.85rem' }}
            >
              📁 Upload Email File (.eml)
            </button>
            <button
              className={`btn-${inputMode === 'paste' ? 'primary' : 'secondary'}`}
              onClick={() => setInputMode('paste')}
              style={{ padding: '6px 14px', fontSize: '0.85rem' }}
            >
              📝 Paste Raw Email Text
            </button>
          </div>

          <form onSubmit={handleScan}>
            {inputMode === 'upload' ? (
              <div style={{
                border: '2px dashed #475569',
                borderRadius: '8px',
                padding: '28px',
                textAlign: 'center',
                background: '#0f172a',
                cursor: 'pointer',
                marginBottom: '16px',
              }}>
                <input
                  type="file"
                  id="emailFileInput"
                  accept=".eml,.msg"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                  style={{ display: 'none' }}
                />
                <label htmlFor="emailFileInput" style={{ cursor: 'pointer', display: 'block' }}>
                  <div style={{ fontSize: '2rem', marginBottom: '8px' }}>📩</div>
                  {file ? (
                    <div style={{ fontWeight: 600, color: '#60a5fa' }}>Selected: {file.name}</div>
                  ) : (
                    <div>
                      <div style={{ fontWeight: 600, color: '#f1f5f9' }}>Click to select an email file (.eml)</div>
                      <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '4px' }}>Drag and drop supported</div>
                    </div>
                  )}
                </label>
              </div>
            ) : (
              <div style={{ marginBottom: '16px' }}>
                <textarea
                  rows={6}
                  placeholder="Paste email headers and body here..."
                  value={rawText}
                  onChange={(e) => setRawText(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '12px',
                    borderRadius: '8px',
                    background: '#0f172a',
                    border: '1px solid #334155',
                    color: '#fff',
                    fontFamily: 'monospace',
                    fontSize: '0.85rem',
                    boxSizing: 'border-box',
                  }}
                />
              </div>
            )}

            {scanError && (
              <div style={{ background: '#7f1d1d', color: '#fecaca', padding: '10px', borderRadius: '6px', marginBottom: '16px', fontSize: '0.85rem' }}>
                ⚠️ {scanError}
              </div>
            )}

            <button
              type="submit"
              className="btn-primary"
              disabled={isScanning || (!file && !rawText.trim())}
              style={{ width: '100%', padding: '12px', fontSize: '1rem', fontWeight: 700 }}
            >
              {isScanning ? '⚙️ Inspecting Forensic Indicators...' : '🔍 Analyze Email Threat Level'}
            </button>
          </form>
        </div>

        {/* Scan Results (Level 1 & Level 2 Progressive Disclosure) */}
        {scanResult && (
          <div style={{
            marginTop: '24px',
            background: '#1e293b',
            borderRadius: '12px',
            padding: '24px 28px',
            border: '1px solid #334155',
          }}>
            {/* Verdict Badge */}
            <div style={{
              borderRadius: '10px',
              padding: '20px 24px',
              color: '#ffffff',
              background: scanResult.verdict === 'DANGEROUS'
                ? 'linear-gradient(135deg, #b91c1c, #7f1d1d)'
                : scanResult.verdict === 'SUSPICIOUS'
                ? 'linear-gradient(135deg, #b45309, #78350f)'
                : 'linear-gradient(135deg, #15803d, #14532d)',
              marginBottom: '20px',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <span style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '1px', opacity: 0.9 }}>
                    CONSUMER VERDICT
                  </span>
                  <div style={{ fontSize: '2rem', fontWeight: 900, letterSpacing: '1px' }}>
                    {scanResult.verdict === 'DANGEROUS' && '🚨 DANGEROUS PHISHING'}
                    {scanResult.verdict === 'SUSPICIOUS' && '⚠️ SUSPICIOUS ANOMALY'}
                    {scanResult.verdict === 'SAFE' && '✅ VERIFIED SAFE'}
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '1.75rem', fontWeight: 800 }}>
                    {scanResult.score} <span style={{ fontSize: '1rem', opacity: 0.8 }}>/ 100</span>
                  </div>
                  <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>Threat Score</div>
                </div>
              </div>

              <div style={{ marginTop: '12px', fontSize: '0.95rem', lineHeight: 1.4, borderTop: '1px solid rgba(255,255,255,0.2)', paddingTop: '10px' }}>
                {scanResult.one_line_explanation}
              </div>
            </div>

            {/* Level 2: Recommended Action & Why */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '16px' }}>
              <div style={{ background: '#0f172a', padding: '16px 20px', borderRadius: '8px', border: '1px solid #334155' }}>
                <h4 style={{ margin: '0 0 6px', color: '#60a5fa', fontSize: '0.85rem', textTransform: 'uppercase' }}>
                  What You Should Do:
                </h4>
                <p style={{ margin: 0, fontSize: '0.95rem', color: '#f1f5f9', fontWeight: 600 }}>
                  {scanResult.action_recommendation}
                </p>
              </div>

              <div style={{ background: '#0f172a', padding: '16px 20px', borderRadius: '8px', border: '1px solid #334155' }}>
                <h4 style={{ margin: '0 0 6px', color: '#94a3b8', fontSize: '0.85rem', textTransform: 'uppercase' }}>
                  Why This Verdict Was Reached:
                </h4>
                <p style={{ margin: 0, fontSize: '0.875rem', color: '#cbd5e1', lineHeight: 1.5 }}>
                  {scanResult.why_explanation}
                </p>
              </div>
            </div>

            {/* Report to SOC Section */}
            <div style={{
              marginTop: '24px',
              paddingTop: '20px',
              borderTop: '1px solid #334155',
            }}>
              {reportSuccess ? (
                <div style={{
                  background: 'rgba(34, 197, 94, 0.15)',
                  border: '1px solid #22c55e',
                  color: '#86efac',
                  padding: '16px 20px',
                  borderRadius: '8px',
                  textAlign: 'center',
                }}>
                  <div style={{ fontSize: '1.2rem', fontWeight: 700 }}>✓ Incident Escalated to SOC Team</div>
                  <div style={{ fontSize: '0.85rem', marginTop: '4px' }}>
                    Your report has been tagged with your identity (<code>{profile.employee_email}</code>) and sent directly to the security administrator's queue for investigation.
                  </div>
                </div>
              ) : (
                <div>
                  <h4 style={{ margin: '0 0 8px', fontSize: '0.95rem', color: '#f8fafc' }}>
                    🚨 Report This Email to Your SOC Security Team
                  </h4>
                  <p style={{ margin: '0 0 12px', fontSize: '0.8rem', color: '#94a3b8' }}>
                    Clicking report immediately flags this email on your administrator's dashboard so analysts can quarantine it across the company.
                  </p>
                  <input
                    type="text"
                    placeholder="Optional: Add a note (e.g., 'Received from unknown vendor asking for gift cards')"
                    value={employeeNotes}
                    onChange={(e) => setEmployeeNotes(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '10px 12px',
                      borderRadius: '6px',
                      background: '#0f172a',
                      border: '1px solid #334155',
                      color: '#fff',
                      fontSize: '0.85rem',
                      boxSizing: 'border-box',
                      marginBottom: '12px',
                    }}
                  />
                  <button
                    onClick={handleReport}
                    disabled={isReporting}
                    style={{
                      width: '100%',
                      padding: '12px',
                      background: '#dc2626',
                      color: '#ffffff',
                      border: 'none',
                      borderRadius: '8px',
                      fontWeight: 700,
                      fontSize: '0.95rem',
                      cursor: 'pointer',
                    }}
                  >
                    {isReporting ? 'Escalating to SOC...' : '🚨 Report to SOC Security Team'}
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
};
