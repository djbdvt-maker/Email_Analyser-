import React, { useState, useEffect } from 'react';
import { EmployeeCodeItem } from '../../contract';
import {
  fetchEmployeeCodes,
  generateEmployeeCode,
  resendEmployeeInvitation,
  revokeEmployeeCode,
} from '../services/api';

interface Props {
  onClose: () => void;
}

export const EmployeeManagementModal: React.FC<Props> = ({ onClose }) => {
  const [codes, setCodes] = useState<EmployeeCodeItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Form states
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [department, setDepartment] = useState('');
  const [sendEmail, setSendEmail] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [newlyCreated, setNewlyCreated] = useState<EmployeeCodeItem | null>(null);

  const loadCodes = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchEmployeeCodes();
      setCodes(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load employee codes');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCodes();
  }, []);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;
    try {
      setIsSubmitting(true);
      setError(null);
      setSuccessMsg(null);
      const created = await generateEmployeeCode({
        employee_email: email,
        employee_name: name || undefined,
        department: department || undefined,
        send_email: sendEmail,
      });
      setNewlyCreated(created);
      setSuccessMsg(`Secret Code ${created.code} generated successfully!`);
      setEmail('');
      setName('');
      setDepartment('');
      loadCodes();
    } catch (err: any) {
      setError(err.message || 'Failed to generate code');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResend = async (codeId: string) => {
    try {
      setError(null);
      await resendEmployeeInvitation(codeId);
      setSuccessMsg('Invitation email dispatched to employee!');
      loadCodes();
    } catch (err: any) {
      setError(err.message || 'Failed to resend email');
    }
  };

  const handleRevoke = async (codeId: string) => {
    if (!window.confirm('Are you sure you want to deactivate this employee access code?')) return;
    try {
      setError(null);
      await revokeEmployeeCode(codeId);
      setSuccessMsg('Employee access code deactivated.');
      loadCodes();
    } catch (err: any) {
      setError(err.message || 'Failed to revoke code');
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSuccessMsg('Copied to clipboard!');
    setTimeout(() => setSuccessMsg(null), 3000);
  };

  const portalBase = window.location.origin;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-container"
        style={{ maxWidth: '860px', width: '92%', maxHeight: '90vh', overflowY: 'auto' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h2 style={{ margin: 0, fontSize: '1.25rem', color: '#f8fafc' }}>
              👥 Employee Access & Secret Code Distribution
            </h2>
            <p style={{ margin: '4px 0 0', fontSize: '0.85rem', color: '#94a3b8' }}>
              Issue secret pairing codes to employees. Employees get zero admin privileges and can only scan/report emails.
            </p>
          </div>
          <button
            onClick={onClose}
            className="btn-secondary"
            style={{ padding: '4px 10px', fontSize: '1rem', cursor: 'pointer' }}
          >
            ✕
          </button>
        </div>

        {error && (
          <div style={{ background: '#7f1d1d', color: '#fecaca', padding: '10px 14px', borderRadius: '6px', margin: '12px 0', fontSize: '0.875rem' }}>
            ⚠️ {error}
          </div>
        )}

        {successMsg && (
          <div style={{ background: '#14532d', color: '#bbf7d0', padding: '10px 14px', borderRadius: '6px', margin: '12px 0', fontSize: '0.875rem' }}>
            ✓ {successMsg}
          </div>
        )}

        {/* Quick Actions & Distribution */}
        <div style={{
          display: 'flex',
          gap: '12px',
          margin: '12px 0 16px',
          background: 'rgba(30, 41, 59, 0.7)',
          padding: '12px 16px',
          borderRadius: '8px',
          border: '1px solid #334155',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
        }}>
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.9rem', color: '#f8fafc' }}>
              🌐 Employee Client Distribution
            </div>
            <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
              Share the standalone Employee Portal or distribute the Chrome Extension (.zip).
            </div>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={() => copyToClipboard(`${portalBase}/portal`)}
              className="btn-secondary"
              style={{ fontSize: '0.8rem', padding: '6px 12px' }}
            >
              📋 Copy Portal Link
            </button>
            <a
              href="/api/v1/admin/employees/download-extension"
              download="hopzero-employee-extension.zip"
              className="btn-primary"
              style={{ fontSize: '0.8rem', padding: '6px 12px', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              📦 Download Extension (.zip)
            </a>
          </div>
        </div>

        {/* Newly Created Code Highlight */}
        {newlyCreated && (
          <div style={{
            background: 'linear-gradient(135deg, rgba(30, 58, 138, 0.4), rgba(15, 23, 42, 0.8))',
            border: '2px dashed #3b82f6',
            borderRadius: '10px',
            padding: '16px 20px',
            margin: '16px 0',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <span style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: '#60a5fa', fontWeight: 700 }}>
                  Active Secret Code for {newlyCreated.employee_email}
                </span>
                <div style={{ fontSize: '1.75rem', fontFamily: 'monospace', fontWeight: 800, color: '#93c5fd', letterSpacing: '3px', margin: '4px 0' }}>
                  {newlyCreated.code}
                </div>
                <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
                  Direct Link: <code style={{ color: '#93c5fd' }}>{portalBase}/portal?code={newlyCreated.code}</code>
                </div>
              </div>
              <button
                className="btn-primary"
                onClick={() => copyToClipboard(`${portalBase}/portal?code=${newlyCreated.code}`)}
                style={{ padding: '8px 16px', fontSize: '0.85rem' }}
              >
                📋 Copy Link & Code
              </button>
            </div>
          </div>
        )}

        {/* Generate Form */}
        <div style={{ background: '#1e293b', padding: '16px 20px', borderRadius: '8px', margin: '16px 0', border: '1px solid #334155' }}>
          <h3 style={{ margin: '0 0 12px 0', fontSize: '1rem', color: '#f1f5f9' }}>
            ➕ Provision New Employee Secret Code
          </h3>
          <form onSubmit={handleGenerate} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
            <div>
              <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '4px' }}>EMPLOYEE EMAIL *</label>
              <input
                type="email"
                required
                placeholder="alice@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                style={{ width: '100%', padding: '8px', borderRadius: '6px', background: '#0f172a', border: '1px solid #334155', color: '#fff', fontSize: '0.85rem' }}
              />
            </div>
            <div>
              <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '4px' }}>FULL NAME</label>
              <input
                type="text"
                placeholder="Alice Smith"
                value={name}
                onChange={(e) => setName(e.target.value)}
                style={{ width: '100%', padding: '8px', borderRadius: '6px', background: '#0f172a', border: '1px solid #334155', color: '#fff', fontSize: '0.85rem' }}
              />
            </div>
            <div>
              <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '4px' }}>DEPARTMENT</label>
              <input
                type="text"
                placeholder="Finance / HR"
                value={department}
                onChange={(e) => setDepartment(e.target.value)}
                style={{ width: '100%', padding: '8px', borderRadius: '6px', background: '#0f172a', border: '1px solid #334155', color: '#fff', fontSize: '0.85rem' }}
              />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'flex-end' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <input
                  type="checkbox"
                  id="sendEmailCheck"
                  checked={sendEmail}
                  onChange={(e) => setSendEmail(e.target.checked)}
                />
                <label htmlFor="sendEmailCheck" style={{ fontSize: '0.8rem', color: '#cbd5e1', cursor: 'pointer' }}>
                  Send Invitation Email via SMTP
                </label>
              </div>
              <button
                type="submit"
                className="btn-primary"
                disabled={isSubmitting}
                style={{ width: '100%', padding: '8px 12px', fontSize: '0.85rem' }}
              >
                {isSubmitting ? 'Generating...' : '⚡ Generate Secret Code'}
              </button>
            </div>
          </form>
        </div>

        {/* Existing Issued Codes Table */}
        <div>
          <h3 style={{ margin: '16px 0 8px 0', fontSize: '1rem', color: '#f1f5f9' }}>
            📋 Enrolled Employees & Codes ({codes.length})
          </h3>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '24px', color: '#94a3b8' }}>Loading codes...</div>
          ) : codes.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '24px', color: '#64748b', background: '#1e293b', borderRadius: '8px' }}>
              No employee codes issued yet. Generate your first code above.
            </div>
          ) : (
            <div style={{ overflowX: 'auto', border: '1px solid #334155', borderRadius: '8px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.825rem' }}>
                <thead>
                  <tr style={{ background: '#0f172a', color: '#94a3b8', borderBottom: '1px solid #334155' }}>
                    <th style={{ padding: '10px 12px' }}>Employee</th>
                    <th style={{ padding: '10px 12px' }}>Department</th>
                    <th style={{ padding: '10px 12px' }}>Secret Code</th>
                    <th style={{ padding: '10px 12px' }}>Status</th>
                    <th style={{ padding: '10px 12px' }}>Scans</th>
                    <th style={{ padding: '10px 12px' }}>Reports</th>
                    <th style={{ padding: '10px 12px' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {codes.map((c) => (
                    <tr key={c.id} style={{ borderBottom: '1px solid #1e293b', color: '#cbd5e1' }}>
                      <td style={{ padding: '10px 12px' }}>
                        <div style={{ fontWeight: 600, color: '#f8fafc' }}>{c.employee_name || c.employee_email}</div>
                        <div style={{ fontSize: '0.75rem', color: '#64748b' }}>{c.employee_email}</div>
                      </td>
                      <td style={{ padding: '10px 12px' }}>{c.department || '—'}</td>
                      <td style={{ padding: '10px 12px' }}>
                        <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#60a5fa', background: '#0f172a', padding: '2px 6px', borderRadius: '4px' }}>
                          {c.code}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <span style={{
                          padding: '2px 8px',
                          borderRadius: '12px',
                          fontSize: '0.75rem',
                          fontWeight: 700,
                          background: c.is_active ? 'rgba(34, 197, 94, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                          color: c.is_active ? '#4ade80' : '#f87171',
                        }}>
                          {c.is_active ? 'Active' : 'Revoked'}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px' }}>{c.scan_count}</td>
                      <td style={{ padding: '10px 12px' }}>
                        <span style={{ fontWeight: c.report_count > 0 ? 800 : 400, color: c.report_count > 0 ? '#fbbf24' : '#94a3b8' }}>
                          {c.report_count}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px', display: 'flex', gap: '6px' }}>
                        <button
                          onClick={() => copyToClipboard(`${portalBase}/portal?code=${c.code}`)}
                          className="btn-secondary"
                          style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                          title="Copy Link & Code"
                        >
                          📋 Link
                        </button>
                        <button
                          onClick={() => handleResend(c.id)}
                          className="btn-secondary"
                          style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                          title="Resend Email"
                        >
                          ✉️ Resend
                        </button>
                        {c.is_active && (
                          <button
                            onClick={() => handleRevoke(c.id)}
                            className="btn-secondary"
                            style={{ padding: '4px 8px', fontSize: '0.75rem', color: '#f87171' }}
                            title="Revoke Access"
                          >
                            ✕
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
