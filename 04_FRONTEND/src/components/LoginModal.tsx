import React, { useState } from 'react';
import { loginUser } from '../services/api';

interface Props {
  onSuccess: () => void;
  onClose?: () => void;
  message?: string | null;
}

export const LoginModal: React.FC<Props> = ({ onSuccess, onClose, message }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(message || null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('Please enter both email and password.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await loginUser(username.trim(), password);
      onSuccess();
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Check credentials.');
    } finally {
      setLoading(false);
    }
  };

  const fillDemoCredentials = () => {
    setUsername('admin@hopzero.local');
    setPassword('changeme123');
    setError(null);
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: '420px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
          <h3>HopZero Analyst Authentication</h3>
          {onClose && (
            <button style={{ color: 'var(--text-muted)', fontSize: '1.2rem' }} onClick={onClose}>
              ✕
            </button>
          )}
        </div>

        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
          Secure authentication for SOC analysts and security operators. Role-based access control and tenant isolation are enforced by the HopZero backend.
        </p>

        {error && (
          <div
            style={{
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid var(--color-dangerous)',
              color: 'var(--color-dangerous)',
              padding: '0.6rem 0.8rem',
              borderRadius: '6px',
              marginBottom: '1rem',
              fontSize: '0.85rem',
            }}
          >
            {error}
          </div>
        )}

        <form onSubmit={handleLogin}>
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.4rem' }}>
              Analyst Email / Username
            </label>
            <input
              type="text"
              className="font-mono"
              placeholder="analyst@acme.test"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{
                width: '100%',
                padding: '0.6rem 0.75rem',
                borderRadius: '6px',
                border: '1px solid var(--border-color)',
                background: 'var(--bg-primary)',
                color: 'var(--text-primary)',
                fontSize: '0.9rem',
              }}
              autoFocus
            />
          </div>

          <div style={{ marginBottom: '1.25rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.4rem' }}>
              Password
            </label>
            <input
              type="password"
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{
                width: '100%',
                padding: '0.6rem 0.75rem',
                borderRadius: '6px',
                border: '1px solid var(--border-color)',
                background: 'var(--bg-primary)',
                color: 'var(--text-primary)',
                fontSize: '0.9rem',
              }}
            />
          </div>

          <button
            type="submit"
            className="btn-primary"
            disabled={loading}
            style={{ width: '100%', justifyContent: 'center', marginBottom: '1rem' }}
          >
            {loading ? 'Authenticating...' : 'Sign In to HopZero'}
          </button>
        </form>

        {/* Demo Credentials Helper Box (Clearly Marked Local Development Only) */}
        <div
          style={{
            borderTop: '1px solid var(--border-color)',
            paddingTop: '0.75rem',
            marginTop: '0.5rem',
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Local Demo Environment:</span>
            <button
              type="button"
              onClick={fillDemoCredentials}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--color-primary)',
                cursor: 'pointer',
                fontWeight: 600,
                fontSize: '0.75rem',
                textDecoration: 'underline',
              }}
            >
              Fill Demo Credentials
            </button>
          </div>
          <span style={{ display: 'block', marginTop: '0.25rem', fontStyle: 'italic' }}>
            Note: Demo credentials are strictly for isolated local evaluation and never permitted in production deployments.
          </span>
        </div>
      </div>
    </div>
  );
};
