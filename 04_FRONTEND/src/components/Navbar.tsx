import React, { useState } from 'react';
import { LoginModal } from './LoginModal';

interface Props {
  onUploadClick: () => void;
  onHomeClick: () => void;
  onGuideClick?: () => void;
  onEmployeesClick?: () => void;
  onPortalClick?: () => void;
  selectedId: string | null;
}

export const Navbar: React.FC<Props> = ({ onUploadClick, onHomeClick, onGuideClick, onEmployeesClick, onPortalClick, selectedId }) => {
  const [showLogin, setShowLogin] = useState(false);
  const isLoggedInAsRole = () => {
    const token = localStorage.getItem('token');
    if (!token || token.length < 50) return false; // not a real JWT
    return true;
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    window.location.reload();
  };

  return (
    <>
    <header className="navbar">
      <div className="nav-brand" style={{ cursor: 'pointer' }} onClick={onHomeClick}>
        <div style={{
          width: '32px',
          height: '32px',
          borderRadius: 'var(--radius-sm)',
          background: 'var(--color-primary)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: 800,
          color: '#fff',
        }}>
          0
        </div>
        <span>HopZero</span>
        <span className="brand-badge">SIH 2026 FORENSICS</span>
        <span className="version-badge" style={{ fontSize: '0.75rem', padding: '2px 8px', borderRadius: '4px', background: 'rgba(255,255,255,0.1)', color: '#94a3b8', border: '1px solid rgba(255,255,255,0.15)', marginLeft: '8px' }}>v4.2.0</span>
      </div>

      <div className="nav-actions">
        {onGuideClick && (
          <button 
            className="btn-secondary" 
            onClick={onGuideClick}
            title="Open Onboarding & Forensics Architecture Guide"
            aria-label="Open Onboarding Guide"
            style={{ padding: '0.4rem 0.65rem' }}
          >
            Guide
          </button>
        )}
        {onEmployeesClick && (
          <button 
            className="btn-secondary" 
            onClick={onEmployeesClick}
            title="Manage Employee Access & Secret Pairing Codes"
            style={{ padding: '0.4rem 0.75rem', background: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', borderColor: 'rgba(59, 130, 246, 0.3)' }}
          >
            👥 Employee Codes
          </button>
        )}
        {onPortalClick && (
          <button 
            className="btn-secondary" 
            onClick={onPortalClick}
            title="Switch to Employee Portal View"
            style={{ padding: '0.4rem 0.75rem' }}
          >
            🔒 Employee Portal
          </button>
        )}
        {selectedId && (
          <button className="btn-secondary" onClick={onHomeClick}>
            Back to List
          </button>
        )}
        <button className="btn-primary" onClick={onUploadClick}>
          <span>+</span> Ingest Email (.eml)
        </button>
        
        {isLoggedInAsRole() ? (
          <button className="btn-secondary" onClick={handleLogout}>
            Logout
          </button>
        ) : (
          <button className="btn-secondary" onClick={() => setShowLogin(true)}>
            SOC Login
          </button>
        )}
      </div>
    </header>
    {showLogin && (
      <LoginModal 
        onSuccess={() => { setShowLogin(false); window.location.reload(); }} 
        onClose={() => setShowLogin(false)} 
      />
    )}
    </>
  );
};
