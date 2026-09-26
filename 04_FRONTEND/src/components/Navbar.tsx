import React, { useState } from 'react';
import { LoginModal } from './LoginModal';

interface Props {
  onUploadClick: () => void;
  onHomeClick: () => void;
  selectedId: string | null;
}

export const Navbar: React.FC<Props> = ({ onUploadClick, onHomeClick, selectedId }) => {
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
      </div>

      <div className="nav-actions">
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
