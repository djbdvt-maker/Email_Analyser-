import React, { useState } from 'react';
import { uploadEmlFile } from '../services/api';

interface Props {
  onClose: () => void;
  onSuccess: (investigationId: string) => void;
}

export const UploadModal: React.FC<Props> = ({ onClose, onSuccess }) => {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError(null);
    try {
      const res = await uploadEmlFile(file);
      onSuccess(res.investigationId);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
          <h3>Ingest Email Evidence (.eml)</h3>
          <button style={{ color: 'var(--text-muted)', fontSize: '1.2rem' }} onClick={onClose}>✕</button>
        </div>

        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
          Upload an RFC 5322 .eml file. Raw bytes will be preserved unaltered with SHA-256 integrity verification, and passed through the deterministic forensic pipeline.
        </p>

        <div style={{
          border: '2px dashed var(--border-color)',
          borderRadius: '8px',
          padding: '2rem',
          textAlign: 'center',
          marginBottom: '1rem',
          background: 'var(--bg-primary)',
          cursor: 'pointer',
        }}>
          <input
            type="file"
            accept=".eml,message/rfc822"
            onChange={handleFileChange}
            style={{ display: 'none' }}
            id="eml-upload-input"
          />
          <label htmlFor="eml-upload-input" style={{ cursor: 'pointer', display: 'block' }}>
            <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>✉️</div>
            <div style={{ fontWeight: 600, color: 'var(--color-primary)' }}>
              {file ? file.name : 'Click to select a .eml file'}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
              {file ? `${(file.size / 1024).toFixed(1)} KB` : 'Supports up to 25MB standard RFC 5322 / MIME emails'}
            </div>
          </label>
        </div>

        {error && (
          <div style={{ background: 'rgba(239, 68, 68, 0.15)', color: 'var(--color-dangerous)', padding: '0.5rem', borderRadius: '4px', fontSize: '0.85rem', marginBottom: '1rem' }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <button className="btn-secondary" onClick={onClose} disabled={uploading}>
            Cancel
          </button>
          <button className="btn-primary" onClick={handleUpload} disabled={!file || uploading}>
            {uploading ? 'Processing Forensics...' : 'Upload & Analyze'}
          </button>
        </div>
      </div>
    </div>
  );
};
