import React, { useState, useEffect } from 'react';

export const LiveAnalysisScreen: React.FC<{ investigationId: string, onComplete: () => void }> = ({ investigationId, onComplete }) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [progress, setProgress] = useState(0);

  const steps = [
    "Extracting metadata and forensic artifacts...",
    "Mapping IP infrastructure to MaxMind Geo...",
    "Running deterministic YARA signatures...",
    "Executing Playwright Chromium Sandbox...",
    "Laya LLM Reasoning Engine processing facts...",
    "Computing Forensic Score & MITRE tags..."
  ];

  useEffect(() => {
    const startTime = Date.now();
    const estDuration = 120000; // 2 minutes max fake progress

    const interval = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const calcProgress = Math.min(99, Math.floor((elapsed / estDuration) * 100));
      setProgress(calcProgress);

      const stepIdx = Math.min(5, Math.floor((calcProgress / 100) * steps.length));
      setCurrentStep(stepIdx);
    }, 1000);

    const checkInterval = setInterval(async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await fetch(`http://localhost:8000/api/v1/investigations/${investigationId}`, {
          headers: token ? { 'Authorization': `Bearer ${token}` } : {}
        });
        if (res.ok) {
          const data = await res.json();
          if (data.status !== 'AWAITING_ANALYSIS') {
            onComplete();
          }
        }
      } catch (e) {}
    }, 3000);

    return () => {
      clearInterval(interval);
      clearInterval(checkInterval);
    };
  }, [steps.length, investigationId, onComplete]);

  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (progress / 100) * circumference;

  return (
    <div style={{ 
      padding: '3rem', 
      color: 'var(--text-primary)', 
      border: '1px solid var(--border-color)', 
      borderRadius: 'var(--radius-lg)', 
      background: 'var(--bg-secondary)',
      maxWidth: '600px',
      margin: '2rem auto',
      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
    }}>
      <div style={{ textAlign: 'center', marginBottom: '2rem', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        
        {/* Progress Circle */}
        <div style={{ position: 'relative', width: '120px', height: '120px', marginBottom: '1rem' }}>
          <svg width="120" height="120" viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
            <circle
              cx="50" cy="50" r={radius}
              stroke="var(--bg-primary)"
              strokeWidth="8"
              fill="transparent"
            />
            <circle
              cx="50" cy="50" r={radius}
              stroke="var(--color-primary)"
              strokeWidth="8"
              fill="transparent"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              style={{ transition: 'stroke-dashoffset 1s linear' }}
            />
          </svg>
          <div style={{ 
            position: 'absolute', 
            top: 0, left: 0, width: '100%', height: '100%', 
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-primary)'
          }}>
            {progress}%
          </div>
        </div>

        <h2 style={{ fontSize: '1.5rem', marginBottom: '0.5rem', color: 'var(--color-primary)' }}>
          ⚙️ Live Artificial Intelligence Analysis
        </h2>
        <p style={{ color: 'var(--text-muted)' }}>
          Please wait while HopZero dissects the artifact...
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {steps.map((step, index) => {
          const isCompleted = index < currentStep;
          const isActive = index === currentStep;
          
          let icon = "⏳";
          let color = "var(--text-muted)";
          
          if (isCompleted) {
            icon = "✅";
            color = "var(--color-success)";
          } else if (isActive) {
            icon = "🔄";
            color = "var(--color-primary)";
          }

          return (
            <div key={index} style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '1rem',
              color: color,
              fontWeight: isActive ? 600 : 400,
              padding: '0.75rem',
              background: isActive ? 'rgba(59, 130, 246, 0.1)' : 'transparent',
              borderRadius: 'var(--radius-sm)',
              border: isActive ? '1px solid var(--color-primary)' : '1px solid transparent',
              transition: 'all 0.3s ease'
            }}>
              <span style={{ fontSize: '1.2rem', animation: isActive ? 'spin 2s linear infinite' : 'none' }}>{icon}</span>
              <span>{step}</span>
            </div>
          );
        })}
      </div>

      <p style={{ 
        marginTop: '2rem', 
        fontSize: '0.85rem', 
        color: 'var(--color-warning)', 
        textAlign: 'center',
        background: 'rgba(245, 158, 11, 0.1)',
        padding: '0.75rem',
        borderRadius: 'var(--radius-sm)'
      }}>
        ⚠️ The Laya AI model takes approx. 1-2 minutes to initialize on first run. This screen will automatically transition when the backend pipeline completes.
      </p>

      <style>
        {`
          @keyframes spin {
            100% { transform: rotate(360deg); }
          }
        `}
      </style>
    </div>
  );
};
