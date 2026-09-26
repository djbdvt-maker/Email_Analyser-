import React, { useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, CartesianGrid
} from 'recharts';
import { InvestigationSummary } from '../../contract';

interface DashboardProps {
  investigations: InvestigationSummary[];
  onSelect: (id: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ investigations, onSelect }) => {
  const [filterType, setFilterType] = useState<'ALL' | 'CRITICAL_HIGH' | 'PENDING'>('ALL');

  // Compute basic stats
  const total = investigations.length;
  const critical = investigations.filter(i => i.severity === 'CRITICAL').length;
  const high = investigations.filter(i => i.severity === 'HIGH').length;
  const pending = investigations.filter(i => i.status === 'UNDER_REVIEW' || i.status === 'AWAITING_ANALYSIS').length;
  
  // Prepare data for severity pie chart
  const severityData = [
    { name: 'Critical', value: critical, color: '#ef4444' }, // red-500
    { name: 'High', value: high, color: '#f97316' }, // orange-500
    { name: 'Medium', value: investigations.filter(i => i.severity === 'MEDIUM').length, color: '#eab308' }, // yellow-500
    { name: 'Low', value: investigations.filter(i => i.severity === 'LOW').length, color: '#22c55e' }, // green-500
    { name: 'Clean', value: investigations.filter(i => i.severity === 'clean').length, color: '#3b82f6' }, // blue-500
    { name: 'Unknown', value: investigations.filter(i => i.severity === undefined).length, color: '#6b7280' }, // gray-500
  ].filter(d => d.value > 0);

  // Status breakdown
  const statusCounts = investigations.reduce((acc, inv) => {
    acc[inv.status] = (acc[inv.status] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  const statusData = Object.keys(statusCounts).map(k => ({
    name: k,
    count: statusCounts[k]
  }));

  // Activity over time (mocked based on actual timestamps)
  const sorted = [...investigations].sort((a, b) => {
    const timeA = new Date(a.createdAt.endsWith('Z') ? a.createdAt : a.createdAt + 'Z').getTime();
    const timeB = new Date(b.createdAt.endsWith('Z') ? b.createdAt : b.createdAt + 'Z').getTime();
    return timeB - timeA;
  });
  
  const timeDataMap: Record<string, number> = {};
  sorted.forEach(inv => {
    const d = new Date(inv.createdAt.endsWith('Z') ? inv.createdAt : inv.createdAt + 'Z');
    const label = `${d.getMonth()+1}/${d.getDate()} ${d.getHours()}:00`;
    timeDataMap[label] = (timeDataMap[label] || 0) + 1;
  });
  
  const timeData = Object.keys(timeDataMap).map(k => ({
    time: k,
    investigations: timeDataMap[k]
  }));

  // Helper for Custom Tooltip
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div style={{ background: '#1e293b', border: '1px solid #334155', padding: '0.5rem', borderRadius: 'var(--radius-sm)' }}>
          <p style={{ margin: 0, fontSize: '0.8rem', color: '#94a3b8' }}>{label}</p>
          <p style={{ margin: 0, fontSize: '0.9rem', color: '#f8fafc', fontWeight: 'bold' }}>
            {payload[0].name}: {payload[0].value}
          </p>
        </div>
      );
    }
    return null;
  };

  let displayInvestigations = [...sorted];
  if (filterType === 'CRITICAL_HIGH') {
    displayInvestigations = displayInvestigations.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH');
  } else if (filterType === 'PENDING') {
    displayInvestigations = displayInvestigations.filter(i => i.status === 'UNDER_REVIEW' || i.status === 'AWAITING_ANALYSIS');
  }

  const cardStyle = (isSelected: boolean, borderColor: string) => ({
    background: isSelected ? 'rgba(59, 130, 246, 0.05)' : 'var(--bg-secondary)',
    border: `1px solid ${isSelected ? borderColor : 'var(--border-color)'}`,
    borderRadius: 'var(--radius-md)',
    padding: '1rem',
    cursor: 'pointer',
    transition: 'all 0.2s',
    boxShadow: isSelected ? `0 0 0 1px ${borderColor}` : 'none'
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Top Stat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
        <div 
          style={cardStyle(filterType === 'ALL', 'var(--text-primary)')}
          onClick={() => setFilterType('ALL')}
        >
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontWeight: 600 }}>TOTAL INVESTIGATIONS</div>
          <div style={{ fontSize: '2rem', fontWeight: 700, marginTop: '0.5rem' }}>{total}</div>
        </div>
        <div 
          style={cardStyle(filterType === 'CRITICAL_HIGH', 'var(--color-dangerous)')}
          onClick={() => setFilterType('CRITICAL_HIGH')}
        >
          <div style={{ color: 'var(--color-dangerous)', fontSize: '0.8rem', fontWeight: 600 }}>CRITICAL / HIGH</div>
          <div style={{ fontSize: '2rem', fontWeight: 700, marginTop: '0.5rem', color: 'var(--color-dangerous)' }}>{critical + high}</div>
        </div>
        <div 
          style={cardStyle(filterType === 'PENDING', 'var(--color-primary)')}
          onClick={() => setFilterType('PENDING')}
        >
          <div style={{ color: 'var(--color-primary)', fontSize: '0.8rem', fontWeight: 600 }}>PENDING ACTIONS</div>
          <div style={{ fontSize: '2rem', fontWeight: 700, marginTop: '0.5rem', color: 'var(--color-primary)' }}>{pending}</div>
        </div>
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)', padding: '1rem' }}>
          <h3 style={{ fontSize: '1rem', marginTop: 0, marginBottom: '1rem', color: 'var(--text-primary)' }}>Severity Breakdown</h3>
          <div style={{ height: '250px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          {/* Legend */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', justifyContent: 'center' }}>
            {severityData.map(d => (
              <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.8rem' }}>
                <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: d.color }}></span>
                {d.name} ({d.value})
              </div>
            ))}
          </div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)', padding: '1rem' }}>
          <h3 style={{ fontSize: '1rem', marginTop: 0, marginBottom: '1rem', color: 'var(--text-primary)' }}>Activity Timeline</h3>
          <div style={{ height: '250px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                <XAxis dataKey="time" stroke="#94a3b8" fontSize={12} tickMargin={10} />
                <YAxis stroke="#94a3b8" fontSize={12} allowDecimals={false} />
                <Tooltip content={<CustomTooltip />} />
                <Line type="monotone" dataKey="investigations" stroke="#3b82f6" strokeWidth={3} dot={{ r: 4, fill: '#3b82f6' }} activeDot={{ r: 6 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)', padding: '1rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3 style={{ fontSize: '1rem', margin: 0, color: 'var(--text-primary)' }}>
            {filterType === 'CRITICAL_HIGH' ? 'Critical & High Severity' : filterType === 'PENDING' ? 'Pending Actions' : 'Recent Investigations'}
          </h3>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.75rem 0.5rem', fontWeight: 600 }}>ID</th>
                <th style={{ padding: '0.75rem 0.5rem', fontWeight: 600 }}>Severity</th>
                <th style={{ padding: '0.75rem 0.5rem', fontWeight: 600 }}>Score</th>
                <th style={{ padding: '0.75rem 0.5rem', fontWeight: 600 }}>Status</th>
                <th style={{ padding: '0.75rem 0.5rem', fontWeight: 600 }}>Date</th>
                <th style={{ padding: '0.75rem 0.5rem', fontWeight: 600 }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {displayInvestigations.slice(0, 15).map(inv => (
                <tr key={inv.investigationId} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '0.75rem 0.5rem', fontFamily: 'monospace' }}>{inv.investigationId.substring(0,8)}...</td>
                  <td style={{ padding: '0.75rem 0.5rem' }}>
                    <span style={{ 
                      padding: '0.2rem 0.5rem', 
                      borderRadius: 'var(--radius-sm)', 
                      fontSize: '0.7rem', 
                      fontWeight: 700,
                      background: inv.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.2)' : inv.severity === 'HIGH' ? 'rgba(249, 115, 22, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                      color: inv.severity === 'CRITICAL' ? '#f87171' : inv.severity === 'HIGH' ? '#fb923c' : '#60a5fa'
                    }}>
                      {inv.severity || 'UNKNOWN'}
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem 0.5rem' }}>{inv.score !== null ? inv.score : '-'}</td>
                  <td style={{ padding: '0.75rem 0.5rem' }}>{inv.status}</td>
                  <td style={{ padding: '0.75rem 0.5rem', color: 'var(--text-muted)' }}>{new Date(inv.createdAt.endsWith('Z') ? inv.createdAt : inv.createdAt + 'Z').toLocaleString()}</td>
                  <td style={{ padding: '0.75rem 0.5rem' }}>
                    <button 
                      className="btn-primary" 
                      style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
                      onClick={() => onSelect(inv.investigationId)}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
              {displayInvestigations.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>No investigations found for this filter.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
