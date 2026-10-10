import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Server,
  PlayCircle,
  Sparkles,
  ChevronRight,
  TrendingUp,
  Bug,
  CheckCircle2,
  RefreshCw,
} from 'lucide-react';
import { api } from '../api/client';
import { FindingMetrics, ScanSession, TargetApp, VulnerabilityFinding } from '../types';

interface DashboardProps {
  onNavigate: (tab: string, targetId?: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ onNavigate }) => {
  const [metrics, setMetrics] = useState<FindingMetrics | null>(null);
  const [sessions, setSessions] = useState<ScanSession[]>([]);
  const [targets, setTargets] = useState<TargetApp[]>([]);
  const [recentFindings, setRecentFindings] = useState<VulnerabilityFinding[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const [m, s, t, f] = await Promise.all([
        api.getFindingStats().catch(() => null),
        api.getSessions().catch(() => []),
        api.getTargets().catch(() => []),
        api.getFindings({ severity: 'HIGH' }).catch(() => []),
      ]);
      setMetrics(m);
      setSessions(s);
      setTargets(t);
      setRecentFindings(f.slice(0, 5));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const totalFindings = metrics?.total_findings || 0;
  const criticalCount = metrics?.by_severity?.CRITICAL || 0;
  const highCount = metrics?.by_severity?.HIGH || 0;
  const medCount = metrics?.by_severity?.MEDIUM || 0;
  const lowCount = metrics?.by_severity?.LOW || 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      {/* Top Banner */}
      <div
        style={{
          background: 'linear-gradient(135deg, #064e3b 0%, #047857 100%)',
          color: '#ffffff',
          borderRadius: '14px',
          padding: '2rem 2.25rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          boxShadow: '0 8px 20px -4px rgba(4, 120, 87, 0.4)',
        }}
      >
        <div style={{ maxWidth: '650px' }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              background: 'rgba(255, 255, 255, 0.15)',
              padding: '0.25rem 0.75rem',
              borderRadius: '9999px',
              fontSize: '0.8rem',
              fontWeight: 600,
              marginBottom: '0.75rem',
            }}
          >
            <Sparkles size={14} color="#a7f3d0" /> Autonomous Security Operations
          </div>
          <h1 style={{ fontSize: '1.85rem', fontWeight: 800, marginBottom: '0.5rem', letterSpacing: '-0.02em' }}>
            Local Web Application Vulnerability Scanner
          </h1>
          <p style={{ color: '#d1fae5', fontSize: '0.95rem', lineHeight: 1.5 }}>
            Automate endpoint discovery, test for OWASP Top 10 vulnerabilities (SQLi, XSS, BFLA, BOLA, CORS, Headers), and leverage the LangGraph AI Copilot for autonomous remediation.
          </p>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <button
            className="btn btn-primary"
            onClick={() => onNavigate('scans')}
            style={{
              backgroundColor: '#ffffff',
              color: '#064e3b',
              fontWeight: 700,
              padding: '0.75rem 1.4rem',
              boxShadow: '0 4px 10px rgba(0, 0, 0, 0.15)',
            }}
          >
            <PlayCircle size={18} /> Launch New Scan
          </button>
          <button
            className="btn"
            onClick={() => onNavigate('agent')}
            style={{
              backgroundColor: 'rgba(255, 255, 255, 0.15)',
              color: '#ffffff',
              border: '1px solid rgba(255, 255, 255, 0.3)',
              fontWeight: 600,
            }}
          >
            <Sparkles size={16} /> Open AI Copilot
          </button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid-4">
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ color: '#64748b', fontSize: '0.825rem', fontWeight: 600 }}>Total Findings</div>
              <div style={{ fontSize: '1.9rem', fontWeight: 800, color: '#0f172a', marginTop: '0.25rem' }}>
                {totalFindings}
              </div>
            </div>
            <div style={{ padding: '0.6rem', borderRadius: '10px', background: '#ecfdf5', color: '#059669' }}>
              <Bug size={22} />
            </div>
          </div>
          <div style={{ fontSize: '0.8rem', color: '#059669', marginTop: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            <TrendingUp size={14} /> Active Across All Scans
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ color: '#64748b', fontSize: '0.825rem', fontWeight: 600 }}>Critical & High</div>
              <div style={{ fontSize: '1.9rem', fontWeight: 800, color: '#dc2626', marginTop: '0.25rem' }}>
                {criticalCount + highCount}
              </div>
            </div>
            <div style={{ padding: '0.6rem', borderRadius: '10px', background: '#fef2f2', color: '#dc2626' }}>
              <ShieldAlert size={22} />
            </div>
          </div>
          <div style={{ fontSize: '0.8rem', color: '#dc2626', marginTop: '0.75rem' }}>
            {criticalCount} Critical | {highCount} High
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ color: '#64748b', fontSize: '0.825rem', fontWeight: 600 }}>Target Applications</div>
              <div style={{ fontSize: '1.9rem', fontWeight: 800, color: '#0f172a', marginTop: '0.25rem' }}>
                {targets.length}
              </div>
            </div>
            <div style={{ padding: '0.6rem', borderRadius: '10px', background: '#eff6ff', color: '#2563eb' }}>
              <Server size={22} />
            </div>
          </div>
          <div style={{ fontSize: '0.8rem', color: '#2563eb', marginTop: '0.75rem' }}>
            Local Authorized Targets
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ color: '#64748b', fontSize: '0.825rem', fontWeight: 600 }}>Scan Executions</div>
              <div style={{ fontSize: '1.9rem', fontWeight: 800, color: '#0f172a', marginTop: '0.25rem' }}>
                {sessions.length}
              </div>
            </div>
            <div style={{ padding: '0.6rem', borderRadius: '10px', background: '#ecfdf5', color: '#047857' }}>
              <CheckCircle2 size={22} />
            </div>
          </div>
          <div style={{ fontSize: '0.8rem', color: '#059669', marginTop: '0.75rem' }}>
            Recorded in MongoDB
          </div>
        </div>
      </div>

      {/* Severity Breakdown Strip */}
      <div className="card">
        <div className="card-header" style={{ marginBottom: '0.75rem' }}>
          <div>
            <div className="card-title">Vulnerability Severity Distribution</div>
            <div className="card-subtitle">Real-time risk profile across discovered vulnerabilities</div>
          </div>
          <button className="btn btn-secondary" onClick={loadData} style={{ padding: '0.4rem 0.75rem' }}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>

        {totalFindings === 0 ? (
          <div style={{ padding: '1rem', textAlign: 'center', color: '#64748b', background: '#f8fafc', borderRadius: '8px' }}>
            No findings recorded yet. Run a security scan to populate vulnerability statistics.
          </div>
        ) : (
          <div>
            <div style={{ display: 'flex', height: 12, borderRadius: 6, overflow: 'hidden', background: '#e2e8f0', marginBottom: '1rem' }}>
              {criticalCount > 0 && (
                <div style={{ width: `${(criticalCount / totalFindings) * 100}%`, background: '#dc2626' }} title={`Critical: ${criticalCount}`} />
              )}
              {highCount > 0 && (
                <div style={{ width: `${(highCount / totalFindings) * 100}%`, background: '#ea580c' }} title={`High: ${highCount}`} />
              )}
              {medCount > 0 && (
                <div style={{ width: `${(medCount / totalFindings) * 100}%`, background: '#ca8a04' }} title={`Medium: ${medCount}`} />
              )}
              {lowCount > 0 && (
                <div style={{ width: `${(lowCount / totalFindings) * 100}%`, background: '#059669' }} title={`Low: ${lowCount}`} />
              )}
            </div>

            <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#dc2626' }} />
                <strong>Critical:</strong> {criticalCount}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ea580c' }} />
                <strong>High:</strong> {highCount}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ca8a04' }} />
                <strong>Medium:</strong> {medCount}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#059669' }} />
                <strong>Low:</strong> {lowCount}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Grid: Recent Scans & High-Risk Findings */}
      <div className="grid-2">
        {/* Recent Scans */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">Recent Scan Sessions</div>
              <div className="card-subtitle">Latest automated and session-based audit runs</div>
            </div>
            <button className="btn btn-outline-primary" onClick={() => onNavigate('scans')} style={{ fontSize: '0.8rem', padding: '0.4rem 0.75rem' }}>
              View All <ChevronRight size={14} />
            </button>
          </div>

          {sessions.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>
              No scan sessions found. Click "Launch New Scan" above to start.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {sessions.slice(0, 4).map((s) => (
                <div
                  key={s.id}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '0.85rem 1rem',
                    borderRadius: '8px',
                    backgroundColor: '#f8fafc',
                    border: '1px solid #e2e8f0',
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem', color: '#0f172a' }}>{s.targetUrl}</div>
                    <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.2rem' }}>
                      ID: {s.engineScanId || s.id.substring(0, 12)} • {s.summary?.totalFindings || 0} findings
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <span className={`badge badge-status-${s.status}`}>{s.status}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* High Risk Findings */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">Priority Vulnerabilities</div>
              <div className="card-subtitle">Critical and high risk findings requiring triage</div>
            </div>
            <button className="btn btn-outline-primary" onClick={() => onNavigate('findings')} style={{ fontSize: '0.8rem', padding: '0.4rem 0.75rem' }}>
              View All <ChevronRight size={14} />
            </button>
          </div>

          {recentFindings.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>
              No high-severity findings detected. All systems looking clean!
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {recentFindings.map((f) => (
                <div
                  key={f.id}
                  style={{
                    padding: '0.85rem 1rem',
                    borderRadius: '8px',
                    backgroundColor: '#ffffff',
                    border: '1px solid #fee2e2',
                    boxShadow: '0 1px 2px rgba(220, 38, 38, 0.05)',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ fontWeight: 700, fontSize: '0.9rem', color: '#991b1b' }}>{f.title}</div>
                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#64748b', marginTop: '0.25rem' }}>
                    Endpoint: <code>{f.method || 'GET'} {f.endpoint || '/'}</code>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
