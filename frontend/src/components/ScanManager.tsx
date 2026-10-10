import React, { useState, useEffect } from 'react';
import {
  PlayCircle,
  Search,
  CheckSquare,
  Square,
  AlertCircle,
  CheckCircle,
  RefreshCw,
  Terminal,
  Shield,
  Layers,
  ChevronRight,
  ExternalLink,
} from 'lucide-react';
import { api } from '../api/client';
import {
  DiscoveredEndpoint,
  ScanSession,
  ScannerMetadata,
  TargetApp,
  VulnerabilityFinding,
} from '../types';

interface ScanManagerProps {
  onViewFinding: (finding: VulnerabilityFinding) => void;
}

export const ScanManager: React.FC<ScanManagerProps> = ({ onViewFinding }) => {
  const [mode, setMode] = useState<'oneshot' | 'session'>('session');
  const [targets, setTargets] = useState<TargetApp[]>([]);
  const [scanners, setScanners] = useState<ScannerMetadata[]>([]);
  const [selectedTargetUrl, setSelectedTargetUrl] = useState('http://localhost:8080');
  const [authToken, setAuthToken] = useState('');
  const [lowPrivToken, setLowPrivToken] = useState('');
  const [selectedScanners, setSelectedScanners] = useState<string[]>([
    'security_headers',
    'cors',
    'authentication',
    'authorization',
    'sqli',
    'xss',
  ]);

  // Session state
  const [activeSession, setActiveSession] = useState<ScanSession | null>(null);
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [sessionFindings, setSessionFindings] = useState<VulnerabilityFinding[]>([]);
  const [sessionStep, setSessionStep] = useState<1 | 2 | 3 | 4>(1);

  // Execution status
  const [running, setRunning] = useState(false);
  const [statusMessage, setStatusMessage] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  useEffect(() => {
    api.getTargets().then(setTargets).catch(() => {});
    api.getScanners().then(setScanners).catch(() => {});
  }, []);

  const toggleScanner = (name: string) => {
    if (selectedScanners.includes(name)) {
      setSelectedScanners(selectedScanners.filter((s) => s !== name));
    } else {
      setSelectedScanners([...selectedScanners, name]);
    }
  };

  const selectAllScanners = () => {
    if (selectedScanners.length === scanners.length) {
      setSelectedScanners([]);
    } else {
      setSelectedScanners(scanners.map((s) => s.name));
    }
  };

  // --- One-Shot Scan ---
  const handleRunOneShot = async () => {
    setRunning(true);
    setErrorMessage('');
    setStatusMessage('Initiating one-shot security scan on ' + selectedTargetUrl + '...');
    try {
      const session = await api.executeOneShotScan({
        target: selectedTargetUrl,
        scanners: selectedScanners,
        auth_token: authToken || undefined,
        low_priv_token: lowPrivToken || undefined,
      });

      setActiveSession(session);
      setStatusMessage('One-shot scan completed! Fetching findings...');
      const findings = await api.getFindings({ scanSessionId: session.id });
      setSessionFindings(findings);
      setStatusMessage(`Scan complete. Found ${findings.length} vulnerabilities.`);
    } catch (err: any) {
      setErrorMessage(err.message || 'Scan failed.');
    } finally {
      setRunning(false);
    }
  };

  // --- Stateful Session Workflow ---
  const handleCreateSession = async () => {
    setRunning(true);
    setErrorMessage('');
    setStatusMessage('Creating persistent ScanContext session in MongoDB...');
    try {
      const session = await api.createSession({
        target: selectedTargetUrl,
        auth_token: authToken || undefined,
        low_priv_token: lowPrivToken || undefined,
      });
      setActiveSession(session);
      setSessionStep(2);
      setStatusMessage(`Session ${session.engineScanId || session.id} initialized.`);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to initialize session.');
    } finally {
      setRunning(false);
    }
  };

  const handleDiscoverEndpoints = async () => {
    if (!activeSession) return;
    setRunning(true);
    setErrorMessage('');
    setStatusMessage('Probing OpenAPI / Swagger specs and crawling attack surface...');
    try {
      const endpoints = await api.discoverSessionEndpoints(activeSession.id);
      setDiscoveredEndpoints(endpoints);
      setSessionStep(3);
      setStatusMessage(`Discovered ${endpoints.length} API routes.`);
    } catch (err: any) {
      setErrorMessage(err.message || 'Endpoint discovery failed.');
    } finally {
      setRunning(false);
    }
  };

  const handleRunSessionScanners = async () => {
    if (!activeSession) return;
    setRunning(true);
    setErrorMessage('');
    setStatusMessage('Executing scanners [' + selectedScanners.join(', ') + ']...');
    try {
      const findings = await api.runSessionScan(activeSession.id, selectedScanners);
      setSessionFindings(findings);
      setSessionStep(4);

      // Refresh session
      const updated = await api.getSession(activeSession.id);
      setActiveSession(updated);
      setStatusMessage(`Completed! Found ${findings.length} new vulnerabilities.`);
    } catch (err: any) {
      setErrorMessage(err.message || 'Session scan execution failed.');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      {/* Mode Switcher Banner */}
      <div className="card" style={{ padding: '1rem 1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#064e3b' }}>Security Vulnerability Scanner</h2>
            <p style={{ fontSize: '0.85rem', color: '#64748b' }}>
              Choose between an automated all-in-one scan or an interactive step-by-step session.
            </p>
          </div>

          <div style={{ display: 'flex', background: '#f1f5f9', padding: '0.25rem', borderRadius: '10px' }}>
            <button
              onClick={() => setMode('session')}
              style={{
                border: 'none',
                padding: '0.5rem 1rem',
                borderRadius: '8px',
                fontSize: '0.85rem',
                fontWeight: mode === 'session' ? 700 : 500,
                background: mode === 'session' ? '#ffffff' : 'transparent',
                color: mode === 'session' ? '#059669' : '#475569',
                boxShadow: mode === 'session' ? '0 1px 3px rgba(0,0,0,0.1)' : 'none',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
              }}
            >
              <Layers size={16} /> Interactive Session (Recommended)
            </button>
            <button
              onClick={() => setMode('oneshot')}
              style={{
                border: 'none',
                padding: '0.5rem 1rem',
                borderRadius: '8px',
                fontSize: '0.85rem',
                fontWeight: mode === 'oneshot' ? 700 : 500,
                background: mode === 'oneshot' ? '#ffffff' : 'transparent',
                color: mode === 'oneshot' ? '#059669' : '#475569',
                boxShadow: mode === 'oneshot' ? '0 1px 3px rgba(0,0,0,0.1)' : 'none',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
              }}
            >
              <PlayCircle size={16} /> One-Shot Scan
            </button>
          </div>
        </div>
      </div>

      {/* Target & Credentials Card */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Shield size={20} color="#059669" /> 1. Target Application & Authentication
          </div>
        </div>

        <div className="grid-2">
          <div className="form-group">
            <label className="form-label">Target Base URL (Must be local: localhost, 127.0.0.1, ::1)</label>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input
                type="text"
                className="form-input"
                value={selectedTargetUrl}
                onChange={(e) => setSelectedTargetUrl(e.target.value)}
                placeholder="http://localhost:8080"
              />
              {targets.length > 0 && (
                <select
                  className="form-select"
                  style={{ width: '180px' }}
                  onChange={(e) => {
                    if (e.target.value) setSelectedTargetUrl(e.target.value);
                  }}
                  defaultValue=""
                >
                  <option value="" disabled>Saved Targets...</option>
                  {targets.map((t) => (
                    <option key={t.id} value={t.baseUrl}>{t.name}</option>
                  ))}
                </select>
              )}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>
              Restricted to local host addresses for safety and authorized testing compliance.
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Valid Authentication Token (Optional)</label>
            <input
              type="text"
              className="form-input"
              value={authToken}
              onChange={(e) => setAuthToken(e.target.value)}
              placeholder="eyJhbGciOi... (Bearer token)"
            />
            <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>
              Used to test authenticated routes and token validation vulnerabilities.
            </div>
          </div>
        </div>

        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Low-Privilege Token for BFLA / BOLA Tests (Optional)</label>
          <input
            type="text"
            className="form-input"
            value={lowPrivToken}
            onChange={(e) => setLowPrivToken(e.target.value)}
            placeholder="Standard user token for privilege escalation checks"
          />
        </div>
      </div>

      {/* Scanner Selector Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <CheckSquare size={20} color="#059669" /> 2. Select Vulnerability Scanners
            </div>
            <div className="card-subtitle">
              Choose which checks the engine should execute against target endpoints.
            </div>
          </div>
          <button className="btn btn-secondary" onClick={selectAllScanners} style={{ padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}>
            {selectedScanners.length === scanners.length ? 'Deselect All' : 'Select All'}
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '0.75rem' }}>
          {scanners.map((s) => {
            const isSelected = selectedScanners.includes(s.name);
            return (
              <div
                key={s.name}
                onClick={() => toggleScanner(s.name)}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '0.75rem',
                  padding: '0.85rem 1rem',
                  borderRadius: '10px',
                  border: `1.5px solid ${isSelected ? '#10b981' : '#e2e8f0'}`,
                  backgroundColor: isSelected ? '#ecfdf5' : '#ffffff',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                <div style={{ marginTop: '0.15rem', color: isSelected ? '#059669' : '#cbd5e1' }}>
                  {isSelected ? <CheckSquare size={18} /> : <Square size={18} />}
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontWeight: 700, fontSize: '0.9rem', color: '#0f172a' }}>{s.name}</span>
                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        padding: '0.1rem 0.45rem',
                        borderRadius: '4px',
                        background: s.riskLevel === 'MEDIUM' ? '#fef3c7' : '#dcfce7',
                        color: s.riskLevel === 'MEDIUM' ? '#92400e' : '#166534',
                      }}
                    >
                      {s.riskLevel} RISK
                    </span>
                  </div>
                  <div style={{ fontSize: '0.785rem', color: '#64748b', marginTop: '0.2rem' }}>
                    {s.description}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Action / Progress Box */}
      {mode === 'oneshot' ? (
        <div className="card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#ecfdf5', borderColor: '#a7f3d0' }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: '1rem', color: '#064e3b' }}>
              Ready to Launch One-Shot Scan
            </div>
            <div style={{ fontSize: '0.85rem', color: '#047857' }}>
              Discovers endpoints and runs {selectedScanners.length} scanners in parallel.
            </div>
          </div>

          <button
            className="btn btn-primary"
            onClick={handleRunOneShot}
            disabled={running || selectedScanners.length === 0}
            style={{ padding: '0.75rem 1.5rem', fontSize: '0.95rem' }}
          >
            {running ? <RefreshCw size={18} className="animate-spin" /> : <PlayCircle size={18} />}
            {running ? 'Scanning Target...' : 'Execute One-Shot Scan'}
          </button>
        </div>
      ) : (
        /* Stateful Session Steps */
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Layers size={20} color="#059669" /> 3. Stateful Workflow Steps
            </div>
          </div>

          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
            {/* Step 1 */}
            <div
              style={{
                flex: 1,
                minWidth: '200px',
                padding: '1rem',
                borderRadius: '10px',
                border: `2px solid ${sessionStep >= 1 ? '#10b981' : '#e2e8f0'}`,
                backgroundColor: sessionStep === 1 ? '#ecfdf5' : '#ffffff',
              }}
            >
              <div style={{ fontWeight: 700, fontSize: '0.85rem', color: '#059669' }}>STEP 1</div>
              <div style={{ fontWeight: 800, fontSize: '1rem', marginTop: '0.2rem' }}>Create Session</div>
              <button
                className="btn btn-primary"
                onClick={handleCreateSession}
                disabled={running}
                style={{ marginTop: '0.75rem', width: '100%', fontSize: '0.8rem', padding: '0.45rem' }}
              >
                {activeSession ? 'Session Ready ✓' : 'Init Session'}
              </button>
            </div>

            {/* Step 2 */}
            <div
              style={{
                flex: 1,
                minWidth: '200px',
                padding: '1rem',
                borderRadius: '10px',
                border: `2px solid ${sessionStep >= 2 ? '#10b981' : '#e2e8f0'}`,
                backgroundColor: sessionStep === 2 ? '#ecfdf5' : '#ffffff',
                opacity: !activeSession ? 0.6 : 1,
              }}
            >
              <div style={{ fontWeight: 700, fontSize: '0.85rem', color: '#059669' }}>STEP 2</div>
              <div style={{ fontWeight: 800, fontSize: '1rem', marginTop: '0.2rem' }}>Discover Routes</div>
              <button
                className="btn btn-primary"
                onClick={handleDiscoverEndpoints}
                disabled={running || !activeSession}
                style={{ marginTop: '0.75rem', width: '100%', fontSize: '0.8rem', padding: '0.45rem' }}
              >
                <Search size={14} /> Discover Endpoints
              </button>
            </div>

            {/* Step 3 */}
            <div
              style={{
                flex: 1,
                minWidth: '200px',
                padding: '1rem',
                borderRadius: '10px',
                border: `2px solid ${sessionStep >= 3 ? '#10b981' : '#e2e8f0'}`,
                backgroundColor: sessionStep === 3 ? '#ecfdf5' : '#ffffff',
                opacity: !activeSession || sessionStep < 2 ? 0.6 : 1,
              }}
            >
              <div style={{ fontWeight: 700, fontSize: '0.85rem', color: '#059669' }}>STEP 3</div>
              <div style={{ fontWeight: 800, fontSize: '1rem', marginTop: '0.2rem' }}>Run Scanners</div>
              <button
                className="btn btn-primary"
                onClick={handleRunSessionScanners}
                disabled={running || !activeSession}
                style={{ marginTop: '0.75rem', width: '100%', fontSize: '0.8rem', padding: '0.45rem' }}
              >
                <PlayCircle size={14} /> Run Selected
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Live Status Log */}
      {(statusMessage || errorMessage) && (
        <div
          style={{
            padding: '1rem 1.25rem',
            borderRadius: '10px',
            backgroundColor: errorMessage ? '#fef2f2' : '#f0fdf4',
            border: `1px solid ${errorMessage ? '#fecaca' : '#bbf7d0'}`,
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
          }}
        >
          {errorMessage ? (
            <AlertCircle size={20} color="#dc2626" />
          ) : (
            <CheckCircle size={20} color="#059669" />
          )}
          <div style={{ fontSize: '0.9rem', color: errorMessage ? '#991b1b' : '#166534', fontWeight: 600 }}>
            {errorMessage || statusMessage}
          </div>
        </div>
      )}

      {/* Discovered Endpoints Table (if any) */}
      {discoveredEndpoints.length > 0 && (
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">Discovered API Attack Surface ({discoveredEndpoints.length})</div>
              <div className="card-subtitle">Endpoints parsed from OpenAPI specifications and crawler links</div>
            </div>
          </div>

          <div className="data-table-container" style={{ maxHeight: '350px' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: '90px' }}>Method</th>
                  <th>Path</th>
                  <th>Authentication</th>
                  <th>Parameters</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {discoveredEndpoints.map((ep, idx) => (
                  <tr key={idx}>
                    <td>
                      <span className={`method-badge method-${ep.method}`}>{ep.method}</span>
                    </td>
                    <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{ep.path}</td>
                    <td>
                      {ep.authenticationRequired ? (
                        <span style={{ color: '#ea580c', fontWeight: 600, fontSize: '0.8rem' }}>Required</span>
                      ) : (
                        <span style={{ color: '#059669', fontSize: '0.8rem' }}>Public</span>
                      )}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                        {ep.parameters.length === 0 ? (
                          <span style={{ color: '#94a3b8', fontSize: '0.8rem' }}>None</span>
                        ) : (
                          ep.parameters.map((p, pIdx) => (
                            <span
                              key={pIdx}
                              style={{
                                background: '#f1f5f9',
                                padding: '0.1rem 0.4rem',
                                borderRadius: '4px',
                                fontSize: '0.75rem',
                              }}
                            >
                              {p.name} ({p.location})
                            </span>
                          ))
                        )}
                      </div>
                    </td>
                    <td style={{ color: '#64748b', fontSize: '0.825rem' }}>
                      {ep.description || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Scan Results Findings Stream */}
      {sessionFindings.length > 0 && (
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">Scan Findings ({sessionFindings.length})</div>
              <div className="card-subtitle">Vulnerabilities confirmed and recorded into MongoDB</div>
            </div>
          </div>

          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: '110px' }}>Severity</th>
                  <th>Vulnerability Title</th>
                  <th>Scanner</th>
                  <th>Endpoint</th>
                  <th>Confidence</th>
                  <th style={{ width: '100px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {sessionFindings.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                    </td>
                    <td style={{ fontWeight: 600 }}>{f.title}</td>
                    <td>
                      <code>{f.scanner}</code>
                    </td>
                    <td style={{ fontFamily: 'monospace' }}>
                      {f.method || 'GET'} {f.endpoint || '/'}
                    </td>
                    <td>
                      <span style={{ fontWeight: 700, color: '#059669' }}>
                        {Math.round((f.confidence || 0) * 100)}%
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn btn-outline-primary"
                        onClick={() => onViewFinding(f)}
                        style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                      >
                        Details <ExternalLink size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
