import React, { useState, useEffect } from 'react';
import {
  Bug,
  Filter,
  Search,
  CheckCircle,
  AlertTriangle,
  XCircle,
  FileText,
  ExternalLink,
  Save,
  X,
  RefreshCw,
} from 'lucide-react';
import { api } from '../api/client';
import { FindingStatus, Severity, VulnerabilityFinding } from '../types';

interface FindingsViewProps {
  selectedFinding?: VulnerabilityFinding | null;
  onClearSelectedFinding?: () => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  selectedFinding: initialSelected,
  onClearSelectedFinding,
}) => {
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');

  // Selected finding for modal
  const [activeFinding, setActiveFinding] = useState<VulnerabilityFinding | null>(null);
  const [triageStatus, setTriageStatus] = useState<FindingStatus>('OPEN');
  const [triageNotes, setTriageNotes] = useState<string>('');
  const [updating, setUpdating] = useState(false);
  const [updateSuccess, setUpdateSuccess] = useState(false);

  const fetchFindings = async () => {
    setLoading(true);
    try {
      const data = await api.getFindings({
        severity: filterSeverity !== 'ALL' ? (filterSeverity as Severity) : undefined,
        status: filterStatus !== 'ALL' ? (filterStatus as FindingStatus) : undefined,
      });
      setFindings(data);
    } catch (err) {
      console.error('Failed to load findings', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [filterSeverity, filterStatus]);

  useEffect(() => {
    if (initialSelected) {
      openDetail(initialSelected);
    }
  }, [initialSelected]);

  const openDetail = (finding: VulnerabilityFinding) => {
    setActiveFinding(finding);
    setTriageStatus(finding.status || 'OPEN');
    setTriageNotes(finding.notes || '');
    setUpdateSuccess(false);
  };

  const handleUpdateStatus = async () => {
    if (!activeFinding) return;
    setUpdating(true);
    setUpdateSuccess(false);
    try {
      const updated = await api.updateFindingStatus(activeFinding.id, triageStatus, triageNotes);
      setActiveFinding(updated);
      setUpdateSuccess(true);
      fetchFindings();
      setTimeout(() => setUpdateSuccess(false), 3000);
    } catch (err) {
      alert('Failed to update status');
    } finally {
      setUpdating(false);
    }
  };

  const filtered = findings.filter((f) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.title?.toLowerCase().includes(q) ||
      f.endpoint?.toLowerCase().includes(q) ||
      f.scanner?.toLowerCase().includes(q) ||
      f.vulnerabilityType?.toLowerCase().includes(q)
    );
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header and Filter Toolbar */}
      <div className="card" style={{ padding: '1.25rem 1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#064e3b' }}>
              Vulnerabilities & Triage
            </h2>
            <p style={{ fontSize: '0.85rem', color: '#64748b' }}>
              Confirmed security findings across all target applications stored in MongoDB.
            </p>
          </div>

          <button className="btn btn-secondary" onClick={fetchFindings} style={{ padding: '0.45rem 0.85rem' }}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>

        {/* Filter controls */}
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: 2, minWidth: '220px', position: 'relative' }}>
            <Search size={16} color="#94a3b8" style={{ position: 'absolute', left: 12, top: 11 }} />
            <input
              type="text"
              className="form-input"
              style={{ paddingLeft: '2.25rem' }}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by title, endpoint, scanner, vulnerability type..."
            />
          </div>

          <div style={{ flex: 1, minWidth: '150px' }}>
            <select
              className="form-select"
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>
          </div>

          <div style={{ flex: 1, minWidth: '160px' }}>
            <select
              className="form-select"
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
            >
              <option value="ALL">All Triage States</option>
              <option value="OPEN">Open</option>
              <option value="CONFIRMED">Confirmed</option>
              <option value="FALSE_POSITIVE">False Positive</option>
              <option value="RESOLVED">Resolved</option>
              <option value="ACCEPTED_RISK">Accepted Risk</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="data-table-container" style={{ border: 'none' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: '100px' }}>Severity</th>
                <th>Vulnerability Title</th>
                <th>Endpoint</th>
                <th>Scanner</th>
                <th>Status</th>
                <th>Confidence</th>
                <th style={{ width: '100px', textAlign: 'center' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '3rem', color: '#64748b' }}>
                    Loading findings from MongoDB...
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '3rem', color: '#64748b' }}>
                    No findings match the selected filters.
                  </td>
                </tr>
              ) : (
                filtered.map((f) => (
                  <tr key={f.id} style={{ cursor: 'pointer' }} onClick={() => openDetail(f)}>
                    <td>
                      <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                    </td>
                    <td style={{ fontWeight: 600, color: '#0f172a' }}>{f.title}</td>
                    <td style={{ fontFamily: 'monospace' }}>
                      <span className={`method-badge method-${f.method || 'GET'}`} style={{ marginRight: '0.4rem' }}>
                        {f.method || 'GET'}
                      </span>
                      {f.endpoint || '/'}
                    </td>
                    <td>
                      <code>{f.scanner}</code>
                    </td>
                    <td>
                      <span
                        style={{
                          fontSize: '0.75rem',
                          fontWeight: 700,
                          padding: '0.2rem 0.5rem',
                          borderRadius: '6px',
                          background:
                            f.status === 'RESOLVED'
                              ? '#dcfce7'
                              : f.status === 'FALSE_POSITIVE'
                              ? '#f1f5f9'
                              : '#fee2e2',
                          color:
                            f.status === 'RESOLVED'
                              ? '#166534'
                              : f.status === 'FALSE_POSITIVE'
                              ? '#475569'
                              : '#991b1b',
                        }}
                      >
                        {f.status || 'OPEN'}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontWeight: 700, color: '#059669' }}>
                        {Math.round((f.confidence || 0) * 100)}%
                      </span>
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <button
                        className="btn btn-outline-primary"
                        onClick={(e) => {
                          e.stopPropagation();
                          openDetail(f);
                        }}
                        style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Finding Detail Modal */}
      {activeFinding && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(15, 23, 42, 0.6)',
            backdropFilter: 'blur(3px)',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            zIndex: 100,
            padding: '1rem',
          }}
          onClick={() => {
            setActiveFinding(null);
            if (onClearSelectedFinding) onClearSelectedFinding();
          }}
        >
          <div
            style={{
              backgroundColor: '#ffffff',
              borderRadius: '16px',
              maxWidth: '850px',
              width: '100%',
              maxHeight: '90vh',
              overflowY: 'auto',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2)',
              border: '1px solid #cbd5e1',
              padding: '2rem',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                  <span className={`badge badge-${activeFinding.severity}`}>{activeFinding.severity}</span>
                  <span style={{ fontSize: '0.8rem', color: '#64748b' }}>
                    Scanner: <code>{activeFinding.scanner}</code> • Confidence: {Math.round((activeFinding.confidence || 0) * 100)}%
                  </span>
                </div>
                <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#0f172a' }}>
                  {activeFinding.title}
                </h2>
              </div>
              <button
                onClick={() => {
                  setActiveFinding(null);
                  if (onClearSelectedFinding) onClearSelectedFinding();
                }}
                style={{
                  background: '#f1f5f9',
                  border: 'none',
                  borderRadius: '50%',
                  width: 32,
                  height: 32,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  cursor: 'pointer',
                  color: '#64748b',
                }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Target & Route Info */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: '0.75rem',
                padding: '1rem',
                background: '#f8fafc',
                borderRadius: '10px',
                border: '1px solid #e2e8f0',
                marginBottom: '1.25rem',
                fontSize: '0.85rem',
              }}
            >
              <div>
                <span style={{ color: '#64748b' }}>Target Application:</span>
                <div style={{ fontWeight: 600 }}>{activeFinding.targetUrl}</div>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Endpoint Route:</span>
                <div style={{ fontWeight: 600, fontFamily: 'monospace' }}>
                  {activeFinding.method || 'GET'} {activeFinding.endpoint || '/'}
                </div>
              </div>
              {activeFinding.parameter && (
                <div>
                  <span style={{ color: '#64748b' }}>Vulnerable Parameter:</span>
                  <div style={{ fontWeight: 700, color: '#dc2626' }}>{activeFinding.parameter}</div>
                </div>
              )}
            </div>

            {/* Description */}
            <div style={{ marginBottom: '1.25rem' }}>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#334155', marginBottom: '0.4rem' }}>
                Description
              </h3>
              <p style={{ color: '#475569', fontSize: '0.9rem', lineHeight: 1.6 }}>
                {activeFinding.description}
              </p>
            </div>

            {/* Exploit Evidence */}
            {activeFinding.evidence && (
              <div style={{ marginBottom: '1.25rem' }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#334155', marginBottom: '0.4rem' }}>
                  Exploitation Proof & Evidence
                </h3>
                <pre className="code-box">{activeFinding.evidence}</pre>
              </div>
            )}

            {/* Recommendation */}
            {activeFinding.recommendation && (
              <div
                style={{
                  padding: '1rem',
                  borderRadius: '10px',
                  backgroundColor: '#ecfdf5',
                  border: '1px solid #a7f3d0',
                  marginBottom: '1.25rem',
                }}
              >
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#065f46', marginBottom: '0.35rem' }}>
                  Remediation Recommendation
                </h3>
                <p style={{ color: '#047857', fontSize: '0.875rem', lineHeight: 1.5 }}>
                  {activeFinding.recommendation}
                </p>
              </div>
            )}

            {/* Interactive Triage Section */}
            <div
              style={{
                marginTop: '1.5rem',
                paddingTop: '1.25rem',
                borderTop: '1px solid #e2e8f0',
              }}
            >
              <h3 style={{ fontSize: '1rem', fontWeight: 800, color: '#064e3b', marginBottom: '0.75rem' }}>
                Vulnerability Triage & Management
              </h3>

              <div className="grid-2" style={{ alignItems: 'flex-start' }}>
                <div className="form-group">
                  <label className="form-label">Triage Status</label>
                  <select
                    className="form-select"
                    value={triageStatus}
                    onChange={(e) => setTriageStatus(e.target.value as FindingStatus)}
                  >
                    <option value="OPEN">OPEN (Requires Investigation)</option>
                    <option value="CONFIRMED">CONFIRMED (Valid Vulnerability)</option>
                    <option value="RESOLVED">RESOLVED (Patch Deployed)</option>
                    <option value="FALSE_POSITIVE">FALSE POSITIVE (Ignore)</option>
                    <option value="ACCEPTED_RISK">ACCEPTED RISK</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Developer Notes</label>
                  <textarea
                    className="form-textarea"
                    rows={2}
                    value={triageNotes}
                    onChange={(e) => setTriageNotes(e.target.value)}
                    placeholder="Add explanation, pull request link, or rationale..."
                  />
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', alignItems: 'center' }}>
                {updateSuccess && (
                  <span style={{ color: '#059669', fontSize: '0.85rem', fontWeight: 600 }}>
                    Status updated in MongoDB ✓
                  </span>
                )}
                <button
                  className="btn btn-primary"
                  onClick={handleUpdateStatus}
                  disabled={updating}
                >
                  <Save size={16} /> {updating ? 'Saving...' : 'Save Triage Status'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
