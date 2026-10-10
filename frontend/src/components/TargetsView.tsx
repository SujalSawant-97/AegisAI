import React, { useState, useEffect } from 'react';
import {
  Server,
  Plus,
  Trash2,
  PlayCircle,
  AlertCircle,
  CheckCircle,
  ExternalLink,
  Shield,
  Key,
} from 'lucide-react';
import { api } from '../api/client';
import { TargetApp } from '../types';

interface TargetsViewProps {
  onScanTarget: (targetUrl: string) => void;
}

export const TargetsView: React.FC<TargetsViewProps> = ({ onScanTarget }) => {
  const [targets, setTargets] = useState<TargetApp[]>([]);
  const [loading, setLoading] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);

  // Form fields
  const [name, setName] = useState('');
  const [baseUrl, setBaseUrl] = useState('http://localhost:8080');
  const [description, setDescription] = useState('');
  const [authToken, setAuthToken] = useState('');
  const [lowPrivToken, setLowPrivToken] = useState('');

  const [formError, setFormError] = useState('');
  const [formSuccess, setFormSuccess] = useState('');

  const loadTargets = async () => {
    setLoading(true);
    try {
      const data = await api.getTargets();
      setTargets(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTargets();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');
    setFormSuccess('');

    try {
      await api.createTarget({
        name: name || baseUrl,
        baseUrl,
        description,
        authToken: authToken || undefined,
        lowPrivToken: lowPrivToken || undefined,
      });

      setFormSuccess('Target registered successfully in MongoDB!');
      setName('');
      setDescription('');
      setAuthToken('');
      setLowPrivToken('');
      setShowAddForm(false);
      loadTargets();
    } catch (err: any) {
      setFormError(err.message || 'Failed to register target.');
    }
  };

  const handleDelete = async (id?: string) => {
    if (!id) return;
    if (!window.confirm('Are you sure you want to remove this target?')) return;

    try {
      await api.deleteTarget(id);
      loadTargets();
    } catch (err: any) {
      alert('Failed to delete target: ' + err.message);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Top Banner */}
      <div className="card" style={{ padding: '1.25rem 1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#064e3b', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Server size={20} color="#059669" /> Target Applications Under Test
            </h2>
            <p style={{ fontSize: '0.85rem', color: '#64748b' }}>
              Registered authorized targets stored in MongoDB.
            </p>
          </div>

          <button
            className="btn btn-primary"
            onClick={() => setShowAddForm(!showAddForm)}
          >
            <Plus size={16} /> {showAddForm ? 'Cancel' : 'Register New Target'}
          </button>
        </div>
      </div>

      {/* Register Target Form */}
      {showAddForm && (
        <div className="card" style={{ border: '2px solid #a7f3d0', backgroundColor: '#f0fdf4' }}>
          <div className="card-header">
            <div className="card-title" style={{ color: '#064e3b' }}>
              Register Target Application
            </div>
          </div>

          <form onSubmit={handleCreate}>
            <div className="grid-2">
              <div className="form-group">
                <label className="form-label">Application Name</label>
                <input
                  type="text"
                  className="form-input"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Spring Boot User Service"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Base URL (Local Only)</label>
                <input
                  type="text"
                  className="form-input"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder="http://localhost:8080"
                  required
                />
                <div style={{ fontSize: '0.75rem', color: '#059669', marginTop: '0.2rem' }}>
                  Safety restriction: localhost, 127.0.0.1, or ::1 only.
                </div>
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Description</label>
              <input
                type="text"
                className="form-input"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Optional notes or environment context"
              />
            </div>

            <div className="grid-2">
              <div className="form-group">
                <label className="form-label">Default Valid Auth Token</label>
                <input
                  type="text"
                  className="form-input"
                  value={authToken}
                  onChange={(e) => setAuthToken(e.target.value)}
                  placeholder="Bearer token for protected endpoints"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Low-Privilege Token (for BFLA / BOLA)</label>
                <input
                  type="text"
                  className="form-input"
                  value={lowPrivToken}
                  onChange={(e) => setLowPrivToken(e.target.value)}
                  placeholder="Standard user token for authorization testing"
                />
              </div>
            </div>

            {formError && (
              <div style={{ padding: '0.75rem', borderRadius: '8px', background: '#fee2e2', color: '#b91c1c', fontSize: '0.85rem', marginBottom: '1rem' }}>
                <AlertCircle size={16} style={{ display: 'inline', verticalAlign: 'middle', marginRight: 6 }} />
                {formError}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setShowAddForm(false)}
              >
                Cancel
              </button>
              <button type="submit" className="btn btn-primary">
                Save Target to MongoDB
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Targets Grid */}
      {targets.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '3rem', color: '#64748b' }}>
          No target applications registered yet. Click "Register New Target" to add your local application.
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: '1.25rem' }}>
          {targets.map((t) => (
            <div key={t.id} className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#0f172a' }}>{t.name}</h3>
                  <button
                    onClick={() => handleDelete(t.id)}
                    title="Delete Target"
                    style={{
                      background: 'none',
                      border: 'none',
                      color: '#94a3b8',
                      cursor: 'pointer',
                      padding: '0.2rem',
                    }}
                  >
                    <Trash2 size={16} />
                  </button>
                </div>

                <div style={{ fontFamily: 'monospace', fontWeight: 600, color: '#059669', fontSize: '0.9rem', marginBottom: '0.75rem' }}>
                  {t.baseUrl}
                </div>

                {t.description && (
                  <p style={{ color: '#64748b', fontSize: '0.825rem', marginBottom: '0.75rem', lineHeight: 1.5 }}>
                    {t.description}
                  </p>
                )}

                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', fontSize: '0.75rem', color: '#475569' }}>
                  {t.authToken && (
                    <span style={{ background: '#ecfdf5', color: '#047857', padding: '0.15rem 0.5rem', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <Key size={12} /> Auth Token Set
                    </span>
                  )}
                  {t.lowPrivToken && (
                    <span style={{ background: '#fefce8', color: '#854d0e', padding: '0.15rem 0.5rem', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <Shield size={12} /> BFLA Token Set
                    </span>
                  )}
                </div>
              </div>

              <div style={{ marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid #f1f5f9', display: 'flex', justifyContent: 'flex-end' }}>
                <button
                  className="btn btn-primary"
                  onClick={() => onScanTarget(t.baseUrl)}
                  style={{ width: '100%', fontSize: '0.85rem' }}
                >
                  <PlayCircle size={16} /> Launch Security Scan
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
