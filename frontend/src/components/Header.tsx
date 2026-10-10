import React from 'react';
import {
  ShieldCheck,
  LayoutDashboard,
  PlayCircle,
  Bug,
  Sparkles,
  Server,
  Activity,
} from 'lucide-react';

interface HeaderProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  backendOnline: boolean;
  engineOnline: boolean;
  onRefreshHealth: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentTab,
  onSelectTab,
  backendOnline,
  engineOnline,
  onRefreshHealth,
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scans', label: 'Security Scans', icon: PlayCircle },
    { id: 'findings', label: 'Vulnerabilities', icon: Bug },
    { id: 'agent', label: 'AI Copilot', icon: Sparkles },
    { id: 'targets', label: 'Targets', icon: Server },
  ];

  return (
    <header
      style={{
        backgroundColor: '#ffffff',
        borderBottom: '1px solid #e2e8f0',
        position: 'sticky',
        top: 0,
        zIndex: 50,
        boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.05)',
      }}
    >
      <div
        style={{
          maxWidth: 1300,
          margin: '0 auto',
          padding: '0.75rem 1.5rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div
            style={{
              backgroundColor: '#059669',
              color: '#ffffff',
              borderRadius: '10px',
              padding: '0.5rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 2px 6px rgba(5, 150, 105, 0.35)',
            }}
          >
            <ShieldCheck size={24} />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: '1.2rem', color: '#064e3b', letterSpacing: '-0.02em' }}>
              SecEngine <span style={{ color: '#059669' }}>AI</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
              Vulnerability Engine & LangGraph Agent
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: 'flex', gap: '0.35rem' }}>
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                  padding: '0.5rem 0.9rem',
                  borderRadius: '8px',
                  fontWeight: active ? 700 : 500,
                  fontSize: '0.875rem',
                  border: 'none',
                  cursor: 'pointer',
                  backgroundColor: active ? '#ecfdf5' : 'transparent',
                  color: active ? '#059669' : '#475569',
                  transition: 'all 0.15s ease',
                }}
              >
                <Icon size={18} color={active ? '#059669' : '#64748b'} />
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Status Indicators */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {/* Spring Boot */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              backgroundColor: backendOnline ? '#ecfdf5' : '#fef2f2',
              color: backendOnline ? '#065f46' : '#991b1b',
              padding: '0.3rem 0.65rem',
              borderRadius: '9999px',
              fontSize: '0.75rem',
              fontWeight: 600,
              border: `1px solid ${backendOnline ? '#a7f3d0' : '#fecaca'}`,
            }}
          >
            <span
              style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                backgroundColor: backendOnline ? '#10b981' : '#ef4444',
              }}
            />
            Spring :8081
          </div>

          {/* FastAPI */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              backgroundColor: engineOnline ? '#ecfdf5' : '#fef2f2',
              color: engineOnline ? '#065f46' : '#991b1b',
              padding: '0.3rem 0.65rem',
              borderRadius: '9999px',
              fontSize: '0.75rem',
              fontWeight: 600,
              border: `1px solid ${engineOnline ? '#a7f3d0' : '#fecaca'}`,
            }}
          >
            <span
              style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                backgroundColor: engineOnline ? '#10b981' : '#ef4444',
              }}
            />
            Engine :8000
          </div>

          <button
            onClick={onRefreshHealth}
            title="Refresh Service Status"
            style={{
              background: '#f8fafc',
              border: '1px solid #cbd5e1',
              borderRadius: '6px',
              padding: '0.35rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              color: '#64748b',
            }}
          >
            <Activity size={16} />
          </button>
        </div>
      </div>
    </header>
  );
};
