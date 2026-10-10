import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Dashboard } from './components/Dashboard';
import { ScanManager } from './components/ScanManager';
import { FindingsView } from './components/FindingsView';
import { AgentView } from './components/AgentView';
import { TargetsView } from './components/TargetsView';
import { VulnerabilityFinding } from './types';
import { api } from './api/client';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [backendOnline, setBackendOnline] = useState<boolean>(true);
  const [engineOnline, setEngineOnline] = useState<boolean>(true);
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null);

  const checkHealth = async () => {
    try {
      await api.getFindingStats();
      setBackendOnline(true);
    } catch {
      setBackendOnline(false);
    }

    try {
      const engine = await api.getEngineHealth();
      setEngineOnline(engine.status === 'ok');
    } catch {
      setEngineOnline(false);
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleNavigate = (tab: string) => {
    setCurrentTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleViewFinding = (finding: VulnerabilityFinding) => {
    setSelectedFinding(finding);
    setCurrentTab('findings');
  };

  const handleScanTarget = (_targetUrl: string) => {
    setCurrentTab('scans');
  };

  return (
    <div className="app-container">
      <Header
        currentTab={currentTab}
        onSelectTab={handleNavigate}
        backendOnline={backendOnline}
        engineOnline={engineOnline}
        onRefreshHealth={checkHealth}
      />

      <main className="main-content">
        {currentTab === 'dashboard' && <Dashboard onNavigate={handleNavigate} />}
        {currentTab === 'scans' && <ScanManager onViewFinding={handleViewFinding} />}
        {currentTab === 'findings' && (
          <FindingsView
            selectedFinding={selectedFinding}
            onClearSelectedFinding={() => setSelectedFinding(null)}
          />
        )}
        {currentTab === 'agent' && <AgentView />}
        {currentTab === 'targets' && <TargetsView onScanTarget={handleScanTarget} />}
      </main>

      <footer
        style={{
          borderTop: '1px solid #e2e8f0',
          padding: '1.5rem',
          textAlign: 'center',
          fontSize: '0.8rem',
          color: '#64748b',
          backgroundColor: '#ffffff',
          marginTop: 'auto',
        }}
      >
        <div style={{ maxWidth: 1300, margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <strong>SecEngine AI</strong> • Autonomous Security Scanner & LangGraph Copilot
          </div>
          <div>
            Built with Spring Boot 3, MongoDB, FastAPI, and React • Emerald & White Theme
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
