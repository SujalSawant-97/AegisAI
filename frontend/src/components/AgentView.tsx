import React, { useState, useEffect, useRef } from 'react';
import {
  Sparkles,
  Send,
  Bot,
  User,
  RefreshCw,
  Terminal,
  Shield,
  HelpCircle,
  Copy,
  Check,
  PlayCircle,
} from 'lucide-react';
import { api } from '../api/client';
import { AgentConversation, TargetApp } from '../types';

export const AgentView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'chat' | 'audit'>('chat');
  const [targets, setTargets] = useState<TargetApp[]>([]);
  const [selectedTarget, setSelectedTarget] = useState('http://localhost:8080');

  // Chat State
  const [sessionId, setSessionId] = useState<string>('');
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'assistant'; content: string }>>([
    {
      role: 'assistant',
      content:
        'Hello! I am your **Autonomous Security Copilot** powered by LangGraph and Gemini. You can ask me to analyze scan findings, provide Spring Boot code fixes, or run automated penetration tests on local endpoints.',
    },
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Autonomous Audit State
  const [auditPrompt, setAuditPrompt] = useState(
    'Perform a comprehensive security audit of http://localhost:8080. Focus on authentication enforcement and SQL injection vulnerabilities.'
  );
  const [auditRunning, setAuditRunning] = useState(false);
  const [auditResult, setAuditResult] = useState<string | null>(null);

  useEffect(() => {
    api.getTargets().then((data) => {
      setTargets(data);
      if (data && data.length > 0) {
        setSelectedTarget(data[0].baseUrl);
        setAuditPrompt(`Perform a comprehensive security audit of ${data[0].baseUrl}.`);
      }
    }).catch(() => {});
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSendMessage = async (customText?: string) => {
    const textToSend = customText || inputMessage;
    if (!textToSend.trim() || loading) return;

    const userMsg = { role: 'user' as const, content: textToSend };
    setMessages((prev) => [...prev, userMsg]);
    setInputMessage('');
    setLoading(true);

    try {
      const conv = await api.sendAgentChat(
        sessionId || undefined,
        textToSend,
        selectedTarget
      );
      if (conv.sessionId) setSessionId(conv.sessionId);

      const lastAssistant = conv.messages[conv.messages.length - 1];
      if (lastAssistant && lastAssistant.role === 'assistant') {
        setMessages((prev) => [...prev, { role: 'assistant', content: lastAssistant.content }]);
      }
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `⚠️ Error communicating with AI Agent: ${err.message || 'Service unavailable'}. Ensure FastAPI is running on port 8000.`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleRunAudit = async () => {
    if (auditRunning) return;
    setAuditRunning(true);
    setAuditResult(null);

    try {
      const conv = await api.runAgentAudit(selectedTarget, auditPrompt);
      const lastMsg = conv.messages[conv.messages.length - 1];
      setAuditResult(lastMsg?.content || 'Audit completed without summary.');
    } catch (err: any) {
      setAuditResult(`⚠️ Audit execution failed: ${err.message || 'Service unavailable'}`);
    } finally {
      setAuditRunning(false);
    }
  };

  const presets = [
    'How do I fix the SQL injection vulnerability in Spring Boot with Spring Data JPA?',
    'Show me a secure Spring Security filter chain to prevent BFLA on /admin routes.',
    'Explain the risk of CORS wildcard origin with credentials flag.',
    'Recommend a strict Content-Security-Policy (CSP) header for modern web apps.',
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header and Switcher */}
      <div className="card" style={{ padding: '1rem 1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#064e3b', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Sparkles size={20} color="#059669" /> AI Security Copilot & LangGraph Agent
            </h2>
            <p style={{ fontSize: '0.85rem', color: '#64748b' }}>
              Autonomous multi-agent penetration testing and conversational security remediation.
            </p>
          </div>

          <div style={{ display: 'flex', background: '#f1f5f9', padding: '0.25rem', borderRadius: '10px' }}>
            <button
              onClick={() => setActiveTab('chat')}
              style={{
                border: 'none',
                padding: '0.5rem 1rem',
                borderRadius: '8px',
                fontSize: '0.85rem',
                fontWeight: activeTab === 'chat' ? 700 : 500,
                background: activeTab === 'chat' ? '#ffffff' : 'transparent',
                color: activeTab === 'chat' ? '#059669' : '#475569',
                boxShadow: activeTab === 'chat' ? '0 1px 3px rgba(0,0,0,0.1)' : 'none',
                cursor: 'pointer',
              }}
            >
              Interactive Security Chat
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              style={{
                border: 'none',
                padding: '0.5rem 1rem',
                borderRadius: '8px',
                fontSize: '0.85rem',
                fontWeight: activeTab === 'audit' ? 700 : 500,
                background: activeTab === 'audit' ? '#ffffff' : 'transparent',
                color: activeTab === 'audit' ? '#059669' : '#475569',
                boxShadow: activeTab === 'audit' ? '0 1px 3px rgba(0,0,0,0.1)' : 'none',
                cursor: 'pointer',
              }}
            >
              Autonomous Agent Audit
            </button>
          </div>
        </div>
      </div>

      {activeTab === 'chat' ? (
        /* Chat Mode */
        <div className="card" style={{ display: 'flex', flexDirection: 'column', height: '650px', padding: 0, overflow: 'hidden' }}>
          {/* Target selector toolbar */}
          <div
            style={{
              padding: '0.75rem 1.25rem',
              backgroundColor: '#f8fafc',
              borderBottom: '1px solid #e2e8f0',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: '0.85rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontWeight: 600, color: '#475569' }}>Context Target:</span>
              <input
                type="text"
                className="form-input"
                style={{ width: '240px', padding: '0.35rem 0.6rem', fontSize: '0.8rem' }}
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value)}
              />
            </div>
            {sessionId && (
              <span style={{ color: '#059669', fontWeight: 600, fontSize: '0.75rem' }}>
                Thread ID: {sessionId}
              </span>
            )}
          </div>

          {/* Messages list */}
          <div
            style={{
              flex: 1,
              overflowY: 'auto',
              padding: '1.5rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem',
            }}
          >
            {messages.map((m, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  gap: '0.75rem',
                  alignItems: 'flex-start',
                  justifyContent: m.role === 'user' ? 'flex-end' : 'flex-start',
                }}
              >
                {m.role === 'assistant' && (
                  <div
                    style={{
                      width: 32,
                      height: 32,
                      borderRadius: '8px',
                      backgroundColor: '#059669',
                      color: '#ffffff',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                    }}
                  >
                    <Bot size={18} />
                  </div>
                )}

                <div
                  style={{
                    maxWidth: '75%',
                    padding: '0.9rem 1.15rem',
                    borderRadius: '12px',
                    fontSize: '0.9rem',
                    lineHeight: 1.6,
                    backgroundColor: m.role === 'user' ? '#059669' : '#ffffff',
                    color: m.role === 'user' ? '#ffffff' : '#0f172a',
                    border: m.role === 'user' ? 'none' : '1px solid #e2e8f0',
                    boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  {m.content}
                </div>

                {m.role === 'user' && (
                  <div
                    style={{
                      width: 32,
                      height: 32,
                      borderRadius: '8px',
                      backgroundColor: '#0f172a',
                      color: '#ffffff',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                    }}
                  >
                    <User size={18} />
                  </div>
                )}
              </div>
            ))}
            {loading && (
              <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', color: '#059669', fontSize: '0.85rem' }}>
                <RefreshCw size={16} className="animate-spin" /> Security Copilot is analyzing and formulating response...
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Suggestions Chips */}
          <div style={{ padding: '0.5rem 1.25rem', backgroundColor: '#f8fafc', borderTop: '1px solid #e2e8f0', display: 'flex', gap: '0.5rem', overflowX: 'auto' }}>
            {presets.map((p, idx) => (
              <button
                key={idx}
                onClick={() => handleSendMessage(p)}
                style={{
                  whiteSpace: 'nowrap',
                  background: '#ffffff',
                  border: '1px solid #cbd5e1',
                  borderRadius: '20px',
                  padding: '0.3rem 0.75rem',
                  fontSize: '0.75rem',
                  color: '#334155',
                  cursor: 'pointer',
                }}
              >
                {p}
              </button>
            ))}
          </div>

          {/* Input Box */}
          <div style={{ padding: '1rem 1.25rem', backgroundColor: '#ffffff', borderTop: '1px solid #e2e8f0', display: 'flex', gap: '0.75rem' }}>
            <input
              type="text"
              className="form-input"
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleSendMessage();
              }}
              placeholder="Ask about vulnerabilities, remediation code, or test strategies..."
            />
            <button
              className="btn btn-primary"
              onClick={() => handleSendMessage()}
              disabled={loading || !inputMessage.trim()}
              style={{ padding: '0.65rem 1.25rem' }}
            >
              <Send size={16} /> Send
            </button>
          </div>
        </div>
      ) : (
        /* Autonomous Audit Mode */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <Sparkles size={20} color="#059669" /> Autonomous Audit Instructions
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Target Application Base URL</label>
              <input
                type="text"
                className="form-input"
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value)}
                placeholder="http://localhost:8080"
              />
            </div>

            <div className="form-group">
              <label className="form-label">Audit Directive for LangGraph Agent</label>
              <textarea
                className="form-textarea"
                rows={3}
                value={auditPrompt}
                onChange={(e) => setAuditPrompt(e.target.value)}
                placeholder="Describe the scope and focus for the autonomous agent..."
              />
            </div>

            <button
              className="btn btn-primary"
              onClick={handleRunAudit}
              disabled={auditRunning}
              style={{ padding: '0.75rem 1.5rem', fontSize: '0.95rem' }}
            >
              {auditRunning ? <RefreshCw size={18} className="animate-spin" /> : <PlayCircle size={18} />}
              {auditRunning ? 'Agent is Auditing Target...' : 'Execute Autonomous AI Audit'}
            </button>
          </div>

          {/* Audit Result Report */}
          {auditResult && (
            <div className="card">
              <div className="card-header">
                <div className="card-title">Executive Security Assessment Report</div>
              </div>
              <div
                style={{
                  background: '#f8fafc',
                  padding: '1.5rem',
                  borderRadius: '10px',
                  border: '1px solid #e2e8f0',
                  lineHeight: 1.7,
                  whiteSpace: 'pre-wrap',
                  fontSize: '0.9rem',
                  color: '#1e293b',
                }}
              >
                {auditResult}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
