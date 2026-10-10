import {
  DiscoveredEndpoint,
  FindingMetrics,
  FindingStatus,
  ScanSession,
  ScannerMetadata,
  Severity,
  TargetApp,
  VulnerabilityFinding,
  AgentConversation,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8081/api';

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const errorBody = await res.text();
    let message = `API Request failed with status ${res.status}`;
    try {
      const parsed = JSON.parse(errorBody);
      message = parsed.message || parsed.detail || message;
    } catch {
      if (errorBody) message = errorBody;
    }
    throw new Error(message);
  }
  if (res.status === 204) {
    return {} as T;
  }
  return res.json();
}

export const api = {
  // --- Targets ---
  async getTargets(): Promise<TargetApp[]> {
    const res = await fetch(`${API_BASE_URL}/targets`);
    return handleResponse<TargetApp[]>(res);
  },

  async createTarget(target: TargetApp): Promise<TargetApp> {
    const res = await fetch(`${API_BASE_URL}/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(target),
    });
    return handleResponse<TargetApp>(res);
  },

  async deleteTarget(id: string): Promise<void> {
    const res = await fetch(`${API_BASE_URL}/targets/${id}`, {
      method: 'DELETE',
    });
    return handleResponse<void>(res);
  },

  // --- Scans ---
  async executeOneShotScan(data: {
    target: string;
    scanners?: string[];
    auth_token?: string;
    low_priv_token?: string;
  }): Promise<ScanSession> {
    const res = await fetch(`${API_BASE_URL}/scans/one-shot`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse<ScanSession>(res);
  },

  async createSession(data: {
    target: string;
    auth_token?: string;
    low_priv_token?: string;
  }): Promise<ScanSession> {
    const res = await fetch(`${API_BASE_URL}/scans/sessions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse<ScanSession>(res);
  },

  async discoverSessionEndpoints(sessionId: string): Promise<DiscoveredEndpoint[]> {
    const res = await fetch(`${API_BASE_URL}/scans/sessions/${sessionId}/discover`, {
      method: 'POST',
    });
    return handleResponse<DiscoveredEndpoint[]>(res);
  },

  async runSessionScan(sessionId: string, scanners: string[]): Promise<VulnerabilityFinding[]> {
    const res = await fetch(`${API_BASE_URL}/scans/sessions/${sessionId}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scanners }),
    });
    return handleResponse<VulnerabilityFinding[]>(res);
  },

  async getSession(sessionId: string): Promise<ScanSession> {
    const res = await fetch(`${API_BASE_URL}/scans/sessions/${sessionId}`);
    return handleResponse<ScanSession>(res);
  },

  async getSessions(): Promise<ScanSession[]> {
    const res = await fetch(`${API_BASE_URL}/scans`);
    return handleResponse<ScanSession[]>(res);
  },

  async deleteSession(sessionId: string): Promise<void> {
    const res = await fetch(`${API_BASE_URL}/scans/sessions/${sessionId}`, {
      method: 'DELETE',
    });
    return handleResponse<void>(res);
  },

  // --- Findings ---
  async getFindings(params?: {
    scanSessionId?: string;
    targetUrl?: string;
    severity?: Severity;
    status?: FindingStatus;
  }): Promise<VulnerabilityFinding[]> {
    const query = new URLSearchParams();
    if (params?.scanSessionId) query.append('scanSessionId', params.scanSessionId);
    if (params?.targetUrl) query.append('targetUrl', params.targetUrl);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.status) query.append('status', params.status);

    const qs = query.toString() ? `?${query.toString()}` : '';
    const res = await fetch(`${API_BASE_URL}/findings${qs}`);
    return handleResponse<VulnerabilityFinding[]>(res);
  },

  async getFindingById(id: string): Promise<VulnerabilityFinding> {
    const res = await fetch(`${API_BASE_URL}/findings/${id}`);
    return handleResponse<VulnerabilityFinding>(res);
  },

  async updateFindingStatus(
    id: string,
    status: FindingStatus,
    notes?: string
  ): Promise<VulnerabilityFinding> {
    const res = await fetch(`${API_BASE_URL}/findings/${id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, notes }),
    });
    return handleResponse<VulnerabilityFinding>(res);
  },

  async getFindingStats(): Promise<FindingMetrics> {
    const res = await fetch(`${API_BASE_URL}/findings/stats`);
    return handleResponse<FindingMetrics>(res);
  },

  // --- Agent ---
  async runAgentAudit(target: string, prompt?: string): Promise<AgentConversation> {
    const res = await fetch(`${API_BASE_URL}/agent/audit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, prompt }),
    });
    return handleResponse<AgentConversation>(res);
  },

  async sendAgentChat(
    sessionId: string | undefined,
    message: string,
    target?: string
  ): Promise<AgentConversation> {
    const res = await fetch(`${API_BASE_URL}/agent/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId, message, target }),
    });
    return handleResponse<AgentConversation>(res);
  },

  async getAgentConversations(): Promise<AgentConversation[]> {
    const res = await fetch(`${API_BASE_URL}/agent/conversations`);
    return handleResponse<AgentConversation[]>(res);
  },

  async getAgentConversation(sessionId: string): Promise<AgentConversation> {
    const res = await fetch(`${API_BASE_URL}/agent/conversations/${sessionId}`);
    return handleResponse<AgentConversation>(res);
  },

  // --- Engine Diagnostics ---
  async getEngineHealth(): Promise<{ status: string; service: string }> {
    const res = await fetch(`${API_BASE_URL}/engine/health`);
    return handleResponse<{ status: string; service: string }>(res);
  },

  async getScanners(): Promise<ScannerMetadata[]> {
    const res = await fetch(`${API_BASE_URL}/engine/scanners`);
    return handleResponse<ScannerMetadata[]>(res);
  },
};
