export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export type FindingStatus = 'OPEN' | 'CONFIRMED' | 'FALSE_POSITIVE' | 'RESOLVED' | 'ACCEPTED_RISK';

export interface TargetApp {
  id?: string;
  name: string;
  baseUrl: string;
  description?: string;
  authToken?: string;
  lowPrivToken?: string;
  defaultHeaders?: Record<string, string>;
  createdAt?: string;
  updatedAt?: string;
}

export interface EndpointParameter {
  name: string;
  location: string;
  required: boolean;
  schemaType?: string;
  description?: string;
}

export interface DiscoveredEndpoint {
  id?: string;
  scanSessionId?: string;
  targetUrl: string;
  method: string;
  path: string;
  authenticationRequired: boolean;
  description?: string;
  parameters: EndpointParameter[];
  discoveredAt?: string;
}

export interface VulnerabilityFinding {
  id: string;
  engineFindingId?: string;
  scanSessionId: string;
  targetUrl: string;
  scanner: string;
  vulnerabilityType: string;
  severity: Severity;
  confidence: number;
  title: string;
  description: string;
  endpoint?: string;
  method?: string;
  parameter?: string;
  evidence?: string;
  recommendation?: string;
  references?: string[];
  metadata?: Record<string, any>;
  status: FindingStatus;
  notes?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface ScanSummary {
  totalEndpoints: number;
  scannedEndpointsCount: number;
  totalFindings: number;
  findingsBySeverity: Record<string, number>;
}

export interface ScannerExecutionError {
  scanner: string;
  error: string;
  metadata?: Record<string, any>;
}

export interface ScanSession {
  id: string;
  engineScanId?: string;
  targetId?: string;
  targetUrl: string;
  status: ScanStatus;
  requestedScanners: string[];
  completedScanners: string[];
  summary: ScanSummary;
  scannerErrors?: ScannerExecutionError[];
  errorMessage?: string;
  startedAt: string;
  completedAt?: string;
}

export interface AgentMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp?: string;
}

export interface AgentConversation {
  id?: string;
  sessionId: string;
  targetUrl?: string;
  initialPrompt?: string;
  messages: AgentMessage[];
  totalMessagesCount: number;
  createdAt?: string;
}

export interface ScannerMetadata {
  name: string;
  description: string;
  vulnerabilityTypes: string[];
  riskLevel: string;
}

export interface FindingMetrics {
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  total_findings: number;
}
