export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type AttackType = 
  | 'Port Scan'
  | 'SYN Flood'
  | 'ICMP Flood'
  | 'ARP Spoofing'
  | 'Brute Force'
  | 'Network Anomaly';

export type AlertStatus = 'Active' | 'Investigating' | 'Resolved';

export interface AlertEvidence {
  packetsCount: number;
  responseCount: number;
  durationStr: string;
  targetCount: number;
  rawDetails: string[];
}

export interface SecurityAlert {
  id: string;
  title: string;
  severity: Severity;
  attackType: AttackType;
  sourceIp: string;
  destinationIp: string;
  sourcePort?: number;
  destinationPort?: number;
  timestamp: string;
  duration: string;
  status: AlertStatus;
  threatScore: number;
  evidence: AlertEvidence;
  aiExplanation: string;
  recommendations: string[];
  interface?: string;
  detectionSource?: 'RULE_ENGINE' | 'ML_ANOMALY';
  modelName?: string;
  modelVersion?: string;
  anomalyScore?: number;
  decisionThreshold?: number;
  observedFeatures?: Record<string, number>;
  captureId?: string;
  captureName?: string;
  sourceType?: 'PCAP' | 'LIVE';
}

export interface CaptureSession {
  id: string;
  filename: string;
  analyzedAt: string;
  packetCount: number;
  flowCount: number;
  threatsDetected: number;
  ruleThreats: number;
  mlThreats: number;
  observedHosts: string[];
  fileSize: number;
  status: string;
}

export interface NotificationItem {
  id: string;
  alertId?: string;
  title: string;
  severity: Severity;
  attackType: AttackType;
  sourceIp: string;
  destinationIp: string;
  timestamp: string;
  detectionSource: 'RULE_ENGINE' | 'ML_ANOMALY';
  isRead: boolean;
  isDismissed: boolean;
  createdAt?: string;
}

export interface LivePacket {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'ARP' | 'DNS' | 'TLS';
  sourcePort: number;
  destinationPort: number;
  size: number;
  flags: string[];
  info: string;
  isSuspicious?: boolean;
  hexPreview?: string;
  isSynthetic?: boolean;
}

export interface AttackReplayStep {
  id: number;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort?: number;
  port: number;
  service: string;
  protocol?: string;
  flags: string;
  packetSize?: number;
  flowId?: string;
  relatedAlertId?: string;
  detectionSource?: string;
  isThreatTrigger?: boolean;
  triggerReason?: string;
  eventType?: string;
  status: string;
  detail: string;
  evidence?: string;
}

export interface AttackScenario {
  id: string;
  name: string;
  attackType: AttackType;
  sourceIp: string;
  targetIp: string;
  duration: string;
  captureId?: string;
  captureName?: string;
  totalPacketsInCapture?: number;
  incidentPacketsCount?: number;
  packetCount: number;
  portsScanned: number;
  anomalyScore: number;
  description: string;
  timeWindow?: string;
  confidence?: string;
  isSummary?: boolean;
  triggerStepIndex?: number;
  knownFacts?: string[];
  uncertainties?: string[];
  steps: AttackReplayStep[];
}

export interface TopologyNode {
  id: string;
  ip: string;
  hostname: string;
  role: 'Router' | 'Server' | 'Workstation' | 'Attacker' | 'IoT' | 'Gateway';
  status: 'Normal' | 'Warning' | 'Compromised' | 'Critical';
  classification?: string;
  x: number;
  y: number;
  packetsIn: number;
  packetsOut: number;
  bytesIn?: number;
  bytesOut?: number;
  openPorts: number[];
  protocols?: string[];
  alertsCount: number;
  associatedAlerts?: string[];
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  mac: string;
  os: string;
  firstSeen?: string;
  lastSeen?: string;
}

export interface TopologyLink {
  id?: string;
  source: string;
  target: string;
  status: 'normal' | 'high-traffic' | 'attack-path';
  protocol: string;
  protocols?: string[];
  ports?: number[];
  packetCount?: number;
  byteCount?: number;
  flowCount?: number;
  evidence?: string[];
}

export interface TopologyResponse {
  dataSource: string;
  captureName?: string;
  totalObservedHosts: number;
  totalActiveLinks: number;
  nodes: TopologyNode[];
  links: TopologyLink[];
}

export interface TopTalker {
  ip: string;
  hostname: string;
  packets: number;
  bytes: string;
  bandwidthMbps: number;
  risk: 'Critical' | 'High' | 'Medium' | 'Low';
  role: string;
}

export interface SecurityReport {
  id: string;
  name: string;
  type: 'Daily Analysis' | 'Threat Assessment' | 'Incident Forensics' | 'Executive Audit';
  generatedDate: string;
  threats: number;
  criticalCount: number;
  status: 'Ready' | 'Processing' | 'Archived';
  fileSize: string;
  author: string;
  summary: string;
  highlights: string[];
}
