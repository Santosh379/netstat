import type { SecurityAlert, LivePacket, AttackScenario, TopologyNode, TopologyLink, SecurityReport } from '../types/network';

export const mockAlerts: SecurityAlert[] = [
  {
    id: 'ALT-101',
    title: 'SYN Flood',
    severity: 'HIGH',
    attackType: 'SYN Flood',
    sourceIp: '192.168.1.15',
    destinationIp: '192.168.1.20',
    sourcePort: 49152,
    destinationPort: 80,
    timestamp: '10:42:12',
    duration: '2.8 seconds',
    status: 'Active',
    threatScore: 90,
    evidence: {
      packetsCount: 4832,
      responseCount: 31,
      durationStr: '2.8 seconds',
      targetCount: 1,
      rawDetails: [
        '4,832 SYN packets sent without completing TCP handshake',
        'Only 31 ACK responses returned by target server',
        'Destination port 80 connection queue saturated'
      ]
    },
    aiExplanation: 'A large number of SYN packets were observed from a single source within a short period, while comparatively few ACK responses were detected.',
    recommendations: [
      'Rate-limit SYN requests',
      'Enable SYN cookies',
      'Investigate the source IP'
    ],
    interface: 'Wi-Fi (wlan0)'
  },
  {
    id: 'ALT-102',
    title: 'Port Scan',
    severity: 'MEDIUM',
    attackType: 'Port Scan',
    sourceIp: '192.168.1.31',
    destinationIp: '192.168.1.20',
    sourcePort: 55432,
    destinationPort: 22,
    timestamp: '10:39:44',
    duration: '2.4 seconds',
    status: 'Investigating',
    threatScore: 70,
    evidence: {
      packetsCount: 1420,
      responseCount: 18,
      durationStr: '2.4 seconds',
      targetCount: 1,
      rawDetails: [
        'Probing sequential ports (:22, :23, :80, :443)',
        'Stealth SYN scan signature detected',
        'Closed ports responded with TCP RST'
      ]
    },
    aiExplanation: 'Multiple connection attempts across consecutive destination ports were detected from a single source in under 3 seconds.',
    recommendations: [
      'Block scanning source IP on firewall',
      'Disable unused open ports on server',
      'Enable port scan detection rules'
    ],
    interface: 'Wi-Fi (wlan0)'
  },
  {
    id: 'ALT-103',
    title: 'Brute Force',
    severity: 'MEDIUM',
    attackType: 'Brute Force',
    sourceIp: '192.168.1.40',
    destinationIp: '192.168.1.10',
    sourcePort: 41200,
    destinationPort: 22,
    timestamp: '10:31:02',
    duration: '45.1 seconds',
    status: 'Resolved',
    threatScore: 65,
    evidence: {
      packetsCount: 840,
      responseCount: 840,
      durationStr: '45.1 seconds',
      targetCount: 1,
      rawDetails: [
        'Repeated failed SSH logins to port 22',
        'Multiple standard usernames attempted (root, admin)',
        'Continuous authentication rejection packets'
      ]
    },
    aiExplanation: 'Rapid succession of failed authentication attempts against SSH port 22 indicating dictionary-based password guessing.',
    recommendations: [
      'Enforce SSH key-based authentication only',
      'Rate-limit SSH login attempts',
      'Use strong password policies'
    ],
    interface: 'Wi-Fi (wlan0)'
  },
  {
    id: 'ALT-104',
    title: 'ICMP Flood',
    severity: 'HIGH',
    attackType: 'ICMP Flood',
    sourceIp: '192.168.1.88',
    destinationIp: '192.168.1.1',
    timestamp: '10:25:18',
    duration: '6.4 seconds',
    status: 'Active',
    threatScore: 85,
    evidence: {
      packetsCount: 9400,
      responseCount: 120,
      durationStr: '6.4 seconds',
      targetCount: 1,
      rawDetails: [
        'Massive volume of ICMP Echo Requests (ping)',
        'Gateway buffer overloaded by ping flood',
        'Packet rate exceeded 1,400 pps'
      ]
    },
    aiExplanation: 'An overwhelming rate of ping requests aimed at the default gateway router causing network congestion.',
    recommendations: [
      'Limit ICMP request rates on router',
      'Drop broadcast ping responses',
      'Inspect host 192.168.1.88 for malware'
    ],
    interface: 'Wi-Fi (wlan0)'
  },
  {
    id: 'ALT-105',
    title: 'ARP Spoofing',
    severity: 'CRITICAL',
    attackType: 'ARP Spoofing',
    sourceIp: '192.168.1.15',
    destinationIp: '192.168.1.10',
    timestamp: '10:14:05',
    duration: '12.0 seconds',
    status: 'Active',
    threatScore: 95,
    evidence: {
      packetsCount: 380,
      responseCount: 0,
      durationStr: '12.0 seconds',
      targetCount: 2,
      rawDetails: [
        'Unsolicited ARP replies broadcast across LAN',
        'Claiming router IP 192.168.1.1 resolves to attacker MAC',
        'Man-in-the-Middle traffic redirection observed'
      ]
    },
    aiExplanation: 'Fake ARP replies detected attempting to poison the local ARP table and intercept traffic between PC-01 and the Router.',
    recommendations: [
      'Enable Dynamic ARP Inspection (DAI)',
      'Use static ARP tables for gateway',
      'Quarantine attacker 192.168.1.15'
    ],
    interface: 'Wi-Fi (wlan0)'
  },
  {
    id: 'ALT-106',
    title: 'Port Scan Sweep',
    severity: 'CRITICAL',
    attackType: 'Port Scan',
    sourceIp: '192.168.1.15',
    destinationIp: '192.168.1.20',
    sourcePort: 54100,
    destinationPort: 80,
    timestamp: '10:05:30',
    duration: '3.1 seconds',
    status: 'Active',
    threatScore: 92,
    evidence: {
      packetsCount: 2100,
      responseCount: 45,
      durationStr: '3.1 seconds',
      targetCount: 1,
      rawDetails: [
        'Rapid port sweep targeting Web and SSH ports',
        'Flagged reconnaissance scan before attack'
      ]
    },
    aiExplanation: 'Targeted scanning tool actively fingerprinting open services on the production server.',
    recommendations: [
      'Quarantine IP 192.168.1.15',
      'Review firewall access rules'
    ],
    interface: 'Wi-Fi (wlan0)'
  }
];

export const mockLivePackets: LivePacket[] = [
  {
    id: 'PKT-101',
    timestamp: '10:42:01',
    sourceIp: '192.168.1.15',
    destinationIp: '192.168.1.20',
    protocol: 'TCP',
    sourcePort: 49182,
    destinationPort: 443,
    size: 512,
    flags: ['SYN'],
    info: '49182 → 443 [SYN] Seq=18293021 Win=1024 Len=0'
  },
  {
    id: 'PKT-102',
    timestamp: '10:42:02',
    sourceIp: '192.168.1.10',
    destinationIp: '192.168.1.20',
    protocol: 'TCP',
    sourcePort: 54112,
    destinationPort: 80,
    size: 1200,
    flags: ['ACK', 'PSH'],
    info: '54112 → 80 [ACK, PSH] GET /index.html'
  },
  {
    id: 'PKT-103',
    timestamp: '10:42:02',
    sourceIp: '192.168.1.31',
    destinationIp: '192.168.1.20',
    protocol: 'TCP',
    sourcePort: 51200,
    destinationPort: 22,
    size: 640,
    flags: ['SYN'],
    info: '51200 → 22 [SYN] Seq=9948210 Win=2048 Len=0'
  },
  {
    id: 'PKT-104',
    timestamp: '10:42:03',
    sourceIp: '192.168.1.15',
    destinationIp: '192.168.1.20',
    protocol: 'TCP',
    sourcePort: 49183,
    destinationPort: 22,
    size: 512,
    flags: ['SYN'],
    info: '49183 → 22 [SYN] Port probe'
  },
  {
    id: 'PKT-105',
    timestamp: '10:42:04',
    sourceIp: '192.168.1.10',
    destinationIp: '192.168.1.1',
    protocol: 'UDP',
    sourcePort: 53120,
    destinationPort: 53,
    size: 78,
    flags: [],
    info: 'Standard DNS query A netscope.local'
  },
  {
    id: 'PKT-106',
    timestamp: '10:42:05',
    sourceIp: '192.168.1.1',
    destinationIp: '192.168.1.10',
    protocol: 'UDP',
    sourcePort: 53,
    destinationPort: 53120,
    size: 94,
    flags: [],
    info: 'DNS response A 192.168.1.20'
  },
  {
    id: 'PKT-107',
    timestamp: '10:42:06',
    sourceIp: '192.168.1.88',
    destinationIp: '192.168.1.1',
    protocol: 'ICMP',
    sourcePort: 0,
    destinationPort: 0,
    size: 64,
    flags: [],
    info: 'Echo (ping) request id=0x12a seq=1'
  },
  {
    id: 'PKT-108',
    timestamp: '10:42:07',
    sourceIp: '192.168.1.1',
    destinationIp: '192.168.1.10',
    protocol: 'ARP',
    sourcePort: 0,
    destinationPort: 0,
    size: 42,
    flags: [],
    info: 'Who has 192.168.1.10? Tell 192.168.1.1'
  }
];

export const mockAttackScenarios: AttackScenario[] = [
  {
    id: 'SCENARIO-PORT-SCAN',
    name: 'Port Scan',
    attackType: 'Port Scan',
    sourceIp: '192.168.1.15',
    targetIp: '192.168.1.20',
    duration: '2.4 sec',
    totalPacketsInCapture: 165,
    incidentPacketsCount: 18,
    packetCount: 6,
    portsScanned: 18,
    anomalyScore: 98.4,
    description: 'Systematic TCP port scan probing standard daemon services from low ports to high management interfaces.',
    steps: [
      { id: 1, timestamp: '10:42:01.002', sourceIp: '192.168.1.15', destinationIp: '192.168.1.20', port: 22, service: 'SSH', flags: 'SYN', status: 'OPEN', detail: 'Packet #1: TCP SYN probe to port 22 (SSH)', eventType: 'RAW_PACKET' },
      { id: 2, timestamp: '10:42:01.114', sourceIp: '192.168.1.15', destinationIp: '192.168.1.20', port: 23, service: 'Telnet', flags: 'SYN', status: 'FILTERED', detail: 'Packet #2: TCP SYN probe to port 23 (Telnet)', eventType: 'RAW_PACKET' },
      { id: 3, timestamp: '10:42:01.227', sourceIp: '192.168.1.15', destinationIp: '192.168.1.20', port: 80, service: 'HTTP', flags: 'SYN', status: 'OPEN', detail: 'Packet #3: TCP SYN probe to port 80 (HTTP)', eventType: 'RAW_PACKET' },
      { id: 4, timestamp: '10:42:01.341', sourceIp: '192.168.1.15', destinationIp: '192.168.1.20', port: 443, service: 'HTTPS', flags: 'SYN', status: 'OPEN', detail: 'Packet #4: TCP SYN probe to port 443 (HTTPS)', eventType: 'RAW_PACKET' },
      { id: 5, timestamp: '10:42:01.455', sourceIp: '192.168.1.15', destinationIp: '192.168.1.20', port: 3306, service: 'MySQL', flags: 'SYN', status: 'FILTERED', detail: 'Packet #5: TCP SYN probe to port 3306 (MySQL)', eventType: 'RAW_PACKET' },
      { id: 6, timestamp: '10:42:01.568', sourceIp: '192.168.1.15', destinationIp: '192.168.1.20', port: 8080, service: 'Dev-API', flags: 'SYN', status: 'OPEN', isThreatTrigger: true, triggerReason: 'Threshold: 15+ unique ports probed', detail: 'Packet #6: TCP SYN probe to port 8080 (Dev-API) - Detection Trigger', eventType: 'RAW_PACKET' }
    ]
  },
  {
    id: 'SCENARIO-SYN-FLOOD',
    name: 'SYN Flood',
    attackType: 'SYN Flood',
    sourceIp: '192.168.1.15',
    targetIp: '192.168.1.20',
    duration: '2.8 sec',
    totalPacketsInCapture: 165,
    incidentPacketsCount: 35,
    packetCount: 3,
    portsScanned: 1,
    anomalyScore: 99.1,
    description: 'High rate of TCP SYN packets sent to exhaust server socket connections without sending final ACK.',
    steps: [
      { id: 1, timestamp: '10:42:12.001', sourceIp: '192.168.1.15', destinationIp: '192.168.1.20', port: 80, service: 'HTTP', flags: 'SYN', status: 'SYN_SENT', detail: 'Packet #1: TCP SYN packet (seq 1001, 64 B) to port 80', eventType: 'RAW_PACKET' },
      { id: 2, timestamp: '10:42:12.350', sourceIp: '192.168.1.15', destinationIp: '192.168.1.20', port: 80, service: 'HTTP', flags: 'SYN', status: 'SYN_SENT', detail: 'Packet #15: Consecutive TCP SYN packet without ACK handshake', eventType: 'RAW_PACKET' },
      { id: 3, timestamp: '10:42:12.800', sourceIp: '192.168.1.15', destinationIp: '192.168.1.20', port: 80, service: 'HTTP', flags: 'SYN', status: 'SYN_SENT', isThreatTrigger: true, triggerReason: 'SYN flood threshold exceeded (>30 SYN packets in time window)', detail: 'Packet #30: High-frequency TCP SYN threshold exceeded', eventType: 'RAW_PACKET' }
    ]
  }
];

export const mockTopologyNodes: TopologyNode[] = [
  {
    id: 'node-router',
    ip: '192.168.1.1',
    hostname: 'Host-192.168.1.1',
    role: 'Workstation',
    status: 'Normal',
    x: 450,
    y: 80,
    packetsIn: 12400,
    packetsOut: 12100,
    openPorts: [80, 53],
    alertsCount: 0,
    riskLevel: 'Low',
    mac: 'Unavailable (L3 IP header only)',
    os: 'Unknown (Heuristic only)'
  },
  {
    id: 'node-pc01',
    ip: '192.168.1.10',
    hostname: 'Host-192.168.1.10',
    role: 'Workstation',
    status: 'Normal',
    x: 230,
    y: 250,
    packetsIn: 3200,
    packetsOut: 3100,
    openPorts: [],
    alertsCount: 0,
    riskLevel: 'Low',
    mac: 'Unavailable (L3 IP header only)',
    os: 'Unknown (Heuristic only)'
  },
  {
    id: 'node-server',
    ip: '192.168.1.20',
    hostname: 'Host-192.168.1.20',
    role: 'Server',
    status: 'Critical',
    x: 450,
    y: 250,
    packetsIn: 24890,
    packetsOut: 4500,
    openPorts: [22, 80, 443, 8080],
    alertsCount: 2,
    riskLevel: 'Critical',
    mac: 'Unavailable (L3 IP header only)',
    os: 'Unknown (Heuristic only)'
  },
  {
    id: 'node-pc02',
    ip: '192.168.1.30',
    hostname: 'Host-192.168.1.30',
    role: 'Workstation',
    status: 'Normal',
    x: 670,
    y: 250,
    packetsIn: 2100,
    packetsOut: 2050,
    openPorts: [],
    alertsCount: 0,
    riskLevel: 'Low',
    mac: 'Unavailable (L3 IP header only)',
    os: 'Unknown (Heuristic only)'
  },
  {
    id: 'node-attacker',
    ip: '192.168.1.15',
    hostname: 'Host-192.168.1.15',
    role: 'Attacker',
    status: 'Compromised',
    x: 450,
    y: 430,
    packetsIn: 800,
    packetsOut: 9800,
    openPorts: [4444],
    alertsCount: 3,
    riskLevel: 'Critical',
    mac: 'Unavailable (L3 IP header only)',
    os: 'Unknown (Heuristic only)'
  }
];

export const mockTopologyLinks: TopologyLink[] = [
  { source: 'node-router', target: 'node-pc01', status: 'normal', protocol: 'LAN' },
  { source: 'node-router', target: 'node-server', status: 'normal', protocol: 'LAN' },
  { source: 'node-router', target: 'node-pc02', status: 'normal', protocol: 'LAN' },
  { source: 'node-attacker', target: 'node-server', status: 'attack-path', protocol: 'Attack Stream' }
];

export const mockTrafficTimeline = {
  '1H': [
    { time: '10:00', packets: 1420 },
    { time: '10:15', packets: 1680 },
    { time: '10:30', packets: 4890 },
    { time: '10:45', packets: 12842 },
    { time: '11:00', packets: 8400 }
  ],
  '6H': [
    { time: '05:00', packets: 840 },
    { time: '06:00', packets: 1100 },
    { time: '07:00', packets: 2400 },
    { time: '08:00', packets: 5200 },
    { time: '09:00', packets: 9100 },
    { time: '10:00', packets: 12842 }
  ],
  '24H': [
    { time: '12:00', packets: 6500 },
    { time: '16:00', packets: 8200 },
    { time: '20:00', packets: 4100 },
    { time: '00:00', packets: 1200 },
    { time: '04:00', packets: 950 },
    { time: '08:00', packets: 9400 },
    { time: '12:00', packets: 12842 }
  ]
};

export const mockProtocolDistribution = [
  { name: 'TCP', value: 61, color: '#06b6d4' },
  { name: 'UDP', value: 24, color: '#3b82f6' },
  { name: 'ICMP', value: 9, color: '#f59e0b' },
  { name: 'ARP', value: 6, color: '#10b981' }
];

export const mockReports: SecurityReport[] = [
  {
    id: 'REP-01',
    name: 'Network Security Report',
    type: 'Daily Analysis',
    generatedDate: '24 Sep 2026',
    threats: 14,
    criticalCount: 2,
    status: 'Ready',
    fileSize: '1.2 MB',
    author: 'NetScope AI',
    summary: 'Summary of detected attacks and anomalies across monitored endpoints.',
    highlights: [
      '14 security threats detected in 24 hours',
      'High SYN flood traffic observed targeting server :80',
      'Port scan detected from 192.168.1.31'
    ]
  },
  {
    id: 'REP-02',
    name: 'Port Scan Analysis',
    type: 'Threat Assessment',
    generatedDate: '23 Sep 2026',
    threats: 3,
    criticalCount: 0,
    status: 'Ready',
    fileSize: '840 KB',
    author: 'NetScope AI',
    summary: 'Detailed probe sequence analysis across host ports.',
    highlights: [
      'Reconnaissance scan identified',
      'Probe on ports 22, 23, 80, 443'
    ]
  },
  {
    id: 'REP-03',
    name: 'SYN Flood Analysis',
    type: 'Incident Forensics',
    generatedDate: '22 Sep 2026',
    threats: 5,
    criticalCount: 1,
    status: 'Ready',
    fileSize: '1.8 MB',
    author: 'NetScope AI',
    summary: 'Detailed packet breakdown of TCP half-open connection flood.',
    highlights: [
      '4,832 SYN packets recorded',
      '31 ACK responses detected'
    ]
  }
];
