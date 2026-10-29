import React, { useState, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { topologyApi } from '../api/topology';
import { packetsApi } from '../api/packets';
import { useMonitoring } from '../context/MonitoringContext';
import { SeverityBadge } from '../components/common/SeverityBadge';
import type { TopologyNode, TopologyResponse, CaptureSession } from '../types/network';
import { 
  Router, 
  Server, 
  Laptop, 
  ShieldAlert, 
  Lock, 
  Unlock,
  RefreshCw,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Filter,
  Layers,
  ArrowRight
} from 'lucide-react';

export const TopologyPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const { addToast, setSelectedAlertForDetail, alerts, activeCaptureId, setActiveCaptureId } = useMonitoring();

  const [captures, setCaptures] = useState<CaptureSession[]>([]);
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>(
    searchParams.get('captureId') || activeCaptureId || ''
  );

  const [topologyData, setTopologyData] = useState<TopologyResponse | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedLinkId, setSelectedLinkId] = useState<string | null>(null);
  const [sourceMode, setSourceMode] = useState<'auto' | 'pcap' | 'live'>('auto');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [roleFilter, setRoleFilter] = useState<string>('ALL');
  const [loading, setLoading] = useState<boolean>(true);
  const [isolating, setIsolating] = useState<boolean>(false);
  
  // Graph view controls
  const [zoom, setZoom] = useState<number>(1.0);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  // Load captures history
  useEffect(() => {
    packetsApi.getCaptures().then((caps) => {
      setCaptures(caps);
    }).catch(() => {});
  }, []);

  const fetchTopology = async () => {
    setLoading(true);
    try {
      const data = await topologyApi.getTopology(sourceMode, selectedCaptureId || undefined);
      setTopologyData(data);
      if (data.nodes.length > 0 && (!selectedNodeId || !data.nodes.some(n => n.id === selectedNodeId))) {
        // Default select suspicious/attacker or first node
        const priorityNode = data.nodes.find(n => n.role === 'Attacker') || 
                             data.nodes.find(n => n.status === 'Critical' || n.status === 'Warning') || 
                             data.nodes[0];
        setSelectedNodeId(priorityNode.id);
      }
    } catch {
      addToast('Topology Error', 'Failed to generate dynamic topology from traffic.', 'danger');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTopology();
  }, [sourceMode, selectedCaptureId]);

  const nodes = topologyData?.nodes || [];
  const links = topologyData?.links || [];

  // Map of node IDs to node objects
  const nodeMap = useMemo(() => {
    const map = new Map<string, TopologyNode>();
    nodes.forEach(n => map.set(n.id, n));
    return map;
  }, [nodes]);

  // Selected node object
  const selectedNode = useMemo(() => {
    return nodes.find(n => n.id === selectedNodeId) || null;
  }, [nodes, selectedNodeId]);

  // Selected link object
  const selectedLink = useMemo(() => {
    return links.find(l => l.id === selectedLinkId) || null;
  }, [links, selectedLinkId]);

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    return nodes.filter(n => {
      if (roleFilter !== 'ALL' && n.role !== roleFilter) return false;
      if (protocolFilter !== 'ALL' && n.protocols && !n.protocols.includes(protocolFilter)) return false;
      return true;
    });
  }, [nodes, roleFilter, protocolFilter]);

  // Filtered links
  const filteredLinks = useMemo(() => {
    const allowedNodeIds = new Set(filteredNodes.map(n => n.id));
    return links.filter(l => {
      if (!allowedNodeIds.has(l.source) || !allowedNodeIds.has(l.target)) return false;
      if (protocolFilter !== 'ALL' && l.protocol !== protocolFilter && (!l.protocols || !l.protocols.includes(protocolFilter))) return false;
      return true;
    });
  }, [links, filteredNodes, protocolFilter]);

  const handleIsolateToggle = async () => {
    if (!selectedNode) return;
    setIsolating(true);
    const isCurrentlyIsolated = selectedNode.classification?.includes('[ISOLATED]');
    try {
      if (isCurrentlyIsolated) {
        await topologyApi.unisolateHost(selectedNode.ip);
        addToast('Quarantine Released', `Host ${selectedNode.ip} traffic restored.`, 'success');
      } else {
        await topologyApi.isolateHost(selectedNode.ip);
        addToast('Switch Port Isolated', `Host ${selectedNode.ip} quarantined at ingress port.`, 'warning');
      }
      fetchTopology();
    } catch {
      addToast('Action Failed', 'Unable to toggle host isolation.', 'danger');
    } finally {
      setIsolating(false);
    }
  };

  const getNodeIcon = (role: string) => {
    switch (role) {
      case 'Router':
      case 'Gateway':
        return <Router className="w-5 h-5" />;
      case 'Server':
        return <Server className="w-5 h-5" />;
      case 'Attacker':
        return <ShieldAlert className="w-5 h-5" />;
      default:
        return <Laptop className="w-5 h-5" />;
    }
  };

  const getNodeColors = (node: TopologyNode) => {
    if (node.role === 'Attacker') {
      return {
        bg: 'fill-red-950/80',
        stroke: '#ef4444',
        text: 'text-red-400',
        badge: 'border-red-500/40 bg-red-950 text-red-300'
      };
    }
    if (node.status === 'Warning') {
      return {
        bg: 'fill-amber-950/80',
        stroke: '#f59e0b',
        text: 'text-amber-400',
        badge: 'border-amber-500/40 bg-amber-950 text-amber-300'
      };
    }
    if (node.role === 'Server') {
      return {
        bg: 'fill-purple-950/80',
        stroke: '#a855f7',
        text: 'text-purple-400',
        badge: 'border-purple-500/40 bg-purple-950 text-purple-300'
      };
    }
    if (node.role === 'Gateway') {
      return {
        bg: 'fill-cyan-950/80',
        stroke: '#06b6d4',
        text: 'text-cyan-400',
        badge: 'border-cyan-500/40 bg-cyan-950 text-cyan-300'
      };
    }
    return {
      bg: 'fill-slate-900/90',
      stroke: '#475569',
      text: 'text-slate-300',
      badge: 'border-slate-700 bg-slate-800 text-slate-300'
    };
  };

  return (
    <div className="space-y-6">
      {/* Header and Source Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-xl border border-slate-800 bg-[#0d131f] p-6 shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold font-mono text-white tracking-tight">
              Dynamic Network Topology
            </h2>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono border border-cyan-500/30 bg-cyan-950/40 text-cyan-300">
              {topologyData?.dataSource || 'Traffic-Derived'}
            </span>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 font-sans mt-0.5">
            Graph nodes and communication edges reconstructed from observed traffic in{' '}
            <strong className="text-white">{topologyData?.captureName || 'current session'}</strong>.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5 flex-wrap self-start sm:self-auto">
          {/* Data Source Selector */}
          <div className="flex items-center rounded-lg border border-slate-800 bg-[#090d16] p-0.5 text-xs font-mono">
            <button
              onClick={() => setSourceMode('auto')}
              className={`px-2.5 py-1 rounded transition-colors ${
                sourceMode === 'auto' ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30' : 'text-slate-400 hover:text-white'
              }`}
            >
              Auto (PCAP/Live)
            </button>
            <button
              onClick={() => setSourceMode('pcap')}
              className={`px-2.5 py-1 rounded transition-colors ${
                sourceMode === 'pcap' ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30' : 'text-slate-400 hover:text-white'
              }`}
            >
              PCAP
            </button>
            <button
              onClick={() => setSourceMode('live')}
              className={`px-2.5 py-1 rounded transition-colors ${
                sourceMode === 'live' ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30' : 'text-slate-400 hover:text-white'
              }`}
            >
              Live Monitor
            </button>
          </div>

          {/* Capture Picker */}
          {captures.length > 0 && sourceMode !== 'live' && (
            <div className="flex items-center gap-1.5 font-mono text-xs">
              <span className="text-slate-400">Capture:</span>
              <select
                value={selectedCaptureId}
                onChange={(e) => {
                  setSelectedCaptureId(e.target.value);
                  if (e.target.value) setActiveCaptureId(e.target.value);
                  setSearchParams(e.target.value ? { captureId: e.target.value } : {});
                }}
                className="rounded-lg border border-slate-800 bg-[#090d16] px-2.5 py-1 text-slate-200 outline-none focus:border-cyan-500 max-w-[200px]"
              >
                <option value="">Active/Latest PCAP</option>
                {captures.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.filename} ({c.packetCount} pkts)
                  </option>
                ))}
              </select>
            </div>
          )}

          <button
            onClick={fetchTopology}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 font-mono text-xs hover:bg-slate-700 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Rebuild</span>
          </button>
        </div>
      </div>

      {/* Main Graph & Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* SVG Network Graph Canvas */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-[#090d16] p-4 shadow-sm flex flex-col relative min-h-[520px] overflow-hidden">
          {/* Top Canvas Toolbar */}
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 text-xs font-mono z-10">
            {/* Filters */}
            <div className="flex items-center gap-2 flex-wrap">
              <Filter className="w-3.5 h-3.5 text-slate-400" />
              <select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
                className="rounded border border-slate-800 bg-[#0d131f] px-2 py-1 text-[11px] text-slate-300 outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Roles ({nodes.length})</option>
                <option value="Attacker">Adversary / Attackers</option>
                <option value="Server">Servers / Targets</option>
                <option value="Gateway">Gateways / Routers</option>
                <option value="Workstation">Endpoints</option>
              </select>

              <select
                value={protocolFilter}
                onChange={(e) => setProtocolFilter(e.target.value)}
                className="rounded border border-slate-800 bg-[#0d131f] px-2 py-1 text-[11px] text-slate-300 outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Protocols</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
                <option value="ARP">ARP</option>
                <option value="TLS">TLS</option>
                <option value="DNS">DNS</option>
              </select>
            </div>

            {/* Canvas Zoom Controls */}
            <div className="flex items-center gap-1 bg-[#0d131f] border border-slate-800 rounded-lg p-0.5">
              <button
                onClick={() => setZoom(prev => Math.min(prev + 0.15, 2.0))}
                className="p-1 text-slate-400 hover:text-white hover:bg-slate-800 rounded"
                title="Zoom in"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setZoom(prev => Math.max(prev - 0.15, 0.5))}
                className="p-1 text-slate-400 hover:text-white hover:bg-slate-800 rounded"
                title="Zoom out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => { setZoom(1.0); setPan({ x: 0, y: 0 }); }}
                className="p-1 text-slate-400 hover:text-white hover:bg-slate-800 rounded"
                title="Reset zoom"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* SVG Canvas */}
          <div className="flex-1 w-full h-full min-h-[440px] flex items-center justify-center relative select-none">
            {nodes.length === 0 ? (
              <div className="text-center p-6 text-slate-500 font-mono text-xs">
                No active hosts observed. Upload a PCAP in PCAP Analyzer or enable Live Sniffer.
              </div>
            ) : (
              <svg 
                className="w-full h-full min-h-[440px]" 
                viewBox="0 0 900 520"
                style={{
                  transform: `scale(${zoom}) translate(${pan.x}px, ${pan.y}px)`,
                  transition: 'transform 0.15s ease-out'
                }}
              >
                <defs>
                  {/* Glowing Arrow Markers for attack edges */}
                  <marker
                    id="arrow-attack"
                    viewBox="0 0 10 10"
                    refX="20"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
                  </marker>
                  <marker
                    id="arrow-normal"
                    viewBox="0 0 10 10"
                    refX="20"
                    refY="5"
                    markerWidth="5"
                    markerHeight="5"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#334155" />
                  </marker>
                </defs>

                {/* Render Communication Links */}
                {filteredLinks.map((link) => {
                  const srcNode = nodeMap.get(link.source);
                  const dstNode = nodeMap.get(link.target);
                  if (!srcNode || !dstNode) return null;

                  const isAttack = link.status === 'attack-path';
                  const isSelected = selectedLinkId === link.id;

                  return (
                    <g 
                      key={link.id || `${link.source}-${link.target}`}
                      onClick={() => {
                        setSelectedLinkId(link.id || null);
                        setSelectedNodeId(null);
                      }}
                      className="cursor-pointer group"
                    >
                      {/* Wider invisible stroke for easier click detection */}
                      <line
                        x1={srcNode.x}
                        y1={srcNode.y}
                        x2={dstNode.x}
                        y2={dstNode.y}
                        stroke="transparent"
                        strokeWidth="14"
                      />
                      
                      {/* Visible stroke */}
                      <line
                        x1={srcNode.x}
                        y1={srcNode.y}
                        x2={dstNode.x}
                        y2={dstNode.y}
                        stroke={isAttack ? '#ef4444' : isSelected ? '#06b6d4' : '#334155'}
                        strokeWidth={isAttack ? 3 : isSelected ? 2.5 : 1.5}
                        strokeDasharray={isAttack ? '5,5' : undefined}
                        className={isAttack ? 'animate-pulse' : undefined}
                        markerEnd={isAttack ? 'url(#arrow-attack)' : 'url(#arrow-normal)'}
                      />

                      {/* Packet Count Badge at midpoint */}
                      <circle
                        cx={(srcNode.x + dstNode.x) / 2}
                        cy={(srcNode.y + dstNode.y) / 2}
                        r="9"
                        fill="#0b101b"
                        stroke={isAttack ? '#ef4444' : '#475569'}
                        strokeWidth="1"
                      />
                      <text
                        x={(srcNode.x + dstNode.x) / 2}
                        y={(srcNode.y + dstNode.y) / 2 + 3}
                        textAnchor="middle"
                        fill="#94a3b8"
                        fontSize="8"
                        fontFamily="monospace"
                        fontWeight="bold"
                      >
                        {(link.packetCount ?? 0) > 99 ? '99+' : (link.packetCount ?? 0)}
                      </text>
                    </g>
                  );
                })}

                {/* Render Topology Nodes */}
                {filteredNodes.map((node) => {
                  const colors = getNodeColors(node);
                  const isSelected = selectedNodeId === node.id;

                  return (
                    <g
                      key={node.id}
                      onClick={() => {
                        setSelectedNodeId(node.id);
                        setSelectedLinkId(null);
                      }}
                      className="cursor-pointer transition-transform duration-150 hover:scale-105"
                    >
                      {/* Outer Selection Aura */}
                      {isSelected && (
                        <circle
                          cx={node.x}
                          cy={node.y}
                          r="34"
                          fill="none"
                          stroke="#06b6d4"
                          strokeWidth="2"
                          strokeDasharray="4,4"
                          className="animate-spin"
                          style={{ animationDuration: '8s' }}
                        />
                      )}

                      {/* Node Circle Background */}
                      <circle
                        cx={node.x}
                        cy={node.y}
                        r="25"
                        className={colors.bg}
                        stroke={colors.stroke}
                        strokeWidth={isSelected ? '3' : '2'}
                      />

                      {/* Node Role Icon */}
                      <foreignObject
                        x={node.x - 12}
                        y={node.y - 12}
                        width="24"
                        height="24"
                        className={`pointer-events-none ${colors.text} flex items-center justify-center`}
                      >
                        {getNodeIcon(node.role)}
                      </foreignObject>

                      {/* Threat Badge Counter */}
                      {node.alertsCount > 0 && (
                        <g>
                          <circle
                            cx={node.x + 18}
                            cy={node.y - 18}
                            r="9"
                            fill="#ef4444"
                            stroke="#0b101b"
                            strokeWidth="2"
                          />
                          <text
                            x={node.x + 18}
                            y={node.y - 15}
                            textAnchor="middle"
                            fill="#ffffff"
                            fontSize="9"
                            fontFamily="monospace"
                            fontWeight="bold"
                          >
                            {node.alertsCount}
                          </text>
                        </g>
                      )}

                      {/* Node IP Text */}
                      <text
                        x={node.x}
                        y={node.y + 40}
                        textAnchor="middle"
                        fill="#ffffff"
                        fontSize="11"
                        fontFamily="monospace"
                        fontWeight="bold"
                      >
                        {node.ip}
                      </text>

                      {/* Sub-label */}
                      <text
                        x={node.x}
                        y={node.y + 53}
                        textAnchor="middle"
                        fill="#94a3b8"
                        fontSize="9"
                        fontFamily="monospace"
                      >
                        {node.hostname.split(' ')[0]}
                      </text>
                    </g>
                  );
                })}
              </svg>
            )}
          </div>

          {/* Graph Legend */}
          <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between flex-wrap gap-2 text-[11px] font-mono text-slate-400">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-slate-600 inline-block" />
                Normal Host
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block" />
                Gateway
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block" />
                Server / Target
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block" />
                Suspicious (ML)
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" />
                Confirmed Attacker (Rules)
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-4 h-0.5 border-t border-red-500 border-dashed inline-block" />
                Attack Path
              </span>
            </div>
            <span>{filteredNodes.length} hosts • {filteredLinks.length} connections</span>
          </div>
        </div>

        {/* Forensic Host / Edge Inspector Sidebar */}
        <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm space-y-5 flex flex-col font-mono text-xs">
          {selectedLink ? (
            // Edge Inspector
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <ArrowRight className="w-4 h-4 text-cyan-400" />
                  <h3 className="font-bold text-sm text-white">Connection Inspector</h3>
                </div>
                <span className={`px-2 py-0.5 rounded text-[10px] border ${
                  selectedLink.status === 'attack-path'
                    ? 'border-red-500/40 bg-red-950 text-red-300'
                    : 'border-cyan-500/40 bg-cyan-950 text-cyan-300'
                }`}>
                  {selectedLink.status.toUpperCase()}
                </span>
              </div>

              <div className="space-y-2 text-slate-300">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Source Host:</span>
                  <span className="text-cyan-300 font-bold">{nodeMap.get(selectedLink.source)?.ip}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Destination Host:</span>
                  <span className="text-white font-bold">{nodeMap.get(selectedLink.target)?.ip}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Packets Observed:</span>
                  <span className="text-white">{selectedLink.packetCount} packets</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Volume Transferred:</span>
                  <span className="text-white">{(((selectedLink.byteCount ?? 0) / 1024)).toFixed(1)} KB</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Protocols:</span>
                  <span className="text-purple-300 font-bold">
                    {selectedLink.protocols?.join(', ') || selectedLink.protocol}
                  </span>
                </div>
                {selectedLink.ports && selectedLink.ports.length > 0 && (
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-500">Target Ports:</span>
                    <span className="text-slate-200">{selectedLink.ports.join(', ')}</span>
                  </div>
                )}
              </div>

              {selectedLink.evidence && selectedLink.evidence.length > 0 && (
                <div className="p-3 rounded-lg border border-red-500/30 bg-red-950/20 text-red-300 space-y-1">
                  <span className="text-[10px] uppercase font-bold text-red-400">Threat Evidence:</span>
                  {selectedLink.evidence.map((ev, i) => (
                    <p key={i} className="text-[11px] font-sans">{ev}</p>
                  ))}
                </div>
              )}
            </div>
          ) : selectedNode ? (
            // Node Inspector
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  {getNodeIcon(selectedNode.role)}
                  <h3 className="font-bold text-sm text-white">{selectedNode.hostname}</h3>
                </div>
                <span className={`px-2 py-0.5 rounded text-[10px] border ${getNodeColors(selectedNode).badge}`}>
                  {selectedNode.role.toUpperCase()}
                </span>
              </div>

              {/* Classification Banner */}
              <div className="p-3 rounded-lg border border-slate-800 bg-[#090d16] space-y-1">
                <span className="text-[10px] uppercase text-slate-500 font-bold">Host Classification:</span>
                <p className="text-xs text-white font-semibold">{selectedNode.classification}</p>
                <p className="text-[11px] text-slate-400 font-sans">{selectedNode.os}</p>
              </div>

              {/* Telemetry Stats */}
              <div className="space-y-2 text-slate-300">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">IP Address:</span>
                  <span className="text-cyan-300 font-bold">{selectedNode.ip}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">MAC Address:</span>
                  <span className="text-slate-300 font-mono text-[11px]">{selectedNode.mac}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Packets In / Out:</span>
                  <span className="text-white">{selectedNode.packetsIn.toLocaleString()} in / {selectedNode.packetsOut.toLocaleString()} out</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Observed Protocols:</span>
                  <span className="text-purple-300">{selectedNode.protocols?.join(', ') || 'TCP'}</span>
                </div>
                {selectedNode.openPorts && selectedNode.openPorts.length > 0 && (
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-500">Target/Open Ports:</span>
                    <span className="text-slate-200">{selectedNode.openPorts.join(', ')}</span>
                  </div>
                )}
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Associated Alerts:</span>
                  <span className={`font-bold ${selectedNode.alertsCount > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                    {selectedNode.alertsCount} alerts
                  </span>
                </div>
              </div>

              {/* Associated Threat Alerts */}
              {selectedNode.alertsCount > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] uppercase font-bold text-slate-400">Associated Incidents:</span>
                  <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                    {alerts
                      .filter(a => a.sourceIp === selectedNode.ip || a.destinationIp === selectedNode.ip)
                      .slice(0, 4)
                      .map(a => (
                        <div
                          key={a.id}
                          onClick={() => setSelectedAlertForDetail(a)}
                          className="p-2 rounded bg-slate-900/80 border border-slate-800 hover:border-cyan-500/50 cursor-pointer flex items-center justify-between text-[11px]"
                        >
                          <span className="text-white truncate max-w-[170px]">{a.title}</span>
                          <SeverityBadge severity={a.severity} size="sm" />
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Port Quarantine / Isolation Button */}
              <div className="pt-2">
                <button
                  onClick={handleIsolateToggle}
                  disabled={isolating}
                  className={`w-full py-2.5 px-3 rounded-lg font-mono text-xs font-bold flex items-center justify-center gap-2 transition-colors ${
                    selectedNode.classification?.includes('[ISOLATED]')
                      ? 'border border-emerald-500/40 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/50'
                      : 'border border-red-500/40 bg-red-950/40 text-red-300 hover:bg-red-900/50'
                  }`}
                >
                  {selectedNode.classification?.includes('[ISOLATED]') ? (
                    <>
                      <Unlock className="w-3.5 h-3.5" />
                      <span>Release Quarantine</span>
                    </>
                  ) : (
                    <>
                      <Lock className="w-3.5 h-3.5" />
                      <span>Isolate Switch Port</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-center text-slate-500 p-6">
              <Layers className="w-8 h-8 mb-2 text-slate-600" />
              <p>Select any node or connection edge in the network map to inspect forensic telemetry.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
