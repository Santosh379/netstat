import React, { useState, useEffect } from 'react';
import { useMonitoring } from '../context/MonitoringContext';
import { ProtocolBadge } from '../components/common/ProtocolBadge';
import { systemApi, type InterfaceInfo } from '../api/system';
import { 
  Play, 
  Square, 
  Activity, 
  HardDrive, 
  Network, 
  Trash2, 
  Search, 
  Radio,
  Cpu,
  Layers,
  Clock,
  AlertCircle
} from 'lucide-react';

export const LiveMonitorPage: React.FC = () => {
  const {
    isMonitoring,
    captureMode,
    startCapture,
    stopCapture,
    clearPackets,
    livePackets,
    packetsPerSec,
    bytesPerSec,
    packetsCapturedCount,
    packetsProcessedCount,
    flowsCount,
    mlInferencesCount,
    elapsedSeconds,
    captureStartTime,
    captureError,
    npcapAvailable,
    hasAdminPrivileges,
    activeInterface,
    setActiveInterface
  } = useMonitoring();

  const [protoFilter, setProtoFilter] = useState<string>('ALL');
  const [search, setSearch] = useState<string>('');
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [selectedIface, setSelectedIface] = useState<string>(activeInterface || 'Synthetic Mode');

  useEffect(() => {
    systemApi.getInterfaces().then((ifaces) => {
      setInterfaces(ifaces);
    }).catch(() => {});
  }, []);

  const handleStart = () => {
    startCapture(selectedIface, selectedIface === 'Synthetic Mode');
  };

  const formatElapsed = (sec: number) => {
    const m = Math.floor(sec / 60);
    const s = Math.floor(sec % 60);
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  const filteredPackets = livePackets.filter((pkt) => {
    if (protoFilter !== 'ALL' && pkt.protocol !== protoFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        pkt.sourceIp.includes(q) ||
        pkt.destinationIp.includes(q) ||
        pkt.info.toLowerCase().includes(q) ||
        String(pkt.destinationPort).includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-6 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <h2 className="text-xl font-bold font-mono text-white tracking-tight">
                Live Network Monitor
              </h2>
              {/* Explicit Mode Indicator */}
              {captureMode === 'REAL' ? (
                <span className="text-[11px] font-mono px-2.5 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-300 font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  REAL PHYSICAL CAPTURE: {activeInterface}
                </span>
              ) : captureMode === 'SYNTHETIC' ? (
                <span className="text-[11px] font-mono px-2.5 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-300 font-bold flex items-center gap-1.5" title="Demonstration simulator running safe synthetic traffic">
                  <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
                  SYNTHETIC SIMULATOR
                </span>
              ) : (
                <span className="text-[11px] font-mono px-2.5 py-0.5 rounded border border-slate-700 bg-slate-800/60 text-slate-400 font-semibold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-slate-500" />
                  CAPTURE STOPPED
                </span>
              )}
            </div>
            <p className="text-xs sm:text-sm text-slate-300 font-sans mt-0.5">
              Stream live network packets, measure throughput, track active flows, and run real-time anomaly detection.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Interface selector */}
            <select
              value={selectedIface}
              onChange={(e) => {
                setSelectedIface(e.target.value);
                setActiveInterface(e.target.value);
              }}
              disabled={isMonitoring}
              className="rounded-lg border border-slate-800 bg-[#090d16] px-3 py-2 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none disabled:opacity-60"
            >
              <option value="Synthetic Mode">Synthetic Mode (Demo)</option>
              {interfaces
                .filter((i) => i.name !== 'Synthetic Mode')
                .map((i) => (
                  <option key={i.name} value={i.name}>
                    {i.description || i.name}
                  </option>
                ))}
            </select>

            <button
              onClick={handleStart}
              disabled={isMonitoring}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg font-mono text-xs font-bold transition-all ${
                isMonitoring
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 opacity-70 cursor-default'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white'
              }`}
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Start Capture</span>
            </button>

            <button
              onClick={stopCapture}
              disabled={!isMonitoring}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg font-mono text-xs font-medium border transition-colors ${
                !isMonitoring
                  ? 'bg-slate-800/40 text-slate-500 border-slate-800 cursor-not-allowed'
                  : 'bg-red-500/20 hover:bg-red-500/30 text-red-300 border-red-500/40'
              }`}
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              <span>Stop</span>
            </button>

            <button
              onClick={clearPackets}
              className="p-2 rounded-lg border border-slate-800 bg-[#090d16] hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
              title="Clear packet buffer"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Clear Diagnostic Banner if Npcap / Admin privileges are missing */}
        {(!npcapAvailable || !hasAdminPrivileges || captureError) && (
          <div className="mt-4 p-3 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-200 text-xs font-sans flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold text-amber-300 font-mono text-xs">
                Capture Environment Diagnostic: {captureError || 'Npcap driver missing or elevated privileges required'}
              </p>
              <p className="text-slate-300 text-[11px] mt-0.5 leading-relaxed">
                {!npcapAvailable ? (
                  <>
                    Windows does not have the Npcap packet capture driver installed (<code className="text-amber-200">wpcap.dll</code>). 
                    To capture real packets from physical network adapters (Ethernet / Wi-Fi), install Npcap from{' '}
                    <a href="https://npcap.com" target="_blank" rel="noreferrer" className="text-cyan-400 underline hover:text-cyan-300">npcap.com</a>{' '}
                    with <em>WinPcap API compatibility</em> and launch the terminal as Administrator. NetScope AI is currently operating in explicit <strong>Synthetic Demonstration Mode</strong>.
                  </>
                ) : !hasAdminPrivileges ? (
                  <>
                    Npcap is installed, but the process does not have Administrator privileges to bind raw network sockets. Run your terminal as Administrator to enable real packet capture.
                  </>
                ) : (
                  captureError
                )}
              </p>
            </div>
          </div>
        )}

        {/* 6 Explicit Metrics: Rate, Throughput, Packets Captured, Packets Processed, Active Flows, ML Inferences */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mt-6 pt-5 border-t border-slate-800">
          {/* Rate */}
          <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5">
            <div className="flex items-center gap-1.5 text-cyan-400 mb-1">
              <Activity className="w-3.5 h-3.5" />
              <p className="text-[10px] font-mono uppercase text-slate-400">Packet Rate</p>
            </div>
            <p className="text-lg font-bold font-mono text-white">
              {isMonitoring ? `${packetsPerSec.toLocaleString()} pkt/s` : '0 pkt/s'}
            </p>
          </div>

          {/* Throughput */}
          <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5">
            <div className="flex items-center gap-1.5 text-blue-400 mb-1">
              <HardDrive className="w-3.5 h-3.5" />
              <p className="text-[10px] font-mono uppercase text-slate-400">Throughput</p>
            </div>
            <p className="text-lg font-bold font-mono text-white">
              {isMonitoring ? bytesPerSec : '0 B/s'}
            </p>
          </div>

          {/* Packets Captured vs Processed */}
          <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5" title="Packets received at sniffer / Parsed packets">
            <div className="flex items-center gap-1.5 text-emerald-400 mb-1">
              <Layers className="w-3.5 h-3.5" />
              <p className="text-[10px] font-mono uppercase text-slate-400">Captured / Ingested</p>
            </div>
            <p className="text-lg font-bold font-mono text-white">
              {packetsCapturedCount.toLocaleString()} / {packetsProcessedCount.toLocaleString()}
            </p>
          </div>

          {/* Active Flows */}
          <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5">
            <div className="flex items-center gap-1.5 text-purple-400 mb-1">
              <Network className="w-3.5 h-3.5" />
              <p className="text-[10px] font-mono uppercase text-slate-400">Flow Conversations</p>
            </div>
            <p className="text-lg font-bold font-mono text-white">
              {flowsCount.toLocaleString()}
            </p>
          </div>

          {/* ML Inferences */}
          <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5" title="Unsupervised anomaly model scoring evaluations executed">
            <div className="flex items-center gap-1.5 text-pink-400 mb-1">
              <Cpu className="w-3.5 h-3.5" />
              <p className="text-[10px] font-mono uppercase text-slate-400">ML Inferences</p>
            </div>
            <p className="text-lg font-bold font-mono text-white">
              {mlInferencesCount.toLocaleString()}
            </p>
          </div>

          {/* Elapsed Time */}
          <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5" title={captureStartTime ? `Started at: ${captureStartTime}` : 'Capture not running'}>
            <div className="flex items-center gap-1.5 text-amber-400 mb-1">
              <Clock className="w-3.5 h-3.5" />
              <p className="text-[10px] font-mono uppercase text-slate-400">Elapsed Time</p>
            </div>
            <p className="text-lg font-bold font-mono text-white">
              {isMonitoring ? formatElapsed(elapsedSeconds) : '00:00'}
            </p>
          </div>
        </div>
      </div>

      {/* Packet Table & Filters */}
      <div className="rounded-xl border border-slate-800 bg-[#0d131f] shadow-sm overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-800 bg-[#090d16] flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Radio className={`w-3.5 h-3.5 ${isMonitoring ? 'text-cyan-400 animate-pulse' : 'text-slate-500'}`} />
            <span className="font-mono text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Live Stream ({filteredPackets.length} in buffer)
            </span>
          </div>

          {/* Protocol Filter Tabs & Search */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex bg-[#0d131f] rounded-lg p-0.5 border border-slate-800 text-[10px] font-mono">
              {(['ALL', 'TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'TLS'] as const).map((proto) => (
                <button
                  key={proto}
                  onClick={() => setProtoFilter(proto)}
                  className={`px-2 py-1 rounded transition-colors ${
                    protoFilter === proto
                      ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {proto}
                </button>
              ))}
            </div>

            <div className="relative">
              <Search className="absolute left-2.5 top-2 h-3 w-3 text-slate-400" />
              <input
                type="text"
                placeholder="Filter IP or port..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-36 rounded-lg border border-slate-800 bg-[#0d131f] py-1 pl-7 pr-2 text-[11px] font-mono text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>
        </div>

        <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="sticky top-0 bg-[#090d16] border-b border-slate-800">
              <tr className="text-[11px] uppercase tracking-wider text-slate-400">
                <th className="py-2.5 px-4 font-semibold">Time</th>
                <th className="py-2.5 px-4 font-semibold">Source</th>
                <th className="py-2.5 px-4 font-semibold">Destination</th>
                <th className="py-2.5 px-4 font-semibold">Protocol</th>
                <th className="py-2.5 px-4 font-semibold">Port</th>
                <th className="py-2.5 px-4 font-semibold">Info</th>
                <th className="py-2.5 px-4 font-semibold text-right">Size</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              {filteredPackets.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-mono text-xs">
                    No packets match the current filter.
                  </td>
                </tr>
              ) : (
                filteredPackets.map((pkt, idx) => (
                  <tr key={pkt.id + idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                      {pkt.timestamp}
                    </td>
                    <td className="py-2.5 px-4 text-cyan-300 font-semibold whitespace-nowrap">
                      {pkt.sourceIp}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300 whitespace-nowrap">
                      {pkt.destinationIp}
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <ProtocolBadge protocol={pkt.protocol} />
                    </td>
                    <td className="py-2.5 px-4 text-slate-300 font-semibold whitespace-nowrap">
                      {pkt.destinationPort || '-'}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 truncate max-w-xs" title={pkt.info}>
                      {pkt.info}
                    </td>
                    <td className="py-2.5 px-4 text-right text-slate-400 whitespace-nowrap">
                      {pkt.size >= 1000 ? `${(pkt.size / 1024).toFixed(1)}KB` : `${pkt.size}B`}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
