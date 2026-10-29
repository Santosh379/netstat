import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { packetsApi, type PcapAnalysisResult } from '../api/packets';
import { useMonitoring } from '../context/MonitoringContext';
import { SeverityBadge } from '../components/common/SeverityBadge';
import type { CaptureSession } from '../types/network';
import { 
  FolderArchive, 
  CheckCircle2, 
  RotateCcw, 
  Sparkles,
  AlertTriangle,
  ShieldAlert,
  Eye,
  Play,
  Network,
  History
} from 'lucide-react';

export const PcapAnalyzerPage: React.FC = () => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { addToast, setSelectedAlertForDetail, setActiveCaptureId } = useMonitoring();
  const navigate = useNavigate();

  const [isDragging, setIsDragging] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressStep, setProgressStep] = useState('');
  const [analysisDone, setAnalysisDone] = useState(false);
  const [result, setResult] = useState<PcapAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [capturesHistory, setCapturesHistory] = useState<CaptureSession[]>([]);

  // Load capture history on mount
  const loadCaptureHistory = () => {
    packetsApi.getCaptures().then((caps) => {
      setCapturesHistory(caps);
    }).catch(() => {});
  };

  useEffect(() => {
    loadCaptureHistory();
  }, []);

  const startAnalysis = async (fileOrSample: File | { name: string; size: number }) => {
    setAnalyzing(true);
    setAnalysisDone(false);
    setError(null);
    setProgress(10);
    setProgressStep('Validating packet capture header...');

    try {
      const data = await packetsApi.analyzePcapFile(fileOrSample, (percent, step) => {
        setProgress(percent);
        setProgressStep(step);
      });

      setResult(data);
      setAnalysisDone(true);
      if (data.captureId) {
        setActiveCaptureId(data.captureId);
      }
      loadCaptureHistory();

      addToast(
        'PCAP Ingestion Complete',
        `Analyzed ${data.packetsAnalyzed.toLocaleString()} packets across ${data.uniqueHosts} hosts.`,
        'success'
      );
    } catch (err: any) {
      console.error('[PcapAnalyzer] Ingestion error:', err);
      const msg = err.message || 'Failed to parse packet capture file.';
      setError(msg);
      addToast('Ingestion Error', msg, 'danger');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      startAnalysis(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      startAnalysis(e.target.files[0]);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-6 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-bold font-mono text-white tracking-tight">
              Isolated PCAP Analyzer
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 font-sans mt-0.5">
              Upload a packet capture trace to extract flow evidence, run rule-based engines, and detect ML outliers.
            </p>
          </div>

          {/* Quick Test Demo Buttons */}
          {!analyzing && (
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => startAnalysis({ name: 'netscope_test_mixed_traffic.pcap', size: 1024 * 90 })}
                className="px-3 py-1.5 rounded-lg border border-purple-500/30 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 font-mono text-xs transition-colors"
                title="165 Packets with SYN Flood, Portscan, and ICMP floods"
              >
                Mixed Traffic PCAP
              </button>
              <button
                onClick={() => startAnalysis({ name: 'sample_syn_flood.pcap', size: 1024 * 140 })}
                className="px-3 py-1.5 rounded-lg border border-red-500/30 bg-red-500/10 hover:bg-red-500/20 text-red-300 font-mono text-xs transition-colors"
              >
                SYN Flood PCAP
              </button>
              <button
                onClick={() => startAnalysis({ name: 'sample_portscan.pcap', size: 1024 * 85 })}
                className="px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 font-mono text-xs transition-colors"
              >
                Port Scan PCAP
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-xl border border-red-500/40 bg-red-950/30 flex items-start gap-3 text-xs font-mono text-red-300">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <div className="flex-1">
            <span className="font-bold block">File Analysis Failed</span>
            <span>{error}</span>
          </div>
          <button
            onClick={() => setError(null)}
            className="text-red-400 hover:text-white"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Drag & Drop Upload Panel */}
      {!analysisDone && !analyzing && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            className={`lg:col-span-2 flex flex-col items-center justify-center p-14 rounded-2xl border-2 border-dashed transition-all bg-[#0d131f]/70 ${
              isDragging
                ? 'border-cyan-400 bg-cyan-950/20'
                : 'border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mb-4">
              <FolderArchive className="w-8 h-8" />
            </div>

            <h3 className="font-mono text-base font-semibold text-white">
              Drop your PCAP file here
            </h3>
            <p className="text-xs font-mono text-slate-400 mt-1 mb-4">
              or browse from local drive
            </p>

            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileSelect}
              accept=".pcap,.pcapng"
              className="hidden"
            />

            <button
              onClick={() => fileInputRef.current?.click()}
              className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold transition-all shadow-md"
            >
              Browse Files
            </button>

            <p className="mt-5 text-xs font-mono text-slate-500">
              Supported: .pcap / .pcapng (Max 50 MB)
            </p>
          </div>

          {/* Previous Capture Sessions History Card */}
          <div className="rounded-2xl border border-slate-800 bg-[#0d131f] p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 border-b border-slate-800 pb-3 mb-3">
                <History className="w-4 h-4 text-cyan-400" />
                <h4 className="font-mono font-bold text-white text-xs uppercase">
                  Recent Captures
                </h4>
              </div>

              {capturesHistory.length === 0 ? (
                <p className="text-xs font-mono text-slate-500 py-6 text-center">
                  No capture sessions logged yet. Upload or test a PCAP above.
                </p>
              ) : (
                <div className="space-y-2 max-h-[260px] overflow-y-auto pr-1">
                  {capturesHistory.slice(0, 5).map((cap) => (
                    <div
                      key={cap.id}
                      onClick={() => {
                        setActiveCaptureId(cap.id);
                        navigate(`/alerts?scope=CAPTURE&captureId=${cap.id}`);
                      }}
                      className="p-2.5 rounded-lg border border-slate-800/80 bg-[#090d16] hover:border-cyan-500/40 cursor-pointer transition-all"
                    >
                      <div className="flex items-center justify-between text-xs font-mono font-bold text-slate-200">
                        <span className="truncate max-w-[160px]">{cap.filename}</span>
                        <span className="text-[10px] text-red-400 bg-red-950/40 px-1.5 py-0.2 rounded border border-red-500/30">
                          {cap.threatsDetected} threats
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mt-1">
                        <span>{cap.packetCount} pkts • {cap.flowCount} flows</span>
                        <span className="text-cyan-400 hover:underline">Inspect →</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <p className="text-[11px] font-mono text-slate-500 mt-3 pt-3 border-t border-slate-800">
              Sessions are persisted with isolated IDs and timestamps.
            </p>
          </div>
        </div>
      )}

      {/* Analyzing Progress State */}
      {analyzing && (
        <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-10 text-center shadow-sm">
          <div className="max-w-md mx-auto space-y-4">
            <div className="flex items-center justify-center gap-2 text-cyan-400 font-mono text-sm font-semibold">
              <Sparkles className="w-4 h-4 animate-spin" />
              <span>Analyzing traffic...</span>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between font-mono text-xs text-slate-400">
                <span>{progressStep}</span>
                <span className="font-bold text-cyan-400">{progress}%</span>
              </div>
              <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full bg-cyan-400 transition-all duration-300"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>

            <p className="text-xs font-mono text-slate-400">
              Extracting packet features & evaluating detection rules...
            </p>
          </div>
        </div>
      )}

      {/* Analysis Complete Results */}
      {analysisDone && !analyzing && result && (
        <div className="space-y-6">
          {/* Capture Session Identity Banner */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 rounded-xl border border-emerald-500/30 bg-emerald-950/20">
            <div className="flex items-start sm:items-center gap-3">
              <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0 mt-0.5 sm:mt-0" />
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="font-mono text-base font-bold text-white">
                    Capture Session: {result.filename}
                  </h3>
                  {result.captureId && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/40 bg-cyan-950/60 text-cyan-300">
                      ID: {result.captureId}
                    </span>
                  )}
                </div>
                <p className="text-xs font-mono text-slate-300 mt-1">
                  Analyzed at {result.analyzedAt || 'Just now'} • {result.filesize} • Processing duration: {result.durationSeconds}s
                </p>
              </div>
            </div>

            {/* Quick Investigation Navigation Buttons */}
            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => {
                  if (result.captureId) setActiveCaptureId(result.captureId);
                  navigate(`/alerts?scope=CAPTURE${result.captureId ? `&captureId=${result.captureId}` : ''}`);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/40 bg-cyan-950/50 hover:bg-cyan-900/60 text-cyan-300 font-mono text-xs transition-colors"
              >
                <Eye className="w-3.5 h-3.5" />
                <span>View Capture Alerts</span>
              </button>

              <button
                onClick={() => {
                  if (result.captureId) setActiveCaptureId(result.captureId);
                  navigate(`/replay${result.captureId ? `?captureId=${result.captureId}` : ''}`);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-purple-500/40 bg-purple-950/50 hover:bg-purple-900/60 text-purple-300 font-mono text-xs transition-colors"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Replay Attack</span>
              </button>

              <button
                onClick={() => {
                  if (result.captureId) setActiveCaptureId(result.captureId);
                  navigate(`/topology?source=pcap${result.captureId ? `&captureId=${result.captureId}` : ''}`);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-indigo-500/40 bg-indigo-950/50 hover:bg-indigo-900/60 text-indigo-300 font-mono text-xs transition-colors"
              >
                <Network className="w-3.5 h-3.5" />
                <span>Inspect Topology</span>
              </button>

              <button
                onClick={() => {
                  setAnalysisDone(false);
                  setResult(null);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 font-mono text-xs hover:bg-slate-700 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Analyze Another</span>
              </button>
            </div>
          </div>

          {/* 5 KPI Cards with Rule/ML breakdown */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
            <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-4 text-center">
              <p className="text-xs font-mono text-slate-400 uppercase">Total Packets</p>
              <p className="text-2xl font-bold font-mono text-white mt-1">
                {result.packetsAnalyzed.toLocaleString()}
              </p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-4 text-center">
              <p className="text-xs font-mono text-slate-400 uppercase">Observed Hosts</p>
              <p className="text-2xl font-bold font-mono text-cyan-400 mt-1">
                {result.uniqueHosts}
              </p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-4 text-center">
              <p className="text-xs font-mono text-slate-400 uppercase">Aggregated Flows</p>
              <p className="text-2xl font-bold font-mono text-blue-400 mt-1">
                {result.tcpConnections}
              </p>
            </div>

            <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-4 text-center">
              <p className="text-xs font-mono text-red-300 uppercase">Rule Threats</p>
              <p className="text-2xl font-bold font-mono text-red-400 mt-1">
                {result.ruleThreats !== undefined ? result.ruleThreats : (result.potentialThreats)}
              </p>
            </div>

            <div className="rounded-xl border border-purple-500/30 bg-purple-950/20 p-4 text-center">
              <p className="text-xs font-mono text-purple-300 uppercase">ML Anomalies</p>
              <p className="text-2xl font-bold font-mono text-purple-400 mt-1">
                {result.mlThreats !== undefined ? result.mlThreats : 0}
              </p>
            </div>
          </div>

          {/* Top Protocols & Detected Signatures */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Protocols Breakdown */}
            <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm space-y-3 font-mono text-xs">
              <h4 className="font-bold text-white uppercase text-[11px] text-slate-400">
                Protocol Breakdown
              </h4>
              <div className="space-y-2">
                {result.topProtocols.map((p) => (
                  <div key={p.name} className="space-y-1">
                    <div className="flex justify-between text-slate-300">
                      <span>{p.name}</span>
                      <span className="font-bold text-cyan-400">{p.percentage}%</span>
                    </div>
                    <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-cyan-400" style={{ width: `${p.percentage}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Detected Signatures */}
            <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm space-y-3 font-mono text-xs">
              <h4 className="font-bold text-white uppercase text-[11px] text-slate-400">
                Detected Attack Signatures
              </h4>
              {result.detectedSignatures.length === 0 ? (
                <p className="text-slate-500 py-4 text-center">No malicious signatures detected.</p>
              ) : (
                <div className="space-y-2">
                  {result.detectedSignatures.map((sig, idx) => (
                    <div key={idx} className="p-3 rounded-lg border border-slate-800 bg-[#090d16] flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-red-400" />
                        <span className="font-bold text-white">{sig.signature}</span>
                      </div>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded uppercase bg-red-500/20 text-red-300 border border-red-500/30">
                        {sig.severity} ({sig.count})
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Captured Security Alerts Table */}
          {result.alerts && result.alerts.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div>
                  <h4 className="font-mono font-bold text-white text-sm">
                    Generated Threat Alerts ({result.alerts.length})
                  </h4>
                  <p className="text-[11px] font-mono text-slate-400 mt-0.5">
                    Individual security incident records parsed from this capture. Click Investigate for forensic explanation.
                  </p>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400 bg-[#090d16]">
                      <th className="py-2.5 px-4 font-semibold">Severity</th>
                      <th className="py-2.5 px-4 font-semibold">Attack Type</th>
                      <th className="py-2.5 px-4 font-semibold">Source</th>
                      <th className="py-2.5 px-4 font-semibold">Destination</th>
                      <th className="py-2.5 px-4 font-semibold">Time</th>
                      <th className="py-2.5 px-4 font-semibold">Detection Source</th>
                      <th className="py-2.5 px-4 font-semibold text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {result.alerts.map((alert) => (
                      <tr
                        key={alert.id}
                        onClick={() => setSelectedAlertForDetail(alert)}
                        className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                      >
                        <td className="py-3 px-4 whitespace-nowrap">
                          <SeverityBadge severity={alert.severity} size="sm" />
                        </td>
                        <td className="py-3 px-4 font-semibold text-white whitespace-nowrap">
                          {alert.attackType}
                        </td>
                        <td className="py-3 px-4 text-cyan-300 font-semibold whitespace-nowrap">
                          {alert.sourceIp}{alert.sourcePort ? `:${alert.sourcePort}` : ''}
                        </td>
                        <td className="py-3 px-4 text-slate-300 whitespace-nowrap">
                          {alert.destinationIp}{alert.destinationPort ? `:${alert.destinationPort}` : ''}
                        </td>
                        <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                          {alert.timestamp}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                            alert.detectionSource === 'ML_ANOMALY'
                              ? 'border-purple-500/40 bg-purple-950/60 text-purple-300'
                              : 'border-cyan-500/40 bg-cyan-950/60 text-cyan-300'
                          }`}>
                            {alert.detectionSource || 'RULE_ENGINE'}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right whitespace-nowrap">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedAlertForDetail(alert);
                            }}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-300 transition-colors"
                          >
                            <Eye className="w-3.5 h-3.5" />
                            <span>Investigate</span>
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
