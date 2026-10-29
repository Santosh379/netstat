import React, { useState, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { replayApi } from '../api/replay';
import { packetsApi } from '../api/packets';
import { useMonitoring } from '../context/MonitoringContext';
import type { AttackScenario, AttackReplayStep, CaptureSession } from '../types/network';
import { 
  Play, 
  Pause, 
  SkipBack, 
  SkipForward, 
  RotateCcw, 
  Server, 
  Laptop, 
  Flame, 
  Clock,
  Gauge,
  CheckCircle2,
  AlertTriangle,
  Info,
  Eye
} from 'lucide-react';

export const AttackReplayPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const alertId = searchParams.get('alertId');
  const { setSelectedAlertForDetail, alerts, activeCaptureId, setActiveCaptureId } = useMonitoring();

  const [captures, setCaptures] = useState<CaptureSession[]>([]);
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>(
    searchParams.get('captureId') || activeCaptureId || ''
  );

  const [scenarios, setScenarios] = useState<AttackScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<AttackScenario | null>(null);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [speed, setSpeed] = useState<number>(1); // 0.5x, 1x, 2x, 4x
  const [filterTriggerOnly, setFilterTriggerOnly] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);

  // Load captures history
  useEffect(() => {
    packetsApi.getCaptures().then((caps) => {
      setCaptures(caps);
    }).catch(() => {});
  }, []);

  // Load scenarios whenever selectedCaptureId or alertId changes
  useEffect(() => {
    setLoading(true);
    if (alertId) {
      replayApi.getScenarioFromAlert(alertId).then((scen) => {
        setSelectedScenario(scen);
        setCurrentStepIndex(0);
        setLoading(false);
      }).catch(() => {
        setLoading(false);
      });
    } else {
      replayApi.getScenarios(selectedCaptureId || undefined).then((list) => {
        setScenarios(list);
        if (list.length > 0) {
          setSelectedScenario(list[0]);
          setCurrentStepIndex(0);
        } else {
          setSelectedScenario(null);
        }
        setLoading(false);
      }).catch(() => {
        setLoading(false);
      });
    }
  }, [alertId, selectedCaptureId]);

  const rawSteps = selectedScenario?.steps || [];
  const steps = useMemo(() => {
    if (!filterTriggerOnly) return rawSteps;
    return rawSteps.filter(s => s.isThreatTrigger);
  }, [rawSteps, filterTriggerOnly]);

  const currentStep: AttackReplayStep | undefined = steps[currentStepIndex] || steps[0];

  // Playback loop
  useEffect(() => {
    let timer: any = null;
    if (isPlaying && steps.length > 0) {
      const intervalMs = Math.max(150, Math.floor(1000 / speed));
      timer = setInterval(() => {
        setCurrentStepIndex((prev) => {
          if (prev >= steps.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, intervalMs);
    }
    return () => clearInterval(timer);
  }, [isPlaying, speed, steps.length]);

  const handleStepJump = (index: number) => {
    setCurrentStepIndex(Math.max(0, Math.min(steps.length - 1, index)));
    setIsPlaying(false);
  };

  const handleOpenAlertDetail = () => {
    if (selectedScenario?.id) {
      const cleanAlertId = selectedScenario.id.replace('SCENARIO-', '');
      const match = alerts.find(a => a.id === cleanAlertId);
      if (match) {
        setSelectedAlertForDetail(match);
      }
    }
  };

  return (
    <div className="space-y-6">
      {loading && (
        <div className="p-3 bg-cyan-950/30 border border-cyan-800/50 rounded-lg text-cyan-300 text-xs font-mono flex items-center gap-2">
          <Clock className="w-4 h-4 animate-spin" /> Loading synchronized replay scenario...
        </div>
      )}
      {/* Header and Scenario Selector */}
      <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-red-950/50 border border-red-500/30 text-red-400">
                <Flame className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-xl font-bold font-mono text-white tracking-tight">
                    Forensic Attack Replay
                  </h2>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono border border-cyan-500/30 bg-cyan-950/40 text-cyan-300">
                    Capture-Grounded
                  </span>
                </div>
                <p className="text-xs sm:text-sm text-slate-300 font-sans mt-0.5">
                  Reproduce the actual packet sequences that triggered intrusion alerts, with honest frame counts and trigger evidence.
                </p>
              </div>
            </div>
          </div>

          {/* Capture Scope and Scenario Pickers */}
          <div className="flex flex-wrap items-center gap-2.5 font-mono text-xs">
            {/* Capture Filter */}
            {captures.length > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="text-slate-400">Capture:</span>
                <select
                  value={selectedCaptureId}
                  onChange={(e) => {
                    setSelectedCaptureId(e.target.value);
                    if (e.target.value) setActiveCaptureId(e.target.value);
                    setSearchParams(e.target.value ? { captureId: e.target.value } : {});
                  }}
                  className="rounded-lg border border-slate-800 bg-[#090d16] px-2.5 py-1.5 text-slate-200 outline-none focus:border-cyan-500 max-w-[200px]"
                >
                  <option value="">All Captures</option>
                  {captures.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.filename} ({c.packetCount} pkts)
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Scenario Picker */}
            {scenarios.length > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="text-slate-400">Incident:</span>
                <select
                  value={selectedScenario?.id || ''}
                  onChange={(e) => {
                    const scen = scenarios.find((s) => s.id === e.target.value);
                    if (scen) {
                      setSelectedScenario(scen);
                      setCurrentStepIndex(0);
                      setIsPlaying(false);
                    }
                  }}
                  className="rounded-lg border border-cyan-500/40 bg-[#090d16] px-3 py-1.5 text-cyan-200 outline-none focus:border-cyan-500 max-w-[260px]"
                >
                  {scenarios.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name} ({s.attackType})
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>
        </div>

        {/* Forensic Summary Metadata Chips */}
        {selectedScenario && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5 pt-4 border-t border-slate-800 font-mono text-xs">
            <div className="bg-[#090d16] p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">Attack Classification</span>
              <span className="text-red-400 font-bold text-sm block mt-0.5">
                {selectedScenario.attackType}
              </span>
              <span className="text-[10px] text-slate-500 block truncate mt-0.5">
                {selectedScenario.captureName || selectedScenario.captureId || 'Session Stream'}
              </span>
            </div>

            <div className="bg-[#090d16] p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">Attacking Source</span>
              <span className="text-cyan-300 font-bold text-sm block mt-0.5 truncate">
                {selectedScenario.sourceIp}
              </span>
              <span className="text-[10px] text-slate-500 block mt-0.5">
                Ports Scanned: {selectedScenario.portsScanned}
              </span>
            </div>

            <div className="bg-[#090d16] p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">Target Host</span>
              <span className="text-purple-300 font-bold text-sm block mt-0.5 truncate">
                {selectedScenario.targetIp}
              </span>
              <span className="text-[10px] text-slate-500 block mt-0.5">
                Duration: {selectedScenario.duration}
              </span>
            </div>

            <div className="bg-[#090d16] p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">Evidence Record Scope</span>
              <span className="text-white font-bold text-sm block mt-0.5">
                {selectedScenario.isSummary 
                  ? 'Flow Summary Record' 
                  : `${selectedScenario.packetCount} verified packet frames`
                }
              </span>
              <span className="text-[10px] text-slate-400 block mt-0.5 truncate">
                {selectedScenario.incidentPacketsCount} incident pkts / {selectedScenario.totalPacketsInCapture || selectedScenario.packetCount} in capture
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Main Interactive Replay & Vector Track */}
      {selectedScenario && currentStep ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Synchronized Vector Transmission Stage & Timeline Controls */}
          <div className="lg:col-span-2 space-y-6">
            {/* Visual Vector Transmission Box */}
            <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-6 shadow-sm relative overflow-hidden">
              <div className="flex items-center justify-between max-w-xl mx-auto py-6">
                {/* Source Node */}
                <div className="flex flex-col items-center z-10">
                  <div className={`w-16 h-16 rounded-2xl flex items-center justify-center transition-all ${
                    currentStep.isThreatTrigger 
                      ? 'bg-red-950 border-2 border-red-500 text-red-400 ring-4 ring-red-500/30' 
                      : 'bg-red-950/40 border border-red-500/40 text-red-400'
                  }`}>
                    <Laptop className="w-8 h-8" />
                  </div>
                  <span className="font-mono text-xs font-bold text-white mt-2">
                    {selectedScenario.sourceIp}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400">
                    Port: {currentStep.sourcePort ? `:${currentStep.sourcePort}` : 'Ephem'}
                  </span>
                </div>

                {/* Packet Flight Path */}
                <div className="flex-1 px-8 relative">
                  {/* Background Track Line */}
                  <div className="h-1.5 w-full bg-slate-800 rounded-full relative overflow-hidden">
                    <div 
                      className="h-full bg-cyan-400 transition-all duration-150"
                      style={{ width: `${((currentStepIndex + 1) / steps.length) * 100}%` }}
                    />
                  </div>

                  {/* Dynamic Packet Marker */}
                  <div 
                    className="absolute top-1/2 -translate-y-1/2 -translate-x-1/2 transition-all duration-150"
                    style={{ left: `${((currentStepIndex + 0.5) / steps.length) * 100}%` }}
                  >
                    <div className={`px-2.5 py-1 rounded font-mono text-[10px] font-bold shadow-xl flex items-center gap-1.5 whitespace-nowrap ${
                      currentStep.isThreatTrigger
                        ? 'bg-red-500 text-white ring-2 ring-red-400 animate-bounce'
                        : 'bg-cyan-500 text-slate-950'
                    }`}>
                      <span>{currentStep.protocol}</span>
                      <span>[{currentStep.flags}]</span>
                      <span>→ :{currentStep.port}</span>
                    </div>
                  </div>

                  {/* Step status details */}
                  <div className="text-center font-mono text-xs text-slate-300 mt-4">
                    <span>Packet #{currentStep.id} &bull; </span>
                    <span className="text-cyan-400 font-bold">{currentStep.packetSize} bytes</span>
                    <span> &bull; Status: </span>
                    <span className={`font-bold ${
                      currentStep.status === 'RST_RECEIVED' ? 'text-amber-400' :
                      currentStep.status === 'OPEN' ? 'text-emerald-400' :
                      currentStep.status === 'SYN_SENT' ? 'text-cyan-300' : 'text-slate-300'
                    }`}>
                      {currentStep.status}
                    </span>
                  </div>
                </div>

                {/* Target Node */}
                <div className="flex flex-col items-center z-10">
                  <div className={`w-16 h-16 rounded-2xl flex items-center justify-center transition-all ${
                    currentStep.isThreatTrigger
                      ? 'bg-purple-950 border-2 border-purple-500 text-purple-300 ring-4 ring-purple-500/30'
                      : 'bg-cyan-950/40 border border-cyan-500/40 text-cyan-400'
                  }`}>
                    <Server className="w-8 h-8" />
                  </div>
                  <span className="font-mono text-xs font-bold text-white mt-2">
                    {selectedScenario.targetIp}
                  </span>
                  <span className="text-[10px] font-mono text-purple-300 font-bold">
                    Target :{currentStep.port}
                  </span>
                </div>
              </div>

              {/* Threshold Trigger Banner */}
              {currentStep.isThreatTrigger && (
                <div className="mt-4 p-2.5 rounded-lg border border-red-500/40 bg-red-950/50 flex items-center justify-between text-xs font-mono text-red-200 animate-in fade-in">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                    <span className="font-bold">DETECTION THRESHOLD MET:</span>
                    <span>Intrusion engine confirmed attack criteria at this packet.</span>
                  </div>
                  <button
                    onClick={handleOpenAlertDetail}
                    className="inline-flex items-center gap-1 text-[11px] underline text-cyan-300 hover:text-white"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    <span>View Alert</span>
                  </button>
                </div>
              )}
            </div>

            {/* Replay Controls & Timeline Scrubber */}
            <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm space-y-4 font-mono text-xs">
              {/* Timeline Scrubber */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-slate-400">
                  <div className="flex items-center gap-2">
                    <Clock className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Timeline: <strong className="text-white">{currentStep.timestamp}</strong></span>
                  </div>
                  <span>Event {currentStepIndex + 1} of {steps.length}</span>
                </div>

                <input
                  type="range"
                  min={0}
                  max={Math.max(0, steps.length - 1)}
                  value={currentStepIndex}
                  onChange={(e) => handleStepJump(Number(e.target.value))}
                  className="w-full h-2.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                />
              </div>

              {/* Playback Button Controls */}
              <div className="flex items-center justify-between pt-1 flex-wrap gap-3">
                <div className="flex items-center gap-2">
                  {/* Step Back */}
                  <button
                    onClick={() => handleStepJump(currentStepIndex - 1)}
                    disabled={currentStepIndex === 0}
                    className="p-2 rounded-lg border border-slate-800 bg-[#090d16] hover:bg-slate-800 text-slate-300 disabled:opacity-30 transition-colors"
                    title="Step Backward (Previous Packet)"
                  >
                    <SkipBack className="w-4 h-4" />
                  </button>

                  {/* Play / Pause */}
                  <button
                    onClick={() => setIsPlaying(!isPlaying)}
                    className="inline-flex items-center gap-2 px-6 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold transition-all shadow-md"
                  >
                    {isPlaying ? (
                      <>
                        <Pause className="w-4 h-4 fill-slate-950" />
                        <span>PAUSE</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 fill-slate-950" />
                        <span>PLAY</span>
                      </>
                    )}
                  </button>

                  {/* Step Forward */}
                  <button
                    onClick={() => handleStepJump(currentStepIndex + 1)}
                    disabled={currentStepIndex === steps.length - 1}
                    className="p-2 rounded-lg border border-slate-800 bg-[#090d16] hover:bg-slate-800 text-slate-300 disabled:opacity-30 transition-colors"
                    title="Step Forward (Next Packet)"
                  >
                    <SkipForward className="w-4 h-4" />
                  </button>

                  {/* Restart */}
                  <button
                    onClick={() => handleStepJump(0)}
                    className="p-2 rounded-lg border border-slate-800 bg-[#090d16] hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
                    title="Restart Replay"
                  >
                    <RotateCcw className="w-4 h-4" />
                  </button>
                </div>

                {/* Speed Controls */}
                <div className="flex items-center gap-1.5 bg-[#090d16] border border-slate-800 rounded-lg p-1">
                  <Gauge className="w-3.5 h-3.5 text-slate-400 ml-1" />
                  {[0.5, 1, 2, 4].map((s) => (
                    <button
                      key={s}
                      onClick={() => setSpeed(s)}
                      className={`px-2 py-0.5 rounded text-[11px] transition-colors ${
                        speed === s
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {s}x
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Scrollable Event Log Table */}
            <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="font-bold text-white uppercase text-[11px]">
                  Packet Sequence Stream ({steps.length} Frames)
                </span>
                <label className="flex items-center gap-1.5 cursor-pointer text-slate-400 hover:text-white text-[11px]">
                  <input
                    type="checkbox"
                    checked={filterTriggerOnly}
                    onChange={(e) => {
                      setFilterTriggerOnly(e.target.checked);
                      setCurrentStepIndex(0);
                    }}
                    className="rounded border-slate-700 bg-slate-900 text-cyan-500 w-3 h-3"
                  />
                  <span>Threat triggers only</span>
                </label>
              </div>

              <div className="max-h-60 overflow-y-auto divide-y divide-slate-800/60 pr-1">
                {steps.map((st, idx) => (
                  <div
                    key={st.id}
                    onClick={() => handleStepJump(idx)}
                    className={`py-2 px-3 rounded flex items-center justify-between gap-3 cursor-pointer transition-colors ${
                      idx === currentStepIndex
                        ? 'bg-cyan-950/40 border border-cyan-500/30'
                        : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-slate-500 w-6">#{st.id}</span>
                      <span className="text-slate-400">{st.timestamp}</span>
                      <span className="text-white truncate max-w-xs">{st.detail}</span>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {st.isThreatTrigger && (
                        <span className="px-1.5 py-0.2 rounded text-[10px] font-bold border border-red-500/40 bg-red-950 text-red-300">
                          TRIGGER
                        </span>
                      )}
                      <span className="text-cyan-300">:{st.port}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Forensic Investigation Summary Drawer */}
          <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm space-y-5 font-mono text-xs flex flex-col justify-between">
            <div className="space-y-4">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
                <Info className="w-4 h-4 text-cyan-400" />
                <h3 className="font-bold text-sm text-white">Incident Investigation Brief</h3>
              </div>

              {/* Observed Activity */}
              <div className="p-3 rounded-lg border border-slate-800 bg-[#090d16] space-y-1">
                <span className="text-[10px] uppercase text-slate-500 font-bold">Observed Activity:</span>
                <p className="text-white font-semibold leading-relaxed">
                  {selectedScenario.description}
                </p>
              </div>

              {/* Confidence & Time Window */}
              <div className="space-y-2 text-slate-300">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Time Window:</span>
                  <span className="text-white">{selectedScenario.timeWindow || '0.069s burst'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Confidence:</span>
                  <span className="text-emerald-400 font-bold">{selectedScenario.confidence || 'High'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Threat Score:</span>
                  <span className="text-red-400 font-bold">{selectedScenario.anomalyScore}/100</span>
                </div>
              </div>

              {/* Known Facts */}
              <div className="space-y-1.5">
                <span className="text-[10px] uppercase font-bold text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Established Facts (Observable):</span>
                </span>
                <ul className="space-y-1 text-slate-300 text-[11px] font-sans pl-1">
                  {(selectedScenario.knownFacts || [
                    `Observed ${selectedScenario.packetCount} packets between endpoints`,
                    `Traffic matched deterministic signature thresholds`
                  ]).map((fact, i) => (
                    <li key={i} className="flex items-start gap-1.5">
                      <span className="text-emerald-400 font-mono mt-0.5">•</span>
                      <span>{fact}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Uncertainties */}
              <div className="space-y-1.5 pt-2">
                <span className="text-[10px] uppercase font-bold text-amber-400 flex items-center gap-1">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>Remaining Uncertainties:</span>
                </span>
                <ul className="space-y-1 text-slate-300 text-[11px] font-sans pl-1">
                  {(selectedScenario.uncertainties || [
                    'Encrypted payloads cannot be validated for application exploit payloads',
                    'Host state inferred without internal agent telemetry'
                  ]).map((unc, i) => (
                    <li key={i} className="flex items-start gap-1.5">
                      <span className="text-amber-400 font-mono mt-0.5">•</span>
                      <span>{unc}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Jump to Alert Modal Action */}
            <div className="pt-4 border-t border-slate-800">
              <button
                onClick={handleOpenAlertDetail}
                className="w-full py-2.5 px-3 rounded-lg font-mono text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 flex items-center justify-center gap-2 transition-colors shadow-md"
              >
                <Eye className="w-4 h-4" />
                <span>Open Forensic Alert Drawer</span>
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-12 text-center font-mono text-xs text-slate-400 space-y-3">
          <p>No attack replay scenarios found. Upload a PCAP in PCAP Analyzer to generate packet sequences.</p>
        </div>
      )}
    </div>
  );
};
