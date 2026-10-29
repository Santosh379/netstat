import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useMonitoring } from '../../context/MonitoringContext';
import { SeverityBadge } from './SeverityBadge';
import { 
  X, 
  ShieldAlert, 
  Play,
  Cpu
} from 'lucide-react';

export const AlertDetailModal: React.FC = () => {
  const { selectedAlertForDetail, setSelectedAlertForDetail } = useMonitoring();
  const navigate = useNavigate();

  if (!selectedAlertForDetail) return null;
  const alert = selectedAlertForDetail;
  const isMlAlert = alert.detectionSource === 'ML_ANOMALY';

  const handleReplayAttack = () => {
    const targetAlertId = alert.id;
    setSelectedAlertForDetail(null);
    navigate(`/replay?alertId=${targetAlertId}`);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div 
        className="relative w-full max-w-2xl rounded-2xl border border-slate-700 bg-[#0d131f] p-6 shadow-2xl text-slate-200 max-h-[90vh] overflow-y-auto"
        role="dialog"
        aria-modal="true"
      >
        {/* Header */}
        <div className="flex items-start justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <span className={`p-2 rounded-lg border ${
              isMlAlert 
                ? 'bg-purple-500/10 text-purple-400 border-purple-500/30' 
                : 'bg-red-500/10 text-red-400 border-red-500/20'
            }`}>
              {isMlAlert ? <Cpu className="w-6 h-6" /> : <ShieldAlert className="w-6 h-6" />}
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-bold font-mono text-white uppercase tracking-tight">
                  {isMlAlert ? '⚡ ' : '🚨 '}{alert.attackType.toUpperCase()} DETECTED
                </h2>
                {isMlAlert && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-purple-500/40 bg-purple-950/60 text-purple-300">
                    ML Anomaly ({alert.modelName || 'IsolationForest'} v{alert.modelVersion || '1.0'})
                  </span>
                )}
              </div>
              <p className="text-xs font-mono text-slate-400 mt-0.5">
                Alert ID: {alert.id} • Source: {alert.detectionSource || 'RULE_ENGINE'}
              </p>
            </div>
          </div>

          <button
            onClick={() => setSelectedAlertForDetail(null)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* 4 Metadata Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 my-5 font-mono text-xs">
          <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3">
            <span className="text-slate-400 uppercase text-[10px] block">Source</span>
            <span className="text-cyan-300 font-bold mt-1 block truncate">{alert.sourceIp}</span>
          </div>

          <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3">
            <span className="text-slate-400 uppercase text-[10px] block">Destination</span>
            <span className="text-blue-300 font-bold mt-1 block truncate">{alert.destinationIp}</span>
          </div>

          <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3">
            <span className="text-slate-400 uppercase text-[10px] block">
              {isMlAlert && alert.anomalyScore !== undefined ? 'Anomaly Score' : 'Time'}
            </span>
            <span className="text-white font-bold mt-1 block">
              {isMlAlert && alert.anomalyScore !== undefined 
                ? `${(alert.anomalyScore * 100).toFixed(1)}%` 
                : alert.timestamp
              }
            </span>
          </div>

          <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3">
            <span className="text-slate-400 uppercase text-[10px] block">Severity</span>
            <div className="mt-1">
              <SeverityBadge severity={alert.severity} size="sm" />
            </div>
          </div>
        </div>

        {/* Anomaly Score Bar if ML Alert */}
        {isMlAlert && alert.anomalyScore !== undefined && (
          <div className="mb-4 rounded-xl border border-purple-900/40 bg-purple-950/20 p-3.5">
            <div className="flex justify-between items-center text-xs font-mono mb-1.5">
              <span className="text-purple-300 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5" />
                Multivariate Isolation Forest Anomaly Score
              </span>
              <span className="font-bold text-white">
                {alert.anomalyScore.toFixed(3)} / Threshold: {(alert.decisionThreshold || 0.5).toFixed(2)}
              </span>
            </div>
            <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
              <div 
                className={`h-full transition-all duration-500 ${
                  alert.anomalyScore >= 0.85 ? 'bg-red-500' : alert.anomalyScore >= 0.65 ? 'bg-amber-500' : 'bg-purple-500'
                }`}
                style={{ width: `${Math.min(alert.anomalyScore * 100, 100)}%` }}
              />
            </div>
          </div>
        )}

        {/* Main Sections: Evidence, Why Detected, Suggested Mitigation */}
        <div className="space-y-4">
          {/* Evidence */}
          <div className="rounded-xl border border-slate-800 bg-[#090d16] p-4">
            <h3 className="text-xs font-mono font-bold uppercase text-slate-300 mb-2">
              Observed Traffic Evidence
            </h3>
            {alert.evidence.rawDetails && alert.evidence.rawDetails.length > 0 ? (
              <ul className="space-y-1 font-mono text-xs text-slate-300">
                {alert.evidence.rawDetails.map((detail, idx) => (
                  <li key={idx} className="flex items-center gap-2">
                    <span className="text-cyan-400">•</span>
                    <span>{detail}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <ul className="space-y-1 font-mono text-xs text-slate-300">
                <li className="flex items-center gap-2">
                  <span className="text-red-400">•</span>
                  <span>{alert.evidence.packetsCount.toLocaleString()} total packets</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-cyan-400">•</span>
                  <span>{alert.evidence.responseCount} responses</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-amber-400">•</span>
                  <span>{alert.evidence.durationStr} flow duration</span>
                </li>
              </ul>
            )}

            {/* Top Contributing Deviations if present */}
            {alert.observedFeatures && Object.keys(alert.observedFeatures).length > 0 && (
              <div className="mt-3 pt-3 border-t border-slate-800/80">
                <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1.5">
                  Top Statistical Deviations from Baseline:
                </span>
                <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                  {Object.entries(alert.observedFeatures).map(([feat, val]) => (
                    <div key={feat} className="bg-slate-900/60 border border-slate-800 rounded px-2 py-1">
                      <span className="text-slate-400 block truncate">{feat}</span>
                      <span className="text-cyan-300 font-bold">{val.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Why was this detected? */}
          <div className="rounded-xl border border-slate-800 bg-[#090d16] p-4">
            <h3 className="text-xs font-mono font-bold uppercase text-slate-300 mb-2">
              SOC Reasoning & Explanation
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed font-sans">
              {alert.aiExplanation}
            </p>
          </div>

          {/* Suggested Mitigation */}
          <div className="rounded-xl border border-slate-800 bg-[#090d16] p-4">
            <h3 className="text-xs font-mono font-bold uppercase text-slate-300 mb-2">
              Defensive Recommendations
            </h3>
            <ul className="space-y-1 text-xs text-slate-300 font-sans">
              {alert.recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span className="text-emerald-400 font-bold">•</span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Modal Actions */}
        <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between">
          <button
            onClick={handleReplayAttack}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold transition-all shadow-md"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Replay Attack</span>
          </button>

          <button
            onClick={() => setSelectedAlertForDetail(null)}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
