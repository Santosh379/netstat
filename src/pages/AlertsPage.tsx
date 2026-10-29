import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useMonitoring } from '../context/MonitoringContext';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { alertsApi, type AlertCounts, type AlertFilterParams } from '../api/alerts';
import { packetsApi } from '../api/packets';
import type { Severity, SecurityAlert, CaptureSession } from '../types/network';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Info, 
  Search, 
  Eye,
  RefreshCw,
  Play,
  Network,
  Clock,
  ChevronLeft,
  ChevronRight,
  CheckCircle2
} from 'lucide-react';

export const AlertsPage: React.FC = () => {
  const { setSelectedAlertForDetail, activeCaptureId, setActiveCaptureId, isBackendConnected } = useMonitoring();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  // Scope & Capture selection
  const initialScope = (searchParams.get('scope') as 'ALL' | 'CAPTURE' | 'LIVE') || (activeCaptureId ? 'CAPTURE' : 'ALL');
  const [scopeFilter, setScopeFilter] = useState<'ALL' | 'CAPTURE' | 'LIVE'>(initialScope);
  const [captures, setCaptures] = useState<CaptureSession[]>([]);
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>(
    searchParams.get('captureId') || activeCaptureId || ''
  );

  // Filters
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL');
  const [attackTypeFilter, setAttackTypeFilter] = useState<string>('ALL');
  const [sourceFilter, setSourceFilter] = useState<'ALL' | 'RULE_ENGINE' | 'ML_ANOMALY'>('ALL');
  const [timeRangeFilter, setTimeRangeFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Sorting & Pagination
  const [sortBy, setSortBy] = useState<'timestamp' | 'threatScore' | 'severity'>('timestamp');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 12;

  // Data & Live state
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [counts, setCounts] = useState<AlertCounts>({ critical: 0, high: 0, medium: 0, low: 0, total: 0 });
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string>('--:--:-- UTC');
  const [autoPoll, setAutoPoll] = useState<boolean>(true);

  const pollIntervalRef = useRef<any>(null);

  // Fetch capture history for the dropdown
  useEffect(() => {
    packetsApi.getCaptures().then((caps) => {
      setCaptures(caps);
      if (caps.length > 0 && !selectedCaptureId) {
        setSelectedCaptureId(caps[0].id);
      }
    }).catch(() => {});
  }, []);

  // Sync selectedCaptureId if activeCaptureId changes in context
  useEffect(() => {
    if (activeCaptureId && !selectedCaptureId) {
      setSelectedCaptureId(activeCaptureId);
    }
  }, [activeCaptureId]);

  // Main data fetcher
  const fetchAlertsData = useCallback(async (isBackground = false) => {
    if (!isBackground) setLoading(true);
    setError(null);

    const activeCid = scopeFilter === 'CAPTURE' ? (selectedCaptureId || undefined) : undefined;
    const activeSourceType = scopeFilter === 'LIVE' ? 'LIVE' : (scopeFilter === 'CAPTURE' ? 'PCAP' : undefined);

    const filterParams: AlertFilterParams = {
      severity: severityFilter,
      attackType: attackTypeFilter !== 'ALL' ? (attackTypeFilter as any) : undefined,
      detectionSource: sourceFilter,
      captureId: activeCid,
      sourceType: activeSourceType,
      timeRange: timeRangeFilter !== 'ALL' ? timeRangeFilter : undefined,
      search: searchQuery.trim() || undefined,
      sortBy,
      sortOrder
    };

    try {
      const [alertList, summaryCounts] = await Promise.all([
        alertsApi.getAlerts(filterParams),
        alertsApi.getSummary({
          captureId: activeCid,
          sourceType: activeSourceType,
          timeRange: timeRangeFilter !== 'ALL' ? timeRangeFilter : undefined
        })
      ]);

      setAlerts(alertList);
      setCounts(summaryCounts);
      const now = new Date();
      setLastUpdated(now.toISOString().substring(11, 19) + ' UTC');
    } catch (err: any) {
      setError('Unable to synchronize with backend database');
    } finally {
      setLoading(false);
    }
  }, [scopeFilter, selectedCaptureId, severityFilter, attackTypeFilter, sourceFilter, timeRangeFilter, searchQuery, sortBy, sortOrder]);

  // Trigger fetch on filter change
  useEffect(() => {
    setCurrentPage(1);
    fetchAlertsData();
  }, [fetchAlertsData]);

  // Auto-polling effect with cleanup
  useEffect(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }

    if (autoPoll) {
      pollIntervalRef.current = setInterval(() => {
        fetchAlertsData(true);
      }, 4000);
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [autoPoll, fetchAlertsData]);

  // Handle scope change
  const handleScopeChange = (newScope: 'ALL' | 'CAPTURE' | 'LIVE') => {
    setScopeFilter(newScope);
    setSearchParams(newScope === 'CAPTURE' && selectedCaptureId ? { scope: newScope, captureId: selectedCaptureId } : { scope: newScope });
  };

  // Pagination slicing
  const totalPages = Math.max(1, Math.ceil(alerts.length / pageSize));
  const paginatedAlerts = alerts.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-bold font-mono text-white tracking-tight">
              Security Alerts Investigation
            </h2>
            <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-[11px] font-mono bg-slate-900 border-slate-700 text-slate-300">
              <span className={`w-2 h-2 rounded-full ${autoPoll && isBackendConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
              <span>{autoPoll ? 'Live Sync (4s)' : 'Sync Paused'}</span>
            </div>
          </div>
          <p className="text-xs sm:text-sm text-slate-400 font-sans mt-1">
            Forensic threat detections correlated with parsed packet headers and statistical flow models.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-[#090d16] text-[11px] font-mono text-slate-400">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Updated: {lastUpdated}</span>
          </div>

          <button
            onClick={() => setAutoPoll(!autoPoll)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
              autoPoll 
                ? 'border-emerald-500/40 bg-emerald-950/30 text-emerald-300 hover:bg-emerald-900/40' 
                : 'border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            {autoPoll ? 'Pause Sync' : 'Resume Sync'}
          </button>

          <button
            onClick={() => fetchAlertsData(false)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-300 font-mono text-xs hover:bg-cyan-900/40 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Scope Selector Tabs */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-2 rounded-xl border border-slate-800 bg-[#090d16]">
        <div className="flex items-center gap-1.5 bg-[#0d131f] p-1 rounded-lg border border-slate-800/80">
          <button
            onClick={() => handleScopeChange('ALL')}
            className={`px-3.5 py-1.5 rounded-md text-xs font-mono transition-all ${
              scopeFilter === 'ALL'
                ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            All Security Alerts ({counts.total})
          </button>

          <button
            onClick={() => handleScopeChange('CAPTURE')}
            className={`px-3.5 py-1.5 rounded-md text-xs font-mono transition-all ${
              scopeFilter === 'CAPTURE'
                ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            Capture Findings
          </button>

          <button
            onClick={() => handleScopeChange('LIVE')}
            className={`px-3.5 py-1.5 rounded-md text-xs font-mono transition-all ${
              scopeFilter === 'LIVE'
                ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            Live Monitoring
          </button>
        </div>

        {/* Capture Dropdown if in Capture Mode */}
        {scopeFilter === 'CAPTURE' && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400">Capture:</span>
            <select
              value={selectedCaptureId}
              onChange={(e) => {
                setSelectedCaptureId(e.target.value);
                setActiveCaptureId(e.target.value);
                setSearchParams({ scope: 'CAPTURE', captureId: e.target.value });
              }}
              className="rounded-lg border border-cyan-500/40 bg-[#0d131f] py-1.5 px-3 text-xs font-mono text-cyan-200 focus:outline-none"
            >
              {captures.length === 0 ? (
                <option value="">No PCAP captures recorded yet</option>
              ) : (
                captures.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.filename} ({c.packetCount} pkts • {c.threatsDetected} threats)
                  </option>
                ))
              )}
            </select>
          </div>
        )}
      </div>

      {/* Scope-Guaranteed Severity Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div
          onClick={() => setSeverityFilter(severityFilter === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
          className={`cursor-pointer rounded-xl border p-4 text-center transition-all ${
            severityFilter === 'CRITICAL'
              ? 'border-red-500 bg-red-950/40 shadow-lg shadow-red-950/30 ring-1 ring-red-500'
              : 'border-red-500/30 bg-[#140b0e] hover:border-red-500/60'
          }`}
        >
          <div className="flex items-center justify-center gap-1.5 text-red-400 mb-1">
            <ShieldAlert className="w-4 h-4" />
            <span className="text-xs font-mono font-bold uppercase">Critical</span>
          </div>
          <p className="text-3xl font-bold font-mono text-white">{counts.critical}</p>
          <span className="text-[10px] font-mono text-slate-500 mt-1 block">Requires immediate isolation</span>
        </div>

        <div
          onClick={() => setSeverityFilter(severityFilter === 'HIGH' ? 'ALL' : 'HIGH')}
          className={`cursor-pointer rounded-xl border p-4 text-center transition-all ${
            severityFilter === 'HIGH'
              ? 'border-orange-500 bg-orange-950/40 shadow-lg shadow-orange-950/30 ring-1 ring-orange-500'
              : 'border-orange-500/30 bg-[#140f0b] hover:border-orange-500/60'
          }`}
        >
          <div className="flex items-center justify-center gap-1.5 text-orange-400 mb-1">
            <AlertTriangle className="w-4 h-4" />
            <span className="text-xs font-mono font-bold uppercase">High</span>
          </div>
          <p className="text-3xl font-bold font-mono text-white">{counts.high}</p>
          <span className="text-[10px] font-mono text-slate-500 mt-1 block">Active anomalous bursts</span>
        </div>

        <div
          onClick={() => setSeverityFilter(severityFilter === 'MEDIUM' ? 'ALL' : 'MEDIUM')}
          className={`cursor-pointer rounded-xl border p-4 text-center transition-all ${
            severityFilter === 'MEDIUM'
              ? 'border-amber-500 bg-amber-950/40 shadow-lg shadow-amber-950/30 ring-1 ring-amber-500'
              : 'border-amber-500/30 bg-[#14140b] hover:border-amber-500/60'
          }`}
        >
          <div className="flex items-center justify-center gap-1.5 text-amber-400 mb-1">
            <Info className="w-4 h-4" />
            <span className="text-xs font-mono font-bold uppercase">Medium</span>
          </div>
          <p className="text-3xl font-bold font-mono text-white">{counts.medium}</p>
          <span className="text-[10px] font-mono text-slate-500 mt-1 block">Heuristic warnings</span>
        </div>

        <div
          onClick={() => setSeverityFilter('ALL')}
          className={`cursor-pointer rounded-xl border p-4 text-center transition-all ${
            severityFilter === 'ALL'
              ? 'border-cyan-500 bg-cyan-950/30 shadow-lg shadow-cyan-950/30 ring-1 ring-cyan-500'
              : 'border-slate-800 bg-[#0d131f] hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-center gap-1.5 text-cyan-400 mb-1">
            <CheckCircle2 className="w-4 h-4" />
            <span className="text-xs font-mono font-bold uppercase">Total Scope</span>
          </div>
          <p className="text-3xl font-bold font-mono text-white">{counts.total}</p>
          <span className="text-[10px] font-mono text-slate-500 mt-1 block">Matched to active filters</span>
        </div>
      </div>

      {/* Filter and Table Panel */}
      <div className="rounded-xl border border-slate-800 bg-[#0d131f] shadow-sm p-5 space-y-4">
        {/* Search & Multifaceted Filters */}
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2.5 flex-1">
            {/* Search Input */}
            <div className="relative w-full sm:w-60">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
              <input
                type="text"
                placeholder="Search IP, attack type, title..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full rounded-lg border border-slate-800 bg-[#090d16] py-1.5 pl-8 pr-3 text-xs font-mono text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            {/* Attack Type Selector */}
            <select
              value={attackTypeFilter}
              onChange={(e) => setAttackTypeFilter(e.target.value)}
              className="rounded-lg border border-slate-800 bg-[#090d16] py-1.5 px-3 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none"
            >
              <option value="ALL">All Attack Types</option>
              <option value="Port Scan">Port Scan</option>
              <option value="SYN Flood">SYN Flood</option>
              <option value="ICMP Flood">ICMP Flood</option>
              <option value="ARP Spoofing">ARP Spoofing</option>
              <option value="Brute Force">Brute Force</option>
              <option value="Network Anomaly">Network Anomaly (ML)</option>
            </select>

            {/* Detection Source Selector */}
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value as any)}
              className="rounded-lg border border-slate-800 bg-[#090d16] py-1.5 px-3 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none"
            >
              <option value="ALL">All Sources</option>
              <option value="RULE_ENGINE">Rule Engine Only</option>
              <option value="ML_ANOMALY">ML Anomaly Only</option>
            </select>

            {/* Time-Range Selector */}
            <select
              value={timeRangeFilter}
              onChange={(e) => setTimeRangeFilter(e.target.value)}
              className="rounded-lg border border-slate-800 bg-[#090d16] py-1.5 px-3 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none"
            >
              <option value="ALL">Time: All History</option>
              <option value="1h">Time: Last 1 Hour</option>
              <option value="24h">Time: Last 24 Hours</option>
              <option value="7d">Time: Last 7 Days</option>
            </select>

            {/* Sort Field */}
            <select
              value={`${sortBy}-${sortOrder}`}
              onChange={(e) => {
                const [sb, so] = e.target.value.split('-') as [any, any];
                setSortBy(sb);
                setSortOrder(so);
              }}
              className="rounded-lg border border-slate-800 bg-[#090d16] py-1.5 px-3 text-xs font-mono text-slate-300 focus:border-cyan-500 focus:outline-none"
            >
              <option value="timestamp-desc">Sort: Newest First</option>
              <option value="timestamp-asc">Sort: Oldest First</option>
              <option value="threatScore-desc">Sort: Highest Threat Score</option>
              <option value="severity-desc">Sort: Highest Severity</option>
            </select>
          </div>

          {(severityFilter !== 'ALL' || attackTypeFilter !== 'ALL' || sourceFilter !== 'ALL' || timeRangeFilter !== 'ALL' || searchQuery) && (
            <button
              onClick={() => {
                setSeverityFilter('ALL');
                setAttackTypeFilter('ALL');
                setSourceFilter('ALL');
                setTimeRangeFilter('ALL');
                setSearchQuery('');
              }}
              className="text-xs font-mono text-cyan-400 hover:underline self-start lg:self-auto shrink-0"
            >
              Reset Filters
            </button>
          )}
        </div>

        {/* Error notification banner if any */}
        {error && (
          <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-950/20 text-amber-300 text-xs font-mono flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => fetchAlertsData(false)} className="underline text-amber-200">Retry</button>
          </div>
        )}

        {/* Alerts Table */}
        <div className="overflow-x-auto rounded-lg border border-slate-800/80">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400 bg-[#090d16]">
                <th className="py-3 px-4 font-semibold">Severity</th>
                <th className="py-3 px-4 font-semibold">Attack Classification</th>
                <th className="py-3 px-4 font-semibold">Provenance / Capture</th>
                <th className="py-3 px-4 font-semibold">Source & Destination</th>
                <th className="py-3 px-4 font-semibold">Timestamp (UTC)</th>
                <th className="py-3 px-4 font-semibold text-center">Score</th>
                <th className="py-3 px-4 font-semibold text-right">Investigation Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {loading && alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-400" />
                    Querying correlated alerts from security database...
                  </td>
                </tr>
              ) : paginatedAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500 font-mono text-xs">
                    No alerts match the active filter criteria.
                  </td>
                </tr>
              ) : (
                paginatedAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => setSelectedAlertForDetail(alert)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 whitespace-nowrap">
                      <SeverityBadge severity={alert.severity} size="sm" />
                    </td>
                    <td className="py-3 px-4 font-semibold text-white whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span>{alert.attackType}</span>
                        {alert.detectionSource === 'ML_ANOMALY' ? (
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-purple-500/40 bg-purple-950/60 text-purple-300">
                            ML Anomaly
                          </span>
                        ) : (
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-cyan-500/40 bg-cyan-950/60 text-cyan-300">
                            Rule Engine
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {alert.captureName || alert.captureId ? (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-blue-500/30 bg-blue-950/40 text-blue-300 truncate max-w-[150px] inline-block" title={alert.captureName || alert.captureId}>
                          PCAP: {alert.captureName || alert.captureId?.substring(0, 8)}
                        </span>
                      ) : (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-500/30 bg-emerald-950/40 text-emerald-300">
                          LIVE MONITOR
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-cyan-300 font-bold">{alert.sourceIp}</span>
                        <span className="text-slate-500">→</span>
                        <span className="text-slate-300">{alert.destinationIp}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {alert.timestamp}
                    </td>
                    <td className="py-3 px-4 text-center whitespace-nowrap">
                      <span className={`font-bold px-2 py-0.5 rounded text-[11px] ${
                        alert.threatScore >= 80 ? 'bg-red-950/80 text-red-300 border border-red-800' :
                        alert.threatScore >= 50 ? 'bg-amber-950/80 text-amber-300 border border-amber-800' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {alert.threatScore}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => setSelectedAlertForDetail(alert)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-300 transition-colors"
                          title="Inspect Evidence & Explanation"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>Investigate</span>
                        </button>

                        <button
                          onClick={() => {
                            navigate(`/replay?alertId=${alert.id}${alert.captureId ? `&captureId=${alert.captureId}` : ''}`);
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-cyan-500/30 bg-cyan-950/40 hover:bg-cyan-900/60 text-[11px] text-cyan-300 transition-colors"
                          title="Forensic Attack Replay"
                        >
                          <Play className="w-3.5 h-3.5" />
                          <span>Replay</span>
                        </button>

                        <button
                          onClick={() => {
                            navigate(`/topology?source=pcap${alert.captureId ? `&captureId=${alert.captureId}` : ''}`);
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-indigo-500/30 bg-indigo-950/40 hover:bg-indigo-900/60 text-[11px] text-indigo-300 transition-colors"
                          title="View In Topology"
                        >
                          <Network className="w-3.5 h-3.5" />
                          <span>Topology</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2 text-xs font-mono text-slate-400">
          <span>
            Showing {alerts.length === 0 ? 0 : (currentPage - 1) * pageSize + 1} to{' '}
            {Math.min(currentPage * pageSize, alerts.length)} of {alerts.length} filtered alerts
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage <= 1}
              className="p-1.5 rounded-lg border border-slate-800 bg-[#090d16] disabled:opacity-30 disabled:cursor-not-allowed hover:bg-slate-800 text-slate-300"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-white font-bold px-2">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage >= totalPages}
              className="p-1.5 rounded-lg border border-slate-800 bg-[#090d16] disabled:opacity-30 disabled:cursor-not-allowed hover:bg-slate-800 text-slate-300"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

