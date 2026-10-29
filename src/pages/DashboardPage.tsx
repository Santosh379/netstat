import React, { useState, useEffect } from 'react';
import { useMonitoring } from '../context/MonitoringContext';
import { analyticsApi, type DashboardStats } from '../api/analytics';
import { mockTrafficTimeline, mockProtocolDistribution } from '../data/mockData';
import type { SecurityAlert } from '../types/network';
import { 
  Play, 
  Pause, 
  Layers, 
  Server, 
  ShieldAlert, 
  CheckCircle,
  AlertTriangle,
  ArrowRight
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  PieChart,
  Pie,
  Cell
} from 'recharts';

export const DashboardPage: React.FC = () => {
  const {
    isMonitoring,
    toggleMonitoring,
    totalPacketsCount,
    activeHostsCount,
    threatsCount,
    setSelectedAlertForDetail,
    captureMode
  } = useMonitoring();

  const [timeRange, setTimeRange] = useState<'1H' | '6H' | '24H'>('1H');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    let mounted = true;
    analyticsApi.getDashboardStats(timeRange).then((data) => {
      if (mounted) {
        setStats(data);
        setLoading(false);
      }
    }).catch(() => {
      if (mounted) setLoading(false);
    });

    return () => {
      mounted = false;
    };
  }, [timeRange]);

  const trafficData = stats?.trafficTimeline || mockTrafficTimeline[timeRange];
  const protocolData = stats?.protocolDistribution || mockProtocolDistribution;
  const recentAlerts: SecurityAlert[] = stats?.recentAlerts && stats.recentAlerts.length > 0 
    ? stats.recentAlerts 
    : [];

  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-xl border border-slate-800 bg-[#0d131f] p-6 shadow-lg">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold font-mono text-white tracking-tight">
              Network Security Dashboard
            </h2>
            {loading && (
              <span className="text-[10px] font-mono text-cyan-400 animate-pulse bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/40">
                Syncing...
              </span>
            )}
            {captureMode === 'REAL' ? (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-300 font-bold">
                REAL PHYSICAL CAPTURE
              </span>
            ) : captureMode === 'SYNTHETIC' ? (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-300 font-bold">
                SYNTHETIC DEMO MODE
              </span>
            ) : (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-slate-700 bg-slate-800/60 text-slate-400">
                CAPTURE STOPPED
              </span>
            )}
          </div>
          <p className="text-xs sm:text-sm text-slate-300">
            Monitor traffic, detect suspicious activity, and investigate network attacks.
          </p>
        </div>

        <button
          onClick={toggleMonitoring}
          className={`inline-flex items-center gap-2 px-5 py-2.5 rounded-lg font-mono text-xs font-bold transition-all shadow-md ${
            isMonitoring
              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 hover:bg-amber-500/30'
              : 'bg-cyan-500 text-slate-950 hover:bg-cyan-400'
          }`}
        >
          {isMonitoring ? (
            <>
              <Pause className="w-4 h-4 fill-current" />
              <span>Stop Monitoring</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-current" />
              <span>Start Monitoring</span>
            </>
          )}
        </button>
      </div>

      {/* 4 Statistics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Packets Analyzed */}
        <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase text-slate-400">Packets Analyzed</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-white mt-2">
            {(totalPacketsCount !== undefined ? totalPacketsCount : (stats?.totalPackets ?? 0)).toLocaleString()}
          </p>
        </div>

        {/* Active Hosts */}
        <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase text-slate-400">Active Hosts</span>
            <Server className="w-4 h-4 text-sky-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-white mt-2">
            {stats?.activeHosts || activeHostsCount}
          </p>
        </div>

        {/* Threats Detected */}
        <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase text-slate-400">Threats Detected</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-red-400 mt-2">
            {stats ? stats.threatsCount : threatsCount}
          </p>
        </div>

        {/* Network Status */}
        <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase text-slate-400">Network Status</span>
            <CheckCircle className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-center gap-2 mt-2 font-mono text-sm font-semibold text-emerald-400">
            <span className={`w-2.5 h-2.5 rounded-full ${isMonitoring ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
            <span>{isMonitoring ? 'Monitoring Ready' : 'Paused'}</span>
          </div>
        </div>
      </div>

      {/* Traffic Chart and Protocol Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Network Traffic Line/Area Chart */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <h3 className="font-mono text-sm font-bold text-white">Network Traffic</h3>
              <p className="text-xs text-slate-400 font-mono">Packets/sec</p>
            </div>

            <div className="flex gap-1 bg-[#090d16] p-1 rounded-lg border border-slate-800 font-mono text-xs">
              {(['1H', '6H', '24H'] as const).map((r) => (
                <button
                  key={r}
                  onClick={() => setTimeRange(r)}
                  className={`px-3 py-1 rounded transition-colors ${
                    timeRange === r
                      ? 'bg-cyan-500/20 text-cyan-300 font-semibold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>

          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1c2638" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip
                  content={({ active, payload, label }) => {
                    if (active && payload && payload.length) {
                      return (
                        <div className="rounded border border-slate-700 bg-[#0a0f1c] p-2 text-xs font-mono">
                          <p className="text-slate-400">{label}</p>
                          <p className="text-cyan-400 font-bold">{payload[0].value} packets/sec</p>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="packets"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fill="url(#trafficGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Distribution Donut */}
        <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm flex flex-col justify-between">
          <div className="pb-3 border-b border-slate-800">
            <h3 className="font-mono text-sm font-bold text-white">Protocol Distribution</h3>
            <p className="text-xs text-slate-400 font-mono">Transport Breakdown</p>
          </div>

          <div className="h-44 w-full flex items-center justify-center my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protocolData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={65}
                  paddingAngle={3}
                  dataKey="value"
                  stroke="#0d131f"
                  strokeWidth={2}
                >
                  {protocolData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-2 border-t border-slate-800/80">
            {protocolData.map((item) => (
              <div key={item.name} className="flex items-center justify-between p-1">
                <span className="flex items-center gap-1.5 text-slate-300">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  {item.name}
                </span>
                <span className="text-white font-bold">{item.value}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div>
            <h3 className="font-mono text-sm font-bold text-white">Recent Security Alerts</h3>
            <p className="text-xs text-slate-400 font-mono">Click an alert to investigate details</p>
          </div>
          <span className="text-xs font-mono text-red-400">
            {recentAlerts.length > 0 ? `Latest ${recentAlerts.length}` : 'No active alerts'}
          </span>
        </div>

        {recentAlerts.length === 0 ? (
          <div className="p-8 text-center text-slate-500 font-mono text-xs">
            No security threats currently detected. Run PCAP analysis or monitor live traffic to detect anomalies.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {recentAlerts.map((alert) => (
              <div
                key={alert.id}
                onClick={() => setSelectedAlertForDetail(alert)}
                className="p-4 rounded-lg border border-slate-800 bg-[#090d16] hover:border-slate-700 cursor-pointer transition-all flex items-center justify-between group"
              >
                <div className="flex items-start gap-3">
                  <span className="p-2 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                    {alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? (
                      <ShieldAlert className="w-4 h-4" />
                    ) : (
                      <AlertTriangle className="w-4 h-4" />
                    )}
                  </span>
                  <div>
                    <h4 className="font-mono text-xs font-bold text-white group-hover:text-cyan-400 transition-colors">
                      {alert.attackType}
                    </h4>
                    <p className="text-xs font-mono text-slate-400 mt-0.5">
                      {alert.sourceIp} → {alert.destinationIp}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                      alert.severity === 'CRITICAL'
                        ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                        : alert.severity === 'HIGH'
                        ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30'
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}
                  >
                    {alert.severity}
                  </span>
                  <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 transition-colors" />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
