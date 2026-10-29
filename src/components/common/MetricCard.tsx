import React from 'react';
import type { ReactNode } from 'react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subValue?: string;
  change?: string;
  changeType?: 'positive' | 'negative' | 'neutral' | 'danger';
  icon: ReactNode;
  accentColor?: 'cyan' | 'blue' | 'amber' | 'red' | 'emerald';
  progress?: number;
  progressColor?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subValue,
  change,
  changeType = 'neutral',
  icon,
  accentColor = 'cyan',
  progress
}) => {
  const accentGlow = {
    cyan: 'border-cyan-500/20 hover:border-cyan-500/40 text-cyan-400 bg-cyan-500/5',
    blue: 'border-sky-500/20 hover:border-sky-500/40 text-sky-400 bg-sky-500/5',
    amber: 'border-amber-500/20 hover:border-amber-500/40 text-amber-400 bg-amber-500/5',
    red: 'border-red-500/20 hover:border-red-500/40 text-red-400 bg-red-500/5',
    emerald: 'border-emerald-500/20 hover:border-emerald-500/40 text-emerald-400 bg-emerald-500/5'
  }[accentColor];

  const changeBadgeClass = {
    positive: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
    negative: 'bg-slate-800 text-slate-400 border border-slate-700',
    neutral: 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/20',
    danger: 'bg-red-500/10 text-red-400 border border-red-500/20'
  }[changeType];

  return (
    <div
      className={`relative overflow-hidden rounded-xl border bg-[#0d131f] p-5 shadow-lg shadow-black/40 transition-all duration-200 hover:-translate-y-0.5 ${accentGlow}`}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
            {title}
          </p>
          <div className="flex items-baseline gap-2 pt-1">
            <span className="font-mono text-2xl font-bold tracking-tight text-white lg:text-3xl">
              {value}
            </span>
            {subValue && (
              <span className="text-xs font-semibold text-slate-400">
                {subValue}
              </span>
            )}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-[#090d16] p-2.5 shadow-inner">
          {icon}
        </div>
      </div>

      <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
        {change && (
          <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium ${changeBadgeClass}`}>
            {change}
          </span>
        )}
        <span className="text-[11px] text-slate-400">
          {title.includes('Packets') ? 'Packets Analyzed' : title.includes('Hosts') ? 'Currently Observed' : title.includes('Threats') ? 'Security Alerts' : 'Elevated Risk'}
        </span>
      </div>

      {typeof progress === 'number' && (
        <div className="mt-3">
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
            <div
              className={`h-full transition-all duration-500 ${
                progress > 75
                  ? 'bg-gradient-to-r from-amber-500 to-red-500'
                  : progress > 50
                  ? 'bg-gradient-to-r from-cyan-500 to-amber-500'
                  : 'bg-gradient-to-r from-emerald-500 to-cyan-500'
              }`}
              style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
            />
          </div>
        </div>
      )}
    </div>
  );
};
