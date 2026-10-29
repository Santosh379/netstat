import React from 'react';
import type { Severity } from '../../types/network';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md' | 'lg';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const configs = {
    CRITICAL: {
      bg: 'bg-red-500/10 border-red-500/30 text-red-400',
      dot: 'bg-red-500 animate-pulse',
      label: 'CRITICAL'
    },
    HIGH: {
      bg: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
      dot: 'bg-orange-500',
      label: 'HIGH'
    },
    MEDIUM: {
      bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
      dot: 'bg-amber-400',
      label: 'MEDIUM'
    },
    LOW: {
      bg: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
      dot: 'bg-cyan-400',
      label: 'LOW'
    }
  };

  const config = configs[severity] || configs.LOW;
  const sizeClasses = size === 'sm' 
    ? 'text-[10px] px-2 py-0.5 tracking-wider' 
    : size === 'lg' 
      ? 'text-xs px-3 py-1 font-semibold' 
      : 'text-[11px] px-2.5 py-0.5 font-medium';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border uppercase tracking-wider font-mono ${config.bg} ${sizeClasses}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />
      {config.label}
    </span>
  );
};
