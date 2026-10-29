import React from 'react';

interface ProtocolBadgeProps {
  protocol: string;
}

export const ProtocolBadge: React.FC<ProtocolBadgeProps> = ({ protocol }) => {
  const p = protocol.toUpperCase();
  let color = 'bg-slate-800 text-slate-300 border-slate-700';

  if (p === 'TCP') {
    color = 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30';
  } else if (p === 'UDP') {
    color = 'bg-blue-500/10 text-blue-300 border-blue-500/30';
  } else if (p === 'ICMP') {
    color = 'bg-amber-500/10 text-amber-300 border-amber-500/30';
  } else if (p === 'ARP') {
    color = 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30';
  } else if (p === 'DNS') {
    color = 'bg-indigo-500/10 text-indigo-300 border-indigo-500/30';
  } else if (p === 'TLS' || p === 'HTTPS') {
    color = 'bg-teal-500/10 text-teal-300 border-teal-500/30';
  }

  return (
    <span
      className={`inline-block font-mono text-[10px] font-semibold tracking-wider px-2 py-0.5 rounded border ${color}`}
    >
      {p}
    </span>
  );
};
