import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useMonitoring } from '../../context/MonitoringContext';
import { 
  Search, 
  Menu,
  Bell
} from 'lucide-react';
import { NotificationCenter } from './NotificationCenter';

interface HeaderProps {
  onToggleMobileMenu: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onToggleMobileMenu }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { packetsPerSec, unreadNotificationsCount, captureMode } = useMonitoring();
  const [searchTerm, setSearchTerm] = useState('');
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);

  const routeTitles: Record<string, { title: string; subtitle: string }> = {
    '/': { title: 'Network Security Dashboard', subtitle: 'Monitor traffic, detect suspicious activity, and investigate network attacks.' },
    '/live': { title: 'Live Network Monitor', subtitle: 'Monitor network packets in real time.' },
    '/pcap': { title: 'PCAP Analyzer', subtitle: 'Upload a packet capture file to analyze network traffic and detect suspicious activity.' },
    '/alerts': { title: 'Security Alerts', subtitle: 'Detected suspicious network activity.' },
    '/replay': { title: 'Attack Replay', subtitle: 'Replay the packet sequence that triggered an alert.' },
    '/topology': { title: 'Network Topology', subtitle: 'Visual map of network hosts, server, and detected attacker.' },
    '/reports': { title: 'Security Reports', subtitle: 'Reports generated from network analysis.' },
    '/settings': { title: 'Settings', subtitle: 'Configure network interface and monitoring options.' }
  };

  const currentRoute = routeTitles[location.pathname] || {
    title: 'NetScope AI',
    subtitle: 'Detect. Analyze. Replay.'
  };

  const handleSearchKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && searchTerm.trim()) {
      navigate(`/alerts?search=${encodeURIComponent(searchTerm.trim())}`);
    }
  };

  return (
    <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-slate-800/80 bg-[#090d16]/90 px-4 sm:px-6 backdrop-blur-md">
      {/* Left Title & Mobile Menu */}
      <div className="flex items-center gap-3 sm:gap-4">
        <button
          onClick={onToggleMobileMenu}
          className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white lg:hidden"
          aria-label="Toggle Navigation"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div>
          <h1 className="font-mono text-sm sm:text-base font-bold text-white tracking-tight">
            {currentRoute.title}
          </h1>
          <p className="hidden md:block text-[11px] text-slate-400 font-sans">
            {currentRoute.subtitle}
          </p>
        </div>
      </div>

      {/* Center Search Bar */}
      <div className="hidden md:flex items-center flex-1 max-w-xs lg:max-w-sm mx-4">
        <div className="relative w-full">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search IP, port or protocol..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            onKeyDown={handleSearchKeyDown}
            className="w-full rounded-lg border border-slate-800 bg-[#0d131f] py-1.5 pl-8 pr-3 text-xs font-mono text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-2.5 sm:gap-3">
        {/* Notification Center Bell */}
        <button
          onClick={() => setIsNotificationsOpen(true)}
          className="relative p-2 rounded-lg border border-slate-800 bg-[#0d131f] text-slate-300 hover:text-white hover:border-slate-700 transition-colors"
          title="Notification Center"
          aria-label="Open notifications"
        >
          <Bell className="w-4 h-4" />
          {unreadNotificationsCount > 0 && (
            <span className="absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-cyan-500 text-[9px] font-mono font-bold text-black ring-2 ring-[#090d16]">
              {unreadNotificationsCount > 9 ? '9+' : unreadNotificationsCount}
            </span>
          )}
        </button>

        {captureMode === 'REAL' ? (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 font-mono text-xs text-emerald-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="font-bold">REAL</span>
            <span className="text-slate-500">|</span>
            <span>{packetsPerSec.toLocaleString()} pkt/s</span>
          </div>
        ) : captureMode === 'SYNTHETIC' ? (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 font-mono text-xs text-amber-300" title="Synthetic demonstration traffic">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
            <span className="font-bold">SYNTHETIC</span>
            <span className="text-slate-500">|</span>
            <span>{packetsPerSec.toLocaleString()} pkt/s</span>
          </div>
        ) : (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-800 bg-[#0d131f] font-mono text-xs text-slate-400">
            <span className="w-2 h-2 rounded-full bg-slate-500" />
            <span className="font-bold">STOPPED</span>
          </div>
        )}
      </div>

      <NotificationCenter
        isOpen={isNotificationsOpen}
        onClose={() => setIsNotificationsOpen(false)}
      />
    </header>
  );
};
