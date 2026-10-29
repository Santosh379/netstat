import React from 'react';
import { NavLink } from 'react-router-dom';
import { useMonitoring } from '../../context/MonitoringContext';
import { 
  Shield, 
  Home, 
  Radio, 
  FolderArchive, 
  AlertTriangle, 
  Flame, 
  Network, 
  FileText, 
  Settings
} from 'lucide-react';

interface SidebarProps {
  isOpen: boolean;
  onCloseMobile: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, onCloseMobile }) => {
  const { isMonitoring, threatsCount } = useMonitoring();

  const navItems = [
    { to: '/', label: 'Dashboard', icon: Home },
    { to: '/live', label: 'Live Monitor', icon: Radio },
    { to: '/pcap', label: 'PCAP Analyzer', icon: FolderArchive },
    { to: '/alerts', label: 'Alerts', icon: AlertTriangle, badge: threatsCount.toString() },
    { to: '/replay', label: 'Attack Replay', icon: Flame },
    { to: '/topology', label: 'Network Topology', icon: Network },
    { to: '/reports', label: 'Reports', icon: FileText }
  ];

  return (
    <>
      {/* Mobile backdrop */}
      {isOpen && (
        <div 
          onClick={onCloseMobile} 
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden"
        />
      )}

      <aside
        className={`fixed top-0 bottom-0 left-0 z-40 flex flex-col w-64 border-r border-slate-800/80 bg-[#090d16] text-slate-300 transition-transform duration-300 ease-in-out lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="p-5 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <span className="font-mono text-base font-bold tracking-wider text-white">
                NETSCOPE AI
              </span>
              <p className="text-[11px] font-mono text-cyan-400/80">
                Detect. Analyze. Replay.
              </p>
            </div>
          </div>
        </div>

        {/* Navigation list */}
        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                onClick={onCloseMobile}
                className={({ isActive }) =>
                  `group relative flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <Icon className={`w-4 h-4 transition-colors ${isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-200'}`} />
                    <span className="flex-1 tracking-wide">{item.label}</span>

                    {item.badge && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full font-semibold bg-red-500/20 text-red-300 border border-red-500/30">
                        {item.badge}
                      </span>
                    )}
                  </>
                )}
              </NavLink>
            );
          })}

          <div className="pt-4 pb-2">
            <div className="h-px bg-slate-800/80 mx-2" />
          </div>

          <NavLink
            to="/settings"
            onClick={onCloseMobile}
            className={({ isActive }) =>
              `group relative flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'
              }`
            }
          >
            <Settings className="w-4 h-4" />
            <span className="flex-1 tracking-wide">Settings</span>
          </NavLink>
        </nav>

        {/* Bottom System Status */}
        <div className="p-4 border-t border-slate-800/80 bg-[#070a12]">
          <div className="flex items-center gap-2 font-mono text-xs text-slate-300">
            <span className="relative flex h-2 w-2">
              <span className={`inline-flex rounded-full h-2 w-2 ${isMonitoring ? 'bg-emerald-400' : 'bg-amber-400'}`} />
            </span>
            <span className="font-medium">
              {isMonitoring ? '● System Ready' : '● Capture Paused'}
            </span>
          </div>
        </div>
      </aside>
    </>
  );
};
