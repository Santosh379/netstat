import React, { useState } from 'react';
import { useMonitoring } from '../../context/MonitoringContext';
import { SeverityBadge } from '../common/SeverityBadge';
import type { Severity } from '../../types/network';
import { 
  Bell, 
  CheckCheck, 
  Trash2, 
  X, 
  ExternalLink, 
  Filter,
  CheckCircle2
} from 'lucide-react';

interface NotificationCenterProps {
  isOpen: boolean;
  onClose: () => void;
}

export const NotificationCenter: React.FC<NotificationCenterProps> = ({ isOpen, onClose }) => {
  const { 
    notifications, 
    unreadNotificationsCount, 
    markNotificationRead, 
    markAllNotificationsRead, 
    dismissNotification, 
    clearReadNotifications,
    setSelectedAlertForDetail,
    alerts
  } = useMonitoring();

  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL');
  const [sourceFilter, setSourceFilter] = useState<'ALL' | 'RULE_ENGINE' | 'ML_ANOMALY'>('ALL');
  const [unreadOnly, setUnreadOnly] = useState<boolean>(false);

  if (!isOpen) return null;

  const filteredNotifications = notifications.filter((notif) => {
    if (notif.isDismissed) return false;
    if (unreadOnly && notif.isRead) return false;
    if (severityFilter !== 'ALL' && notif.severity !== severityFilter) return false;
    if (sourceFilter !== 'ALL' && notif.detectionSource !== sourceFilter) return false;
    return true;
  });

  const handleNotificationClick = (alertId?: string, notifId?: string) => {
    if (notifId) {
      markNotificationRead(notifId);
    }
    if (alertId) {
      const foundAlert = alerts.find((a) => a.id === alertId);
      if (foundAlert) {
        setSelectedAlertForDetail(foundAlert);
        onClose();
      }
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/50 backdrop-blur-xs flex justify-end animate-in fade-in duration-200">
      {/* Backdrop click to close */}
      <div className="absolute inset-0" onClick={onClose} />

      {/* Drawer Panel */}
      <div className="relative w-full max-w-md bg-[#090d16] border-l border-slate-800 shadow-2xl flex flex-col h-full z-10 animate-in slide-in-from-right duration-250">
        {/* Top Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 bg-[#0d131f]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-500/30 text-cyan-400">
              <Bell className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-mono text-sm font-bold text-white tracking-wide">
                  Notification Center
                </h3>
                {unreadNotificationsCount > 0 && (
                  <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                    {unreadNotificationsCount} new
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400">
                Security alerts & anomaly notifications
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            aria-label="Close notifications"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Global Actions Bar */}
        <div className="flex items-center justify-between px-5 py-2.5 bg-[#0b101b] border-b border-slate-800/80 text-[11px] font-mono">
          <div className="flex items-center gap-3">
            <button
              onClick={() => markAllNotificationsRead()}
              disabled={unreadNotificationsCount === 0}
              className="inline-flex items-center gap-1 text-slate-300 hover:text-cyan-300 disabled:opacity-40 disabled:hover:text-slate-300 transition-colors"
            >
              <CheckCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>Mark all read</span>
            </button>
            <span className="text-slate-700">|</span>
            <button
              onClick={() => clearReadNotifications()}
              className="inline-flex items-center gap-1 text-slate-400 hover:text-red-400 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear read</span>
            </button>
          </div>

          <label className="flex items-center gap-1.5 cursor-pointer text-slate-400 hover:text-slate-200">
            <input
              type="checkbox"
              checked={unreadOnly}
              onChange={(e) => setUnreadOnly(e.target.checked)}
              className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0 w-3.5 h-3.5"
            />
            <span>Unread only</span>
          </label>
        </div>

        {/* Filters Bar */}
        <div className="px-5 py-2.5 bg-[#090d16] border-b border-slate-800 flex items-center gap-2 flex-wrap text-xs">
          <Filter className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          
          {/* Severity Dropdown */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as any)}
            className="rounded border border-slate-800 bg-[#0d131f] px-2 py-1 text-[11px] font-mono text-slate-300 outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Detection Source Dropdown */}
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value as any)}
            className="rounded border border-slate-800 bg-[#0d131f] px-2 py-1 text-[11px] font-mono text-slate-300 outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Sources</option>
            <option value="RULE_ENGINE">Rule Engine</option>
            <option value="ML_ANOMALY">ML Anomaly</option>
          </select>

          {(severityFilter !== 'ALL' || sourceFilter !== 'ALL' || unreadOnly) && (
            <button
              onClick={() => {
                setSeverityFilter('ALL');
                setSourceFilter('ALL');
                setUnreadOnly(false);
              }}
              className="text-[10px] text-cyan-400 hover:underline font-mono ml-auto"
            >
              Reset
            </button>
          )}
        </div>

        {/* Notifications Scrollable List */}
        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 p-2 space-y-1">
          {filteredNotifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-center px-4">
              <CheckCircle2 className="w-10 h-10 text-emerald-400/40 mb-2" />
              <p className="font-mono text-sm font-semibold text-slate-300">
                All clear
              </p>
              <p className="text-xs text-slate-500 font-sans mt-1 max-w-xs">
                No notifications match the active filter criteria. Incoming threat events will appear here in real time.
              </p>
            </div>
          ) : (
            filteredNotifications.map((notif) => (
              <div
                key={notif.id}
                onClick={() => handleNotificationClick(notif.alertId, notif.id)}
                className={`group relative p-3.5 rounded-lg transition-all cursor-pointer border ${
                  notif.isRead
                    ? 'border-transparent bg-transparent hover:bg-slate-800/40'
                    : 'border-cyan-500/20 bg-cyan-950/20 hover:bg-cyan-950/30'
                }`}
              >
                <div className="flex items-start gap-2.5">
                  {/* Unread indicator */}
                  <div className="pt-1.5 shrink-0">
                    <div className={`w-2 h-2 rounded-full ${notif.isRead ? 'bg-transparent' : 'bg-cyan-400 shadow-sm shadow-cyan-400'}`} />
                  </div>

                  {/* Body */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <SeverityBadge severity={notif.severity} size="sm" />
                      <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${
                        notif.detectionSource === 'ML_ANOMALY'
                          ? 'border-purple-500/40 bg-purple-950/50 text-purple-300'
                          : 'border-cyan-500/40 bg-cyan-950/50 text-cyan-300'
                      }`}>
                        {notif.detectionSource === 'ML_ANOMALY' ? 'ML Anomaly' : 'Rule Engine'}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500 ml-auto whitespace-nowrap">
                        {notif.timestamp}
                      </span>
                    </div>

                    <h4 className="font-semibold text-xs text-white group-hover:text-cyan-300 transition-colors truncate">
                      {notif.title}
                    </h4>

                    <p className="text-[11px] font-mono text-slate-400 mt-1 flex items-center gap-1.5">
                      <span className="text-cyan-300">{notif.sourceIp}</span>
                      <span>→</span>
                      <span className="text-slate-300">{notif.destinationIp}</span>
                    </p>
                  </div>

                  {/* Right Actions */}
                  <div className="flex items-center gap-1 shrink-0 opacity-70 group-hover:opacity-100 transition-opacity">
                    {!notif.isRead && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          markNotificationRead(notif.id);
                        }}
                        title="Mark as read"
                        className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-cyan-300 transition-colors"
                      >
                        <CheckCheck className="w-3.5 h-3.5" />
                      </button>
                    )}
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        dismissNotification(notif.id);
                      }}
                      title="Dismiss notification"
                      className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-red-400 transition-colors"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Direct investigation hint on hover */}
                {notif.alertId && (
                  <div className="hidden group-hover:flex items-center gap-1 text-[10px] font-mono text-cyan-400/90 mt-2 pl-4">
                    <ExternalLink className="w-3 h-3" />
                    <span>Click to inspect forensic alert details</span>
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* Bottom Status Footer */}
        <div className="px-5 py-3 border-t border-slate-800 bg-[#0d131f] text-[11px] font-mono text-slate-400 flex items-center justify-between">
          <span>{filteredNotifications.length} items listed</span>
          <span className="text-slate-500">NetScope AI SOC Bus</span>
        </div>
      </div>
    </div>
  );
};
