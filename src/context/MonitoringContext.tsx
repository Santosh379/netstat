import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import type { ReactNode } from 'react';
import type { LivePacket, SecurityAlert, NotificationItem } from '../types/network';
import { packetsApi } from '../api/packets';
import { systemApi } from '../api/system';
import { alertsApi } from '../api/alerts';
import { notificationsApi } from '../api/notifications';

export interface ToastMessage {
  id: string;
  title: string;
  message: string;
  type: 'info' | 'success' | 'warning' | 'danger';
  dedupKey?: string;
}

interface MonitoringContextType {
  isMonitoring: boolean;
  toggleMonitoring: () => void;
  stopCapture: () => void;
  clearPackets: () => void;
  livePackets: LivePacket[];
  packetsPerSec: number;
  bytesPerSec: string;
  totalPacketsCount: number;
  activeHostsCount: number;
  threatsCount: number;
  threatScore: number;
  selectedAlertForDetail: SecurityAlert | null;
  setSelectedAlertForDetail: (alert: SecurityAlert | null) => void;
  toasts: ToastMessage[];
  addToast: (title: string, message: string, type?: 'info' | 'success' | 'warning' | 'danger', dedupKey?: string) => void;
  removeToast: (id: string) => void;
  activeInterface: string;
  setActiveInterface: (iface: string) => void;
  isSynthetic: boolean;
  captureMode: 'REAL' | 'SYNTHETIC' | 'STOPPED';
  packetsCapturedCount: number;
  packetsProcessedCount: number;
  flowsCount: number;
  mlInferencesCount: number;
  elapsedSeconds: number;
  captureStartTime: string | null;
  captureError: string | null;
  npcapAvailable: boolean;
  hasAdminPrivileges: boolean;
  startCapture: (iface?: string, forceSynthetic?: boolean) => Promise<void>;
  isBackendConnected: boolean;
  activeCaptureId: string | null;
  setActiveCaptureId: (id: string | null) => void;
  // Live Alerts
  alerts: SecurityAlert[];
  fetchAlerts: () => Promise<void>;
  // Notifications
  notifications: NotificationItem[];
  unreadNotificationsCount: number;
  refreshNotifications: () => Promise<void>;
  markNotificationRead: (id: string) => Promise<void>;
  markAllNotificationsRead: () => Promise<void>;
  dismissNotification: (id: string) => Promise<void>;
  clearReadNotifications: () => Promise<void>;
}

const MonitoringContext = createContext<MonitoringContextType | undefined>(undefined);

export const MonitoringProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [isMonitoring, setIsMonitoring] = useState<boolean>(false);
  const [captureMode, setCaptureMode] = useState<'REAL' | 'SYNTHETIC' | 'STOPPED'>('STOPPED');
  const [livePackets, setLivePackets] = useState<LivePacket[]>([]);
  const [packetsPerSec, setPacketsPerSec] = useState<number>(0);
  const [bytesPerSec, setBytesPerSec] = useState<string>('0 B/s');
  const [totalPacketsCount, setTotalPacketsCount] = useState<number>(0);
  const [packetsCapturedCount, setPacketsCapturedCount] = useState<number>(0);
  const [packetsProcessedCount, setPacketsProcessedCount] = useState<number>(0);
  const [flowsCount, setFlowsCount] = useState<number>(0);
  const [mlInferencesCount, setMlInferencesCount] = useState<number>(0);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);
  const [captureStartTime, setCaptureStartTime] = useState<string | null>(null);
  const [captureError, setCaptureError] = useState<string | null>(null);
  const [npcapAvailable, setNpcapAvailable] = useState<boolean>(false);
  const [hasAdminPrivileges, setHasAdminPrivileges] = useState<boolean>(false);
  const [activeHostsCount, setActiveHostsCount] = useState<number>(0);
  const [threatsCount, setThreatsCount] = useState<number>(0);
  const [threatScore, setThreatScore] = useState<number>(0);
  const [selectedAlertForDetail, setSelectedAlertForDetail] = useState<SecurityAlert | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [activeInterface, setActiveInterface] = useState<string>('Synthetic Mode');
  const [isSynthetic, setIsSynthetic] = useState<boolean>(true);
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);
  const [activeCaptureId, setActiveCaptureId] = useState<string | null>(null);

  // Live Alerts State
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);

  // Notifications State
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [unreadNotificationsCount, setUnreadNotificationsCount] = useState<number>(0);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);

  // Non-intrusive brief toast with strict deduplication (max 1 toast on screen)
  const addToast = useCallback((
    title: string,
    message: string,
    type: 'info' | 'success' | 'warning' | 'danger' = 'info',
    dedupKey?: string
  ) => {
    setToasts((prev) => {
      if (dedupKey && prev.some((t) => t.dedupKey === dedupKey)) {
        return prev;
      }
      const id = `${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
      // Cap at 1 toast to prevent stacking screen obscurities
      return [{ id, title, message, type, dedupKey }];
    });

    setTimeout(() => {
      setToasts((prev) => (dedupKey ? prev.filter((t) => t.dedupKey !== dedupKey) : prev.slice(1)));
    }, 3800);
  }, []);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // Fetch alerts from backend
  const fetchAlerts = useCallback(async () => {
    try {
      const data = await alertsApi.getAlerts();
      setAlerts(data);
      const sum = await alertsApi.getSummary();
      setThreatsCount(sum.total);
      if (sum.critical > 0) setThreatScore(92);
      else if (sum.high > 0) setThreatScore(78);
      else setThreatScore(45);
    } catch {
      // Backend unavailable
    }
  }, []);

  // Fetch notifications
  const refreshNotifications = useCallback(async () => {
    try {
      const notifs = await notificationsApi.getNotifications({ limit: 100 });
      setNotifications(notifs);
      const countRes = await notificationsApi.getUnreadCount();
      setUnreadNotificationsCount(countRes.unreadCount);
    } catch {
      // Offline fallback
    }
  }, []);

  const markNotificationRead = useCallback(async (id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, isRead: true } : n))
    );
    setUnreadNotificationsCount((prev) => Math.max(0, prev - 1));
    try {
      await notificationsApi.markAsRead(id);
    } catch {}
  }, []);

  const markAllNotificationsRead = useCallback(async () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
    setUnreadNotificationsCount(0);
    try {
      await notificationsApi.markAllAsRead();
    } catch {}
  }, []);

  const dismissNotification = useCallback(async (id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
    try {
      await notificationsApi.dismissNotification(id);
      const countRes = await notificationsApi.getUnreadCount();
      setUnreadNotificationsCount(countRes.unreadCount);
    } catch {}
  }, []);

  const clearReadNotifications = useCallback(async () => {
    setNotifications((prev) => prev.filter((n) => !n.isRead));
    try {
      await notificationsApi.clearReadNotifications();
    } catch {}
  }, []);

  // Initial sync
  useEffect(() => {
    systemApi.getStatus().then((status) => {
      if (status.backend_available) {
        setIsBackendConnected(true);
        setIsSynthetic(status.is_synthetic);
        setActiveInterface(status.active_interface);
        setIsMonitoring(status.is_monitoring);
        setCaptureMode(status.capture_mode || (status.is_monitoring ? (status.is_synthetic ? 'SYNTHETIC' : 'REAL') : 'STOPPED'));
        if (status.packets_captured !== undefined) setPacketsCapturedCount(status.packets_captured);
        if (status.packets_processed !== undefined) {
          setPacketsProcessedCount(status.packets_processed);
          setTotalPacketsCount(status.packets_processed);
        }
        if (status.flows_count !== undefined) setFlowsCount(status.flows_count);
        if (status.ml_inferences_count !== undefined) setMlInferencesCount(status.ml_inferences_count);
        if (status.elapsed_seconds !== undefined) setElapsedSeconds(status.elapsed_seconds);
        if (status.capture_error !== undefined) setCaptureError(status.capture_error);
        if (status.npcap_available !== undefined) setNpcapAvailable(status.npcap_available);
        if (status.has_admin_privileges !== undefined) setHasAdminPrivileges(status.has_admin_privileges);
      }
    }).catch(() => {});

    fetchAlerts();
    refreshNotifications();
  }, [fetchAlerts, refreshNotifications]);

  // Connect to WebSocket /ws/live with automatic reconnection
  useEffect(() => {
    let unmounted = false;

    function connectWs() {
      if (unmounted) return;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/live`;

      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (unmounted) return;
          setIsBackendConnected(true);
        };

        ws.onmessage = (event) => {
          if (unmounted) return;
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'packet' && msg.data) {
              const pkt: LivePacket = msg.data;
              setLivePackets((prev) => [pkt, ...prev.slice(0, 79)]);
              setTotalPacketsCount((prev) => prev + 1);
              setPacketsProcessedCount((prev) => prev + 1);
              setPacketsCapturedCount((prev) => prev + 1);
              if (pkt.isSynthetic !== undefined) {
                setIsSynthetic(pkt.isSynthetic);
              }
            } else if (msg.type === 'stats' && msg.data) {
              setPacketsPerSec(msg.data.packetsPerSec);
              setBytesPerSec(msg.data.bytesPerSec);
              if (msg.data.captureMode) setCaptureMode(msg.data.captureMode);
              if (msg.data.packetsCaptured !== undefined) setPacketsCapturedCount(msg.data.packetsCaptured);
              if (msg.data.packetsProcessed !== undefined) {
                setPacketsProcessedCount(msg.data.packetsProcessed);
                setTotalPacketsCount(msg.data.packetsProcessed);
              } else if (msg.data.totalPackets !== undefined) {
                setTotalPacketsCount(msg.data.totalPackets);
              }
              if (msg.data.flowsCount !== undefined) setFlowsCount(msg.data.flowsCount);
              if (msg.data.mlInferencesCount !== undefined) setMlInferencesCount(msg.data.mlInferencesCount);
              if (msg.data.elapsedSeconds !== undefined) setElapsedSeconds(msg.data.elapsedSeconds);
              if (msg.data.startTime !== undefined) setCaptureStartTime(msg.data.startTime);
              if (msg.data.captureError !== undefined) setCaptureError(msg.data.captureError);
              if (msg.data.npcapAvailable !== undefined) setNpcapAvailable(msg.data.npcapAvailable);
              if (msg.data.hasAdminPrivileges !== undefined) setHasAdminPrivileges(msg.data.hasAdminPrivileges);
              if (msg.data.activeConnections !== undefined) {
                setActiveHostsCount(msg.data.activeConnections);
              }
            } else if (msg.type === 'alert' && msg.data) {
              const alert: SecurityAlert = msg.data;
              
              // 1. Live sync into alerts list
              setAlerts((prev) => {
                if (prev.some((a) => a.id === alert.id)) return prev;
                return [alert, ...prev];
              });
              setThreatsCount((prev) => prev + 1);

              // 2. Add to notifications
              const notifItem: NotificationItem = {
                id: `NTF-${alert.id}`,
                alertId: alert.id,
                title: alert.title,
                severity: alert.severity,
                attackType: alert.attackType,
                sourceIp: alert.sourceIp,
                destinationIp: alert.destinationIp,
                timestamp: alert.timestamp,
                detectionSource: alert.detectionSource || 'RULE_ENGINE',
                isRead: false,
                isDismissed: false,
                createdAt: new Date().toISOString()
              };
              setNotifications((prev) => {
                if (prev.some((n) => n.id === notifItem.id || n.alertId === alert.id)) return prev;
                return [notifItem, ...prev.slice(0, 99)];
              });
              setUnreadNotificationsCount((prev) => prev + 1);

              // 3. Intrusive toasts removed: ONLY brief toast for CRITICAL rule attacks, never for normal inferences
              if (alert.severity === 'CRITICAL') {
                addToast(
                  `CRITICAL: ${alert.attackType.toUpperCase()}`,
                  `${alert.sourceIp} -> ${alert.destinationIp}`,
                  'danger',
                  alert.id
                );
              }
            }
          } catch {
            // Heartbeat
          }
        };

        ws.onerror = () => {};

        ws.onclose = () => {
          if (unmounted) return;
          setIsBackendConnected(false);
          reconnectTimeoutRef.current = setTimeout(connectWs, 3000);
        };
      } catch {
        reconnectTimeoutRef.current = setTimeout(connectWs, 3000);
      }
    }

    connectWs();

    return () => {
      unmounted = true;
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
    };
  }, [addToast]);

  const toggleMonitoring = async () => {
    if (isMonitoring) {
      await stopCapture();
    } else {
      await startCapture();
    }
  };

  const startCapture = async (iface?: string, forceSynthetic: boolean = false) => {
    try {
      const res = await packetsApi.startCapture(iface, forceSynthetic);
      setIsMonitoring(true);
      if (res.capture_mode) {
        setCaptureMode(res.capture_mode as 'REAL' | 'SYNTHETIC' | 'STOPPED');
      } else {
        setCaptureMode(res.is_synthetic ? 'SYNTHETIC' : 'REAL');
      }
      setCaptureError(res.capture_error || null);
    } catch {
      setIsMonitoring(true);
      setCaptureMode('SYNTHETIC');
    }
  };

  const stopCapture = async () => {
    try {
      await packetsApi.stopCapture();
      setIsMonitoring(false);
      setCaptureMode('STOPPED');
      setPacketsPerSec(0);
      setBytesPerSec('0 B/s');
    } catch {
      setIsMonitoring(false);
      setCaptureMode('STOPPED');
      setPacketsPerSec(0);
      setBytesPerSec('0 B/s');
    }
  };

  const clearPackets = () => {
    setLivePackets([]);
  };

  return (
    <MonitoringContext.Provider
      value={{
        isMonitoring,
        toggleMonitoring,
        startCapture,
        stopCapture,
        clearPackets,
        livePackets,
        packetsPerSec,
        bytesPerSec,
        totalPacketsCount,
        packetsCapturedCount,
        packetsProcessedCount,
        flowsCount,
        mlInferencesCount,
        elapsedSeconds,
        captureStartTime,
        captureError,
        npcapAvailable,
        hasAdminPrivileges,
        activeHostsCount,
        threatsCount,
        threatScore,
        selectedAlertForDetail,
        setSelectedAlertForDetail,
        toasts,
        addToast,
        removeToast,
        activeInterface,
        setActiveInterface,
        isSynthetic,
        captureMode,
        isBackendConnected,
        activeCaptureId,
        setActiveCaptureId,
        alerts,
        fetchAlerts,
        notifications,
        unreadNotificationsCount,
        refreshNotifications,
        markNotificationRead,
        markAllNotificationsRead,
        dismissNotification,
        clearReadNotifications
      }}
    >
      {children}
    </MonitoringContext.Provider>
  );
};

export const useMonitoring = (): MonitoringContextType => {
  const context = useContext(MonitoringContext);
  if (!context) {
    throw new Error('useMonitoring must be used within a MonitoringProvider');
  }
  return context;
};
