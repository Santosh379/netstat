import { mockAlerts } from '../data/mockData';
import { apiFetch } from './client';
import type { SecurityAlert, AlertStatus, Severity, AttackType } from '../types/network';

export interface AlertCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface AlertFilterParams {
  severity?: Severity | 'ALL';
  attackType?: AttackType | 'ALL';
  status?: AlertStatus | 'ALL';
  detectionSource?: 'RULE_ENGINE' | 'ML_ANOMALY' | 'ALL';
  captureId?: string;
  sourceType?: 'PCAP' | 'LIVE' | 'ALL';
  timeRange?: string;
  search?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  offset?: number;
  limit?: number;
}

export const alertsApi = {
  async getAlerts(filters?: AlertFilterParams): Promise<SecurityAlert[]> {
    const params = new URLSearchParams();
    if (filters?.severity && filters.severity !== 'ALL') params.set('severity', filters.severity);
    if (filters?.attackType && filters.attackType !== 'ALL') params.set('attackType', filters.attackType);
    if (filters?.status && filters.status !== 'ALL') params.set('status', filters.status);
    if (filters?.detectionSource && filters.detectionSource !== 'ALL') params.set('detectionSource', filters.detectionSource);
    if (filters?.captureId) params.set('captureId', filters.captureId);
    if (filters?.sourceType && filters.sourceType !== 'ALL') params.set('sourceType', filters.sourceType);
    if (filters?.timeRange && filters.timeRange !== 'ALL') params.set('timeRange', filters.timeRange);
    if (filters?.search) params.set('search', filters.search);
    if (filters?.sortBy) params.set('sortBy', filters.sortBy);
    if (filters?.sortOrder) params.set('sortOrder', filters.sortOrder);
    if (filters?.offset !== undefined) params.set('offset', String(filters.offset));
    if (filters?.limit !== undefined) params.set('limit', String(filters.limit));

    const query = params.toString() ? `?${params.toString()}` : '';

    try {
      return await apiFetch<SecurityAlert[]>(`/alerts${query}`);
    } catch (err) {
      console.warn('[alertsApi] Backend unavailable, using local fallback:', err);
      let results = [...mockAlerts];
      if (filters) {
        if (filters.severity && filters.severity !== 'ALL') {
          results = results.filter((a) => a.severity === filters.severity);
        }
        if (filters.attackType && filters.attackType !== 'ALL') {
          results = results.filter((a) => a.attackType === filters.attackType);
        }
        if (filters.status && filters.status !== 'ALL') {
          results = results.filter((a) => a.status === filters.status);
        }
        if (filters.captureId) {
          results = results.filter((a) => a.captureId === filters.captureId);
        }
        if (filters.search) {
          const q = filters.search.toLowerCase();
          results = results.filter(
            (a) =>
              a.title.toLowerCase().includes(q) ||
              a.sourceIp.includes(q) ||
              a.destinationIp.includes(q) ||
              a.attackType.toLowerCase().includes(q)
          );
        }
      }
      return results;
    }
  },

  async getSummary(filters?: { captureId?: string; sourceType?: string; timeRange?: string }): Promise<AlertCounts> {
    const params = new URLSearchParams();
    if (filters?.captureId) params.set('captureId', filters.captureId);
    if (filters?.sourceType && filters.sourceType !== 'ALL') params.set('sourceType', filters.sourceType);
    if (filters?.timeRange && filters.timeRange !== 'ALL') params.set('timeRange', filters.timeRange);
    const query = params.toString() ? `?${params.toString()}` : '';

    try {
      return await apiFetch<AlertCounts>(`/alerts/summary${query}`);
    } catch {
      return {
        critical: mockAlerts.filter(a => a.severity === 'CRITICAL').length,
        high: mockAlerts.filter(a => a.severity === 'HIGH').length,
        medium: mockAlerts.filter(a => a.severity === 'MEDIUM').length,
        low: mockAlerts.filter(a => a.severity === 'LOW').length,
        total: mockAlerts.length
      };
    }
  },

  async getAlertById(id: string): Promise<SecurityAlert | undefined> {
    try {
      return await apiFetch<SecurityAlert>(`/alerts/${id}`);
    } catch {
      return mockAlerts.find((a) => a.id === id);
    }
  },

  async updateAlertStatus(id: string, status: AlertStatus): Promise<boolean> {
    try {
      const res = await apiFetch<{ success: boolean }>(`/alerts/${id}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });
      return res.success;
    } catch {
      const alert = mockAlerts.find((a) => a.id === id);
      if (alert) {
        alert.status = status;
        return true;
      }
      return false;
    }
  },

  async blockIp(ipAddress: string): Promise<{ success: boolean; ruleId: string; message?: string }> {
    try {
      return await apiFetch<{ success: boolean; ruleId: string; message: string }>('/alerts/block-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ipAddress })
      });
    } catch {
      return {
        success: Boolean(ipAddress),
        ruleId: `FW-BLOCK-${Math.floor(Math.random() * 90000 + 10000)}`,
        message: 'Simulated fallback firewall rule generated'
      };
    }
  }
};
