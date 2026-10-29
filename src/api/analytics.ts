import { 
  mockTrafficTimeline, 
  mockProtocolDistribution 
} from '../data/mockData';
import { apiFetch } from './client';
import type { SecurityAlert } from '../types/network';

export interface DashboardStats {
  totalPackets: number;
  activeHosts: number;
  threatsCount: number;
  threatScore: number;
  networkStatus: string;
  trafficTimeline: Array<{ time: string; packets: number }>;
  protocolDistribution: Array<{ name: string; value: number; color: string }>;
  recentAlerts: SecurityAlert[];
}

export const analyticsApi = {
  async getDashboardStats(timeRange: '1H' | '6H' | '24H' = '1H'): Promise<DashboardStats> {
    try {
      return await apiFetch<DashboardStats>(`/dashboard/stats?timeRange=${timeRange}`);
    } catch {
      return {
        totalPackets: 12842,
        activeHosts: 27,
        threatsCount: 14,
        threatScore: 72,
        networkStatus: 'Monitoring Ready',
        trafficTimeline: mockTrafficTimeline[timeRange] || mockTrafficTimeline['1H'],
        protocolDistribution: mockProtocolDistribution,
        recentAlerts: []
      };
    }
  },

  async getTrafficTimeline(timeRange: '1H' | '6H' | '24H' = '1H') {
    try {
      return await apiFetch<Array<{ time: string; packets: number }>>(`/analytics/timeline?timeRange=${timeRange}`);
    } catch {
      return mockTrafficTimeline[timeRange] || mockTrafficTimeline['1H'];
    }
  },

  async getProtocolDistribution() {
    try {
      return await apiFetch<Array<{ name: string; value: number; color: string }>>('/analytics/protocols');
    } catch {
      return mockProtocolDistribution;
    }
  }
};
