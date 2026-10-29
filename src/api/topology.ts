import { apiFetch } from './client';
import type { TopologyResponse } from '../types/network';

export const topologyApi = {
  async getTopology(source: 'auto' | 'pcap' | 'live' = 'auto', captureId?: string): Promise<TopologyResponse> {
    const params = new URLSearchParams({ source });
    if (captureId) params.set('captureId', captureId);
    return await apiFetch<TopologyResponse>(`/topology?${params.toString()}`);
  },

  async isolateHost(nodeId: string): Promise<boolean> {
    try {
      const res = await apiFetch<{ success: boolean }>(`/topology/isolate/${nodeId}`, {
        method: 'POST'
      });
      return res.success;
    } catch {
      return false;
    }
  },

  async unisolateHost(nodeId: string): Promise<boolean> {
    try {
      const res = await apiFetch<{ success: boolean }>(`/topology/unisolate/${nodeId}`, {
        method: 'POST'
      });
      return res.success;
    } catch {
      return false;
    }
  }
};
