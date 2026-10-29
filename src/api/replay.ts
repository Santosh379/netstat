import { apiFetch } from './client';
import { mockAttackScenarios } from '../data/mockData';
import type { AttackScenario } from '../types/network';

export const replayApi = {
  async getScenarios(captureId?: string): Promise<AttackScenario[]> {
    const params = new URLSearchParams();
    if (captureId) params.set('capture_id', captureId);
    const query = params.toString() ? `?${params.toString()}` : '';
    try {
      return await apiFetch<AttackScenario[]>(`/replay/scenarios${query}`);
    } catch {
      return mockAttackScenarios;
    }
  },

  async getScenario(id: string, captureId?: string): Promise<AttackScenario> {
    const params = new URLSearchParams();
    if (captureId) params.set('capture_id', captureId);
    const query = params.toString() ? `?${params.toString()}` : '';
    try {
      return await apiFetch<AttackScenario>(`/replay/scenario/${id}${query}`);
    } catch {
      return mockAttackScenarios.find((s) => s.id === id) || mockAttackScenarios[0];
    }
  },

  async getScenarioFromAlert(alertId: string): Promise<AttackScenario> {
    try {
      return await apiFetch<AttackScenario>(`/replay/from-alert/${alertId}`);
    } catch {
      return mockAttackScenarios[0];
    }
  }
};
