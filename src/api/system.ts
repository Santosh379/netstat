import { apiFetch } from './client';

export interface MLModelInfo {
  available: boolean;
  model_name?: string;
  model_version?: string;
  schema_version?: string;
  trained_at?: string;
  training_samples?: number;
  decision_threshold?: number;
  features_count?: number;
  features?: string[];
  error?: string;
}

export interface SystemStatus {
  status: string;
  version: string;
  backend_available: boolean;
  capture_mode?: 'REAL' | 'SYNTHETIC' | 'STOPPED';
  live_capture_supported: boolean;
  npcap_available: boolean;
  has_admin_privileges: boolean;
  active_interface: string;
  is_monitoring: boolean;
  is_synthetic: boolean;
  message: string;
  capture_error?: string | null;
  packets_captured?: number;
  packets_processed?: number;
  flows_count?: number;
  ml_inferences_count?: number;
  elapsed_seconds?: number;
  ml_enabled?: boolean;
  ml_model_info?: MLModelInfo;
}

export interface InterfaceInfo {
  name: string;
  description: string;
  ip?: string;
  mac?: string;
  is_up: boolean;
  speed_mbps?: number;
}

export interface SystemSettings {
  interface: string;
  packet_capture_enabled: boolean;
  dark_mode: boolean;
  synthetic_mode: boolean;
  ml_enabled?: boolean;
}

export const systemApi = {
  async getStatus(): Promise<SystemStatus> {
    try {
      return await apiFetch<SystemStatus>('/system/status');
    } catch {
      return {
        status: 'offline',
        version: '1.0.0',
        backend_available: false,
        live_capture_supported: false,
        npcap_available: false,
        has_admin_privileges: false,
        active_interface: 'Synthetic Mode',
        is_monitoring: false,
        is_synthetic: true,
        message: 'Backend server offline',
        ml_enabled: true
      };
    }
  },

  async getInterfaces(): Promise<InterfaceInfo[]> {
    try {
      return await apiFetch<InterfaceInfo[]>('/system/interfaces');
    } catch {
      return [
        { name: 'Wi-Fi', description: 'Wi-Fi (Wireless Adapter)', is_up: true },
        { name: 'Ethernet', description: 'Ethernet (Gigabit Controller)', is_up: true },
        { name: 'Synthetic Mode', description: 'Synthetic Simulator (Safe demonstration engine)', ip: '192.168.1.10', is_up: true }
      ];
    }
  },

  async getSettings(): Promise<SystemSettings> {
    try {
      return await apiFetch<SystemSettings>('/system/settings');
    } catch {
      return {
        interface: 'Synthetic Mode',
        packet_capture_enabled: true,
        dark_mode: true,
        synthetic_mode: true,
        ml_enabled: true
      };
    }
  },

  async updateSettings(settings: Partial<SystemSettings>): Promise<SystemSettings> {
    try {
      return await apiFetch<SystemSettings>('/system/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
      });
    } catch {
      return {
        interface: settings.interface || 'Synthetic Mode',
        packet_capture_enabled: settings.packet_capture_enabled ?? true,
        dark_mode: settings.dark_mode ?? true,
        synthetic_mode: settings.synthetic_mode ?? true,
        ml_enabled: settings.ml_enabled ?? true
      };
    }
  },

  async getMlStatus(): Promise<{ enabled: boolean; details: MLModelInfo }> {
    try {
      return await apiFetch<{ enabled: boolean; details: MLModelInfo }>('/system/ml');
    } catch {
      return {
        enabled: true,
        details: { available: false, model_name: 'IsolationForest', model_version: '1.0.0' }
      };
    }
  },

  async toggleMl(): Promise<{ enabled: boolean; message: string }> {
    try {
      return await apiFetch<{ enabled: boolean; message: string }>('/system/ml/toggle', {
        method: 'POST'
      });
    } catch {
      return { enabled: true, message: 'ML toggled locally' };
    }
  },

  async getMlPerformance(): Promise<{ active_model: MLModelInfo; comparison: any }> {
    return await apiFetch<{ active_model: MLModelInfo; comparison: any }>('/system/ml/performance');
  },

  async switchMlModel(modelName: string): Promise<{ success: boolean; message: string; active_model?: any }> {
    return await apiFetch<{ success: boolean; message: string; active_model?: any }>('/system/ml/switch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model_name: modelName })
    });
  },

  async trainMlModel(modelType: string = 'HistGradientBoosting'): Promise<{ status: string; message: string }> {
    return await apiFetch<{ status: string; message: string }>('/system/ml/train', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model_type: modelType })
    });
  },

  async getTrainingStatus(): Promise<{ is_training: boolean; last_result?: any; error?: string }> {
    return await apiFetch<{ is_training: boolean; last_result?: any; error?: string }>('/system/ml/train/status');
  }
};

