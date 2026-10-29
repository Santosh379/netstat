import { apiFetch } from './client';
import type { NotificationItem } from '../types/network';

export interface NotificationFilterParams {
  severity?: string;
  detectionSource?: string;
  unreadOnly?: boolean;
  limit?: number;
}

export interface NotificationCountResponse {
  unreadCount: number;
  totalCount: number;
}

export const notificationsApi = {
  getNotifications: async (params?: NotificationFilterParams): Promise<NotificationItem[]> => {
    const q = new URLSearchParams();
    if (params?.severity && params.severity !== 'ALL') q.append('severity', params.severity);
    if (params?.detectionSource && params.detectionSource !== 'ALL') q.append('detection_source', params.detectionSource);
    if (params?.unreadOnly) q.append('unread_only', 'true');
    if (params?.limit) q.append('limit', params.limit.toString());
    const queryStr = q.toString() ? `?${q.toString()}` : '';
    return apiFetch<NotificationItem[]>(`/notifications${queryStr}`);
  },

  getUnreadCount: async (): Promise<NotificationCountResponse> => {
    return apiFetch<NotificationCountResponse>('/notifications/unread-count');
  },

  markAsRead: async (id: string): Promise<{ success: boolean; id: string }> => {
    return apiFetch<{ success: boolean; id: string }>(`/notifications/${id}/read`, {
      method: 'PATCH'
    });
  },

  markAllAsRead: async (): Promise<{ success: boolean; markedCount: number }> => {
    return apiFetch<{ success: boolean; markedCount: number }>('/notifications/mark-all-read', {
      method: 'POST'
    });
  },

  dismissNotification: async (id: string): Promise<{ success: boolean; id: string }> => {
    return apiFetch<{ success: boolean; id: string }>(`/notifications/${id}`, {
      method: 'DELETE'
    });
  },

  clearReadNotifications: async (): Promise<{ success: boolean; clearedCount: number }> => {
    return apiFetch<{ success: boolean; clearedCount: number }>('/notifications/clear/read', {
      method: 'DELETE'
    });
  }
};
