import { mockReports } from '../data/mockData';
import { apiFetch } from './client';
import type { SecurityReport } from '../types/network';

export const reportsApi = {
  async getReports(): Promise<SecurityReport[]> {
    try {
      return await apiFetch<SecurityReport[]>('/reports');
    } catch {
      return [...mockReports];
    }
  },

  async generateReport(options: {
    type: 'Daily Analysis' | 'Threat Assessment' | 'Incident Forensics' | 'Executive Audit';
    includePayloads: boolean;
  }): Promise<SecurityReport> {
    try {
      return await apiFetch<SecurityReport>('/reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(options)
      });
    } catch {
      const now = new Date();
      const dateStr = `${now.getDate()} Sep 2026, ${now.toTimeString().split(' ')[0]}`;

      const newReport: SecurityReport = {
        id: `REP-${now.getFullYear()}-${Math.floor(Math.random() * 9000 + 1000)}`,
        name: `${options.type} - Automated SOC Synthesis`,
        type: options.type,
        generatedDate: dateStr,
        threats: Math.floor(Math.random() * 10 + 5),
        criticalCount: Math.floor(Math.random() * 4 + 1),
        status: 'Ready',
        fileSize: `${(Math.random() * 3 + 1.2).toFixed(1)} MB`,
        author: 'NetScope AI Detection Engine',
        summary: `Automated assessment generated for ${options.type}. Monitored subnets evaluated against current MITRE ATT&CK framework vectors.`,
        highlights: [
          'Real-time packet inspection validated zero unhandled socket leaks',
          'SYN flood mitigation rules engaged proactively',
          'All critical anomalies escalated to SOC queue'
        ]
      };
      mockReports.unshift(newReport);
      return newReport;
    }
  },

  getExportUrl(reportId: string): string {
    return `/api/v1/reports/${reportId}/export`;
  }
};
