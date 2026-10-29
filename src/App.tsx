import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { MonitoringProvider } from './context/MonitoringContext';
import { Layout } from './components/layout/Layout';
import { DashboardPage } from './pages/DashboardPage';
import { LiveMonitorPage } from './pages/LiveMonitorPage';
import { PcapAnalyzerPage } from './pages/PcapAnalyzerPage';
import { AlertsPage } from './pages/AlertsPage';
import { AttackReplayPage } from './pages/AttackReplayPage';
import { TopologyPage } from './pages/TopologyPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';

export function App() {
  return (
    <MonitoringProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<DashboardPage />} />
            <Route path="live" element={<LiveMonitorPage />} />
            <Route path="pcap" element={<PcapAnalyzerPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="replay" element={<AttackReplayPage />} />
            <Route path="topology" element={<TopologyPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </MonitoringProvider>
  );
}

export default App;
