import React, { useState, useEffect } from 'react';
import { reportsApi } from '../api/reports';
import { useMonitoring } from '../context/MonitoringContext';
import type { SecurityReport } from '../types/network';
import { 
  FileText, 
  Plus, 
  X,
  CheckCircle2,
  ExternalLink,
  Download
} from 'lucide-react';

export const ReportsPage: React.FC = () => {
  const { addToast } = useMonitoring();
  const [reports, setReports] = useState<SecurityReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<SecurityReport | null>(null);
  const [showGeneratedNotice, setShowGeneratedNotice] = useState<boolean>(false);
  const [generating, setGenerating] = useState<boolean>(false);

  const fetchReports = () => {
    reportsApi.getReports().then((data) => {
      setReports(data);
    }).catch(() => {});
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const newReport = await reportsApi.generateReport({
        type: 'Daily Analysis',
        includePayloads: false
      });
      setReports([newReport, ...reports]);
      setShowGeneratedNotice(true);
      addToast('Report Synthesized', `Generated report ${newReport.id} with ${newReport.threats} findings.`, 'success');
      setTimeout(() => setShowGeneratedNotice(false), 3000);
    } catch {
      addToast('Report Error', 'Failed to generate report from backend.', 'danger');
    } finally {
      setGenerating(false);
    }
  };

  const handleDownloadJson = (rep: SecurityReport) => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(rep, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `${rep.name.toLowerCase().replace(/\s+/g, '_')}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleOpenHtmlExport = (reportId: string) => {
    const url = reportsApi.getExportUrl(reportId);
    window.open(url, '_blank');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-6 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-bold font-mono text-white tracking-tight">
              Security Reports
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 font-sans mt-0.5">
              Automated executive and technical threat reports synthesized from captured network incidents.
            </p>
          </div>

          <button
            onClick={handleGenerate}
            disabled={generating}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold transition-all shadow-md self-start sm:self-auto disabled:opacity-50"
          >
            <Plus className="w-3.5 h-3.5 stroke-[3]" />
            <span>{generating ? 'Generating...' : 'Generate Report'}</span>
          </button>
        </div>

        {showGeneratedNotice && (
          <div className="mt-4 p-3 rounded-lg border border-emerald-500/30 bg-emerald-950/20 text-emerald-400 font-mono text-xs flex items-center gap-2 animate-in fade-in">
            <CheckCircle2 className="w-4 h-4" />
            <span>New report synthesized from security findings and added to persistent database.</span>
          </div>
        )}
      </div>

      {/* Reports Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0d131f] shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400 bg-[#090d16]">
                <th className="py-3 px-4 font-semibold">Report</th>
                <th className="py-3 px-4 font-semibold">Date</th>
                <th className="py-3 px-4 font-semibold">Threats</th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {reports.map((report) => (
                <tr key={report.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3.5 px-4">
                    <div className="flex items-center gap-2.5">
                      <FileText className="w-4 h-4 text-cyan-400 shrink-0" />
                      <div>
                        <span className="font-bold text-white block">{report.name}</span>
                        <span className="text-[10px] text-slate-400">{report.type} &bull; {report.id}</span>
                      </div>
                    </div>
                  </td>
                  <td className="py-3.5 px-4 text-slate-300 whitespace-nowrap">
                    {report.generatedDate}
                  </td>
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span className="text-red-400 font-bold">{report.threats}</span>
                  </td>
                  <td className="py-3.5 px-4 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => setSelectedReport(report)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs transition-colors"
                      >
                        View
                      </button>
                      <button
                        onClick={() => handleOpenHtmlExport(report.id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 text-xs transition-colors"
                        title="Open Printable HTML Report"
                      >
                        <ExternalLink className="w-3 h-3" />
                        <span>Print</span>
                      </button>
                      <button
                        onClick={() => handleDownloadJson(report)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs transition-colors"
                      >
                        JSON
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Simple View Modal */}
      {selectedReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-lg rounded-2xl border border-slate-700 bg-[#0d131f] p-6 shadow-2xl font-mono text-xs text-slate-200">
            <div className="flex items-start justify-between border-b border-slate-800 pb-3 mb-4">
              <div>
                <h3 className="text-base font-bold text-white">
                  {selectedReport.name}
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Generated on {selectedReport.generatedDate} &bull; {selectedReport.fileSize}
                </p>
              </div>
              <button
                onClick={() => setSelectedReport(null)}
                className="p-1 rounded text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4">
              <div className="p-3 rounded-lg border border-slate-800 bg-[#090d16]">
                <p className="text-slate-300 font-sans leading-relaxed">
                  {selectedReport.summary}
                </p>
              </div>

              <div>
                <span className="text-slate-400 font-bold uppercase text-[10px] block mb-2">
                  Threat Highlights
                </span>
                <ul className="space-y-1">
                  {selectedReport.highlights.map((h, i) => (
                    <li key={i} className="flex items-center gap-2 text-slate-300">
                      <span className="text-cyan-400">•</span>
                      <span>{h}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-800 flex justify-end gap-2">
              <button
                onClick={() => handleOpenHtmlExport(selectedReport.id)}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30 font-bold"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Open HTML</span>
              </button>
              <button
                onClick={() => handleDownloadJson(selectedReport)}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
              >
                <Download className="w-3.5 h-3.5" />
                <span>JSON</span>
              </button>
              <button
                onClick={() => setSelectedReport(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
