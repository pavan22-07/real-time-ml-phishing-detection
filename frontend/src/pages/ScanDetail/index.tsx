import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { scansApi } from "@/api/scans";
import type { ScanRecord } from "@/types/scans";
import {
  ShieldIcon,
  ChevronLeftIcon,
  CheckCircleIcon,
  OctagonAlertIcon,
  LockIcon,
  CopyIcon,
  CheckIcon,
} from "@/icons";
import {
  formatDateTime,
  formatDecision,
  formatRiskScore,
} from "@/utils/formatters";

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let isMounted = true;
    async function loadScan() {
      if (!id) return;
      setIsLoading(true);
      setErrorMsg(null);
      try {
        const data = await scansApi.getScanDetail(id);
        if (isMounted) setScan(data);
      } catch {
        if (isMounted) {
          setErrorMsg(
            "Scan report not found or access denied. Each record is strictly isolated to its creator."
          );
        }
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    loadScan();
    return () => {
      isMounted = false;
    };
  }, [id]);

  const handleCopyReport = () => {
    if (!scan) return;
    const reportText = `SecureLens Phishing Audit Report
Scan ID: ${scan.id}
URL: ${scan.url}
Final Decision: ${scan.final_decision}
Cybersecurity Risk Score: ${scan.cybersecurity.risk_score}/100 (${scan.cybersecurity.verdict})
ML Prediction: ${scan.machine_learning.prediction} (Raw Probability: ${scan.machine_learning.raw_phishing_probability})
Timestamp: ${scan.timestamp}
Reasons: ${scan.reasons.join("; ")}
Warnings: ${scan.warnings.join("; ")}`;

    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (isLoading) {
    return (
      <div className="py-24 text-center text-xs text-slate-400">
        <span className="inline-block size-8 rounded-full border-2 border-sky-400 border-t-transparent animate-spin mb-3" />
        <p>Loading security audit report for inspection ID: {id}...</p>
      </div>
    );
  }

  if (errorMsg || !scan) {
    return (
      <div className="max-w-2xl mx-auto rounded-2xl border border-rose-500/30 bg-rose-500/10 p-8 text-center text-xs text-rose-300">
        <OctagonAlertIcon className="size-10 text-rose-400 mx-auto mb-3" />
        <h3 className="text-sm font-bold">Unable to Load Scan Record</h3>
        <p className="mt-1 text-slate-400">{errorMsg || "Record not found."}</p>
        <div className="mt-5">
          <Link
            to="/scans"
            className="inline-flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors"
          >
            <ChevronLeftIcon className="size-4" />
            <span>Return to Scan History</span>
          </Link>
        </div>
      </div>
    );
  }

  const decisionMeta = formatDecision(scan.final_decision);
  const riskMeta = formatRiskScore(scan.cybersecurity.risk_score);

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Top Breadcrumb & Action bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <Link
          to="/scans"
          className="inline-flex items-center gap-2 text-xs font-semibold text-slate-400 hover:text-white transition-colors"
        >
          <ChevronLeftIcon className="size-4" />
          <span>Back to Scan History</span>
        </Link>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopyReport}
            className="inline-flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-800 hover:text-white transition-colors cursor-pointer"
          >
            {copied ? (
              <>
                <CheckIcon className="size-4 text-emerald-400" />
                <span className="text-emerald-400">Copied to Clipboard</span>
              </>
            ) : (
              <>
                <CopyIcon className="size-4" />
                <span>Copy Summary Report</span>
              </>
            )}
          </button>
          <button
            onClick={() => window.print()}
            className="hidden sm:inline-flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-800 hover:text-white transition-colors cursor-pointer"
          >
            <span>Print Report</span>
          </button>
        </div>
      </div>

      {/* Primary Report Card */}
      <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6 sm:p-8 shadow-2xl space-y-6">
        {/* Header Section */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-sky-400">
                Security Audit Report
              </span>
              <span className="text-slate-500">&bull;</span>
              <span className="font-mono text-xs text-slate-400">ID: {scan.id}</span>
            </div>
            <h1 className="text-2xl font-extrabold text-white">
              Target URL Analysis Breakdown
            </h1>
            <p className="text-xs text-slate-400">
              Generated on {formatDateTime(scan.timestamp)}
            </p>
          </div>

          <div className="text-left sm:text-right">
            <span
              className={`inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-extrabold border ${decisionMeta.badgeClass}`}
            >
              <span className={`size-2.5 rounded-full ${decisionMeta.dotColor}`} />
              {decisionMeta.label}
            </span>
            {scan.degraded_mode && (
              <span className="block mt-1 text-[11px] font-semibold text-amber-400">
                * Pipeline Degraded Mode Active
              </span>
            )}
          </div>
        </div>

        {/* URL Target Display */}
        <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
          <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
            Inspected Destination URL
          </span>
          <p className="font-mono text-sm text-slate-100 break-all">{scan.url}</p>
        </div>

        {/* Multi-Engine Analysis Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
          {/* Cybersecurity Rule Engine Section */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <ShieldIcon className="size-5 text-sky-400" />
                <h3 className="text-sm font-bold text-white">Cybersecurity Rule Engine</h3>
              </div>
              <span className="text-[10px] font-mono uppercase bg-slate-950 px-2 py-0.5 rounded text-sky-400 border border-slate-800">
                {scan.cybersecurity.status || "NORMAL"}
              </span>
            </div>

            <div className="space-y-3">
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Rule Verdict:</span>
                <span className="font-bold text-slate-100">
                  {scan.cybersecurity.verdict || "UNKNOWN"}
                </span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Deterministic Risk Score:</span>
                <span className={`font-bold ${riskMeta.colorClass}`}>
                  {riskMeta.score} ({riskMeta.label})
                </span>
              </div>
            </div>

            <p className="text-[11px] text-slate-400 pt-2 border-t border-slate-800/80 leading-relaxed">
              Checks brand spoofing tokens, IDN homoglyphs (Cyrillic/Greek spoofing), IP literals, and deceptive URL paths.
            </p>
          </div>

          {/* Machine Learning Classifier Section */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <LockIcon className="size-5 text-indigo-400" />
                <h3 className="text-sm font-bold text-white">Machine Learning Engine</h3>
              </div>
              <span className="text-[10px] font-mono uppercase bg-slate-950 px-2 py-0.5 rounded text-indigo-400 border border-slate-800">
                {scan.machine_learning.status || "NORMAL"}
              </span>
            </div>

            <div className="space-y-3">
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Random Forest Prediction:</span>
                <span className="font-bold text-slate-100">
                  {scan.machine_learning.prediction || "UNKNOWN"}
                </span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Raw Phishing Probability:</span>
                <span className="font-mono font-bold text-slate-100">
                  {scan.machine_learning.raw_phishing_probability !== null
                    ? scan.machine_learning.raw_phishing_probability.toFixed(4)
                    : "N/A"}
                </span>
              </div>
            </div>

            <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-2.5 text-[11px] text-amber-300">
              <span className="font-semibold block">Notice:</span>
              <span>Raw ML phishing probability &mdash; not calibrated.</span>
            </div>
          </div>
        </div>

        {/* Reasons & Trigger Diagnostics */}
        <div className="space-y-3 pt-2">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <CheckCircleIcon className="size-4 text-sky-400" />
            <span>Diagnostic Trigger Reasons</span>
          </h3>

          {scan.reasons && scan.reasons.length > 0 ? (
            <ul className="space-y-2">
              {scan.reasons.map((reason, idx) => (
                <li
                  key={idx}
                  className="rounded-xl bg-slate-950/60 border border-slate-800/80 p-3 text-xs text-slate-200 flex items-start gap-2.5"
                >
                  <span className="mt-0.5 size-1.5 rounded-full bg-sky-400 shrink-0" />
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-400 italic bg-slate-950/40 p-3 rounded-xl border border-slate-800">
              No adverse heuristic violations triggered. Target conforms to standard domain conventions.
            </p>
          )}
        </div>

        {/* Warnings */}
        {scan.warnings && scan.warnings.length > 0 && (
          <div className="space-y-2 pt-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400">
              Engine Warnings &amp; Advisories
            </h3>
            <ul className="space-y-2">
              {scan.warnings.map((warn, idx) => (
                <li
                  key={idx}
                  className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-300"
                >
                  {warn}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
