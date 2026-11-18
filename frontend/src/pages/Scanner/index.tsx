import { useState } from "react";
import { useNavigate } from "react-router";
import { scansApi } from "@/api/scans";
import type { ScanRecord } from "@/types/scans";
import {
  ShieldIcon,
  BoltIcon,
  CheckCircleIcon,
  LockIcon,
  ArrowRightIcon,
  XIcon,
} from "@/icons";
import { formatDateTime, formatDecision, formatRiskScore } from "@/utils/formatters";
import type { AxiosError } from "axios";

export default function ScannerPage() {
  const [urlInput, setUrlInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanRecord | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const navigate = useNavigate();

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    const targetUrl = urlInput.trim();
    if (!targetUrl) {
      setErrorMsg("Please enter a URL to analyze.");
      return;
    }

    setIsScanning(true);
    setScanResult(null);

    try {
      const result = await scansApi.submitScan({ url: targetUrl });
      setScanResult(result);
    } catch (err) {
      const axiosErr = err as AxiosError<{
        url?: string[];
        detail?: string;
        error?: string;
        message?: string;
      }>;
      if (axiosErr.response?.data) {
        const d = axiosErr.response.data;
        if (d.url && d.url.length > 0) {
          setErrorMsg(d.url[0]);
        } else if (d.detail) {
          setErrorMsg(d.detail);
        } else if (d.message) {
          setErrorMsg(d.message);
        } else if (d.error) {
          setErrorMsg(d.error);
        } else {
          setErrorMsg("Scan failed. Please verify the URL structure.");
        }
      } else if (axiosErr.code === "ECONNABORTED") {
        setErrorMsg("Scan request timed out. The URL evaluation engine took longer than expected.");
      } else {
        const targetUrl = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";
        setErrorMsg(`Network error connecting to the Unified Scanning Engine at ${targetUrl}. Please verify your backend server is running.`);
      }
    } finally {
      setIsScanning(false);
    }
  };

  const handleSample = (sampleUrl: string) => {
    setUrlInput(sampleUrl);
    setErrorMsg(null);
  };

  const decisionMeta = scanResult ? formatDecision(scanResult.final_decision) : null;
  const riskMeta = scanResult ? formatRiskScore(scanResult.cybersecurity.risk_score) : null;

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="rounded-2xl border border-slate-800 bg-[#0B1220] p-6 shadow-xl">
        <div className="flex items-center gap-2 mb-1">
          <span className="flex size-2 rounded-full bg-sky-400 animate-pulse" />
          <span className="text-xs font-semibold uppercase tracking-wider text-sky-400">
            Real-Time Analysis Console
          </span>
        </div>
        <h1 className="text-2xl font-extrabold tracking-tight text-white font-outfit sm:text-3xl">
          Unified URL Phishing Scanner
        </h1>
        <p className="mt-1 text-xs text-slate-400 max-w-2xl">
          Submit any target URL to invoke the dual-engine pipeline: deterministic cybersecurity heuristics and machine learning threat prediction with zero-trust arbitration.
        </p>
      </div>

      {/* Main Scan Input Card */}
      <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6 shadow-xl">
        <form onSubmit={handleScan} className="space-y-4">
          <label htmlFor="scan-url-input" className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
            Target Destination URL
          </label>

          <div className="relative">
            <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-4 text-slate-400">
              <BoltIcon className="size-5" />
            </div>
            <input
              id="scan-url-input"
              type="text"
              required
              disabled={isScanning}
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="https://example.com/login or paste suspicious link..."
              className="w-full h-14 pl-12 pr-12 rounded-xl border border-slate-700 bg-slate-950/80 text-sm font-mono text-white placeholder:text-slate-500 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-500/20 disabled:opacity-50"
            />
            {urlInput && (
              <button
                type="button"
                onClick={() => setUrlInput("")}
                className="absolute inset-y-0 right-0 flex items-center pr-4 text-slate-400 hover:text-slate-200"
                aria-label="Clear URL"
              >
                <XIcon className="size-4" />
              </button>
            )}
          </div>

          {/* Quick Samples */}
          <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-slate-400">
            <span className="text-[11px] font-semibold text-slate-400">Test Heuristics:</span>
            <button
              type="button"
              onClick={() => handleSample("https://google.com")}
              className="rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1 text-[11px] text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
            >
              Legitimate Domain (google.com)
            </button>
            <button
              type="button"
              onClick={() => handleSample("http://paypal-security-update.account-verification.tk/login")}
              className="rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1 text-[11px] text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
            >
              Brand Spoofing &amp; High-Risk TLD
            </button>
            <button
              type="button"
              onClick={() => handleSample("http://192.168.1.1/admin-panel")}
              className="rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1 text-[11px] text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
            >
              IP-Literal Target
            </button>
          </div>

          {errorMsg && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
              <p className="font-semibold">Submission Error</p>
              <p className="mt-0.5">{errorMsg}</p>
            </div>
          )}

          <div className="pt-2">
            <button
              type="submit"
              disabled={isScanning}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 px-8 py-3.5 text-xs font-bold text-white shadow-xl shadow-sky-500/20 hover:from-sky-400 hover:to-indigo-500 transition-all cursor-pointer disabled:opacity-50"
            >
              {isScanning ? (
                <>
                  <span className="size-4 rounded-full border-2 border-white/20 border-t-white animate-spin" />
                  <span>Executing Multi-Engine Analysis...</span>
                </>
              ) : (
                <>
                  <BoltIcon className="size-4" />
                  <span>Execute Real-Time Scan</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Loading Skeleton */}
      {isScanning && (
        <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-8 shadow-xl text-center space-y-4">
          <div className="mx-auto flex size-14 items-center justify-center rounded-2xl bg-sky-500/10 text-sky-400 border border-sky-500/20">
            <BoltIcon className="size-7 animate-pulse" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Analyzing Target Telemetry</h3>
            <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
              Running IDN homoglyph checks, brand impersonation dictionary matching, Random Forest ML prediction, and policy arbitration...
            </p>
          </div>
        </div>
      )}

      {/* Structured Scan Result Display */}
      {scanResult && decisionMeta && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Prominent Unified Engine Decision Banner */}
          <div
            className={`rounded-2xl border ${decisionMeta.borderColor} ${decisionMeta.bgColor} p-6 shadow-2xl`}
          >
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className={`flex size-3 rounded-full ${decisionMeta.dotColor}`} />
                  <span className="text-xs font-bold uppercase tracking-widest text-slate-300">
                    Unified Decision Engine
                  </span>
                </div>
                <h2 className={`text-3xl font-extrabold tracking-tight ${decisionMeta.textColor}`}>
                  {decisionMeta.label}
                </h2>
                <p className="text-xs text-slate-300 max-w-xl">
                  {scanResult.final_decision === "ALLOW"
                    ? "Heuristics and ML classifier verified no malicious patterns. This URL is safe according to active policy."
                    : scanResult.final_decision === "WARN"
                    ? "Suspicious signals or moderate risk detected. Exercise heightened vigilance before proceeding."
                    : scanResult.final_decision === "BLOCK"
                    ? "Critical phishing vectors or brand spoofing detected. Access is prohibited by zero-trust policy."
                    : "The detection pipeline operated in degraded mode due to engine timeout or partial service failure."}
                </p>
              </div>

              <div className="flex flex-col items-start sm:items-end gap-2">
                <span className="text-[11px] font-mono text-slate-400">
                  {formatDateTime(scanResult.timestamp)}
                </span>
                <button
                  onClick={() => navigate(`/scans/${scanResult.id}`)}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-xs font-semibold text-sky-400 hover:text-sky-300 hover:bg-slate-800 transition-colors"
                >
                  <span>Detailed Audit Report</span>
                  <ArrowRightIcon className="size-3.5" />
                </button>
              </div>
            </div>
          </div>

          {/* Submitted Target URL Bar */}
          <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Analyzed URL:
            </span>
            <span className="font-mono text-xs text-slate-100 break-all bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
              {scanResult.url}
            </span>
          </div>

          {/* Engine Verdict Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Cybersecurity Engine Card */}
            <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-2">
                  <ShieldIcon className="size-5 text-sky-400" />
                  <h3 className="text-sm font-bold text-white">Cybersecurity Rule Engine</h3>
                </div>
                <span className="text-[10px] font-mono uppercase bg-slate-900 px-2 py-0.5 rounded text-sky-400 border border-slate-800">
                  Status: {scanResult.cybersecurity.status || "COMPLETED"}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                  <span className="text-[11px] text-slate-400 block">Rule Verdict</span>
                  <span className="text-sm font-bold text-slate-100 mt-1 block">
                    {scanResult.cybersecurity.verdict || "UNKNOWN"}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                  <span className="text-[11px] text-slate-400 block">Heuristic Risk Score</span>
                  <span className={`text-sm font-bold mt-1 block ${riskMeta?.colorClass}`}>
                    {riskMeta?.score} ({riskMeta?.label})
                  </span>
                </div>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">
                Evaluated against brand spoofing dictionaries, IDN homoglyphs, IP literals, and structural risk thresholds.
              </p>
            </div>

            {/* ML Engine Card */}
            <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-2">
                  <LockIcon className="size-5 text-indigo-400" />
                  <h3 className="text-sm font-bold text-white">Machine Learning Engine</h3>
                </div>
                <span className="text-[10px] font-mono uppercase bg-slate-900 px-2 py-0.5 rounded text-indigo-400 border border-slate-800">
                  Status: {scanResult.machine_learning.status || "COMPLETED"}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                  <span className="text-[11px] text-slate-400 block">Model Prediction</span>
                  <span className="text-sm font-bold text-slate-100 mt-1 block">
                    {scanResult.machine_learning.prediction || "UNKNOWN"}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                  <span className="text-[11px] text-slate-400 block">Raw Probability</span>
                  <span className="text-sm font-mono font-bold text-slate-100 mt-1 block">
                    {scanResult.machine_learning.raw_phishing_probability !== null
                      ? scanResult.machine_learning.raw_phishing_probability.toFixed(4)
                      : "N/A"}
                  </span>
                </div>
              </div>

              {/* Crucial Section 8 Requirement */}
              <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-3 text-[11px] text-amber-300">
                <p className="font-semibold">Model Calibration Notice:</p>
                <p className="mt-0.5 text-amber-200/80">
                  Raw ML phishing probability &mdash; not calibrated.
                </p>
                <span className="inline-block mt-1 font-mono text-[10px] text-slate-400">
                  Calibration Status: {scanResult.machine_learning.is_calibrated ? "Calibrated" : "Uncalibrated (Default)"}
                </span>
              </div>
            </div>
          </div>

          {/* Reasons & Trigger Findings */}
          <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6 shadow-xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <CheckCircleIcon className="size-4 text-sky-400" />
              <span>Diagnostic Findings &amp; Reasons</span>
            </h3>

            {scanResult.reasons && scanResult.reasons.length > 0 ? (
              <ul className="space-y-2">
                {scanResult.reasons.map((reason, idx) => (
                  <li
                    key={idx}
                    className="flex items-start gap-2.5 rounded-xl bg-slate-950/60 border border-slate-800/80 p-3 text-xs text-slate-200"
                  >
                    <span className="mt-0.5 size-1.5 rounded-full bg-sky-400 shrink-0" />
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-slate-400 italic">
                No adverse heuristic risk signals triggered for this URL.
              </p>
            )}

            {scanResult.warnings && scanResult.warnings.length > 0 && (
              <div className="pt-2">
                <h4 className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-2">
                  System Warnings
                </h4>
                <ul className="space-y-1.5">
                  {scanResult.warnings.map((warn, idx) => (
                    <li
                      key={idx}
                      className="rounded-lg bg-amber-500/10 border border-amber-500/30 p-2.5 text-xs text-amber-300"
                    >
                      {warn}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
