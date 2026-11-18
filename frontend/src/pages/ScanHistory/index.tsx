import { useEffect, useState, useMemo } from "react";
import { Link, useNavigate } from "react-router";
import { scansApi } from "@/api/scans";
import type { ScanDecision, ScanRecord } from "@/types/scans";
import {
  BoltIcon,
  SearchIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ArrowRightIcon,
} from "@/icons";
import {
  formatDateTime,
  formatDecision,
  formatRiskScore,
  truncateUrl,
} from "@/utils/formatters";

export default function ScanHistoryPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [hasNext, setHasNext] = useState(false);
  const [hasPrev, setHasPrev] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Filters and search
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedDecision, setSelectedDecision] = useState<string>("ALL");
  const [sortBy, setSortBy] = useState<"newest" | "oldest" | "risk_high" | "risk_low">("newest");

  const navigate = useNavigate();

  const fetchScans = async (page: number) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const data = await scansApi.getScans(page);
      setScans(data.results);
      setTotalCount(data.count);
      setHasNext(Boolean(data.next));
      setHasPrev(Boolean(data.previous));
      setCurrentPage(page);
    } catch {
      setErrorMsg("Failed to retrieve scan history. Please check your network connection.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchScans(currentPage);
  }, [currentPage]);

  // Client-side search and filtering over the retrieved page of records
  const filteredScans = useMemo(() => {
    let result = [...scans];

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      result = result.filter(
        (s) =>
          s.url.toLowerCase().includes(q) ||
          s.final_decision.toLowerCase().includes(q) ||
          (s.machine_learning.prediction &&
            s.machine_learning.prediction.toLowerCase().includes(q))
      );
    }

    if (selectedDecision !== "ALL") {
      result = result.filter((s) => s.final_decision === selectedDecision);
    }

    result.sort((a, b) => {
      if (sortBy === "oldest") {
        return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      }
      if (sortBy === "risk_high") {
        return (b.cybersecurity.risk_score ?? 0) - (a.cybersecurity.risk_score ?? 0);
      }
      if (sortBy === "risk_low") {
        return (a.cybersecurity.risk_score ?? 0) - (b.cybersecurity.risk_score ?? 0);
      }
      // default newest
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });

    return result;
  }, [scans, searchQuery, selectedDecision, sortBy]);

  const totalPages = Math.ceil(totalCount / 20) || 1;

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 rounded-2xl border border-slate-800 bg-[#0B1220] p-6 shadow-xl">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white font-outfit">
            Telemetry Scan History
          </h1>
          <p className="mt-1 text-xs text-slate-400">
            Immutable audit log of all URL security inspections across Unified Engine arbitration pipelines.
          </p>
        </div>

        <Link
          to="/scanner"
          className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 px-4 py-2.5 text-xs font-bold text-white shadow-lg shadow-sky-500/20 hover:from-sky-400 hover:to-indigo-500 transition-all shrink-0"
        >
          <BoltIcon className="size-4" />
          <span>New Inspection</span>
        </Link>
      </div>

      {/* Filter and Search Bar */}
      <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-4 shadow-xl flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Search */}
        <div className="relative w-full md:w-80">
          <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
            <SearchIcon className="size-4" />
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search URLs, domains, or signals..."
            className="w-full h-9 pl-9 pr-3 rounded-xl border border-slate-700 bg-slate-950 text-xs text-white placeholder:text-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          <span className="text-[11px] font-semibold text-slate-400 uppercase">Filter:</span>
          {(["ALL", "ALLOW", "WARN", "BLOCK", "ERROR"] as const).map((dec) => (
            <button
              key={dec}
              onClick={() => setSelectedDecision(dec)}
              className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition-colors cursor-pointer ${
                selectedDecision === dec
                  ? "bg-sky-500 text-white shadow-sm shadow-sky-500/30"
                  : "bg-slate-900 border border-slate-700/80 text-slate-300 hover:bg-slate-800"
              }`}
            >
              {dec}
            </button>
          ))}
        </div>

        {/* Sort Select */}
        <div className="flex items-center gap-2 w-full md:w-auto justify-end">
          <label htmlFor="sort-by-select" className="text-[11px] font-semibold text-slate-400 uppercase">Sort:</label>
          <select
            id="sort-by-select"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
            className="h-9 rounded-xl border border-slate-700 bg-slate-950 px-3 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
          >
            <option value="newest">Newest First</option>
            <option value="oldest">Oldest First</option>
            <option value="risk_high">Risk: High to Low</option>
            <option value="risk_low">Risk: Low to High</option>
          </select>
        </div>
      </div>

      {errorMsg && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-300">
          <p className="font-semibold">{errorMsg}</p>
        </div>
      )}

      {/* Main Table Card */}
      <div className="rounded-2xl border border-slate-800 bg-[#111B2E] shadow-xl overflow-hidden">
        {isLoading ? (
          <div className="py-16 text-center text-xs text-slate-400">
            <span className="inline-block size-6 rounded-full border-2 border-sky-400 border-t-transparent animate-spin mb-3" />
            <p>Fetching paginated audit telemetry...</p>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="py-16 text-center">
            <div className="mx-auto flex size-12 items-center justify-center rounded-2xl bg-slate-900 border border-slate-800 text-slate-400 mb-3">
              <BoltIcon className="size-6 text-sky-400" />
            </div>
            <h4 className="text-sm font-semibold text-slate-200">No Scans Found</h4>
            <p className="text-xs text-slate-400 mt-1">
              {searchQuery || selectedDecision !== "ALL"
                ? "No scans match your current filter parameters."
                : "Your account has no recorded scans yet."}
            </p>
            <div className="mt-4">
              <Link
                to="/scanner"
                className="inline-flex items-center gap-2 rounded-xl bg-sky-500 px-4 py-2 text-xs font-bold text-white hover:bg-sky-400 transition-colors shadow-md shadow-sky-500/20"
              >
                <span>Run a New Scan</span>
              </Link>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-4">Target Destination URL</th>
                  <th className="p-4">Unified Verdict</th>
                  <th className="p-4">Heuristic Risk</th>
                  <th className="p-4">ML Prediction</th>
                  <th className="p-4">Raw ML Prob.</th>
                  <th className="p-4">Timestamp</th>
                  <th className="p-4 text-right">Audit</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {filteredScans.map((scan) => {
                  const decisionMeta = formatDecision(scan.final_decision as ScanDecision);
                  const riskMeta = formatRiskScore(scan.cybersecurity.risk_score);

                  return (
                    <tr
                      key={scan.id}
                      className="hover:bg-slate-800/40 transition-colors"
                    >
                      <td className="p-4 font-mono font-medium max-w-sm truncate text-slate-200">
                        {truncateUrl(scan.url, 50)}
                      </td>
                      <td className="p-4">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[10px] font-bold border ${decisionMeta.badgeClass}`}
                        >
                          <span
                            className={`size-1.5 rounded-full ${decisionMeta.dotColor}`}
                          />
                          {decisionMeta.label}
                        </span>
                      </td>
                      <td className="p-4">
                        <span className={`font-semibold ${riskMeta.colorClass}`}>
                          {riskMeta.score}
                        </span>
                      </td>
                      <td className="p-4">
                        <span className="text-slate-300 font-medium">
                          {scan.machine_learning.prediction || "N/A"}
                        </span>
                      </td>
                      <td className="p-4 font-mono text-slate-400">
                        {scan.machine_learning.raw_phishing_probability !== null
                          ? scan.machine_learning.raw_phishing_probability.toFixed(3)
                          : "N/A"}
                      </td>
                      <td className="p-4 text-slate-400 font-mono text-[11px]">
                        {formatDateTime(scan.timestamp)}
                      </td>
                      <td className="p-4 text-right">
                        <button
                          onClick={() => navigate(`/scans/${scan.id}`)}
                          className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-semibold text-sky-400 hover:bg-slate-800 hover:text-sky-300 transition-colors cursor-pointer"
                        >
                          <span>Report</span>
                          <ArrowRightIcon className="size-3" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Backend Pagination Controls */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-slate-800 px-4 py-3 bg-slate-900/40 text-xs text-slate-400">
          <div>
            Showing Page <span className="font-semibold text-white">{currentPage}</span> of{" "}
            <span className="font-semibold text-white">{totalPages}</span> ({totalCount} total scans)
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => fetchScans(currentPage - 1)}
              disabled={!hasPrev || isLoading}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
            >
              <ChevronLeftIcon className="size-4" />
              <span>Previous</span>
            </button>
            <button
              onClick={() => fetchScans(currentPage + 1)}
              disabled={!hasNext || isLoading}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
            >
              <span>Next</span>
              <ChevronRightIcon className="size-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
