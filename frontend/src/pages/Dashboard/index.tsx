import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router";
import Chart from "react-apexcharts";
import { dashboardApi } from "@/api/dashboard";
import { scansApi } from "@/api/scans";
import { useAuth } from "@/context/AuthContext";
import type { DashboardStats } from "@/types/dashboard";
import type { ScanRecord } from "@/types/scans";
import {
  ShieldIcon,
  BoltIcon,
  CheckCircleIcon,
  OctagonAlertIcon,
  TableIcon,
  ArrowRightIcon,
} from "@/icons";
import {
  formatDateTime,
  formatDecision,
  formatRiskScore,
  truncateUrl,
} from "@/utils/formatters";

export default function DashboardPage() {
  const { user } = useAuth();
  const navigate = useNavigate();

  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentScans, setRecentScans] = useState<ScanRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    async function loadDashboardData() {
      setIsLoading(true);
      setErrorMsg(null);
      try {
        const [statsData, scansData] = await Promise.all([
          dashboardApi.getStats(),
          scansApi.getScans(1),
        ]);
        if (isMounted) {
          setStats(statsData);
          setRecentScans(scansData.results.slice(0, 5));
        }
      } catch {
        if (isMounted) {
          setErrorMsg(
            "Failed to load real-time telemetry. Please check API server availability."
          );
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    loadDashboardData();

    return () => {
      isMounted = false;
    };
  }, []);

  const totalScans = stats?.total_scans ?? 0;
  const totalAllow = stats?.total_allow ?? 0;
  const totalWarn = stats?.total_warn ?? 0;
  const totalBlock = stats?.total_block ?? 0;
  const totalError = stats?.total_error ?? 0;

  // Real data for Donut Chart
  const chartSeries = [totalAllow, totalWarn, totalBlock, totalError];
  const chartOptions: ApexCharts.ApexOptions = {
    chart: {
      type: "donut",
      background: "transparent",
      fontFamily: "Outfit, sans-serif",
    },
    labels: ["Safe (ALLOW)", "Suspicious (WARN)", "Phishing (BLOCK)", "Degraded (ERROR)"],
    colors: ["#22C55E", "#F59E0B", "#EF4444", "#64748B"],
    stroke: {
      show: true,
      colors: ["#111B2E"],
      width: 2,
    },
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      labels: {
        colors: "#94A3B8",
      },
      itemMargin: {
        horizontal: 10,
        vertical: 4,
      },
    },
    tooltip: {
      theme: "dark",
      y: {
        formatter: (val) => `${val} URLs`,
      },
    },
    plotOptions: {
      pie: {
        donut: {
          size: "72%",
          labels: {
            show: true,
            name: {
              show: true,
              color: "#94A3B8",
              fontSize: "12px",
            },
            value: {
              show: true,
              color: "#F8FAFC",
              fontSize: "20px",
              fontWeight: 700,
              formatter: () => `${totalScans}`,
            },
            total: {
              show: true,
              label: "Total Scans",
              color: "#94A3B8",
              formatter: () => `${totalScans}`,
            },
          },
        },
      },
    },
  };

  // Bar chart options comparing decisions
  const barSeries = [
    {
      name: "Total Verdicts",
      data: [totalAllow, totalWarn, totalBlock, totalError],
    },
  ];
  const barOptions: ApexCharts.ApexOptions = {
    chart: {
      type: "bar",
      background: "transparent",
      fontFamily: "Outfit, sans-serif",
      toolbar: { show: false },
    },
    plotOptions: {
      bar: {
        borderRadius: 6,
        columnWidth: "40%",
        distributed: true,
      },
    },
    colors: ["#22C55E", "#F59E0B", "#EF4444", "#64748B"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      show: false,
    },
    xaxis: {
      categories: ["ALLOW", "WARN", "BLOCK", "ERROR"],
      labels: {
        style: {
          colors: "#94A3B8",
          fontSize: "11px",
          fontWeight: 600,
        },
      },
      axisBorder: { show: false },
      axisTicks: { show: false },
    },
    yaxis: {
      labels: {
        style: {
          colors: "#94A3B8",
          fontSize: "11px",
        },
      },
    },
    grid: {
      borderColor: "#1E293B",
      strokeDashArray: 3,
    },
    tooltip: {
      theme: "dark",
      y: {
        formatter: (val) => `${val} URLs`,
      },
    },
  };

  const currentDate = new Date().toLocaleDateString("en-US", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  return (
    <div className="space-y-6">
      {/* Top Banner & Welcome Section */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 rounded-2xl border border-slate-800 bg-[#0B1220] p-6 shadow-xl">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex size-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-semibold uppercase tracking-wider text-sky-400">
              Security Operations Center
            </span>
          </div>
          <h1 className="mt-1 text-2xl font-extrabold tracking-tight text-white font-outfit sm:text-3xl">
            Welcome back, {user?.username || "Analyst"}
          </h1>
          <p className="mt-1 text-xs text-slate-400">{currentDate}</p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/scanner"
            className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 px-4 py-2.5 text-xs font-bold text-white shadow-lg shadow-sky-500/20 hover:from-sky-400 hover:to-indigo-500 transition-all"
          >
            <BoltIcon className="size-4" />
            <span>Launch URL Scanner</span>
          </Link>
          <Link
            to="/scans"
            className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/60 px-4 py-2.5 text-xs font-semibold text-slate-200 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <TableIcon className="size-4" />
            <span>View All Scans</span>
          </Link>
        </div>
      </div>

      {errorMsg && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-300">
          <p className="font-semibold">{errorMsg}</p>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        {/* Total Scans */}
        <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">Total Scans</span>
            <div className="flex size-8 items-center justify-center rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <BoltIcon className="size-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-2xl font-bold text-white">
              {isLoading ? "-" : totalScans}
            </h3>
            <span className="text-[11px] text-slate-400 mt-0.5 block">
              {stats?.recent_scans_count ?? 0} in past 24h
            </span>
          </div>
        </div>

        {/* Safe URLs (ALLOW) */}
        <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">Safe (ALLOW)</span>
            <div className="flex size-8 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <CheckCircleIcon className="size-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-2xl font-bold text-emerald-400">
              {isLoading ? "-" : totalAllow}
            </h3>
            <span className="text-[11px] text-slate-400 mt-0.5 block">
              {totalScans > 0 ? `${((totalAllow / totalScans) * 100).toFixed(0)}% of total` : "0% of total"}
            </span>
          </div>
        </div>

        {/* Suspicious URLs (WARN) */}
        <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">Suspicious (WARN)</span>
            <div className="flex size-8 items-center justify-center rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <OctagonAlertIcon className="size-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-2xl font-bold text-amber-400">
              {isLoading ? "-" : totalWarn}
            </h3>
            <span className="text-[11px] text-slate-400 mt-0.5 block">
              Heuristic flags triggered
            </span>
          </div>
        </div>

        {/* Blocked URLs (BLOCK) */}
        <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">Blocked (PHISHING)</span>
            <div className="flex size-8 items-center justify-center rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <ShieldIcon className="size-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-2xl font-bold text-rose-400">
              {isLoading ? "-" : totalBlock}
            </h3>
            <span className="text-[11px] text-slate-400 mt-0.5 block">
              Threat vectors mitigated
            </span>
          </div>
        </div>

        {/* Error Scans (ERROR) */}
        <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">Degraded (ERROR)</span>
            <div className="flex size-8 items-center justify-center rounded-lg bg-slate-500/10 text-slate-400 border border-slate-500/20">
              <ShieldIcon className="size-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-2xl font-bold text-slate-300">
              {isLoading ? "-" : totalError}
            </h3>
            <span className="text-[11px] text-slate-400 mt-0.5 block">
              Safe failover handling
            </span>
          </div>
        </div>
      </div>

      {/* Charts & Engine Health Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Decision Breakdown (Donut) */}
        <div className="lg:col-span-5 rounded-2xl border border-slate-800 bg-[#111B2E] p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
              <h2 className="text-sm font-bold text-white">Decision Distribution</h2>
              <span className="text-[11px] text-slate-400">Authenticated Telemetry</span>
            </div>
            <p className="mt-2 text-xs text-slate-400">
              Breakdown of all processed URLs across Unified Engine arbitration categories.
            </p>
          </div>

          <div className="py-6 flex items-center justify-center">
            {totalScans === 0 ? (
              <div className="text-center py-8">
                <p className="text-xs text-slate-400">No telemetry recorded yet.</p>
                <Link
                  to="/scanner"
                  className="mt-3 inline-flex items-center gap-1.5 text-xs text-sky-400 hover:underline"
                >
                  <span>Submit your first scan</span>
                  <ArrowRightIcon className="size-3" />
                </Link>
              </div>
            ) : (
              <Chart
                options={chartOptions}
                series={chartSeries}
                type="donut"
                width={320}
              />
            )}
          </div>

          <div className="border-t border-slate-800/80 pt-3 text-[11px] text-slate-400 flex justify-between">
            <span>Latest Scan:</span>
            <span className="font-mono text-slate-300">
              {formatDateTime(stats?.latest_scan_timestamp)}
            </span>
          </div>
        </div>

        {/* Verdict Distribution (Bar Chart) & Engine Status */}
        <div className="lg:col-span-7 space-y-6">
          <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
              <h2 className="text-sm font-bold text-white">Detection Trends by Verdict</h2>
              <span className="text-[11px] text-slate-400">Aggregate Scan Metrics</span>
            </div>
            <div className="pt-4">
              {totalScans === 0 ? (
                <div className="h-56 flex items-center justify-center text-xs text-slate-400">
                  Telemetry awaiting first URL analysis
                </div>
              ) : (
                <Chart
                  options={barOptions}
                  series={barSeries}
                  type="bar"
                  height={220}
                />
              )}
            </div>
          </div>

          {/* Engine Health Status Widget */}
          <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-5 shadow-xl">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
              Detection Engines Status
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                <span className="text-slate-300 font-medium">Cybersecurity Rule Engine</span>
                <span className="rounded-md bg-emerald-500/15 px-2 py-0.5 text-[10px] font-bold text-emerald-400 border border-emerald-500/30">
                  HEALTHY
                </span>
              </div>
              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                <span className="text-slate-300 font-medium">ML Inference Engine</span>
                <span className="rounded-md bg-emerald-500/15 px-2 py-0.5 text-[10px] font-bold text-emerald-400 border border-emerald-500/30">
                  ONLINE
                </span>
              </div>
              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                <span className="text-slate-300 font-medium">Unified Decision Policy</span>
                <span className="rounded-md bg-emerald-500/15 px-2 py-0.5 text-[10px] font-bold text-emerald-400 border border-emerald-500/30">
                  ENFORCED
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans Table Section */}
      <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6 shadow-xl">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-4">
          <div>
            <h2 className="text-base font-bold text-white">Recent Telemetry Scans</h2>
            <p className="text-xs text-slate-400">
              Latest URL assessments conducted by your analyst account.
            </p>
          </div>
          <Link
            to="/scans"
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-sky-400 hover:text-sky-300 transition-colors"
          >
            <span>Complete History</span>
            <ArrowRightIcon className="size-3.5" />
          </Link>
        </div>

        {isLoading ? (
          <div className="py-12 text-center text-xs text-slate-400">
            <span className="inline-block size-6 rounded-full border-2 border-sky-400 border-t-transparent animate-spin mb-2" />
            <p>Loading real-time scan records...</p>
          </div>
        ) : recentScans.length === 0 ? (
          <div className="py-12 text-center">
            <div className="mx-auto flex size-12 items-center justify-center rounded-2xl bg-slate-900 border border-slate-800 text-slate-400 mb-3">
              <BoltIcon className="size-6 text-sky-400" />
            </div>
            <h4 className="text-sm font-semibold text-slate-200">No Scans Recorded</h4>
            <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
              You haven't scanned any target URLs yet. Run your first threat scan now to populate your dashboard.
            </p>
            <div className="mt-4">
              <Link
                to="/scanner"
                className="inline-flex items-center gap-2 rounded-xl bg-sky-500 px-4 py-2 text-xs font-bold text-white hover:bg-sky-400 transition-colors shadow-md shadow-sky-500/20"
              >
                <BoltIcon className="size-4" />
                <span>Scan a URL</span>
              </Link>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] tracking-wider">
                <tr>
                  <th className="p-3">Target URL</th>
                  <th className="p-3">Final Decision</th>
                  <th className="p-3">Cyber Risk</th>
                  <th className="p-3">ML Prediction</th>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {recentScans.map((scan) => {
                  const decisionMeta = formatDecision(scan.final_decision);
                  const riskMeta = formatRiskScore(scan.cybersecurity.risk_score);

                  return (
                    <tr
                      key={scan.id}
                      className="hover:bg-slate-800/40 transition-colors"
                    >
                      <td className="p-3 font-mono font-medium max-w-xs truncate text-slate-200">
                        {truncateUrl(scan.url, 45)}
                      </td>
                      <td className="p-3">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[10px] font-bold border ${decisionMeta.badgeClass}`}
                        >
                          <span
                            className={`size-1.5 rounded-full ${decisionMeta.dotColor}`}
                          />
                          {decisionMeta.label}
                        </span>
                      </td>
                      <td className="p-3">
                        <span className={`font-semibold ${riskMeta.colorClass}`}>
                          {riskMeta.score}
                        </span>
                      </td>
                      <td className="p-3">
                        <span className="text-slate-300">
                          {scan.machine_learning.prediction || "N/A"}
                        </span>
                      </td>
                      <td className="p-3 text-slate-400 font-mono text-[11px]">
                        {formatDateTime(scan.timestamp)}
                      </td>
                      <td className="p-3 text-right">
                        <button
                          onClick={() => navigate(`/scans/${scan.id}`)}
                          className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 text-[11px] font-semibold text-sky-400 hover:bg-slate-800 hover:text-sky-300 transition-colors cursor-pointer"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
