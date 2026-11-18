import { useState } from "react";
import { useTheme } from "@/context/ThemeContext";
import { useAuth } from "@/context/AuthContext";
import { ShieldIcon, GearIcon, SunIcon, MoonIcon, CheckCircleIcon } from "@/icons";

export default function SettingsPage() {
  const { themeMode, setThemeMode } = useTheme();
  const { user } = useAuth();

  const [tableDensity, setTableDensity] = useState<"compact" | "comfortable">("comfortable");
  const [autoRefreshTelemetry, setAutoRefreshTelemetry] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const handleSavePreferences = () => {
    localStorage.setItem("securelens_table_density", tableDensity);
    localStorage.setItem("securelens_auto_refresh", String(autoRefreshTelemetry));
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 2500);
  };

  const apiBaseUrl =
    import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Title */}
      <div className="rounded-2xl border border-slate-800 bg-[#0B1220] p-6 shadow-xl">
        <h1 className="text-2xl font-extrabold tracking-tight text-white font-outfit">
          Platform &amp; Console Settings
        </h1>
        <p className="mt-1 text-xs text-slate-400">
          Configure interface appearance, client display parameters, and inspect active security specifications.
        </p>
      </div>

      {saveSuccess && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircleIcon className="size-4 text-emerald-400" />
          <span>Interface display preferences saved successfully.</span>
        </div>
      )}

      {/* Theme Preferences */}
      <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6 shadow-xl space-y-4">
        <div className="border-b border-slate-800/80 pb-3 flex items-center gap-2">
          <SunIcon className="size-5 text-amber-400" />
          <h2 className="text-sm font-bold text-white">Visual Theme Preference</h2>
        </div>

        <p className="text-xs text-slate-400">
          Select your console theme. SecureLens defaults to an enterprise Dark Navy theme optimized for security operations centers.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-1">
          <button
            type="button"
            onClick={() => setThemeMode("dark")}
            className={`flex flex-col items-start p-4 rounded-xl border text-left transition-all cursor-pointer ${
              themeMode === "dark"
                ? "border-sky-500 bg-sky-500/10 text-white shadow-lg shadow-sky-500/10"
                : "border-slate-800 bg-slate-900/60 text-slate-400 hover:border-slate-700 hover:text-slate-200"
            }`}
          >
            <div className="flex items-center gap-2 mb-2">
              <MoonIcon className="size-4 text-sky-400" />
              <span className="text-xs font-bold text-white">Dark Navy (Recommended)</span>
            </div>
            <span className="text-[11px] text-slate-400">
              High contrast, low eye-strain SOC security palette (#080D19).
            </span>
          </button>

          <button
            type="button"
            onClick={() => setThemeMode("light")}
            className={`flex flex-col items-start p-4 rounded-xl border text-left transition-all cursor-pointer ${
              themeMode === "light"
                ? "border-sky-500 bg-sky-500/10 text-white shadow-lg shadow-sky-500/10"
                : "border-slate-800 bg-slate-900/60 text-slate-400 hover:border-slate-700 hover:text-slate-200"
            }`}
          >
            <div className="flex items-center gap-2 mb-2">
              <SunIcon className="size-4 text-amber-400" />
              <span className="text-xs font-bold text-white">Light Mode</span>
            </div>
            <span className="text-[11px] text-slate-400">
              Clean light surfaces for daytime reporting.
            </span>
          </button>

          <button
            type="button"
            onClick={() => setThemeMode("auto")}
            className={`flex flex-col items-start p-4 rounded-xl border text-left transition-all cursor-pointer ${
              themeMode === "auto"
                ? "border-sky-500 bg-sky-500/10 text-white shadow-lg shadow-sky-500/10"
                : "border-slate-800 bg-slate-900/60 text-slate-400 hover:border-slate-700 hover:text-slate-200"
            }`}
          >
            <div className="flex items-center gap-2 mb-2">
              <GearIcon className="size-4 text-indigo-400" />
              <span className="text-xs font-bold text-white">System Sync</span>
            </div>
            <span className="text-[11px] text-slate-400">
              Automatically match OS dark/light mode preference.
            </span>
          </button>
        </div>
      </div>

      {/* Display Preferences */}
      <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6 shadow-xl space-y-4">
        <div className="border-b border-slate-800/80 pb-3 flex items-center gap-2">
          <GearIcon className="size-5 text-sky-400" />
          <h2 className="text-sm font-bold text-white">Display Preferences</h2>
        </div>

        <div className="space-y-4 text-xs">
          <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div>
              <p className="font-semibold text-slate-200">Table Row Density</p>
              <p className="text-[11px] text-slate-400">
                Adjust vertical spacing for telemetry tables.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setTableDensity("compact")}
                className={`rounded-lg px-3 py-1 text-xs font-semibold cursor-pointer ${
                  tableDensity === "compact"
                    ? "bg-sky-500 text-white"
                    : "bg-slate-800 text-slate-400 hover:text-white"
                }`}
              >
                Compact
              </button>
              <button
                type="button"
                onClick={() => setTableDensity("comfortable")}
                className={`rounded-lg px-3 py-1 text-xs font-semibold cursor-pointer ${
                  tableDensity === "comfortable"
                    ? "bg-sky-500 text-white"
                    : "bg-slate-800 text-slate-400 hover:text-white"
                }`}
              >
                Comfortable
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div>
              <p className="font-semibold text-slate-200">Auto-Refresh Telemetry</p>
              <p className="text-[11px] text-slate-400">
                Periodically fetch fresh scan statistics when dashboard is active.
              </p>
            </div>
            <input
              type="checkbox"
              checked={autoRefreshTelemetry}
              onChange={(e) => setAutoRefreshTelemetry(e.target.checked)}
              className="size-4 rounded border-slate-700 bg-slate-900 text-sky-500 focus:ring-sky-500"
            />
          </div>

          <button
            type="button"
            onClick={handleSavePreferences}
            className="rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 px-5 py-2 text-xs font-bold text-white shadow-md shadow-sky-500/20 hover:from-sky-400 hover:to-indigo-500 transition-all cursor-pointer"
          >
            Save Display Settings
          </button>
        </div>
      </div>

      {/* Security & Backend Contracts Specification */}
      <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6 shadow-xl space-y-4">
        <div className="border-b border-slate-800/80 pb-3 flex items-center gap-2">
          <ShieldIcon className="size-5 text-sky-400" />
          <h2 className="text-sm font-bold text-white">Backend Security &amp; Session Specifications</h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase font-bold text-slate-400">API Gateway Endpoint</span>
            <span className="font-mono text-slate-200 block truncate">{apiBaseUrl}</span>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase font-bold text-slate-400">Active User Context</span>
            <span className="text-slate-200 block font-semibold">{user?.username} ({user?.email})</span>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase font-bold text-slate-400">Access Token Lifetime</span>
            <span className="text-slate-200 block font-semibold">60 Minutes (Rotating Bearer JWT)</span>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase font-bold text-slate-400">Refresh Token Lifetime</span>
            <span className="text-slate-200 block font-semibold">7 Days (Session Storage Isolated)</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 text-[11px] text-slate-400 leading-relaxed">
          <span className="font-semibold text-slate-300 block mb-1">Architecture Disclosure:</span>
          JWT tokens are stored strictly within dedicated in-memory client services and sessionStorage to mitigate long-term persistent disk exposure. Automatic token refresh is coordinated through promise-queue mutex locks to eliminate duplicate refresh requests.
        </div>
      </div>
    </div>
  );
}
