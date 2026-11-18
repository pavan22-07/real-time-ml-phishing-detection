import { Link } from "react-router";
import { ShieldIcon, ChevronLeftIcon, LayoutGridIcon } from "@/icons";

export default function NotFoundPage() {
  return (
    <div className="min-h-screen bg-[#080D19] text-[#F8FAFC] flex flex-col items-center justify-center p-6 text-center">
      <div className="relative mb-6">
        <div className="flex size-24 items-center justify-center rounded-3xl bg-slate-900/80 border border-slate-800 text-sky-400 shadow-2xl">
          <ShieldIcon className="size-12 text-sky-400" />
        </div>
        <span className="absolute -top-2 -right-2 rounded-lg bg-rose-500/20 border border-rose-500/40 px-2 py-0.5 text-xs font-mono font-bold text-rose-400">
          404
        </span>
      </div>

      <h1 className="text-3xl font-extrabold tracking-tight text-white font-outfit sm:text-4xl">
        Page Not Found
      </h1>
      <p className="mt-2 text-xs sm:text-sm text-slate-400 max-w-md mx-auto leading-relaxed">
        The requested endpoint or threat inspection route does not exist within the SecureLens console routing table.
      </p>

      <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-3">
        <Link
          to="/dashboard"
          className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 px-6 py-3 text-xs font-bold text-white shadow-lg shadow-sky-500/20 hover:from-sky-400 hover:to-indigo-500 transition-all"
        >
          <LayoutGridIcon className="size-4" />
          <span>Return to Dashboard</span>
        </Link>
        <Link
          to="/"
          className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900/60 px-6 py-3 text-xs font-semibold text-slate-200 hover:bg-slate-800 hover:text-white transition-colors"
        >
          <ChevronLeftIcon className="size-4" />
          <span>Product Overview</span>
        </Link>
      </div>

      <div className="mt-16 text-xs text-slate-400">
        SecureLens Real-Time ML-Based Phishing Detection System
      </div>
    </div>
  );
}
