import { Link, Outlet } from "react-router";
import { ShieldIcon } from "@/icons";

export default function AuthLayout() {
  return (
    <div className="flex min-h-screen bg-[#080D19] text-[#F8FAFC]">
      {/* Form Section */}
      <div className="flex flex-1 flex-col justify-center px-4 py-12 sm:px-6 lg:flex-none lg:w-1/2 xl:w-5/12">
        <div className="mx-auto w-full max-w-sm lg:w-96">
          <div className="mb-8">
            <Link to="/" className="inline-flex items-center gap-3 group">
              <div className="flex size-10 items-center justify-center rounded-xl bg-gradient-to-br from-sky-500/30 to-indigo-500/20 text-sky-400 border border-sky-500/40 shadow-lg shadow-sky-500/10 group-hover:border-sky-400 transition-colors">
                <ShieldIcon className="size-6 text-sky-400" />
              </div>
              <div className="flex flex-col">
                <span className="text-xl font-extrabold tracking-tight text-white font-outfit">
                  Secure<span className="text-sky-400">Lens</span>
                </span>
                <span className="text-[10px] font-medium tracking-wide text-slate-400 uppercase">
                  Phishing Prevention System
                </span>
              </div>
            </Link>
          </div>

          <Outlet />
        </div>
      </div>

      {/* Security Showcase Hero Section (Desktop) */}
      <div className="relative hidden w-0 flex-1 lg:block bg-[#0B1220] border-l border-slate-800">
        <div className="absolute inset-0 flex flex-col justify-between p-12 bg-radial from-sky-500/5 via-transparent to-transparent">
          <div className="flex items-center justify-between">
            <div className="inline-flex items-center gap-2 rounded-full border border-sky-500/30 bg-sky-500/10 px-3 py-1 text-xs font-semibold text-sky-300">
              <span className="flex size-1.5 rounded-full bg-sky-400 animate-ping" />
              Unified Phishing Defense Architecture
            </div>
            <span className="text-xs text-slate-400">SOC Grade Detection</span>
          </div>

          <div className="space-y-6 max-w-lg">
            <h2 className="text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
              Stop Phishing Before It Reaches Your Network.
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              SecureLens fuses deterministic cybersecurity rule engines with a high-accuracy Random Forest classifier. Real-time URL threat scoring, IDN homoglyph identification, and zero-trust decision policies protect your enterprise from zero-day credential harvesting.
            </p>

            <div className="grid grid-cols-2 gap-4 pt-4">
              <div className="rounded-xl border border-slate-800 bg-[#111B2E]/90 p-4">
                <div className="text-xs font-semibold text-sky-400">Cybersecurity Engine</div>
                <div className="text-xs text-slate-400 mt-1">Rule-based brand spoofing, TLD, & IDN detection</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-[#111B2E]/90 p-4">
                <div className="text-xs font-semibold text-indigo-400">Machine Learning</div>
                <div className="text-xs text-slate-400 mt-1">Lexical and structural threat vector inference</div>
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between border-t border-slate-800/80 pt-6 text-xs text-slate-400">
            <span>219 Verified Engine Regression Tests</span>
            <span>REST API &bull; JWT Authentication</span>
          </div>
        </div>
      </div>
    </div>
  );
}
