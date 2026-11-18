import { Link } from "react-router";
import { useAuth } from "@/context/AuthContext";
import {
  ShieldIcon,
  BoltIcon,
  CheckCircleIcon,
  LockIcon,
  LayoutGridIcon,
  ArrowRightIcon,
  TableIcon,
  OctagonAlertIcon,
} from "@/icons";

export default function LandingPage() {
  const { isAuthenticated } = useAuth();

  return (
    <div className="min-h-screen bg-[#080D19] text-[#F8FAFC]">
      {/* Top Navbar */}
      <nav className="sticky top-0 z-40 border-b border-slate-800/80 bg-[#080D19]/90 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <Link to="/" className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-xl bg-gradient-to-br from-sky-500/30 to-indigo-500/20 text-sky-400 border border-sky-500/40 shadow-lg shadow-sky-500/10">
              <ShieldIcon className="size-6 text-sky-400" />
            </div>
            <div className="flex flex-col">
              <span className="text-lg font-extrabold tracking-tight text-white font-outfit">
                Secure<span className="text-sky-400">Lens</span>
              </span>
              <span className="text-[9px] font-medium tracking-wide text-slate-400 uppercase">
                Phishing Detection System
              </span>
            </div>
          </Link>

          <div className="hidden md:flex items-center gap-8 text-xs font-semibold text-slate-300">
            <a href="#how-it-works" className="hover:text-sky-400 transition-colors">
              How It Works
            </a>
            <a href="#features" className="hover:text-sky-400 transition-colors">
              Features
            </a>
            <a href="#architecture" className="hover:text-sky-400 transition-colors">
              Architecture
            </a>
            <a href="#security" className="hover:text-sky-400 transition-colors">
              Security & Privacy
            </a>
          </div>

          <div className="flex items-center gap-3">
            {isAuthenticated ? (
              <Link
                to="/dashboard"
                className="inline-flex items-center gap-2 rounded-xl bg-sky-500 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-400 transition-colors shadow-md shadow-sky-500/20"
              >
                <LayoutGridIcon className="size-4" />
                <span>Go to Dashboard</span>
              </Link>
            ) : (
              <>
                <Link
                  to="/login"
                  className="rounded-xl px-3 py-2 text-xs font-semibold text-slate-300 hover:text-white transition-colors"
                >
                  Log In
                </Link>
                <Link
                  to="/register"
                  className="inline-flex items-center gap-1.5 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 px-4 py-2 text-xs font-semibold text-white shadow-md shadow-sky-500/20 hover:from-sky-400 hover:to-indigo-500 transition-all"
                >
                  <span>Get Started</span>
                  <ArrowRightIcon className="size-3.5" />
                </Link>
              </>
            )}
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative overflow-hidden pt-16 pb-20 sm:pt-24 sm:pb-28">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 text-center">
          <div className="inline-flex items-center gap-2 rounded-full border border-sky-500/30 bg-sky-500/10 px-3.5 py-1 text-xs font-semibold text-sky-300 mb-6">
            <span className="flex size-2 rounded-full bg-sky-400 animate-pulse" />
            Dual-Engine Zero-Trust Phishing Prevention Platform
          </div>

          <h1 className="text-4xl font-extrabold tracking-tight text-white sm:text-6xl max-w-4xl mx-auto leading-tight">
            Stop Phishing Before It Reaches You.
          </h1>

          <p className="mt-6 text-base sm:text-lg text-slate-300 max-w-2xl mx-auto leading-relaxed">
            SecureLens combines deterministic cybersecurity heuristic rules with machine learning inference to inspect suspicious URLs in real time. Defend against IDN homoglyphs, brand spoofing, and stealthy credential harvesting attacks.
          </p>

          <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              to={isAuthenticated ? "/scanner" : "/register"}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 px-6 py-3.5 text-sm font-bold text-white shadow-xl shadow-sky-500/25 hover:from-sky-400 hover:to-indigo-500 transition-all"
            >
              <BoltIcon className="size-5" />
              <span>Start Scanning</span>
            </Link>
            <a
              href="#features"
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900/60 px-6 py-3.5 text-sm font-bold text-slate-200 hover:bg-slate-800 hover:text-white transition-colors"
            >
              <span>Explore Features</span>
            </a>
          </div>

          {/* Interactive Product Preview Card */}
          <div className="mt-14 max-w-5xl mx-auto rounded-2xl border border-slate-800 bg-[#0B1220] p-4 sm:p-6 shadow-2xl shadow-black/80 text-left">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-4 mb-5">
              <div className="flex items-center gap-2">
                <span className="size-3 rounded-full bg-rose-500/80" />
                <span className="size-3 rounded-full bg-amber-500/80" />
                <span className="size-3 rounded-full bg-emerald-500/80" />
                <span className="ml-2 text-xs font-mono text-slate-400">
                  console.securelens.local &mdash; threat-inspector
                </span>
              </div>
              <span className="rounded-md bg-emerald-500/10 px-2 py-0.5 text-[11px] font-semibold text-emerald-400 border border-emerald-500/20">
                Decision Engine Live
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 rounded-xl bg-[#111B2E] border border-slate-800">
                <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                  <span>Target URL Sample</span>
                  <span className="text-[10px] text-sky-400 font-mono">HTTPS</span>
                </div>
                <div className="text-xs font-mono text-slate-200 break-all bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
                  https://paypa1-security-verify.com/login
                </div>
                <div className="mt-3 flex items-center justify-between text-xs">
                  <span className="text-slate-400">Cybersecurity Risk:</span>
                  <span className="font-bold text-rose-400">85/100 (High)</span>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#111B2E] border border-slate-800">
                <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                  <span>ML Inference Signal</span>
                  <span className="text-[10px] text-indigo-400 font-mono">Random Forest</span>
                </div>
                <div className="space-y-1.5 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-400">ML Prediction:</span>
                    <span className="font-semibold text-rose-400">Phishing</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-400">Raw ML Probability:</span>
                    <span className="font-mono text-slate-200">0.942</span>
                  </div>
                </div>
                <div className="mt-2 text-[10px] text-slate-400 italic">
                  *Raw ML probability &mdash; not calibrated.
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#111B2E] border border-rose-500/30 bg-rose-500/5">
                <div className="flex items-center justify-between text-xs text-rose-300 mb-2">
                  <span>Unified Verdict</span>
                  <OctagonAlertIcon className="size-4 text-rose-400" />
                </div>
                <div className="bg-slate-950/80 p-2.5 rounded-lg border border-rose-500/40 text-center">
                  <span className="text-sm font-extrabold text-rose-400 uppercase tracking-widest">
                    BLOCK (PHISHING)
                  </span>
                  <p className="text-[10px] text-slate-400 mt-1">
                    Zero-Trust Policy Enforced
                  </p>
                </div>
                <div className="mt-3 text-[11px] text-slate-300">
                  Detected brand impersonation targeting PayPal &amp; suspicious TLD.
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="py-20 border-t border-slate-800 bg-[#0B1220]/60">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto">
            <h2 className="text-xs font-bold uppercase tracking-widest text-sky-400">
              Pipeline Operation
            </h2>
            <p className="mt-2 text-3xl font-extrabold text-white sm:text-4xl">
              How SecureLens Detects Malicious URLs
            </p>
            <p className="mt-4 text-sm text-slate-400">
              Every submitted URL passes through four synchronized detection stages before reaching an authoritative decision.
            </p>
          </div>

          <div className="mt-16 grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6">
              <div className="flex size-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-400 font-bold text-sm mb-4 border border-sky-500/20">
                01
              </div>
              <h3 className="text-base font-bold text-white">URL Telemetry & Parsing</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Normalizes URL schemas, extracts registered domains, validates URI syntax, and performs initial structure auditing.
              </p>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6">
              <div className="flex size-10 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-400 font-bold text-sm mb-4 border border-indigo-500/20">
                02
              </div>
              <h3 className="text-base font-bold text-white">Cybersecurity Rule Engine</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Applies deterministic checks: brand impersonation dictionaries, IDN homoglyph Cyrillic spoofing, and IP-literal hostnames.
              </p>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6">
              <div className="flex size-10 items-center justify-center rounded-xl bg-purple-500/10 text-purple-400 font-bold text-sm mb-4 border border-purple-500/20">
                03
              </div>
              <h3 className="text-base font-bold text-white">Machine Learning Predictor</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Extracts 30+ lexical and structural features into an optimized Random Forest classifier to yield a raw phishing probability score.
              </p>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6 border-sky-500/30">
              <div className="flex size-10 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-400 font-bold text-sm mb-4 border border-emerald-500/20">
                04
              </div>
              <h3 className="text-base font-bold text-white">Unified Decision Policy</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Arbitrates heuristic scores against ML predictions to synthesize the final ALLOW, WARN, BLOCK, or ERROR verdict with audit reasons.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Key Features Section */}
      <section id="features" className="py-20 border-t border-slate-800">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <h2 className="text-xs font-bold uppercase tracking-widest text-sky-400">
              Enterprise Defense
            </h2>
            <p className="mt-2 text-3xl font-extrabold text-white sm:text-4xl">
              Engineered for Real-World Threat Prevention
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-6 rounded-2xl border border-slate-800 bg-[#111B2E]">
              <div className="flex size-10 items-center justify-center rounded-xl bg-sky-500/20 text-sky-400 mb-4 border border-sky-500/30">
                <ShieldIcon className="size-5" />
              </div>
              <h4 className="text-base font-bold text-white">Brand Impersonation Guard</h4>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Flags deceptive keywords, lookalike domains, and subtle sub-domain combinations targeting high-value financial and SaaS brands.
              </p>
            </div>

            <div className="p-6 rounded-2xl border border-slate-800 bg-[#111B2E]">
              <div className="flex size-10 items-center justify-center rounded-xl bg-indigo-500/20 text-indigo-400 mb-4 border border-indigo-500/30">
                <LockIcon className="size-5" />
              </div>
              <h4 className="text-base font-bold text-white">IDN Homoglyph Detection</h4>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Detects mixed-script attacks where Unicode glyphs visually mirror Latin characters to deceive unsuspecting users.
              </p>
            </div>

            <div className="p-6 rounded-2xl border border-slate-800 bg-[#111B2E]">
              <div className="flex size-10 items-center justify-center rounded-xl bg-purple-500/20 text-purple-400 mb-4 border border-purple-500/30">
                <BoltIcon className="size-5" />
              </div>
              <h4 className="text-base font-bold text-white">Zero-Day Lexical Analysis</h4>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Machine learning model detects newly registered malicious domains that do not yet appear in static blacklist feeds.
              </p>
            </div>

            <div className="p-6 rounded-2xl border border-slate-800 bg-[#111B2E]">
              <div className="flex size-10 items-center justify-center rounded-xl bg-emerald-500/20 text-emerald-400 mb-4 border border-emerald-500/30">
                <CheckCircleIcon className="size-5" />
              </div>
              <h4 className="text-base font-bold text-white">Zero-Trust Decision Policy</h4>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                No single engine possesses unchecked authority. High-risk cybersecurity findings trigger strict blocking even if ML is uncertain.
              </p>
            </div>

            <div className="p-6 rounded-2xl border border-slate-800 bg-[#111B2E]">
              <div className="flex size-10 items-center justify-center rounded-xl bg-amber-500/20 text-amber-400 mb-4 border border-amber-500/30">
                <OctagonAlertIcon className="size-5" />
              </div>
              <h4 className="text-base font-bold text-white">Degraded Mode Resilience</h4>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                If an underlying engine encounters a failure, the system falls back safely to degraded mode rather than throwing silent crashes.
              </p>
            </div>

            <div className="p-6 rounded-2xl border border-slate-800 bg-[#111B2E]">
              <div className="flex size-10 items-center justify-center rounded-xl bg-sky-500/20 text-sky-400 mb-4 border border-sky-500/30">
                <TableIcon className="size-5" />
              </div>
              <h4 className="text-base font-bold text-white">Complete Audit Logs</h4>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Every scan is recorded with full engine timestamps, raw feature telemetry, and actionable reasoning for security compliance.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Detection Architecture Section */}
      <section id="architecture" className="py-20 border-t border-slate-800 bg-[#0B1220]/60">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <h2 className="text-xs font-bold uppercase tracking-widest text-sky-400">
              System Architecture
            </h2>
            <p className="mt-2 text-3xl font-extrabold text-white sm:text-4xl">
              Multi-Layered Detection Hierarchy
            </p>
          </div>

          <div className="max-w-4xl mx-auto rounded-2xl border border-slate-800 bg-[#111B2E] p-6 sm:p-8">
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 rounded-xl bg-slate-900/80 border border-slate-800">
                <div>
                  <h4 className="text-sm font-bold text-sky-300">Layer 1: URL Normalization &amp; Heuristics</h4>
                  <p className="text-xs text-slate-400 mt-1">
                    Canonicalization, length thresholds, entropy calculation, and structural token parsing.
                  </p>
                </div>
                <span className="mt-2 sm:mt-0 rounded-lg bg-sky-500/15 px-3 py-1 text-[11px] font-mono text-sky-400 border border-sky-500/30">
                  Pre-processing
                </span>
              </div>

              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 rounded-xl bg-slate-900/80 border border-slate-800">
                <div>
                  <h4 className="text-sm font-bold text-indigo-300">Layer 2: Dual Inference Engines</h4>
                  <p className="text-xs text-slate-400 mt-1">
                    Concurrent evaluation: Rule Engine risk score (0-100) and ML Random Forest inference probability.
                  </p>
                </div>
                <span className="mt-2 sm:mt-0 rounded-lg bg-indigo-500/15 px-3 py-1 text-[11px] font-mono text-indigo-400 border border-indigo-500/30">
                  Parallel Execution
                </span>
              </div>

              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 rounded-xl bg-slate-900/80 border border-slate-800">
                <div>
                  <h4 className="text-sm font-bold text-emerald-300">Layer 3: Unified Policy Arbitration</h4>
                  <p className="text-xs text-slate-400 mt-1">
                    Definitive decision matrices determine ALLOW, WARN, BLOCK, or ERROR verdict with explicit explanation strings.
                  </p>
                </div>
                <span className="mt-2 sm:mt-0 rounded-lg bg-emerald-500/15 px-3 py-1 text-[11px] font-mono text-emerald-400 border border-emerald-500/30">
                  Policy Arbitration
                </span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Security and Privacy Section */}
      <section id="security" className="py-20 border-t border-slate-800">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 text-center max-w-3xl">
          <h2 className="text-xs font-bold uppercase tracking-widest text-sky-400">
            Privacy &amp; Compliance
          </h2>
          <p className="mt-2 text-3xl font-extrabold text-white sm:text-4xl">
            Enterprise Security Standards
          </p>
          <p className="mt-4 text-xs sm:text-sm text-slate-300 leading-relaxed">
            SecureLens isolates scan audit records strictly to authenticated user boundaries. Passwords are never stored in plain text, API endpoints enforce rate-limited scoped throttling, and unhandled server errors are sanitized to prevent internal trace exposure.
          </p>

          <div className="mt-10">
            <Link
              to={isAuthenticated ? "/scanner" : "/register"}
              className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 px-8 py-3.5 text-sm font-bold text-white shadow-xl shadow-sky-500/25 hover:from-sky-400 hover:to-indigo-500 transition-all"
            >
              <span>Protect Your Organization Today</span>
              <ArrowRightIcon className="size-4" />
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-[#0B1220] py-12">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <div className="flex size-8 items-center justify-center rounded-lg bg-sky-500/20 text-sky-400 border border-sky-500/30">
              <ShieldIcon className="size-4 text-sky-400" />
            </div>
            <span className="text-sm font-bold text-white">
              Secure<span className="text-sky-400">Lens</span>
            </span>
          </div>

          <p className="text-xs text-slate-400 text-center">
            &copy; {new Date().getFullYear()} SecureLens Phishing Detection &amp; Prevention System. Built for security operations teams.
          </p>

          <div className="flex items-center gap-4 text-xs text-slate-400">
            <Link to="/login" className="hover:text-white transition-colors">
              Sign In
            </Link>
            <span>&bull;</span>
            <Link to="/register" className="hover:text-white transition-colors">
              Register
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
