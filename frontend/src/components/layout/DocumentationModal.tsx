import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ShieldIcon, LockIcon, BoltIcon, CheckCircleIcon, XIcon } from "@/icons";

interface DocumentationModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function DocumentationModal({ isOpen, onClose }: DocumentationModalProps) {
  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto bg-[#111B2E] border border-slate-700 text-slate-100 p-6 rounded-2xl shadow-2xl">
        <DialogHeader className="flex flex-row items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-xl bg-sky-500/20 text-sky-400 border border-sky-500/30">
              <ShieldIcon className="size-5" />
            </div>
            <div>
              <DialogTitle className="text-lg font-bold text-slate-100">
                SecureLens System Architecture & Documentation
              </DialogTitle>
              <p className="text-xs text-slate-400">
                Real-Time ML-Based Phishing Detection & Prevention System
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <XIcon className="size-5" />
          </button>
        </DialogHeader>

        <div className="space-y-6 pt-4 text-sm text-slate-300">
          <section className="space-y-2">
            <h4 className="flex items-center gap-2 font-semibold text-sky-400 text-sm">
              <BoltIcon className="size-4" />
              1. Unified Decision Engine Architecture
            </h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              SecureLens enforces zero-trust URL security via a synchronized multi-engine pipeline. URLs submitted for scanning are processed across deterministic cybersecurity heuristics and an optimized Random Forest machine learning model before synthesizing a final policy verdict.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                <span className="text-xs font-semibold text-sky-300">Cybersecurity Engine</span>
                <p className="text-[11px] text-slate-400 mt-1">
                  Evaluates IDN homoglyphs, brand spoofing, URL structure, and heuristic risk scoring (0-100).
                </p>
              </div>
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                <span className="text-xs font-semibold text-indigo-300">ML Engine</span>
                <p className="text-[11px] text-slate-400 mt-1">
                  Calculates raw probability from 30+ lexical, domain, and structural features.
                </p>
              </div>
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                <span className="text-xs font-semibold text-emerald-300">Unified Decision</span>
                <p className="text-[11px] text-slate-400 mt-1">
                  Applies strict arbitration policies to produce authoritative ALLOW, WARN, BLOCK, or ERROR decisions.
                </p>
              </div>
            </div>
          </section>

          <section className="space-y-2">
            <h4 className="flex items-center gap-2 font-semibold text-sky-400 text-sm">
              <LockIcon className="size-4" />
              2. Decision Policies & Thresholds
            </h4>
            <div className="overflow-x-auto rounded-xl border border-slate-800">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider">
                  <tr>
                    <th className="p-3">Decision</th>
                    <th className="p-3">Policy Criteria</th>
                    <th className="p-3">User Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 bg-slate-950/40">
                  <tr>
                    <td className="p-3 font-semibold text-emerald-400">ALLOW</td>
                    <td className="p-3 text-slate-300">
                      Risk Score &lt; 30, ML Prediction = Legitimate, No critical security violations.
                    </td>
                    <td className="p-3 text-slate-400">Safe to proceed.</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-semibold text-amber-400">WARN</td>
                    <td className="p-3 text-slate-300">
                      Risk Score 30-69, Suspicious heuristics, or engine disagreement requiring user caution.
                    </td>
                    <td className="p-3 text-slate-400">Exercise extreme vigilance.</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-semibold text-rose-400">BLOCK</td>
                    <td className="p-3 text-slate-300">
                      Risk Score &ge; 70, Known brand spoofing, IDN attack, or ML Prediction = Phishing.
                    </td>
                    <td className="p-3 text-slate-400">Access immediately restricted.</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-semibold text-slate-400">ERROR</td>
                    <td className="p-3 text-slate-300">
                      Degraded mode: Engine timeout or internal error handled gracefully without system crash.
                    </td>
                    <td className="p-3 text-slate-400">Review warnings and retry scan.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section className="space-y-2">
            <h4 className="flex items-center gap-2 font-semibold text-sky-400 text-sm">
              <CheckCircleIcon className="size-4" />
              3. Raw ML Probability Disclaimer
            </h4>
            <p className="text-xs text-slate-400 leading-relaxed bg-slate-900/50 p-3 rounded-xl border border-slate-800">
              In accordance with Section 8 specification, raw ML probabilities are displayed as uncalibrated model outputs (
              <span className="text-slate-200 font-mono">is_calibrated: false</span>
              ). They represent preliminary mathematical inference before policy arbitration and must never be treated as verified statistical confidence intervals.
            </p>
          </section>
        </div>
      </DialogContent>
    </Dialog>
  );
}
