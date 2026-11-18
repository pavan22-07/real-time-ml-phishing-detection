import type { ScanDecision } from "@/types/scans";

export function formatDecision(decision: ScanDecision): {
  label: string;
  badgeClass: string;
  dotColor: string;
  textColor: string;
  bgColor: string;
  borderColor: string;
} {
  switch (decision) {
    case "ALLOW":
      return {
        label: "ALLOW (SAFE)",
        badgeClass: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
        dotColor: "bg-emerald-500",
        textColor: "text-emerald-400",
        bgColor: "bg-emerald-500/10",
        borderColor: "border-emerald-500/30",
      };
    case "WARN":
      return {
        label: "WARN (SUSPICIOUS)",
        badgeClass: "bg-amber-500/15 text-amber-400 border-amber-500/30",
        dotColor: "bg-amber-500",
        textColor: "text-amber-400",
        bgColor: "bg-amber-500/10",
        borderColor: "border-amber-500/30",
      };
    case "BLOCK":
      return {
        label: "BLOCK (PHISHING)",
        badgeClass: "bg-rose-500/15 text-rose-400 border-rose-500/30",
        dotColor: "bg-rose-500",
        textColor: "text-rose-400",
        bgColor: "bg-rose-500/10",
        borderColor: "border-rose-500/30",
      };
    case "ERROR":
    default:
      return {
        label: "ERROR (DEGRADED)",
        badgeClass: "bg-slate-500/15 text-slate-400 border-slate-500/30",
        dotColor: "bg-slate-500",
        textColor: "text-slate-400",
        bgColor: "bg-slate-500/10",
        borderColor: "border-slate-500/30",
      };
  }
}

export function formatDateTime(isoString?: string | null): string {
  if (!isoString) return "N/A";
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toLocaleString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZoneName: "short",
    });
  } catch {
    return isoString;
  }
}

export function formatRiskScore(score: number | null): {
  score: string;
  label: string;
  colorClass: string;
} {
  if (score === null || score === undefined) {
    return { score: "N/A", label: "Unknown", colorClass: "text-slate-400" };
  }
  if (score >= 70) {
    return { score: `${score}/100`, label: "High Risk", colorClass: "text-rose-400" };
  }
  if (score >= 30) {
    return { score: `${score}/100`, label: "Moderate Risk", colorClass: "text-amber-400" };
  }
  return { score: `${score}/100`, label: "Low Risk", colorClass: "text-emerald-400" };
}

export function truncateUrl(url: string, maxLength: number = 60): string {
  if (!url) return "";
  if (url.length <= maxLength) return url;
  return `${url.substring(0, maxLength)}...`;
}
