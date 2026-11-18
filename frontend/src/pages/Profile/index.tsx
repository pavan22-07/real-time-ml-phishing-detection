import { useAuth } from "@/context/AuthContext";
import { formatDateTime } from "@/utils/formatters";
import { ShieldIcon, CheckCircleIcon, MailIcon } from "@/icons";

export default function ProfilePage() {
  const { user } = useAuth();

  const displayName = user?.username || "Security Analyst";
  const displayEmail = user?.email || "analyst@securelens.local";
  const initials = displayName.substring(0, 2).toUpperCase();

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Page Title */}
      <div className="rounded-2xl border border-slate-800 bg-[#0B1220] p-6 shadow-xl">
        <h1 className="text-2xl font-extrabold tracking-tight text-white font-outfit">
          Analyst Profile &amp; Identity
        </h1>
        <p className="mt-1 text-xs text-slate-400">
          Authenticated credentials and security clearance details for your SecureLens session.
        </p>
      </div>

      {/* Main Profile Card */}
      <div className="rounded-2xl border border-slate-800 bg-[#111B2E] p-6 sm:p-8 shadow-xl space-y-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-5 border-b border-slate-800/80 pb-6">
          <div className="flex size-20 items-center justify-center rounded-2xl bg-gradient-to-br from-sky-500/30 to-indigo-500/20 text-2xl font-extrabold text-sky-400 border border-sky-500/30 shadow-lg shadow-sky-500/10">
            {initials}
          </div>

          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-white">{displayName}</h2>
              <span className="rounded-md bg-sky-500/10 px-2.5 py-0.5 text-xs font-semibold text-sky-400 border border-sky-500/20">
                {user?.is_staff ? "Security Administrator" : "Threat Analyst"}
              </span>
            </div>
            <p className="text-xs text-slate-400 flex items-center gap-1.5">
              <MailIcon className="size-3.5 text-slate-400" />
              <span>{displayEmail}</span>
            </p>
          </div>
        </div>

        {/* Credentials and Account Details Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-semibold uppercase text-[10px] tracking-wider">
              Account Identifier
            </span>
            <span className="font-mono text-slate-200 block text-sm">
              UID #{user?.id ?? "N/A"}
            </span>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-semibold uppercase text-[10px] tracking-wider">
              Assigned Username
            </span>
            <span className="text-slate-200 block text-sm font-semibold">
              {user?.username}
            </span>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-semibold uppercase text-[10px] tracking-wider">
              Date Joined / Provisioned
            </span>
            <span className="font-mono text-slate-200 block text-sm">
              {formatDateTime(user?.date_joined)}
            </span>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-semibold uppercase text-[10px] tracking-wider">
              Last Login Activity
            </span>
            <span className="font-mono text-slate-200 block text-sm">
              {user?.last_login ? formatDateTime(user.last_login) : "Active session"}
            </span>
          </div>
        </div>

        {/* Permissions & Scopes Section */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <ShieldIcon className="size-4 text-sky-400" />
            <span>Assigned Security Scopes &amp; Throttling Limits</span>
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs pt-1">
            <div className="flex items-center gap-2 text-slate-300">
              <CheckCircleIcon className="size-4 text-emerald-400" />
              <span>URL Scanning (60/min)</span>
            </div>
            <div className="flex items-center gap-2 text-slate-300">
              <CheckCircleIcon className="size-4 text-emerald-400" />
              <span>Audit Log Retrieval</span>
            </div>
            <div className="flex items-center gap-2 text-slate-300">
              <CheckCircleIcon className="size-4 text-emerald-400" />
              <span>Telemetry Dashboard (200/min)</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
