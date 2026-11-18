import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown";
import { BellIcon, CheckCircleIcon, ShieldIcon } from "@/icons";

interface SecurityAlert {
  id: string;
  title: string;
  message: string;
  time: string;
  severity: "info" | "warning" | "success";
}

const INITIAL_ALERTS: SecurityAlert[] = [
  {
    id: "1",
    title: "Unified Decision Engine",
    message: "Cybersecurity and ML inference pipelines operating synchronously.",
    time: "Live Status",
    severity: "success",
  },
  {
    id: "2",
    title: "Phishing Model Active",
    message: "Random Forest classifier loaded with calibrated threat intelligence.",
    time: "Active Engine",
    severity: "info",
  },
  {
    id: "3",
    title: "Zero-Trust Enforcement",
    message: "Strict deterministic policies active for high-risk heuristics.",
    time: "Policy Enforced",
    severity: "warning",
  },
];

export default function NotificationDropdown() {
  const [isOpen, setIsOpen] = useState(false);
  const [hasUnread, setHasUnread] = useState(true);
  const [alerts, setAlerts] = useState<SecurityAlert[]>(INITIAL_ALERTS);

  const handleOpenChange = (open: boolean) => {
    setIsOpen(open);
    if (open) {
      setHasUnread(false);
    }
  };

  return (
    <DropdownMenu open={isOpen} onOpenChange={handleOpenChange}>
      <DropdownMenuTrigger
        render={
          <Button
            variant="outline"
            size="icon-lg"
            className="relative border-slate-700 bg-slate-900/60 text-slate-300 hover:bg-slate-800 hover:text-white"
            aria-label="Security notifications"
          >
            {hasUnread && (
              <span className="absolute top-2 right-2 flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-sky-500"></span>
              </span>
            )}
            <BellIcon className="size-5" />
          </Button>
        }
      />

      <DropdownMenuContent
        align="end"
        className="w-80 rounded-xl border border-slate-700 bg-[#111B2E] p-2 shadow-2xl text-slate-200"
      >
        <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <ShieldIcon className="size-4 text-sky-400" />
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
              System Health & Alerts
            </h4>
          </div>
          <span className="rounded-md bg-sky-500/10 px-2 py-0.5 text-[10px] font-medium text-sky-400 border border-sky-500/20">
            {alerts.length} Active
          </span>
        </div>

        <div className="max-h-72 overflow-y-auto divide-y divide-slate-800/60 py-1">
          {alerts.map((alert) => (
            <DropdownMenuItem
              key={alert.id}
              className="flex flex-col items-start gap-1 p-3 text-left focus:bg-slate-800/80 cursor-default rounded-lg"
            >
              <div className="flex w-full items-center justify-between">
                <span className="text-xs font-semibold text-slate-200">
                  {alert.title}
                </span>
                <span className="text-[10px] font-medium text-slate-400">
                  {alert.time}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                {alert.message}
              </p>
            </DropdownMenuItem>
          ))}
        </div>

        <DropdownMenuSeparator className="my-1 border-t border-slate-800" />

        <div className="p-1">
          <button
            type="button"
            onClick={() => setAlerts([])}
            className="w-full flex items-center justify-center gap-1.5 rounded-lg py-1.5 text-center text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 transition-colors"
          >
            <CheckCircleIcon className="size-3.5" />
            <span>Clear alert notifications</span>
          </button>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
