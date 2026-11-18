import { Link } from "react-router";
import NotificationDropdown from "@/components/shared/header/notification-dropdown";
import ThemeToggleButton from "@/components/shared/header/theme-toggler";
import UserDropdown from "@/components/shared/header/user-dropdown";
import { BoltIcon, MenuTwoIcon } from "@/icons";

interface HeaderProps {
  onToggleMobile: () => void;
}

export function Header({ onToggleMobile }: HeaderProps) {
  const currentDateStr = new Date().toLocaleDateString("en-US", {
    weekday: "short",
    year: "numeric",
    month: "short",
    day: "numeric",
  });

  return (
    <header className="sticky top-0 z-20 flex h-16 w-full items-center justify-between border-b border-slate-800 bg-[#080D19]/90 px-4 sm:px-6 backdrop-blur-md">
      {/* Left: Mobile hamburger & Date / Status */}
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleMobile}
          className="flex xl:hidden p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          aria-label="Open mobile navigation"
        >
          <MenuTwoIcon className="size-5" />
        </button>

        <div className="hidden sm:flex flex-col">
          <div className="flex items-center gap-2">
            <span className="flex size-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-semibold text-slate-200">
              Live Threat Shield Active
            </span>
          </div>
          <span className="text-[11px] text-slate-400">{currentDateStr}</span>
        </div>
      </div>

      {/* Right: Quick Scan Shortcut + Notifications + Theme Toggle + User Menu */}
      <div className="flex items-center gap-2 sm:gap-3">
        <Link
          to="/scanner"
          className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-md shadow-sky-500/20 hover:from-sky-400 hover:to-indigo-500 transition-all focus:outline-none"
        >
          <BoltIcon className="size-4" />
          <span className="hidden sm:inline">Scan URL</span>
        </Link>

        <div className="h-4 w-px bg-slate-800 hidden sm:block mx-1" />

        <ThemeToggleButton />
        <NotificationDropdown />
        <UserDropdown />
      </div>
    </header>
  );
}
