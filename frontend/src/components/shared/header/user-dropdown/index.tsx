import { useState } from "react";
import { useNavigate } from "react-router";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown";
import { useAuth } from "@/context/AuthContext";
import { ChevronDownIcon, GearIcon, LogOutIcon, UserCircleIcon } from "@/icons";
import { cn } from "@/utils";

export default function UserDropdown() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const displayName = user?.username || "Security Analyst";
  const displayEmail = user?.email || "analyst@securelens.local";
  const initials = displayName.substring(0, 2).toUpperCase();

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger className="dropdown-toggle flex items-center gap-3 rounded-xl border border-slate-700/60 bg-slate-900/60 px-3 py-1.5 text-slate-200 transition-colors hover:border-slate-600 focus:outline-none">
        <span className="flex size-8 items-center justify-center rounded-lg bg-sky-500/20 text-xs font-bold text-sky-400 border border-sky-500/30">
          {initials}
        </span>

        <div className="hidden text-left sm:block">
          <span className="block text-xs font-semibold text-slate-200 leading-tight">
            {displayName}
          </span>
          <span className="block text-[11px] text-slate-400 truncate max-w-[120px]">
            {user?.is_staff ? "Admin" : "Analyst"}
          </span>
        </div>

        <ChevronDownIcon
          className={cn(
            "size-4 text-slate-400 transition-transform duration-200",
            isOpen ? "rotate-180" : "rotate-0"
          )}
        />
      </DropdownMenuTrigger>

      <DropdownMenuContent
        align="end"
        className="w-56 rounded-xl border border-slate-700 bg-[#111B2E] p-1.5 shadow-2xl text-slate-200"
      >
        <div className="px-3 py-2 border-b border-slate-800">
          <p className="text-xs font-medium text-slate-400">Signed in as</p>
          <p className="text-sm font-semibold text-slate-100 truncate">{displayName}</p>
          <p className="text-xs text-slate-400 truncate">{displayEmail}</p>
        </div>

        <div className="py-1">
          <DropdownMenuItem
            className="flex items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800/80 cursor-pointer"
            onClick={() => navigate("/profile")}
          >
            <UserCircleIcon className="size-4 text-sky-400" />
            <span>Profile Overview</span>
          </DropdownMenuItem>

          <DropdownMenuItem
            className="flex items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800/80 cursor-pointer"
            onClick={() => navigate("/settings")}
          >
            <GearIcon className="size-4 text-indigo-400" />
            <span>Platform Settings</span>
          </DropdownMenuItem>
        </div>

        <DropdownMenuSeparator className="my-1 border-t border-slate-800" />

        <DropdownMenuItem
          className="flex items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium text-rose-400 hover:bg-rose-500/10 cursor-pointer"
          onClick={handleLogout}
        >
          <LogOutIcon className="size-4 text-rose-400" />
          <span>Sign Out</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
