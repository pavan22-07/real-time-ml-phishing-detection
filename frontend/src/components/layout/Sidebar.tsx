import { NavLink, useLocation, useNavigate } from "react-router";
import { useAuth } from "@/context/AuthContext";
import {
  LayoutGridIcon,
  BoltIcon,
  TableIcon,
  UserCircleIcon,
  GearIcon,
  InfoCircleIcon,
  LogOutIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  XIcon,
} from "@/icons";
import { ShieldIcon } from "@/icons";
import { cn } from "@/utils";

interface SidebarProps {
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  isMobileOpen: boolean;
  onCloseMobile: () => void;
  onOpenDocModal: () => void;
}

interface NavSectionItem {
  name: string;
  path: string;
  icon: React.ReactNode;
  badge?: string;
}

interface NavSection {
  title: string;
  items: NavSectionItem[];
}

export function Sidebar({
  isCollapsed,
  onToggleCollapse,
  isMobileOpen,
  onCloseMobile,
  onOpenDocModal,
}: SidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const navSections: NavSection[] = [
    {
      title: "OVERVIEW",
      items: [
        {
          name: "Dashboard",
          path: "/dashboard",
          icon: <LayoutGridIcon className="size-5 shrink-0" />,
        },
      ],
    },
    {
      title: "DETECTION",
      items: [
        {
          name: "New Scan",
          path: "/scanner",
          icon: <BoltIcon className="size-5 shrink-0" />,
          badge: "Live",
        },
        {
          name: "Scan History",
          path: "/scans",
          icon: <TableIcon className="size-5 shrink-0" />,
        },
      ],
    },
    {
      title: "ACCOUNT",
      items: [
        {
          name: "Profile",
          path: "/profile",
          icon: <UserCircleIcon className="size-5 shrink-0" />,
        },
        {
          name: "Settings",
          path: "/settings",
          icon: <GearIcon className="size-5 shrink-0" />,
        },
      ],
    },
  ];

  const sidebarContent = (
    <div className="flex h-full flex-col justify-between overflow-y-auto py-5 px-3">
      <div>
        {/* Brand Header */}
        <div className="flex items-center justify-between px-2 mb-6">
          <NavLink
            to="/dashboard"
            className="flex items-center gap-3 group focus:outline-none"
            onClick={onCloseMobile}
          >
            <div className="flex size-10 items-center justify-center rounded-xl bg-gradient-to-br from-sky-500/30 to-indigo-500/20 text-sky-400 border border-sky-500/40 shadow-lg shadow-sky-500/10 group-hover:border-sky-400 transition-colors">
              <ShieldIcon className="size-6 text-sky-400" />
            </div>
            {!isCollapsed && (
              <div className="flex flex-col">
                <span className="text-base font-extrabold tracking-tight text-white font-outfit">
                  Secure<span className="text-sky-400">Lens</span>
                </span>
                <span className="text-[10px] font-medium tracking-wide text-slate-400 uppercase">
                  Threat Engine
                </span>
              </div>
            )}
          </NavLink>

          {/* Mobile close button */}
          <button
            onClick={onCloseMobile}
            className="xl:hidden p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
            aria-label="Close navigation"
          >
            <XIcon className="size-5" />
          </button>
        </div>

        {/* Navigation Sections */}
        <nav className="space-y-6">
          {navSections.map((section) => (
            <div key={section.title} className="space-y-1">
              {!isCollapsed && (
                <div className="px-3 pb-1.5 text-[10px] font-bold tracking-widest text-slate-400 uppercase">
                  {section.title}
                </div>
              )}
              <div className="space-y-1">
                {section.items.map((item) => {
                  const isActive =
                    location.pathname === item.path ||
                    (item.path !== "/dashboard" &&
                      location.pathname.startsWith(item.path));
                  return (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      onClick={onCloseMobile}
                      title={isCollapsed ? item.name : undefined}
                      className={cn(
                        "group flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs font-semibold transition-all duration-200",
                        isActive
                          ? "bg-sky-500/15 text-sky-400 border border-sky-500/30 shadow-sm shadow-sky-500/10"
                          : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200 border border-transparent",
                        isCollapsed && "justify-center px-2"
                      )}
                    >
                      <span
                        className={cn(
                          "transition-colors",
                          isActive
                            ? "text-sky-400"
                            : "text-slate-400 group-hover:text-slate-200"
                        )}
                      >
                        {item.icon}
                      </span>
                      {!isCollapsed && (
                        <div className="flex grow items-center justify-between">
                          <span>{item.name}</span>
                          {item.badge && (
                            <span className="rounded-full bg-sky-500/20 px-2 py-0.5 text-[10px] font-bold text-sky-300 border border-sky-500/30">
                              {item.badge}
                            </span>
                          )}
                        </div>
                      )}
                    </NavLink>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>
      </div>

      {/* Footer Support & System Status */}
      <div className="space-y-2 pt-6 border-t border-slate-800/80">
        <button
          onClick={onOpenDocModal}
          className={cn(
            "w-full flex items-center gap-3 rounded-xl px-3 py-2 text-xs font-medium text-slate-400 hover:bg-slate-800/60 hover:text-slate-200 transition-colors",
            isCollapsed && "justify-center px-2"
          )}
          title={isCollapsed ? "Help & Documentation" : undefined}
        >
          <InfoCircleIcon className="size-4 shrink-0 text-slate-400" />
          {!isCollapsed && <span>Architecture & Docs</span>}
        </button>

        <button
          onClick={handleLogout}
          className={cn(
            "w-full flex items-center gap-3 rounded-xl px-3 py-2 text-xs font-medium text-rose-400 hover:bg-rose-500/10 hover:text-rose-300 transition-colors",
            isCollapsed && "justify-center px-2"
          )}
          title={isCollapsed ? "Sign Out" : undefined}
        >
          <LogOutIcon className="size-4 shrink-0 text-rose-400" />
          {!isCollapsed && <span>Sign Out</span>}
        </button>

        {/* Desktop Collapse Toggle */}
        <div className="hidden xl:flex justify-end pt-2">
          <button
            onClick={onToggleCollapse}
            className="flex items-center justify-center size-8 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-400 hover:text-white hover:border-slate-700 transition-colors"
            aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {isCollapsed ? (
              <ChevronRightIcon className="size-4" />
            ) : (
              <ChevronLeftIcon className="size-4" />
            )}
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop Sidebar */}
      <aside
        className={cn(
          "hidden xl:flex flex-col shrink-0 border-r border-slate-800 bg-[#0B1220] transition-all duration-300 z-30 sticky top-0 h-screen",
          isCollapsed ? "w-20" : "w-64"
        )}
      >
        {sidebarContent}
      </aside>

      {/* Mobile Drawer Backdrop */}
      {isMobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm xl:hidden transition-opacity"
          onClick={onCloseMobile}
        />
      )}

      {/* Mobile Drawer */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 w-72 bg-[#0B1220] border-r border-slate-800 transform transition-transform duration-300 ease-in-out xl:hidden",
          isMobileOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        {sidebarContent}
      </aside>
    </>
  );
}
