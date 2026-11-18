import { useState } from "react";
import { Outlet } from "react-router";
import { Header } from "@/components/layout/Header";
import { Sidebar } from "@/components/layout/Sidebar";
import { DocumentationModal } from "@/components/layout/DocumentationModal";
import { ScrollToTop } from "@/components/shared/scroll-to-top";

export default function AppLayout() {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const [isDocModalOpen, setIsDocModalOpen] = useState(false);

  return (
    <div className="flex min-h-screen bg-[#080D19] text-[#F8FAFC]">
      <Sidebar
        isCollapsed={isCollapsed}
        onToggleCollapse={() => setIsCollapsed(!isCollapsed)}
        isMobileOpen={isMobileOpen}
        onCloseMobile={() => setIsMobileOpen(false)}
        onOpenDocModal={() => setIsDocModalOpen(true)}
      />

      <div className="flex flex-1 flex-col min-w-0">
        <Header onToggleMobile={() => setIsMobileOpen(true)} />

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">
          <Outlet />
        </main>

        <footer className="border-t border-slate-800/80 bg-[#0B1220]/60 py-4 px-6 text-center text-xs text-slate-400">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-2 max-w-7xl mx-auto">
            <span className="font-medium">
              Secure<span className="text-sky-400">Lens</span> &copy; {new Date().getFullYear()} — Enterprise Threat Intelligence
            </span>
            <span className="text-[11px] text-slate-400">
              Cybersecurity Heuristics + Random Forest ML + Zero-Trust Decision Policy
            </span>
          </div>
        </footer>
      </div>

      <DocumentationModal
        isOpen={isDocModalOpen}
        onClose={() => setIsDocModalOpen(false)}
      />

      <ScrollToTop />
    </div>
  );
}
