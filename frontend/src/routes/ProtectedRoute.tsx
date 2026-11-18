import { Navigate, Outlet, useLocation } from "react-router";
import { useAuth } from "@/context/AuthContext";
import { ShieldIcon } from "@/icons";

export function ProtectedRoute() {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-[#080D19] text-slate-200">
        <div className="relative flex size-16 items-center justify-center">
          <div className="absolute inset-0 rounded-full border-2 border-sky-500/20 animate-ping" />
          <div className="absolute inset-0 rounded-full border-2 border-t-sky-400 border-r-transparent border-b-sky-500/40 border-l-transparent animate-spin" />
          <ShieldIcon className="size-8 text-sky-400" />
        </div>
        <p className="mt-4 text-xs font-semibold uppercase tracking-widest text-slate-400 animate-pulse">
          Authenticating Threat Console...
        </p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <Outlet />;
}
