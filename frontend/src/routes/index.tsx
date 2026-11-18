import { lazy, Suspense } from "react";
import { Routes, Route } from "react-router";
import AppLayout from "@/layouts/AppLayout";
import AuthLayout from "@/layouts/AuthLayout";
import { ProtectedRoute } from "./ProtectedRoute";
import { ShieldIcon } from "@/icons";

// Lazy-loaded routes for performance & bundle splitting
const LandingPage = lazy(() => import("@/pages/Landing"));
const LoginPage = lazy(() => import("@/pages/Login"));
const RegisterPage = lazy(() => import("@/pages/Register"));
const DashboardPage = lazy(() => import("@/pages/Dashboard"));
const ScannerPage = lazy(() => import("@/pages/Scanner"));
const ScanHistoryPage = lazy(() => import("@/pages/ScanHistory"));
const ScanDetailPage = lazy(() => import("@/pages/ScanDetail"));
const ProfilePage = lazy(() => import("@/pages/Profile"));
const SettingsPage = lazy(() => import("@/pages/Settings"));
const NotFoundPage = lazy(() => import("@/pages/NotFound"));

function PageSuspenseFallback() {
  return (
    <div className="flex h-96 w-full flex-col items-center justify-center">
      <div className="flex size-12 items-center justify-center rounded-2xl bg-sky-500/10 text-sky-400 border border-sky-500/20 mb-3 animate-pulse">
        <ShieldIcon className="size-6" />
      </div>
      <p className="text-xs text-slate-400">Loading SecureLens console module...</p>
    </div>
  );
}

export function AppRoutes() {
  return (
    <Suspense fallback={<PageSuspenseFallback />}>
      <Routes>
        {/* Public Landing */}
        <Route path="/" element={<LandingPage />} />

        {/* Authentication Routes */}
        <Route element={<AuthLayout />}>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
        </Route>

        {/* Authenticated Protected Operations */}
        <Route element={<ProtectedRoute />}>
          <Route element={<AppLayout />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/scanner" element={<ScannerPage />} />
            <Route path="/scans" element={<ScanHistoryPage />} />
            <Route path="/scans/:id" element={<ScanDetailPage />} />
            <Route path="/profile" element={<ProfilePage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
        </Route>

        {/* 404 Fallback */}
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Suspense>
  );
}
