import React, { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router";
import { useAuth } from "@/context/AuthContext";
import { EyeCloseIcon, EyeIcon, LockIcon, UserIcon } from "@/icons";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import type { AxiosError } from "axios";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || "/dashboard";

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    const cleanUsername = username.trim();
    if (!cleanUsername) {
      setErrorMsg("Please enter your username or email address.");
      return;
    }
    if (!password) {
      setErrorMsg("Please enter your password.");
      return;
    }

    setIsSubmitting(true);
    try {
      await login({ username: cleanUsername, password });
      navigate(from, { replace: true });
    } catch (err) {
      const axiosErr = err as AxiosError<{
        detail?: string;
        error?: string;
        non_field_errors?: string[];
        username?: string[];
        password?: string[];
      }>;

      if (axiosErr.response?.data) {
        const data = axiosErr.response.data;
        if (data.detail) {
          setErrorMsg(data.detail);
        } else if (data.non_field_errors && data.non_field_errors.length > 0) {
          setErrorMsg(data.non_field_errors[0]);
        } else if (data.username && data.username.length > 0) {
          setErrorMsg(data.username[0]);
        } else if (data.password && data.password.length > 0) {
          setErrorMsg(data.password[0]);
        } else if (data.error) {
          setErrorMsg(data.error);
        } else {
          setErrorMsg("Invalid username or password. Please try again.");
        }
      } else {
        const targetUrl = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";
        setErrorMsg(`Unable to connect to the authentication server at ${targetUrl}. Please verify your backend server is running.`);
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="w-full">
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight text-white font-outfit">
          Sign In to SecureLens
        </h1>
        <p className="mt-1 text-xs text-slate-400">
          Enter your authorized credentials to access the threat console.
        </p>
      </div>

      {errorMsg && (
        <div className="mb-5 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
          <p className="font-semibold">Authentication Error</p>
          <p className="mt-0.5">{errorMsg}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <Label htmlFor="username" className="text-xs font-semibold text-slate-300">
            Username or Email
          </Label>
          <div className="relative mt-1.5">
            <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
              <UserIcon className="size-4" />
            </div>
            <Input
              id="username"
              type="text"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. analyst or analyst@securelens.local"
              className="pl-9 bg-slate-900/80 border-slate-700 text-slate-100 placeholder:text-slate-400 text-xs h-10 rounded-xl focus:border-sky-500 focus:ring-1 focus:ring-sky-500"
            />
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between">
            <Label htmlFor="password" className="text-xs font-semibold text-slate-300">
              Password
            </Label>
          </div>
          <div className="relative mt-1.5">
            <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
              <LockIcon className="size-4" />
            </div>
            <Input
              id="password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your account password"
              className="pl-9 pr-10 bg-slate-900/80 border-slate-700 text-slate-100 placeholder:text-slate-400 text-xs h-10 rounded-xl focus:border-sky-500 focus:ring-1 focus:ring-sky-500"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute inset-y-0 right-0 flex items-center pr-3 text-slate-400 hover:text-slate-200"
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? (
                <EyeCloseIcon className="size-4" />
              ) : (
                <EyeIcon className="size-4" />
              )}
            </button>
          </div>
        </div>

        <div className="flex items-center justify-between text-xs pt-1">
          <div className="flex items-center gap-2">
            <Checkbox
              id="remember"
              checked={rememberMe}
              onCheckedChange={(checked) => setRememberMe(!!checked)}
              className="rounded border-slate-700 data-[state=checked]:bg-sky-500 data-[state=checked]:border-sky-500"
            />
            <label htmlFor="remember" className="text-slate-400 cursor-pointer select-none">
              Remember active session
            </label>
          </div>
        </div>

        <Button
          type="submit"
          disabled={isSubmitting}
          className="w-full h-10 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 text-xs font-bold text-white shadow-lg shadow-sky-500/20 hover:from-sky-400 hover:to-indigo-500 transition-all cursor-pointer disabled:opacity-50"
        >
          {isSubmitting ? (
            <span className="flex items-center gap-2">
              <span className="size-3.5 rounded-full border-2 border-white/20 border-t-white animate-spin" />
              Authenticating...
            </span>
          ) : (
            "Authenticate & Access Console"
          )}
        </Button>
      </form>

      <div className="mt-6 text-center text-xs text-slate-400">
        Need access?{" "}
        <Link
          to="/register"
          className="font-semibold text-sky-400 hover:text-sky-300 transition-colors"
        >
          Register an analyst account
        </Link>
      </div>
    </div>
  );
}
