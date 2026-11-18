import React, { useState } from "react";
import { Link, useNavigate } from "react-router";
import { useAuth } from "@/context/AuthContext";
import { EyeCloseIcon, EyeIcon, LockIcon, MailIcon, UserIcon, CheckCircleIcon } from "@/icons";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { AxiosError } from "axios";

export default function RegisterPage() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string[]>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { register } = useAuth();
  const navigate = useNavigate();

  // Password strength checks matching Django validators
  const hasMinLength = password.length >= 8;
  const hasLetter = /[a-zA-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const passwordsMatch = password && password === passwordConfirm;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setFieldErrors({});

    const cleanUsername = username.trim();
    const cleanEmail = email.trim();

    if (!cleanUsername) {
      setErrorMsg("Please enter a username.");
      return;
    }
    if (!cleanEmail) {
      setErrorMsg("Please enter a valid email address.");
      return;
    }
    if (!hasMinLength) {
      setErrorMsg("Password must be at least 8 characters long.");
      return;
    }
    if (password !== passwordConfirm) {
      setErrorMsg("Passwords do not match.");
      return;
    }

    setIsSubmitting(true);
    try {
      await register({
        username: cleanUsername,
        email: cleanEmail,
        password,
        password_confirm: passwordConfirm,
      });
      navigate("/dashboard", { replace: true });
    } catch (err) {
      const axiosErr = err as AxiosError<{
        detail?: string;
        username?: string[];
        email?: string[];
        password?: string[];
        password_confirm?: string[];
        non_field_errors?: string[];
      }>;

      if (axiosErr.response?.data) {
        const data = axiosErr.response.data;
        const { detail: _d, ...restFields } = data;
        setFieldErrors(restFields as Record<string, string[]>);
        if (data.detail) {
          setErrorMsg(data.detail);
        } else if (data.non_field_errors && data.non_field_errors.length > 0) {
          setErrorMsg(data.non_field_errors[0]);
        } else if (data.username && data.username.length > 0) {
          setErrorMsg(`Username: ${data.username[0]}`);
        } else if (data.email && data.email.length > 0) {
          setErrorMsg(`Email: ${data.email[0]}`);
        } else if (data.password && data.password.length > 0) {
          setErrorMsg(`Password: ${data.password[0]}`);
        } else if (data.password_confirm && data.password_confirm.length > 0) {
          setErrorMsg(`Confirm Password: ${data.password_confirm[0]}`);
        } else {
          setErrorMsg("Registration failed. Please review your input.");
        }
      } else {
        const targetUrl = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";
        setErrorMsg(`Unable to reach the registration service at ${targetUrl}. Please verify your backend server is running.`);
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="w-full">
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight text-white font-outfit">
          Create Analyst Account
        </h1>
        <p className="mt-1 text-xs text-slate-400">
          Provision credentials to begin scanning and analyzing threats.
        </p>
      </div>

      {errorMsg && (
        <div className="mb-5 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
          <p className="font-semibold">Registration Issue</p>
          <p className="mt-0.5">{errorMsg}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <Label htmlFor="reg-username" className="text-xs font-semibold text-slate-300">
            Username
          </Label>
          <div className="relative mt-1.5">
            <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
              <UserIcon className="size-4" />
            </div>
            <Input
              id="reg-username"
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. security_analyst"
              className="pl-9 bg-slate-900/80 border-slate-700 text-slate-100 placeholder:text-slate-400 text-xs h-10 rounded-xl focus:border-sky-500 focus:ring-1 focus:ring-sky-500"
            />
          </div>
          {fieldErrors.username && (
            <p className="mt-1 text-[11px] text-rose-400">{fieldErrors.username[0]}</p>
          )}
        </div>

        <div>
          <Label htmlFor="reg-email" className="text-xs font-semibold text-slate-300">
            Official Email Address
          </Label>
          <div className="relative mt-1.5">
            <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
              <MailIcon className="size-4" />
            </div>
            <Input
              id="reg-email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="e.g. analyst@enterprise.com"
              className="pl-9 bg-slate-900/80 border-slate-700 text-slate-100 placeholder:text-slate-400 text-xs h-10 rounded-xl focus:border-sky-500 focus:ring-1 focus:ring-sky-500"
            />
          </div>
          {fieldErrors.email && (
            <p className="mt-1 text-[11px] text-rose-400">{fieldErrors.email[0]}</p>
          )}
        </div>

        <div>
          <Label htmlFor="reg-password" className="text-xs font-semibold text-slate-300">
            Password
          </Label>
          <div className="relative mt-1.5">
            <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
              <LockIcon className="size-4" />
            </div>
            <Input
              id="reg-password"
              type={showPassword ? "text" : "password"}
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Min. 8 characters"
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
          {fieldErrors.password && (
            <p className="mt-1 text-[11px] text-rose-400">{fieldErrors.password[0]}</p>
          )}
        </div>

        <div>
          <Label htmlFor="reg-confirm" className="text-xs font-semibold text-slate-300">
            Confirm Password
          </Label>
          <div className="relative mt-1.5">
            <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
              <LockIcon className="size-4" />
            </div>
            <Input
              id="reg-confirm"
              type={showPassword ? "text" : "password"}
              required
              value={passwordConfirm}
              onChange={(e) => setPasswordConfirm(e.target.value)}
              placeholder="Repeat your password"
              className="pl-9 bg-slate-900/80 border-slate-700 text-slate-100 placeholder:text-slate-400 text-xs h-10 rounded-xl focus:border-sky-500 focus:ring-1 focus:ring-sky-500"
            />
          </div>
          {fieldErrors.password_confirm && (
            <p className="mt-1 text-[11px] text-rose-400">{fieldErrors.password_confirm[0]}</p>
          )}
        </div>

        {/* Security / Password Guidance */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-3 text-[11px] text-slate-400 space-y-1.5">
          <p className="font-semibold text-slate-300">Password Requirements:</p>
          <div className="grid grid-cols-2 gap-1.5">
            <div className={`flex items-center gap-1.5 ${hasMinLength ? "text-emerald-400" : "text-slate-400"}`}>
              <CheckCircleIcon className="size-3" />
              <span>&ge; 8 characters</span>
            </div>
            <div className={`flex items-center gap-1.5 ${hasLetter ? "text-emerald-400" : "text-slate-400"}`}>
              <CheckCircleIcon className="size-3" />
              <span>Contains letters</span>
            </div>
            <div className={`flex items-center gap-1.5 ${hasNumber ? "text-emerald-400" : "text-slate-400"}`}>
              <CheckCircleIcon className="size-3" />
              <span>Contains digits</span>
            </div>
            <div className={`flex items-center gap-1.5 ${passwordsMatch ? "text-emerald-400" : "text-slate-400"}`}>
              <CheckCircleIcon className="size-3" />
              <span>Passwords match</span>
            </div>
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
              Creating Account...
            </span>
          ) : (
            "Create Account & Access Console"
          )}
        </Button>
      </form>

      <div className="mt-6 text-center text-xs text-slate-400">
        Already have an analyst account?{" "}
        <Link
          to="/login"
          className="font-semibold text-sky-400 hover:text-sky-300 transition-colors"
        >
          Sign In
        </Link>
      </div>
    </div>
  );
}
