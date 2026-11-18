import {
  createContext,
  useEffect,
  useState,
  useCallback,
  type ReactNode,
} from "react";
import { authApi } from "@/api/auth";
import {
  getRefreshToken,
  setAuthTokens,
  clearAuthSession,
  onSessionExpired,
} from "@/api/client";
import type {
  LoginCredentials,
  RegisterCredentials,
  UserProfile,
} from "@/types/auth";
import axios from "axios";

export interface AuthContextType {
  user: UserProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  register: (credentials: RegisterCredentials) => Promise<void>;
  logout: () => void;
  refreshProfile: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const logout = useCallback(() => {
    authApi.logout();
    setUser(null);
  }, []);

  const refreshProfile = useCallback(async () => {
    try {
      const profile = await authApi.getProfile();
      setUser(profile);
    } catch {
      logout();
    }
  }, [logout]);

  // Initial bootstrap: restore session from sessionStorage
  useEffect(() => {
    const initAuth = async () => {
      const storedRefresh = getRefreshToken();
      const storedAccess = sessionStorage.getItem("securelens_access_token");

      if (!storedRefresh && !storedAccess) {
        setIsLoading(false);
        return;
      }

      // If access token already exists, try fetching profile directly
      if (storedAccess) {
        try {
          const profile = await authApi.getProfile();
          setUser(profile);
          setIsLoading(false);
          return;
        } catch {
          // Access token might be expired, fall through to refresh
        }
      }

      if (storedRefresh) {
        try {
          const baseURL =
            import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";
          const refreshRes = await axios.post<{ access: string; refresh?: string }>(
            `${baseURL}/auth/token/refresh/`,
            { refresh: storedRefresh }
          );

          setAuthTokens(
            refreshRes.data.access,
            refreshRes.data.refresh || storedRefresh
          );

          const profile = await authApi.getProfile();
          setUser(profile);
        } catch {
          clearAuthSession();
          setUser(null);
        }
      }

      setIsLoading(false);
    };

    initAuth();

    // Listen for 401 unrecoverable refresh failures from API client
    const unsubscribe = onSessionExpired(() => {
      setUser(null);
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const login = async (credentials: LoginCredentials) => {
    setIsLoading(true);
    try {
      const response = await authApi.login(credentials);
      setUser(response.user);
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (credentials: RegisterCredentials) => {
    setIsLoading(true);
    try {
      const response = await authApi.register(credentials);
      setUser(response.user);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        refreshProfile,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export { useAuth } from "@/hooks/useAuth";
