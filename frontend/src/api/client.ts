/**
 * Centralized API client with resilient JWT refresh queue and interceptors.
 *
 * Security Architecture:
 * - Token management is encapsulated within this service.
 * - Refresh & access tokens are stored in sessionStorage to limit persistence exposure.
 * - Concurrency control prevents duplicate simultaneous refresh calls.
 * - Sensitive tokens are never logged.
 */

import axios, {
  type AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from "axios";
import type { TokenRefreshResponse } from "@/types/auth";

const BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";

// Memory storage initialized from sessionStorage for tab persistence
let currentAccessToken: string | null = sessionStorage.getItem(
  "securelens_access_token"
);
let currentRefreshToken: string | null = sessionStorage.getItem(
  "securelens_refresh_token"
);

// Concurrency control for token refresh
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (token: string) => void;
  reject: (error: unknown) => void;
}> = [];

const processQueue = (error: unknown, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else if (token) {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

export const setAuthTokens = (access: string | null, refresh: string | null) => {
  currentAccessToken = access;
  currentRefreshToken = refresh;

  if (access) {
    sessionStorage.setItem("securelens_access_token", access);
  } else {
    sessionStorage.removeItem("securelens_access_token");
  }

  if (refresh) {
    sessionStorage.setItem("securelens_refresh_token", refresh);
  } else {
    sessionStorage.removeItem("securelens_refresh_token");
  }
};

export const getAccessToken = (): string | null => currentAccessToken;
export const getRefreshToken = (): string | null => currentRefreshToken;

export const clearAuthSession = () => {
  currentAccessToken = null;
  currentRefreshToken = null;
  sessionStorage.removeItem("securelens_access_token");
  sessionStorage.removeItem("securelens_refresh_token");
};

// Subscriptions for auth state changes (e.g., session expired)
type AuthStateCallback = () => void;
const logoutListeners: Set<AuthStateCallback> = new Set();

export const onSessionExpired = (callback: AuthStateCallback) => {
  logoutListeners.add(callback);
  return () => {
    logoutListeners.delete(callback);
  };
};

const notifySessionExpired = () => {
  clearAuthSession();
  logoutListeners.forEach((callback) => callback());
};

export const apiClient: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 30000, // 30s timeout for deep multi-engine heuristics
});

// Request Interceptor: Attach Access Token
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = currentAccessToken || sessionStorage.getItem("securelens_access_token");
    if (token && !config.headers.Authorization) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error: AxiosError) => Promise.reject(error)
);

// Response Interceptor: Seamless Token Refresh & Concurrency Queue
apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & {
      _retry?: boolean;
    };

    if (!originalRequest) {
      return Promise.reject(error);
    }

    // Do not attempt refresh on auth endpoints (login, register, token/refresh)
    const isAuthEndpoint =
      originalRequest.url?.includes("/auth/login/") ||
      originalRequest.url?.includes("/auth/register/") ||
      originalRequest.url?.includes("/auth/token/refresh/");

    if (error.response?.status === 401 && !originalRequest._retry && !isAuthEndpoint) {
      if (isRefreshing) {
        // Queue pending request while refresh completes
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((newToken) => {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            return apiClient(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      const refresh = getRefreshToken();
      if (!refresh) {
        isRefreshing = false;
        notifySessionExpired();
        return Promise.reject(error);
      }

      try {
        const refreshResponse = await axios.post<TokenRefreshResponse>(
          `${BASE_URL}/auth/token/refresh/`,
          { refresh }
        );

        const newAccessToken = refreshResponse.data.access;
        const newRefreshToken = refreshResponse.data.refresh || refresh;

        setAuthTokens(newAccessToken, newRefreshToken);
        processQueue(null, newAccessToken);

        originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
        return apiClient(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        notifySessionExpired();
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);
