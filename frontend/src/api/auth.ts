/**
 * Authentication API Service.
 */

import { apiClient, setAuthTokens, clearAuthSession } from "./client";
import type {
  AuthResponse,
  LoginCredentials,
  RegisterCredentials,
  UserProfile,
} from "@/types/auth";

export const authApi = {
  /**
   * Register a new user account.
   * DRF returns 201 with message, user, and initial JWT token pair.
   */
  async register(credentials: RegisterCredentials): Promise<AuthResponse> {
    const response = await apiClient.post<AuthResponse>(
      "/auth/register/",
      credentials
    );
    const { tokens } = response.data;
    if (tokens?.access) {
      setAuthTokens(tokens.access, tokens.refresh);
    }
    return response.data;
  },

  /**
   * Authenticate user credentials.
   * DRF returns 200 with message, user profile, and JWT tokens.
   */
  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    const response = await apiClient.post<AuthResponse>(
      "/auth/login/",
      credentials
    );
    const { tokens } = response.data;
    if (tokens?.access) {
      setAuthTokens(tokens.access, tokens.refresh);
    }
    return response.data;
  },

  /**
   * Retrieve authenticated user's profile.
   */
  async getProfile(): Promise<UserProfile> {
    const response = await apiClient.get<UserProfile>("/auth/profile/");
    return response.data;
  },

  /**
   * Terminate active frontend session.
   */
  logout(): void {
    clearAuthSession();
  },
};
