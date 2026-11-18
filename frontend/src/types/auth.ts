/**
 * Authentication and User Types conforming to DRF backend contracts.
 */

export interface UserProfile {
  id: number;
  username: string;
  email: string;
  first_name?: string;
  last_name?: string;
  date_joined?: string;
  last_login?: string | null;
  is_staff?: boolean;
}

export interface AuthTokens {
  access: string;
  refresh: string;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface RegisterCredentials {
  username: string;
  email: string;
  password: string;
  password_confirm: string;
}

export interface AuthResponse {
  message: string;
  user: UserProfile;
  tokens: AuthTokens;
}

export interface TokenRefreshResponse {
  access: string;
  refresh?: string;
}
