/**
 * Dashboard Metrics API Service.
 */

import { apiClient } from "./client";
import type { DashboardStats } from "@/types/dashboard";

export const dashboardApi = {
  /**
   * Fetch aggregate scan statistics for the authenticated user.
   */
  async getStats(): Promise<DashboardStats> {
    const response = await apiClient.get<DashboardStats>("/dashboard/stats/");
    return response.data;
  },
};
