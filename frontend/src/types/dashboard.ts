/**
 * Dashboard metrics type contract strictly matching DRF DashboardStatsSerializer.
 */

export interface DashboardStats {
  total_scans: number;
  total_allow: number;
  total_warn: number;
  total_block: number;
  total_error: number;
  recent_scans_count: number;
  latest_scan_timestamp: string | null;
}
