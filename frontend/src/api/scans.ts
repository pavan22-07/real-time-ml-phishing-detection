/**
 * Scan Analysis API Service.
 */

import { apiClient } from "./client";
import type {
  PaginatedScanList,
  ScanRecord,
  ScanRequestPayload,
} from "@/types/scans";

export const scansApi = {
  /**
   * Submit a URL for analysis through the Unified Phishing Detection Pipeline.
   * Returns complete multi-engine scan record.
   */
  async submitScan(payload: ScanRequestPayload): Promise<ScanRecord> {
    const response = await apiClient.post<ScanRecord>("/scans/", payload);
    return response.data;
  },

  /**
   * Retrieve paginated history of scans for current authenticated user.
   */
  async getScans(page: number = 1): Promise<PaginatedScanList> {
    const response = await apiClient.get<PaginatedScanList>("/scans/", {
      params: { page },
    });
    return response.data;
  },

  /**
   * Retrieve single detailed scan report by UUID.
   */
  async getScanDetail(id: string): Promise<ScanRecord> {
    const response = await apiClient.get<ScanRecord>(`/scans/${id}/`);
    return response.data;
  },
};
