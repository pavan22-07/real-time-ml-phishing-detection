/**
 * Scan data models strictly reflecting Django backend serializers and Section 8 specification.
 */

export type ScanDecision = "ALLOW" | "WARN" | "BLOCK" | "ERROR";

export interface CybersecuritySummary {
  status: string | null;
  verdict: string | null;
  risk_score: number | null;
}

export interface MachineLearningSummary {
  status: string | null;
  prediction: string | null;
  raw_phishing_probability: number | null;
  is_calibrated: boolean;
}

export interface ScanRecord {
  id: string; // UUID
  url: string;
  final_decision: ScanDecision;
  degraded_mode: boolean;
  cybersecurity: CybersecuritySummary;
  machine_learning: MachineLearningSummary;
  reasons: string[];
  warnings: string[];
  timestamp: string; // ISO-8601
}

export interface ScanRequestPayload {
  url: string;
}

export interface PaginatedScanList {
  count: number;
  next: string | null;
  previous: string | null;
  results: ScanRecord[];
}
