// Mirrors backend/app/schemas.py.
export type RiskLevel = "low_risk" | "suspicious" | "high_risk" | "confirmed_malicious" | "inconclusive";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  module: string;
  title: string;
  severity: Severity;
  description: string;
  evidence: Record<string, unknown>;
  source: string;
  impact?: string | null;
  recommendation?: string | null;
  limitations?: string | null;
}

export interface RedirectHop {
  url: string;
  status?: number | null;
  ip?: string | null;
}

export interface Target {
  submitted: string;
  final_url?: string | null;
  registered_domain?: string | null;
  hostname?: string | null;
  ip_addresses: string[];
  redirect_chain: RedirectHop[];
  domain_created?: string | null;
  domain_age_days?: number | null;
  registrar?: string | null;
  page_title?: string | null;
}

export interface Tls {
  https: boolean;
  valid?: boolean | null;
  subject_cn?: string | null;
  san: string[];
  issuer?: string | null;
  issuer_org?: string | null;
  not_before?: string | null;
  not_after?: string | null;
  days_remaining?: number | null;
  hostname_match?: boolean | null;
  key_type?: string | null;
  key_bits?: number | null;
  signature_algorithm?: string | null;
  protocol?: string | null;
  chain: Record<string, string | null>[];
  ct_log_entries?: number | null;
  verdict: "valid" | "suspicious" | "potentially_compromised" | "unavailable";
}

export interface Indicators {
  urls: string[];
  domains: string[];
  emails: string[];
  phones: string[];
  upi_ids: string[];
}

export interface ModelScore {
  model: string;
  label: string;
  probability: number;
  details: Record<string, unknown>;
}

export interface Correlation {
  report_id: string;
  shared: string[];
  risk_level: RiskLevel;
  analyzed_at: string;
}

export interface EmailInfo {
  from_address?: string | null;
  from_domain?: string | null;
  display_name?: string | null;
  reply_to: string[];
  return_path?: string | null;
  subject?: string | null;
  sender_is_freemail: boolean;
  auth: {
    spf?: string | null;
    dkim?: string | null;
    dmarc?: string | null;
    spf_aligned?: boolean | null;
    dkim_aligned?: boolean | null;
  };
  dmarc_policy?: string | null;
  link_mismatches: { text: string; href: string; text_domain: string; href_domain: string }[];
  attachments: {
    filename: string;
    content_type: string;
    size: number;
    detected_type?: string | null;
    risky: boolean;
    reasons: string[];
  }[];
  body_report_id?: string | null;
}

export interface CheckStatus {
  name: string;
  status: "ok" | "failed" | "skipped" | "unavailable";
  detail?: string | null;
}

export interface Report {
  report_id: string;
  input_type: "url" | "domain" | "message" | "email";
  input: string;
  analyzed_at: string;
  risk_level: RiskLevel;
  risk_score: number;
  confidence: number;
  findings: Finding[];
  checks: CheckStatus[];
  target?: Target | null;
  tls?: Tls | null;
  indicators?: Indicators | null;
  model_scores: ModelScore[];
  linked_reports: string[];
  correlations: Correlation[];
  explanation: { summary: string; key_points: string[]; generated_by: string };
  recommendations: string[];
  limitations: string[];
  report_hash: string;
  email?: EmailInfo | null;
}

export interface JobInfo {
  job_id: string;
  status: "queued" | "running" | "done" | "failed";
  elapsed_ms: number;
  report_id?: string | null;
  error?: string | null;
  cached: boolean;
  report?: Report | null;
}

export interface ReportSummary {
  report_id: string;
  analyzed_at: string;
  input_type: Report["input_type"];
  risk_level: RiskLevel;
  report_hash: string;
  input_preview: string;
}

export interface Stats {
  total_reports: number;
  by_risk_level: Partial<Record<RiskLevel, number>>;
  by_input_type: Record<string, number>;
  recurring_indicators: Record<string, { value: string; reports: number }[]>;
}

export interface Health {
  status: string;
  feeds: { openphish_urls: number; tranco_domains: number };
  system2: { student_up: boolean; fallback_up: boolean };
}

export interface ChainStatus {
  enabled: boolean;
  connected: boolean;
  detail?: string;
  chain_id?: number;
  contract_address?: string;
  total_reports?: number;
  signer?: string | null;
  signer_balance_eth?: number | null;
  explorer?: string | null;
}

export interface ChainVerify {
  report_id: string;
  recomputed_hash: string;
  chain_id: number;
  contract_address: string;
  anchored: boolean;
  integrity_ok?: boolean | null;
  onchain_hash?: string | null;
  registry_id?: number | null;
  reporter?: string | null;
  onchain_timestamp?: string | null;
  tx_hash?: string | null;
  block_number?: number | null;
  explorer_url?: string | null;
  detail?: string | null;
}

export interface ChainLookup {
  indicator_hash: string;
  count: number;
}

export interface S2Result {
  model: string;
  json_valid_rate?: number;
  binary_accuracy?: number;
  scam_recall?: number;
  legit_false_positive_rate?: number;
  evidence_grounding_rate?: number;
  avg_latency_ms?: number;
}

export interface Models {
  url?: {
    model: string;
    test: { roc_auc: number; ece: number; false_positive_rate: number };
    holdout_openphish_live: Record<string, number>;
    holdout_real_legit_subdomains: Record<string, unknown>;
  };
  s2?: { n: number; held_out: string; results: S2Result[] };
}
