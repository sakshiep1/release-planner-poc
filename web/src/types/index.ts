export interface ReleaseBranch {
  id: string;
  name: string;
  ocp_version: string;
  cert_manager_version: string;
  go_version: string;
  support_start: string | null;
  support_end: string | null;
  is_eus: boolean;
  active: boolean;
  cve_count: number;
  total_effort_days: number;
}

export interface JiraTicketInfo {
  jira_key: string;
  summary: string;
  status: string;
  affected_image: string;
}

export interface MatrixCell {
  risk_level: string;
  fix_type: string;
  effort_tshirt: string;
  effort_hours: number;
  symbol_reachable: boolean;
  component: string;
  jira_verdict: string | null;
  affected_image: string | null;
  jira_ticket_count: number;
  jira_tickets: JiraTicketInfo[];
}

export interface MatrixRow {
  cve_id: string;
  severity: string;
  cvss_score: number | null;
  affected_module: string;
  source: string;
  jira_key: string | null;
  linked_prs: string[];
  jira_ticket_count: number;
  branches: Record<string, MatrixCell>;
}

export interface MatrixOut {
  branch_names: string[];
  rows: MatrixRow[];
}

export interface PlanItemOut {
  id: string;
  branch_name: string;
  target_date: string;
  urgency: string;
  estimated_effort_days: number;
  cve_ids: string[];
  status: string;
  notes: string;
}

export interface ReleasePlanOut {
  id: string;
  name: string;
  status: string;
  created_at: string;
  items: PlanItemOut[];
}

export interface EffortBranchSummary {
  branch_name: string;
  cve_count: number;
  total_effort_days: number;
  s_count: number;
  m_count: number;
  l_count: number;
  xl_count: number;
  na_count: number;
}

export interface EffortSummaryOut {
  branches: EffortBranchSummary[];
  total_effort_days: number;
  total_cve_count: number;
}

export interface BranchCVEOut {
  branch_id: string;
  branch_name: string;
  risk_level: string;
  confidence: string;
  dependency_type: string;
  current_version: string;
  symbol_reachable: boolean;
  fix_type: string | null;
  effort_hours: number;
  effort_tshirt: string;
  component: string;
  jira_verdict: string | null;
  affected_image: string | null;
  jira_tickets: JiraTicketInfo[];
}

export interface CVEDetailOut {
  id: string;
  cve_id: string;
  go_vuln_id: string | null;
  ghsa_id: string | null;
  severity_rating: string;
  cvss_score: number | null;
  affected_module: string;
  affected_package: string;
  vulnerable_versions: string;
  fixed_version: string | null;
  description: string;
  analysis_date: string | null;
  evidence_json: string;
  jira_key: string | null;
  source: string;
  linked_prs: string;
  branches: BranchCVEOut[];
}

export interface ScanRunOut {
  id: string;
  branch_id: string | null;
  branch_name?: string | null;
  scan_type: string;
  started_at: string;
  completed_at: string | null;
  status: string;
  cves_found: number;
  error_log: string;
}

export interface ConfigOut {
  repository: Record<string, unknown>;
  jira: Record<string, unknown>;
  branches: Record<string, unknown>[];
  effort_defaults: Record<string, unknown>;
  urgency_rules: Record<string, unknown>;
}

export interface JiraPostResult {
  status: string;
  jira_key: string;
  reason: string;
}

export interface JiraStatus {
  enabled: boolean;
  credentials_configured?: boolean;
  project_key: string;
  last_sync: string | null;
  jira_linked_cves: number;
  tickets_linked: number;
  cves_with_pr_links: number;
  last_sync_results: Record<string, unknown>;
}
