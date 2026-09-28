import type {
  MatrixOut,
  ReleasePlanOut,
  EffortSummaryOut,
  ReleaseBranch,
  CVEDetailOut,
  ScanRunOut,
  ConfigOut,
  JiraStatus,
  JiraPostResult,
} from "../types";

const BASE = "/api/v1";

async function fetchJSON<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export const api = {
  getBranches: () => fetchJSON<ReleaseBranch[]>(`${BASE}/branches`),

  getMatrix: (branches?: string[]) => {
    const params = branches?.length ? `?branches=${branches.join(",")}` : "";
    return fetchJSON<MatrixOut>(`${BASE}/matrix${params}`);
  },

  getPlan: () => fetchJSON<ReleasePlanOut>(`${BASE}/plan`),

  getEffort: (branches?: string[]) => {
    const params = branches?.length ? `?branches=${branches.join(",")}` : "";
    return fetchJSON<EffortSummaryOut>(`${BASE}/effort${params}`);
  },

  getReport: async () => {
    const res = await fetch(`${BASE}/report`);
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.text();
  },

  getCVEDetail: (cveId: string) =>
    fetchJSON<CVEDetailOut>(`${BASE}/cves/${cveId}`),

  getScans: () => fetchJSON<ScanRunOut[]>(`${BASE}/scans`),

  getConfig: () => fetchJSON<ConfigOut>(`${BASE}/branches/config`),

  getJiraStatus: () => fetchJSON<JiraStatus>(`${BASE}/jira/status`),

  triggerJiraDiscover: () =>
    fetch(`${BASE}/jira/discover`, { method: "POST" }),

  importEvidence: (evidencePath: string, component: string, branchName?: string) =>
    fetch(`${BASE}/scans/import`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        evidence_path: evidencePath,
        component,
        branch_name: branchName || null,
      }),
    }),

  triggerScan: (scanType: "full" | "analyze" | "jira" = "full", branches?: string[]) =>
    fetch(`${BASE}/scans/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_type: scanType,
        branches: branches?.length ? branches : null,
      }),
    }),

  generatePlan: () => fetch(`${BASE}/plan/generate`, { method: "POST" }),

  syncBranches: () => fetch(`${BASE}/branches/sync`, { method: "POST" }),

  postCVEToJira: async (cveId: string): Promise<JiraPostResult> => {
    const res = await fetch(`${BASE}/cves/${cveId}/post-to-jira`, {
      method: "POST",
    });
    if (!res.ok) {
      const detail = await res.text();
      throw new Error(`${res.status}: ${detail}`);
    }
    return res.json();
  },
};
