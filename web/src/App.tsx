import { useCallback, useEffect, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api } from "./services/api";
import type {
  MatrixOut,
  MatrixCell,
  MatrixRow,
  ReleasePlanOut,
  EffortSummaryOut,
  ReleaseBranch,
  CVEDetailOut,
  ScanRunOut,
  ConfigOut,
  JiraStatus,
} from "./types";

// ─── Color helpers ───────────────────────────────────────────
const SEV_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-900/60 text-red-300 border-red-700",
  HIGH: "bg-orange-900/50 text-orange-300 border-orange-700",
  MEDIUM: "bg-yellow-900/40 text-yellow-300 border-yellow-700",
  LOW: "bg-green-900/40 text-green-300 border-green-700",
  UNKNOWN: "bg-terminal-surface text-terminal-muted border-terminal-border",
};

const FIX_LABELS: Record<string, string> = {
  VERSION_BUMP: "Version Bump",
  TRIVIAL_BACKPORT: "Sustaining Backport",
  NON_TRIVIAL_BACKPORT: "Non-Trivial Backport",
  NEEDS_REVIEW: "Needs Review",
  NOT_APPLICABLE: "Not Applicable",
  CHAIBOT_ANALYSIS_REQUIRED: "ChaiBot Analysis Required",
};

const FIX_TYPE_COLORS: Record<string, string> = {
  VERSION_BUMP: "bg-blue-900/50 text-blue-300 border-blue-700",
  TRIVIAL_BACKPORT: "bg-cyan-900/50 text-cyan-300 border-cyan-700",
  NON_TRIVIAL_BACKPORT: "bg-orange-900/50 text-orange-300 border-orange-700",
  NEEDS_REVIEW: "bg-red-900/50 text-red-300 border-red-700",
  NOT_APPLICABLE: "bg-terminal-surface text-terminal-muted border-terminal-border",
  CHAIBOT_ANALYSIS_REQUIRED: "bg-amber-900/50 text-amber-300 border-amber-700",
};

const URGENCY_COLORS: Record<string, string> = {
  CRITICAL: "text-terminal-red border-terminal-red",
  HIGH: "text-terminal-orange border-terminal-orange",
  ROUTINE: "text-terminal-green border-terminal-green",
};

function sevBadge(sev: string) {
  const cls = SEV_COLORS[sev] || SEV_COLORS.UNKNOWN;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold border ${cls}`}>
      {sev}
    </span>
  );
}

function fixTypeBadge(fixType: string | null | undefined) {
  if (!fixType) return <span className="text-terminal-muted text-xs">—</span>;
  const cls = FIX_TYPE_COLORS[fixType] || FIX_TYPE_COLORS.NEEDS_REVIEW;
  const label = FIX_LABELS[fixType] || fixType;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium border ${cls}`}>
      {label}
    </span>
  );
}

function jiraTicketUrl(jiraBaseUrl: string, jiraKey: string) {
  const base = jiraBaseUrl.replace(/\/$/, "");
  return `${base}/browse/${jiraKey}`;
}

// ─── Branch Single-Select Dropdown ────────────────────────────
function BranchSelector({
  branches,
  selected,
  onChange,
}: {
  branches: ReleaseBranch[];
  selected: string;
  onChange: (name: string) => void;
}) {
  const activeBranches = branches.filter((b) => b.active);
  return (
    <select
      value={selected}
      onChange={(e) => onChange(e.target.value)}
      className="px-3 py-1.5 bg-terminal-surface border border-terminal-border rounded text-sm text-terminal-text hover:border-terminal-accent focus:border-terminal-accent focus:outline-none transition"
    >
      {activeBranches.map((b) => (
        <option key={b.name} value={b.name}>
          {b.name} ({b.cve_count} CVEs)
        </option>
      ))}
    </select>
  );
}

// ─── Component-Grouped CVE Table ─────────────────────────────
function inferComponent(row: MatrixRow, branchNames: string[]): string {
  for (const bn of branchNames) {
    const cell = row.branches[bn];
    if (cell?.affected_image) {
      const img = cell.affected_image.toLowerCase();
      if (img.includes("acmesolver") || img.includes("acme-solver"))
        return "Operand: jetstack-acmesolver";
      if (img.includes("controller") && !img.includes("webhook"))
        return "Operand: jetstack-cert-manager-controller";
      if (img.includes("webhook"))
        return "Operand: jetstack-cert-manager-webhook";
      if (img.includes("cainjector") || img.includes("ca-injector"))
        return "Operand: jetstack-cert-manager-cainjector";
      if (img.includes("cert-manager-rhel") || img.includes("cert-manager-operator"))
        return "Operand: jetstack-cert-manager-rhel9";
      if (img.includes("operator"))
        return "Operator";
      return `Operand: ${img.split("/").pop() || img}`;
    }
  }
  // Fall back to module name
  const mod = row.affected_module?.toLowerCase() || "";
  if (mod.includes("operator")) return "Operator";
  if (mod.includes("cert-manager")) return "Operand: cert-manager";
  return "Uncategorized";
}

interface CVEGroupedViewProps {
  data: MatrixOut | null;
  jiraBaseUrl: string;
  onCVEClick: (cveId: string) => void;
}

function CVEGroupedView({ data, jiraBaseUrl, onCVEClick }: CVEGroupedViewProps) {
  if (!data || data.rows.length === 0)
    return <p className="text-terminal-muted italic">No CVE data loaded. Click "Full Analysis" to start.</p>;

  // Group CVEs by component
  const groups: Record<string, MatrixRow[]> = {};
  for (const row of data.rows) {
    const comp = inferComponent(row, data.branch_names);
    if (!groups[comp]) groups[comp] = [];
    groups[comp].push(row);
  }

  // Sort groups: Operands first, then Operator, then Uncategorized
  const sortedKeys = Object.keys(groups).sort((a, b) => {
    if (a.startsWith("Operand") && !b.startsWith("Operand")) return -1;
    if (!a.startsWith("Operand") && b.startsWith("Operand")) return 1;
    if (a === "Operator") return b === "Uncategorized" ? -1 : 1;
    return a.localeCompare(b);
  });

  return (
    <div className="space-y-6">
      {sortedKeys.map((groupName) => {
        const rows = groups[groupName];
        return (
          <div key={groupName} className="bg-terminal-surface/20 rounded-lg border border-terminal-border overflow-hidden">
            <div className="px-4 py-3 bg-terminal-surface/40 border-b border-terminal-border flex items-center gap-3">
              <span className="text-sm">
                {groupName.startsWith("Operand") ? "📦" : groupName === "Operator" ? "⚙️" : "📋"}
              </span>
              <h3 className="text-sm font-bold text-terminal-text">{groupName}</h3>
              <span className="text-xs text-terminal-muted ml-auto">{rows.length} CVE{rows.length !== 1 ? "s" : ""}</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-terminal-border/50 text-terminal-muted text-xs uppercase tracking-wider">
                    <th className="px-4 py-2 text-left">CVE ID</th>
                    <th className="px-3 py-2 text-left">Jira Ticket</th>
                    <th className="px-3 py-2 text-left">Fix Type</th>
                    <th className="px-3 py-2 text-left">Severity</th>
                    <th className="px-3 py-2 text-right">CVSS</th>
                    <th className="px-3 py-2 text-left">Due Date</th>
                    <th className="px-3 py-2 text-left">Module</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-terminal-border/30">
                  {rows.map((row) => {
                    const cell = data.branch_names.length > 0 ? row.branches[data.branch_names[0]] : undefined;
                    const dueDate = cell?.due_date;
                    const isOverdue = dueDate ? new Date(dueDate) < new Date() : false;
                    return (
                      <tr
                        key={row.cve_id}
                        className="hover:bg-terminal-surface/60 transition-colors cursor-pointer"
                        onClick={() => onCVEClick(row.cve_id)}
                      >
                        <td className="px-4 py-2.5">
                          <span className="text-terminal-accent font-medium">{row.cve_id}</span>
                        </td>
                        <td className="px-3 py-2.5" onClick={(e) => e.stopPropagation()}>
                          {row.jira_key ? (
                            <a
                              href={jiraTicketUrl(jiraBaseUrl, row.jira_key)}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-purple-400 hover:text-purple-300 hover:underline text-xs font-medium"
                            >
                              {row.jira_key}
                            </a>
                          ) : (
                            <span className="text-terminal-muted text-xs">—</span>
                          )}
                          {row.jira_ticket_count > 1 && (
                            <span className="ml-1 px-1.5 py-0.5 bg-purple-900/40 text-purple-300 text-[9px] rounded-full font-medium">
                              +{row.jira_ticket_count - 1}
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2.5">
                          {fixTypeBadge(cell?.fix_type)}
                        </td>
                        <td className="px-3 py-2.5">
                          {sevBadge(row.severity)}
                        </td>
                        <td className="px-3 py-2.5 text-right tabular-nums text-terminal-muted">
                          {row.cvss_score != null ? row.cvss_score.toFixed(1) : "—"}
                        </td>
                        <td className="px-3 py-2.5">
                          {dueDate ? (
                            <span className={`text-xs font-mono ${isOverdue ? "text-terminal-red font-bold" : "text-terminal-muted"}`}>
                              {dueDate}
                              {isOverdue && <span className="ml-1 text-[9px]">⚠️</span>}
                            </span>
                          ) : (
                            <span className="text-terminal-muted text-xs">—</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5 text-terminal-muted text-xs truncate max-w-[200px]">
                          {row.affected_module}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── CVE Detail Slide-out Panel ──────────────────────────────
function CVEDetailPanel({
  cveId,
  jiraBaseUrl,
  onClose,
}: {
  cveId: string;
  jiraBaseUrl: string;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<CVEDetailOut | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api
      .getCVEDetail(cveId)
      .then(setDetail)
      .catch(() => setDetail(null))
      .finally(() => setLoading(false));
  }, [cveId]);

  const linkedPrs = (() => {
    if (!detail?.linked_prs) return [];
    try {
      return JSON.parse(detail.linked_prs) as string[];
    } catch {
      return [];
    }
  })();

  return (
    <>
      <div
        className="fixed inset-0 bg-black/40 z-40"
        onClick={onClose}
      />
      <div className="fixed right-0 top-0 h-full w-full max-w-lg bg-terminal-bg border-l border-terminal-border z-50 overflow-y-auto shadow-2xl">
        <div className="sticky top-0 bg-terminal-bg border-b border-terminal-border px-5 py-3 flex items-center justify-between">
          <h2 className="text-lg font-bold text-terminal-text">{cveId}</h2>
          <button
            onClick={onClose}
            className="p-1 text-terminal-muted hover:text-terminal-text transition"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-40 text-terminal-muted">
            Loading...
          </div>
        ) : !detail ? (
          <div className="p-5 text-terminal-red">Failed to load CVE details.</div>
        ) : (
          <div className="p-5 space-y-5">
            {/* Header metadata */}
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-terminal-muted text-xs block">Severity</span>
                {sevBadge(detail.severity_rating)}
              </div>
              <div>
                <span className="text-terminal-muted text-xs block">CVSS</span>
                <span className="text-xl font-bold text-terminal-accent">
                  {detail.cvss_score != null ? detail.cvss_score.toFixed(1) : "—"}
                </span>
              </div>
              <div className="col-span-2">
                <span className="text-terminal-muted text-xs block">Module</span>
                <span className="text-sm font-mono">{detail.affected_module || "—"}</span>
              </div>
              {detail.fixed_version && (
                <div>
                  <span className="text-terminal-muted text-xs block">Fixed in</span>
                  <span className="text-sm font-mono text-terminal-green">{detail.fixed_version}</span>
                </div>
              )}
              {detail.vulnerable_versions && (
                <div>
                  <span className="text-terminal-muted text-xs block">Affected Version</span>
                  <span className="text-sm font-mono text-terminal-orange">{detail.vulnerable_versions}</span>
                </div>
              )}
              {detail.jira_key && (
                <div>
                  <span className="text-terminal-muted text-xs block">Jira Ticket</span>
                  <a
                    href={jiraTicketUrl(jiraBaseUrl, detail.jira_key)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-purple-400 hover:underline"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {detail.jira_key}
                  </a>
                </div>
              )}
            </div>

            {/* All linked Jira tickets */}
            {(() => {
              const allTickets = detail.branches.flatMap((bc) => bc.jira_tickets || []);
              const seen = new Set<string>();
              const unique = allTickets.filter((t) => {
                if (seen.has(t.jira_key)) return false;
                seen.add(t.jira_key);
                return true;
              });
              if (unique.length <= 1) return null;
              return (
                <div>
                  <h3 className="text-xs font-bold text-terminal-muted uppercase mb-2">
                    Linked Jira Tickets ({unique.length})
                  </h3>
                  <div className="space-y-1.5">
                    {unique.map((t) => (
                      <a
                        key={t.jira_key}
                        href={jiraTicketUrl(jiraBaseUrl, t.jira_key)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 px-3 py-1.5 bg-terminal-surface/40 border border-terminal-border rounded text-sm hover:border-purple-500 transition"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <span className="text-purple-400 font-medium shrink-0">{t.jira_key}</span>
                        {t.affected_image && (
                          <span className="text-terminal-muted text-xs font-mono truncate">{t.affected_image}</span>
                        )}
                        <span className={`ml-auto text-[10px] shrink-0 ${t.status?.toLowerCase().includes("done") || t.status?.toLowerCase().includes("closed") ? "text-green-400" : "text-terminal-muted"}`}>
                          {t.status}
                        </span>
                      </a>
                    ))}
                  </div>
                </div>
              );
            })()}

            {detail.description && (
              <div>
                <h3 className="text-xs font-bold text-terminal-muted uppercase mb-1">ChaiBot Analysis</h3>
                <div className="text-sm text-terminal-text leading-relaxed prose prose-invert prose-sm max-w-none bg-terminal-surface/30 p-3 rounded border border-terminal-border max-h-80 overflow-y-auto">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{detail.description}</ReactMarkdown>
                </div>
              </div>
            )}

            {linkedPrs.length > 0 && (
              <div>
                <h3 className="text-xs font-bold text-terminal-muted uppercase mb-2">Linked Pull Requests</h3>
                <div className="space-y-1.5">
                  {linkedPrs.map((pr) => {
                    const prNum = pr.split("/pull/")[1] || pr;
                    const repoPath = pr.replace("https://github.com/", "").split("/pull/")[0] || "";
                    return (
                      <a
                        key={pr}
                        href={pr}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 px-3 py-1.5 bg-terminal-surface/40 border border-terminal-border rounded text-sm hover:border-terminal-accent transition"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <span className="text-terminal-muted text-xs">{repoPath}</span>
                        <span className="text-terminal-accent font-medium">#{prNum}</span>
                      </a>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Per-branch analysis (ChaiBot analysis breakdown) */}
            <div>
              <h3 className="text-xs font-bold text-terminal-muted uppercase mb-2">ChaiBot Analysis</h3>
              <div className="space-y-2">
                {detail.branches.map((bc) => (
                  <div
                    key={bc.branch_id}
                    className="bg-terminal-surface/40 border border-terminal-border rounded-lg p-3 text-sm"
                  >
                    <div className="flex justify-between items-start mb-2">
                      <span className="font-medium text-terminal-text">{bc.branch_name}</span>
                      {fixTypeBadge(bc.fix_type)}
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-xs">
                      <div>
                        <span className="text-terminal-muted block">Risk</span>
                        <span className={bc.risk_level === "CRITICAL" ? "text-terminal-red font-bold" : bc.risk_level === "HIGH" ? "text-terminal-orange font-bold" : ""}>
                          {bc.risk_level}
                        </span>
                      </div>
                      <div>
                        <span className="text-terminal-muted block">Fix Type</span>
                        <span>{bc.fix_type ? FIX_LABELS[bc.fix_type] || bc.fix_type : "—"}</span>
                      </div>
                      <div>
                        <span className="text-terminal-muted block">Effort</span>
                        <span>{bc.effort_tshirt || "—"} ({bc.effort_hours}h)</span>
                      </div>
                      <div>
                        <span className="text-terminal-muted block">Dep Type</span>
                        <span>{bc.dependency_type}</span>
                      </div>
                      <div>
                        <span className="text-terminal-muted block">Version</span>
                        <span className="font-mono">{bc.current_version || "—"}</span>
                      </div>
                      <div>
                        <span className="text-terminal-muted block">Reachable</span>
                        <span className={bc.symbol_reachable ? "text-terminal-red" : "text-terminal-green"}>
                          {bc.symbol_reachable ? "YES" : "NO"}
                        </span>
                      </div>
                      {bc.due_date && (
                        <div className="col-span-3">
                          <span className="text-terminal-muted block">Due Date</span>
                          <span className="font-mono text-xs">{bc.due_date}</span>
                        </div>
                      )}
                      {bc.affected_image && (
                        <div className="col-span-3">
                          <span className="text-terminal-muted block">Image</span>
                          <span className="font-mono text-xs">{bc.affected_image}</span>
                        </div>
                      )}
                    </div>
                    {bc.remediation_fix && (
                      <div className="mt-2 px-2 py-1.5 bg-green-900/20 border border-green-700/30 rounded text-xs text-green-300">
                        <span className="font-bold">Remediation:</span> {bc.remediation_fix}
                      </div>
                    )}
                    {bc.notes && (
                      <div className="mt-2 px-2 py-1.5 bg-amber-900/20 border border-amber-700/30 rounded text-xs text-amber-300">
                        {bc.notes}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Remediation Fix */}
            {(() => {
              const allRemediation = detail.branches
                .map((bc) => bc.remediation_fix)
                .filter((r) => r && r.trim());
              const unique = [...new Set(allRemediation)];
              if (unique.length === 0) return null;
              return (
                <div>
                  <h3 className="text-xs font-bold text-terminal-muted uppercase mb-1">Remediation Fix</h3>
                  {unique.map((r, i) => (
                    <div key={i} className="text-sm text-terminal-green bg-green-900/20 border border-green-700/30 rounded px-3 py-2 mb-1">
                      {r}
                    </div>
                  ))}
                </div>
              );
            })()}
          </div>
        )}
      </div>
    </>
  );
}

// ─── Effort Summary ──────────────────────────────────────────
function EffortSummary({ data }: { data: EffortSummaryOut | null }) {
  if (!data) return null;
  const max = Math.max(...data.branches.map((b) => b.total_effort_days), 1);

  return (
    <div className="space-y-4">
      <div className="flex gap-6 text-sm">
        <div>
          Total effort:{" "}
          <span className="font-bold text-terminal-accent">
            {data.total_effort_days.toFixed(1)} days
          </span>
        </div>
        <div>
          CVEs:{" "}
          <span className="font-bold text-terminal-accent">
            {data.total_cve_count}
          </span>
        </div>
      </div>
      <div className="space-y-3">
        {data.branches.map((b) => (
          <div key={b.branch_name}>
            <div className="flex justify-between text-sm mb-1">
              <span className="font-medium">{b.branch_name}</span>
              <span className="text-terminal-muted">
                {b.cve_count} CVEs · {b.total_effort_days.toFixed(1)}d
              </span>
            </div>
            <div className="w-full bg-terminal-border/30 rounded-full h-5 flex overflow-hidden">
              {b.s_count > 0 && (
                <div
                  className="bg-blue-600 h-full flex items-center justify-center text-[10px] font-bold"
                  style={{ width: `${((b.s_count * 3) / (max * 8)) * 100}%`, minWidth: "20px" }}
                  title={`${b.s_count} Version Bump`}
                >S:{b.s_count}</div>
              )}
              {b.m_count > 0 && (
                <div
                  className="bg-cyan-600 h-full flex items-center justify-center text-[10px] font-bold"
                  style={{ width: `${((b.m_count * 8) / (max * 8)) * 100}%`, minWidth: "20px" }}
                  title={`${b.m_count} Sustaining Backport`}
                >M:{b.m_count}</div>
              )}
              {b.l_count > 0 && (
                <div
                  className="bg-orange-600 h-full flex items-center justify-center text-[10px] font-bold"
                  style={{ width: `${((b.l_count * 20) / (max * 8)) * 100}%`, minWidth: "20px" }}
                  title={`${b.l_count} Non-Trivial Backport`}
                >L:{b.l_count}</div>
              )}
              {b.xl_count > 0 && (
                <div
                  className="bg-red-600 h-full flex items-center justify-center text-[10px] font-bold"
                  style={{ width: `${((b.xl_count * 28) / (max * 8)) * 100}%`, minWidth: "20px" }}
                  title={`${b.xl_count} Needs Review`}
                >XL:{b.xl_count}</div>
              )}
            </div>
          </div>
        ))}
      </div>
      <div className="flex gap-4 text-[11px] text-terminal-muted">
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-blue-600 inline-block" /> S (Bump)</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-cyan-600 inline-block" /> M (Backport)</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-orange-600 inline-block" /> L (Hard BP)</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-600 inline-block" /> XL (Review)</span>
      </div>
    </div>
  );
}

// ─── Release Plan Timeline ───────────────────────────────────
function ReleasePlan({ data }: { data: ReleasePlanOut | null }) {
  if (!data || !data.items || data.items.length === 0)
    return (
      <p className="text-terminal-muted italic">
        No release plan generated yet. Run Full Analysis first.
      </p>
    );

  return (
    <div className="space-y-4">
      <div className="text-sm text-terminal-muted">
        {data.name} · <span className="capitalize">{data.status}</span>
      </div>
      <div className="space-y-3">
        {data.items.map((item) => {
          const uc = URGENCY_COLORS[item.urgency] || URGENCY_COLORS.ROUTINE;
          return (
            <div
              key={item.id}
              className={`border rounded-lg p-4 bg-terminal-surface/40 ${uc.split(" ")[1] || "border-terminal-border"}`}
            >
              <div className="flex justify-between items-start mb-2">
                <div>
                  <span className="font-bold text-terminal-text">{item.branch_name}</span>
                  <span className={`ml-3 text-xs font-bold uppercase ${uc.split(" ")[0]}`}>{item.urgency}</span>
                </div>
                <div className="text-right">
                  <div className="text-sm font-medium text-terminal-accent">{item.target_date}</div>
                  <div className="text-xs text-terminal-muted">{item.estimated_effort_days.toFixed(1)} days</div>
                </div>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {item.cve_ids.map((cid) => (
                  <span
                    key={cid}
                    className="px-2 py-0.5 bg-terminal-bg rounded text-xs text-terminal-muted border border-terminal-border"
                  >
                    {cid}
                  </span>
                ))}
              </div>
              {item.notes && (
                <div className="mt-2 text-xs text-terminal-muted">{item.notes}</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Report View ─────────────────────────────────────────────
function ReportView() {
  const [markdown, setMarkdown] = useState<string>("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api
      .getReport()
      .then(setMarkdown)
      .catch(() => setMarkdown("*Failed to load report. Run Full Analysis first.*"))
      .finally(() => setLoading(false));
  }, []);

  const handleDownload = () => {
    const blob = new Blob([markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "release-plan-report.md";
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading)
    return <div className="text-terminal-muted italic">Loading report...</div>;

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <button
          onClick={handleDownload}
          className="px-3 py-1.5 bg-terminal-accent/20 border border-terminal-accent text-terminal-accent text-sm rounded hover:bg-terminal-accent/30 transition flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          Download .md
        </button>
      </div>
      <div className="prose prose-invert prose-sm max-w-none bg-terminal-surface/30 p-6 rounded-lg border border-terminal-border overflow-auto">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{markdown}</ReactMarkdown>
      </div>
    </div>
  );
}

// ─── Scan History ────────────────────────────────────────────
function ScanHistory({ refreshKey }: { refreshKey?: number }) {
  const [scans, setScans] = useState<ScanRunOut[]>([]);

  useEffect(() => {
    api.getScans().then(setScans).catch(() => {});
  }, [refreshKey]);

  if (scans.length === 0)
    return <p className="text-xs text-terminal-muted italic">No scan history.</p>;

  const statusBadge = (s: string) => {
    const colors: Record<string, string> = {
      completed: "bg-terminal-green/20 text-terminal-green",
      running: "bg-terminal-yellow/20 text-terminal-yellow",
      failed: "bg-terminal-red/20 text-terminal-red",
    };
    return (
      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${colors[s] || "bg-terminal-surface text-terminal-muted"}`}>
        {s}
      </span>
    );
  };

  return (
    <div className="space-y-1.5 max-h-48 overflow-y-auto">
      {scans.map((s) => (
        <div
          key={s.id}
          className="bg-terminal-bg/50 rounded px-2 py-1.5 flex items-center justify-between text-xs"
        >
          <div className="flex items-center gap-2">
            {statusBadge(s.status)}
            <span className="text-terminal-muted capitalize">{s.scan_type}</span>
            {s.branch_name && (
              <span className="text-terminal-accent font-mono text-[10px]">{s.branch_name}</span>
            )}
          </div>
          <div className="text-right text-terminal-muted">
            <div>{s.cves_found} CVEs</div>
            <div className="text-[10px]">
              {new Date(s.started_at).toLocaleString(undefined, {
                month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
              })}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Config View ─────────────────────────────────────────────
function ConfigView() {
  const [config, setConfig] = useState<ConfigOut | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    api.getConfig().then(setConfig).catch(() => {});
  }, []);

  if (!config) return null;

  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="text-xs font-bold text-terminal-muted uppercase flex items-center gap-1 hover:text-terminal-accent transition w-full text-left"
      >
        <svg className={`w-3 h-3 transition-transform ${open ? "rotate-90" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
        Configuration
      </button>
      {open && (
        <pre className="mt-2 bg-terminal-bg p-3 rounded text-[10px] text-terminal-muted overflow-x-auto max-h-56 overflow-y-auto border border-terminal-border font-mono leading-relaxed">
          {JSON.stringify(config, null, 2)}
        </pre>
      )}
    </div>
  );
}

// ─── Jira Status Panel ───────────────────────────────────────
function JiraStatusPanel() {
  const [status, setStatus] = useState<JiraStatus | null>(null);

  useEffect(() => {
    api.getJiraStatus().then(setStatus).catch(() => {});
  }, []);

  if (!status) return null;

  return (
    <div className="space-y-2">
      <h3 className="text-[10px] font-bold text-terminal-muted uppercase tracking-wider flex items-center gap-2">
        <span className="text-purple-400">🎫</span> Jira Integration
      </h3>
      <div className="grid grid-cols-2 gap-1.5 text-xs">
        <div className="bg-terminal-bg/50 rounded px-2 py-1.5">
          <div className="text-terminal-muted text-[10px]">Status</div>
          <div className={status.enabled ? "text-terminal-green font-bold" : "text-terminal-red"}>
            {status.enabled ? "Enabled" : "Disabled"}
          </div>
        </div>
        <div className="bg-terminal-bg/50 rounded px-2 py-1.5">
          <div className="text-terminal-muted text-[10px]">Credentials</div>
          <div className={status.credentials_configured ? "text-terminal-green font-bold" : "text-terminal-red"}>
            {status.credentials_configured ? "Configured" : "Missing"}
          </div>
        </div>
        <div className="bg-terminal-bg/50 rounded px-2 py-1.5">
          <div className="text-terminal-muted text-[10px]">Linked CVEs</div>
          <div className="font-bold">{status.jira_linked_cves}</div>
        </div>
        <div className="bg-terminal-bg/50 rounded px-2 py-1.5">
          <div className="text-terminal-muted text-[10px]">With PRs</div>
          <div className="font-bold">{status.cves_with_pr_links}</div>
        </div>
      </div>
    </div>
  );
}

// ─── Scan progress types ─────────────────────────────────────
type ScanProgressMsg = {
  branch?: string;
  status?: string;
  cve?: string;
  progress?: string;
  cve_index?: number;
  cve_total?: number;
  cves_found?: number;
  branches_scanned?: number;
};

const SCAN_STATUS_LABELS: Record<string, string> = {
  jira_discovery: "Discovering CVEs from Jira",
  analyzing: "Parsing ChaiBot analysis",
  classifying: "Classifying fix types",
  estimating: "Estimating effort",
};

function scanStatusLabel(status?: string) {
  if (!status) return "Analyzing";
  return SCAN_STATUS_LABELS[status] || status.replace(/_/g, " ");
}

// ─── SSE Progress Bar ────────────────────────────────────────
function SSEProgress({
  onScanComplete,
  onProgressChange,
}: {
  onScanComplete?: () => void;
  onProgressChange?: (msg: ScanProgressMsg | null) => void;
}) {
  const [msg, setMsg] = useState<ScanProgressMsg | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const onCompleteRef = useRef(onScanComplete);
  const onProgressRef = useRef(onProgressChange);
  onCompleteRef.current = onScanComplete;
  onProgressRef.current = onProgressChange;

  useEffect(() => {
    onProgressRef.current?.(msg);
  }, [msg]);

  useEffect(() => {
    const es = new EventSource("/api/v1/events/stream");
    esRef.current = es;
    es.addEventListener("scan_progress", (e) => {
      try {
        const data = JSON.parse(e.data);
        setMsg(data);
        if (data.status === "all_completed" || (data.status === "completed" && data.cves_found !== undefined)) {
          setTimeout(() => {
            setMsg(null);
            onCompleteRef.current?.();
          }, 1500);
        }
      } catch { /* ignore */ }
    });
    es.onerror = () => { setMsg(null); };
    return () => es.close();
  }, []);

  if (!msg) return null;

  if (msg.status === "all_completed") {
    return (
      <div className="bg-terminal-green/10 border border-terminal-green/30 rounded px-3 py-2 text-xs text-terminal-green">
        <div className="flex items-center gap-2">
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          <span className="font-medium">Analysis complete</span>
          <span className="text-terminal-muted">{msg.branches_scanned} branch{msg.branches_scanned !== 1 ? "es" : ""}</span>
        </div>
      </div>
    );
  }

  if (msg.status === "completed" && msg.cves_found !== undefined) {
    return (
      <div className="bg-terminal-green/10 border border-terminal-green/30 rounded px-3 py-2 text-xs text-terminal-green">
        <div className="flex items-center gap-2">
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          <span className="font-medium">{msg.branch}</span>
          <span className="text-terminal-muted">{msg.cves_found} CVEs found</span>
        </div>
      </div>
    );
  }

  const pct = msg.cve_index && msg.cve_total ? Math.round((msg.cve_index / msg.cve_total) * 100) : null;

  return (
    <div className="bg-terminal-accent/10 border border-terminal-accent/30 rounded px-3 py-2 text-xs text-terminal-accent">
      <div className="flex items-center gap-2">
        <svg className="w-3 h-3 animate-spin shrink-0" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        <div className="flex-1 min-w-0">
          <div className="font-medium truncate">
            {msg.branch ? msg.branch.replace(/^cert-manager-/, "") : "Branch"}
            <span className="text-terminal-muted font-normal ml-1">— {scanStatusLabel(msg.status)}</span>
          </div>
          {msg.cve && <div className="font-mono text-[10px] text-terminal-muted truncate">{msg.cve}</div>}
          {pct !== null && (
            <div className="mt-1.5 h-1 bg-terminal-border rounded overflow-hidden">
              <div className="h-full bg-terminal-accent transition-all duration-300" style={{ width: `${pct}%` }} />
            </div>
          )}
        </div>
        {(msg.progress || (msg.cve_index && msg.cve_total)) && (
          <span className="text-terminal-muted font-mono shrink-0">
            {msg.progress || `${msg.cve_index}/${msg.cve_total}`}
          </span>
        )}
      </div>
    </div>
  );
}

function AnalysisOverlay({ progress }: { progress: ScanProgressMsg | null }) {
  if (!progress || progress.status === "all_completed") return null;
  if (progress.status === "completed" && progress.cves_found !== undefined) return null;

  const pct = progress.cve_index && progress.cve_total
    ? Math.round((progress.cve_index / progress.cve_total) * 100)
    : null;

  return (
    <div className="absolute inset-0 z-20 bg-terminal-bg/70 backdrop-blur-[1px] flex items-center justify-center pointer-events-none">
      <div className="bg-terminal-surface border border-terminal-accent/40 rounded-lg px-6 py-5 shadow-xl max-w-md w-full mx-4 pointer-events-auto">
        <div className="flex items-start gap-3">
          <svg className="w-6 h-6 animate-spin text-terminal-accent shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-semibold text-terminal-text">
              {scanStatusLabel(progress.status)}
            </div>
            {progress.branch && (
              <div className="text-xs text-terminal-muted mt-0.5">{progress.branch.replace(/^cert-manager-/, "")}</div>
            )}
            {progress.cve && (
              <div className="font-mono text-xs text-terminal-accent mt-2">{progress.cve}</div>
            )}
            {pct !== null && (
              <div className="mt-3">
                <div className="flex justify-between text-[10px] text-terminal-muted mb-1">
                  <span>CVE progress</span>
                  <span>{progress.cve_index}/{progress.cve_total} ({pct}%)</span>
                </div>
                <div className="h-1.5 bg-terminal-border rounded overflow-hidden">
                  <div className="h-full bg-terminal-accent transition-all duration-300" style={{ width: `${pct}%` }} />
                </div>
              </div>
            )}
            <p className="text-[10px] text-terminal-muted mt-3">
              Fetching ChaiBot analysis from Jira comments…
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Main App ────────────────────────────────────────────────
type Tab = "matrix" | "effort" | "plan" | "report";

export default function App() {
  const [tab, setTab] = useState<Tab>("matrix");
  const [matrix, setMatrix] = useState<MatrixOut | null>(null);
  const [plan, setPlan] = useState<ReleasePlanOut | null>(null);
  const [effort, setEffort] = useState<EffortSummaryOut | null>(null);
  const [branches, setBranches] = useState<ReleaseBranch[]>([]);
  const [selectedBranch, setSelectedBranch] = useState<string>("");
  const [selectedCVE, setSelectedCVE] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanHistoryKey, setScanHistoryKey] = useState(0);
  const [jiraBaseUrl, setJiraBaseUrl] = useState("https://redhat.atlassian.net");
  const [displayName, setDisplayName] = useState("");
  const [scanProgress, setScanProgress] = useState<ScanProgressMsg | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const branchInitialized = useRef(false);
  const branchSyncInFlight = useRef<Promise<void> | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadBranches = useCallback(async () => {
    try {
      let b = await api.getBranches();
      if (b.length === 0) {
        if (!branchSyncInFlight.current) {
          branchSyncInFlight.current = api.syncBranches().then(() => undefined).finally(() => {
            branchSyncInFlight.current = null;
          });
        }
        await branchSyncInFlight.current;
        b = await api.getBranches();
      }
      setBranches(b);
      if (!branchInitialized.current) {
        const first = b.find((br) => br.active);
        if (first) setSelectedBranch(first.name);
        branchInitialized.current = true;
      }
    } catch { /* ignore */ }
  }, []);

  const loadData = useCallback(async () => {
    setError(null);
    try {
      const filter = selectedBranch ? [selectedBranch] : undefined;
      const [m, p, e] = await Promise.all([
        api.getMatrix(filter),
        api.getPlan(),
        api.getEffort(filter),
      ]);
      setMatrix(m);
      setPlan(p);
      setEffort(e);
    } catch (err: any) {
      setError(err.message);
    }
  }, [selectedBranch]);

  useEffect(() => {
    loadBranches();
    api.getConfig().then((cfg) => {
      const url = (cfg.jira as { url?: string })?.url;
      if (url) setJiraBaseUrl(url);
      const dn = (cfg.repository as { display_name?: string })?.display_name;
      if (dn) setDisplayName(dn);
    }).catch(() => {});
  }, [loadBranches]);

  useEffect(() => {
    if (selectedBranch) loadData();
  }, [selectedBranch, loadData]);

  const handleRefresh = useCallback(() => {
    loadBranches();
    loadData();
    setScanHistoryKey((k) => k + 1);
  }, [loadBranches, loadData]);

  // Full Analysis button handler — scans ALL active branches
  async function doFullAnalysis() {
    setAnalyzing(true);
    try {
      await api.triggerFullAnalysis();
      let polls = 0;
      pollRef.current = setInterval(() => {
        polls++;
        handleRefresh();
        if (polls > 100 && pollRef.current) {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setAnalyzing(false);
        }
      }, 3000);
    } catch (e) {
      console.error(e);
      setAnalyzing(false);
    }
  }

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const tabs: { key: Tab; label: string }[] = [
    { key: "matrix", label: "CVE Dashboard" },
    { key: "effort", label: "Effort Summary" },
    { key: "plan", label: "Release Plan" },
    { key: "report", label: "Report" },
  ];

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-terminal-border bg-terminal-surface/60 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-terminal-green animate-pulse" />
          <h1 className="text-lg font-bold text-terminal-text tracking-tight">
            CVE Release Planner
          </h1>
          <span className="text-xs text-terminal-muted">
            {displayName || "cert-manager z-stream"}
          </span>
        </div>
        <div className="flex items-center gap-4">
          <BranchSelector
            branches={branches}
            selected={selectedBranch}
            onChange={setSelectedBranch}
          />
        </div>
      </header>

      <div className="flex-1 flex flex-col lg:flex-row">
        {/* Sidebar */}
        <aside className="w-full lg:w-72 border-b lg:border-b-0 lg:border-r border-terminal-border bg-terminal-surface/30 p-4 space-y-4 overflow-y-auto">
          {/* Full Analysis Button */}
          <div className="space-y-2">
            <h2 className="text-sm font-bold text-terminal-muted uppercase tracking-wider">
              Actions
            </h2>
            <button
              className="w-full px-4 py-3 bg-gradient-to-r from-indigo-900/60 to-purple-900/60 border border-indigo-500 text-indigo-200 text-sm font-medium rounded-lg hover:from-indigo-800/70 hover:to-purple-800/70 transition disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              disabled={analyzing}
              onClick={doFullAnalysis}
            >
              {analyzing ? (
                <>
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Analyzing…
                </>
              ) : (
                <>🔬 Full Analysis</>
              )}
            </button>
            <p className="text-[10px] text-terminal-muted leading-relaxed">
              Jira discovery → ChaiBot comment parsing → Classify → Estimate → Release Plan
            </p>
          </div>

          <SSEProgress
            onProgressChange={setScanProgress}
            onScanComplete={() => {
              if (pollRef.current) {
                clearInterval(pollRef.current);
                pollRef.current = null;
              }
              setAnalyzing(false);
              handleRefresh();
            }}
          />

          {/* Quick stats */}
          {effort && (
            <div className="pt-4 border-t border-terminal-border space-y-2">
              <h3 className="text-xs font-bold text-terminal-muted uppercase">Summary</h3>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="bg-terminal-bg rounded p-2">
                  <div className="text-terminal-muted text-[10px] uppercase">CVEs</div>
                  <div className="text-xl font-bold text-terminal-accent">{effort.total_cve_count}</div>
                </div>
                <div className="bg-terminal-bg rounded p-2">
                  <div className="text-terminal-muted text-[10px] uppercase">Effort</div>
                  <div className="text-xl font-bold text-terminal-yellow">{effort.total_effort_days.toFixed(1)}d</div>
                </div>
              </div>
            </div>
          )}

          {/* Jira status */}
          <div className="pt-4 border-t border-terminal-border">
            <JiraStatusPanel />
          </div>

          {/* Scan History */}
          <div className="pt-4 border-t border-terminal-border space-y-2">
            <h3 className="text-xs font-bold text-terminal-muted uppercase">Scan History</h3>
            <ScanHistory refreshKey={scanHistoryKey} />
          </div>

          {/* Config View */}
          <div className="pt-4 border-t border-terminal-border">
            <ConfigView />
          </div>
        </aside>

        {/* Main content */}
        <main className="flex-1 p-6 space-y-4 overflow-hidden relative">
          <AnalysisOverlay progress={scanProgress} />
          <nav className="flex gap-1 border-b border-terminal-border pb-px">
            {tabs.map((t) => (
              <button
                key={t.key}
                className={`px-4 py-2 text-sm font-medium rounded-t transition ${
                  tab === t.key
                    ? "bg-terminal-surface text-terminal-accent border border-b-0 border-terminal-border"
                    : "text-terminal-muted hover:text-terminal-text"
                }`}
                onClick={() => setTab(t.key)}
              >
                {t.label}
              </button>
            ))}
          </nav>

          {error && (
            <div className="bg-red-900/30 border border-terminal-red text-terminal-red px-4 py-2 rounded text-sm">
              {error}
            </div>
          )}

          <div className="overflow-auto">
            {tab === "matrix" && (
              <CVEGroupedView data={matrix} jiraBaseUrl={jiraBaseUrl} onCVEClick={setSelectedCVE} />
            )}
            {tab === "effort" && <EffortSummary data={effort} />}
            {tab === "plan" && <ReleasePlan data={plan} />}
            {tab === "report" && <ReportView />}
          </div>
        </main>
      </div>

      {/* CVE Detail Panel */}
      {selectedCVE && (
        <CVEDetailPanel
          cveId={selectedCVE}
          jiraBaseUrl={jiraBaseUrl}
          onClose={() => setSelectedCVE(null)}
        />
      )}
    </div>
  );
}
