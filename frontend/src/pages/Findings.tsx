import React, { useState, useEffect } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress, Grid,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer, TableSortLabel,
  FormControl, InputLabel, Select, MenuItem, Button, Tabs, Tab, Skeleton,
  Dialog, DialogTitle, DialogContent, DialogActions, Alert, Tooltip, IconButton,
  Snackbar, TextField, Collapse,
} from "@mui/material";
import {
  BugReport, DeleteOutlined, CleaningServices, FileDownload, CheckCircle, Cancel,
  VisibilityOff, Visibility, AutoAwesome, Refresh,
} from "@mui/icons-material";
import * as Icons from "@mui/icons-material";
import { useMsal } from "@azure/msal-react";
import { loginRequest } from "../auth/msalConfig";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { findingsApi, projectsApi, scansApi, postureApi } from "../services/api";
import { Finding, Project, FindingCategoriesResponse, Scan } from "../types";
import { fromNow } from "../utils/datetime";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8000/api/v1";

// Add suppress/playbook endpoints to findingsApi locally
async function suppressFinding(clientId: string, findingId: string, reason: string, token: string): Promise<void> {
  const res = await fetch(`${API_BASE}/clients/${clientId}/findings/${findingId}/suppress`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ reason }),
  });
  if (!res.ok) throw new Error("Suppress failed");
}

async function unsuppressFinding(clientId: string, findingId: string, token: string): Promise<void> {
  const res = await fetch(`${API_BASE}/clients/${clientId}/findings/${findingId}/suppress`, {
    method: "DELETE",
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
  if (!res.ok) throw new Error("Unsuppress failed");
}

async function generatePlaybook(clientId: string, findingId: string, token: string): Promise<Finding> {
  const res = await fetch(`${API_BASE}/clients/${clientId}/findings/${findingId}/playbook`, {
    method: "POST",
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
  if (!res.ok) throw new Error("Playbook generation failed");
  return res.json();
}

const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50", info: "#4285F4",
};
const STATUS_COLOR: Record<string, string> = {
  open: "#ff9800", remediated: "#00e676", accepted: "#34A853", false_positive: "rgba(255,255,255,0.4)",
};

function CatIcon({ name, sx }: { name: string; sx?: any }) {
  const C = (Icons as any)[name] || Icons.Apps;
  return <C sx={sx || { fontSize: 14 }} />;
}

// Mirror of backend services/finding_classifier.py — used to derive
// per-scan category counts from the already-fetched findings list without
// an extra API call. Must be kept in sync with the Python original.
const _SECTIONS_META: [string, string, [string, string, string][]][] = [
  ["security_posture", "Security Posture", [
    ["vulnerability",       "Vulnerability Findings",       "BugReport"],
    ["cloud_configuration", "Cloud Configuration Findings", "CloudQueue"],
    ["host_configuration",  "Host Configuration Findings",  "Computer"],
    ["attack_surface",      "Attack Surface Findings",      "Public"],
    ["data",                "Data Findings",                "Storage"],
    ["secret",              "Secret Findings",              "VpnKey"],
    ["end_of_life",         "End of Life Findings",         "EventBusy"],
    ["sast",                "SAST Findings",                "Code"],
    ["web",                 "Web Findings",                 "Language"],
    ["network_exposure",    "Network Exposure",             "Lan"],
    ["excessive_access",    "Excessive Access Findings",    "GroupAdd"],
    ["identity_access",     "Identity Access Findings",     "Person"],
    ["ai_security",         "AI Security Findings",         "Psychology"],
  ]],
  ["threat_detection", "Threat Detection", [
    ["detections", "Detections", "Notifications"],
  ]],
  ["secure_development", "Secure Development", [
    ["code_build_scans",     "Code & Build Scans",           "Build"],
    ["kubernetes_admission", "Kubernetes Admission Reviews", "AllInbox"],
  ]],
];
const _CAT_TO_SEC: Record<string, string> = {};
for (const [sec, , cats] of _SECTIONS_META) for (const [cat] of cats) _CAT_TO_SEC[cat] = sec;

function _classifyFinding(f: Finding): [string, string] {
  const title = (f.title || "").toLowerCase();
  const rt    = (f.resource_type || "").toLowerCase();
  const ctrl  = (f.control_id || "").toUpperCase();
  const sp = "security_posture";
  if (rt.startsWith("web/") || ctrl.startsWith("ZAP-") || ctrl.startsWith("CWE-")) return [sp, "web"];
  if (["xss","cross-site scripting","sql injection","csrf","clickjacking","session fixation","open redirect"].some(k => title.includes(k))) return [sp, "web"];
  if (f.cve_id || (f.cvss_score && f.cvss_score > 0)) return [sp, "vulnerability"];
  if (["secret","credential leaked","api key exposed","private key"].some(k => title.includes(k))) return [sp, "secret"];
  if (["end of life","end-of-life","eol","deprecated","out of support","unsupported version"].some(k => title.includes(k))) return [sp, "end_of_life"];
  if (["sast","code scan","source code"].some(k => title.includes(k))) return [sp, "sast"];
  if (["prompt injection","ai model","llm","model jailbreak"].some(k => title.includes(k))) return [sp, "ai_security"];
  if (["alert","detection","anomalous","suspicious activity","runtime threat"].some(k => title.includes(k))) return ["threat_detection", "detections"];
  if (["admission webhook","podsecuritypolicy","k8s admission"].some(k => title.includes(k))) return ["secure_development", "kubernetes_admission"];
  if (["ci pipeline","build artifact","container image scan","image scan"].some(k => title.includes(k))) return ["secure_development", "code_build_scans"];
  if (["nsg","port ","internet","public ip","0.0.0.0/0","exposed"].some(k => title.includes(k))) return [sp, "network_exposure"];
  if (["SC-7","AC-17"].includes(ctrl) || rt.includes("networksecuritygroups") || rt.includes("securitygroup")) return [sp, "network_exposure"];
  if (["public dns","exposed endpoint","publicly accessible","front door"].some(k => title.includes(k))) return [sp, "attack_surface"];
  if (["mfa","multi-factor","password policy","authentication","sign-in"].some(k => title.includes(k))) return [sp, "identity_access"];
  if (["AC-2","IA-2"].includes(ctrl)) return [sp, "identity_access"];
  if (["owner role","admin","privilege","rbac"].some(k => title.includes(k))) return [sp, "excessive_access"];
  if (ctrl === "AC-6") return [sp, "excessive_access"];
  if (["storage","blob","bucket","encryption","tls","https-only","encrypt"].some(k => title.includes(k))) return [sp, "data"];
  if (rt.includes("storageaccounts") || rt.includes("::s3::") || rt.includes("buckets")) return [sp, "data"];
  if (rt.includes("virtualmachines") || rt.includes("ec2") || rt.includes("googleapis.com/instance")) return [sp, "host_configuration"];
  return [sp, "cloud_configuration"];
}

// Per-category accent colors — keeps each tile distinct in the grid.
const CAT_COLOR: Record<string, string> = {
  vulnerability:       "#f44336",
  cloud_configuration: "#4285F4",
  host_configuration:  "#34A853",
  attack_surface:      "#ff6d00",
  data:                "#ff9800",
  secret:              "#ffd54f",
  end_of_life:         "#9e9e9e",
  sast:                "#00e676",
  web:                 "#FBBC04",
  network_exposure:    "#03a9f4",
  excessive_access:    "#ff5252",
  identity_access:     "#f06292",
  ai_security:         "#ba68c8",
  detections:          "#ff4081",
  code_build_scans:    "#26c6da",
  kubernetes_admission:"#9ccc65",
};

function CategoryTile({ cat, active, onClick }: {
  cat: { key: string; label: string; icon: string; count: number };
  active: boolean;
  onClick: () => void;
}) {
  const color = CAT_COLOR[cat.key] || "#4285F4";
  const empty = cat.count === 0;
  return (
    <Card onClick={onClick}
      sx={{
        bgcolor: active ? `${color}15` : "#1E1E1E",
        border: active ? `1px solid ${color}` : "1px solid rgba(255,255,255,0.08)",
        borderRadius: 2, cursor: "pointer", height: "100%",
        transition: "transform .12s, border-color .12s, background-color .12s",
        opacity: empty && !active ? 0.6 : 1,
        "&:hover": {
          borderColor: color,
          bgcolor: active ? `${color}20` : `${color}08`,
          transform: "translateY(-1px)",
        },
      }}>
      <CardContent sx={{ p: 1.75, "&:last-child": { pb: 1.75 } }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.75 }}>
          <Box sx={{ width: 32, height: 32, borderRadius: 1, bgcolor: `${color}20`,
            display: "flex", alignItems: "center", justifyContent: "center" }}>
            <CatIcon name={cat.icon} sx={{ fontSize: 18, color }} />
          </Box>
          <Typography sx={{ color: empty ? "rgba(255,255,255,0.5)" : "text.secondary",
            fontSize: 26, fontWeight: 700, lineHeight: 1, ml: "auto" }}>
            {cat.count}
          </Typography>
        </Box>
        <Typography variant="body2" sx={{ color: "text.secondary",
          fontSize: 12, fontWeight: 500, lineHeight: 1.25 }}>
          {cat.label}
        </Typography>
      </CardContent>
    </Card>
  );
}

export default function Findings() {
  const qc = useQueryClient();
  const { clientId } = useActiveClient();
  const { instance, accounts } = useMsal();
  const [projectId, setProjectId] = useState("");
  const [scanId, setScanId] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [section, setSection] = useState("security_posture");
  const [category, setCategory] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [showSuppressed, setShowSuppressed] = React.useState(false);

  const handleExport = async () => {
    const account = accounts[0];
    let token = "";
    if (account) {
      try {
        const resp = await instance.acquireTokenSilent({ ...loginRequest, account });
        token = resp.accessToken;
      } catch { }
    }
    const params = new URLSearchParams();
    if (sevFilter) params.set("severity", sevFilter);
    if (statusFilter) params.set("status", statusFilter);
    if (scanId) params.set("scan_id", scanId);
    const res = await fetch(
      `${API_BASE}/clients/${clientId}/findings/export/?${params}`,
      { headers: token ? { Authorization: `Bearer ${token}` } : {} }
    );
    if (!res.ok) return;
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `findings-${clientId}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", clientId],
    queryFn: () => projectsApi.list(clientId),
    enabled: !!clientId,
  });
  const { data: scans = [] } = useQuery<Scan[]>({
    queryKey: ["scans-for-findings", clientId],
    queryFn: () => scansApi.list(clientId),
    enabled: !!clientId,
  });
  const { data: catData } = useQuery<FindingCategoriesResponse>({
    queryKey: ["findings-categories", clientId, projectId, statusFilter],
    queryFn: () => findingsApi.categories(clientId, projectId || undefined, statusFilter || "open"),
    enabled: !!clientId,
  });
  const { data: findings = [], isLoading } = useQuery<Finding[]>({
    queryKey: ["findings-all", clientId, projectId, scanId, sevFilter, statusFilter, section, category, showSuppressed],
    queryFn: async () => {
      const params: Record<string, any> = {};
      if (sevFilter) params.severity = sevFilter;
      if (statusFilter) params.status = statusFilter;
      if (projectId) params.project_id = projectId;
      if (section) params.section = section;
      if (category) params.category = category;
      if (scanId) params.scan_id = scanId;
      if (showSuppressed) params.include_suppressed = true;
      const { data } = await (await import("../services/api")).apiClient.get(
        `/clients/${clientId}/findings/`,
        { params }
      );
      return data;
    },
    enabled: !!clientId,
  });

  // Posture history for MTTR display (last 30 days, latest snapshot)
  const { data: postureHistory = [] } = useQuery<any[]>({
    queryKey: ["posture-history-findings", clientId],
    queryFn: () => postureApi.getHistory(clientId, 30),
    enabled: !!clientId,
  });
  const sortedPosture = [...postureHistory].sort(
    (a, b) => new Date(a.captured_at).getTime() - new Date(b.captured_at).getTime()
  );
  const latestPosture = sortedPosture[sortedPosture.length - 1] ?? null;
  const prevPosture = sortedPosture[sortedPosture.length - 2] ?? null;

  // When a specific scan is selected the catData query still returns global
  // (all-scan) counts. Recompute counts from the already-fetched scan-filtered
  // findings list so the tiles reflect only that scan's data.
  const scanFilteredCatData = React.useMemo((): FindingCategoriesResponse | null => {
    if (!scanId || findings.length === 0) return null;
    const secCounts: Record<string, Record<string, number>> = {};
    for (const f of findings) {
      const [sec, cat] = _classifyFinding(f);
      if (!secCounts[sec]) secCounts[sec] = {};
      secCounts[sec][cat] = (secCounts[sec][cat] || 0) + 1;
    }
    const sections = _SECTIONS_META.map(([key, label, cats]) => ({
      key,
      label,
      total: Object.values(secCounts[key] || {}).reduce((a, b) => a + b, 0),
      categories: cats.map(([catKey, catLabel, catIcon]) => ({
        key: catKey, label: catLabel, icon: catIcon,
        count: (secCounts[key] || {})[catKey] || 0,
      })),
    }));
    return { sections, grand_total: findings.length };
  }, [scanId, findings]);

  const effectiveCatData = scanId ? scanFilteredCatData : catData;

  const sectionData = (effectiveCatData?.sections || []).find((s) => s.key === section);
  // Only surface sections that actually have findings — empty ones (e.g. Threat
  // Detection with no runtime source, Secure Development with no code scans) are
  // hidden so the page doesn't show blank tabs.
  const visibleSections = (effectiveCatData?.sections || []).filter((s) => s.total > 0);
  // If the active section has no findings, jump to the first populated one.
  useEffect(() => {
    if (visibleSections.length && !visibleSections.some((s) => s.key === section)) {
      setSection(visibleSections[0].key);
      setCategory("");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effectiveCatData]); // eslint-disable-line react-hooks/exhaustive-deps

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: any) => findingsApi.update(clientId, id, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["findings-all"] }); setSelected(null); },
  });

  const [pendingDelete, setPendingDelete] = React.useState<Finding | null>(null);
  const [snack, setSnack] = React.useState<string>("");

  const deleteMutation = useMutation({
    mutationFn: (findingId: string) => findingsApi.delete(clientId, findingId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings-all"] });
      qc.invalidateQueries({ queryKey: ["findings-categories"] });
      setPendingDelete(null);
      setSelected(null);
      setSnack("Finding deleted");
    },
  });

  const cleanupBlankMutation = useMutation({
    mutationFn: () => findingsApi.cleanupBlank(clientId),
    onSuccess: (resp: any) => {
      qc.invalidateQueries({ queryKey: ["findings-all"] });
      qc.invalidateQueries({ queryKey: ["findings-categories"] });
      setSnack(`Deleted ${resp?.deleted ?? 0} blank finding(s)`);
    },
  });

  // Suppress dialog state
  const [suppressTarget, setSuppressTarget] = React.useState<Finding | null>(null);
  const [suppressReason, setSuppressReason] = React.useState("");

  // Playbook state
  const [playbookFindingId, setPlaybookFindingId] = React.useState<string | null>(null);
  const [playbookLoading, setPlaybookLoading] = React.useState(false);
  const [playbookData, setPlaybookData] = React.useState<Record<string, string>>({});
  const [playbookOpen, setPlaybookOpen] = React.useState<Record<string, boolean>>({});

  const suppressMutation = useMutation({
    mutationFn: async ({ finding, reason }: { finding: Finding; reason: string }) => {
      const account = accounts[0];
      let token = "";
      if (account) {
        try { const r = await instance.acquireTokenSilent({ ...loginRequest, account }); token = r.accessToken; } catch { }
      }
      await suppressFinding(clientId, finding.id, reason, token);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings-all"] });
      qc.invalidateQueries({ queryKey: ["findings-categories"] });
      setSuppressTarget(null);
      setSuppressReason("");
      setSnack("Finding suppressed");
    },
  });

  const unsuppressMutation = useMutation({
    mutationFn: async (findingId: string) => {
      const account = accounts[0];
      let token = "";
      if (account) {
        try { const r = await instance.acquireTokenSilent({ ...loginRequest, account }); token = r.accessToken; } catch { }
      }
      await unsuppressFinding(clientId, findingId, token);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings-all"] });
      qc.invalidateQueries({ queryKey: ["findings-categories"] });
      setSnack("Finding unsuppressed");
    },
  });

  const handleGeneratePlaybook = async (f: Finding) => {
    // If playbook already exists on the finding object, just toggle panel
    if (f.playbook && !playbookData[f.id]) {
      setPlaybookData(prev => ({ ...prev, [f.id]: f.playbook! }));
    }
    setPlaybookOpen(prev => ({ ...prev, [f.id]: !prev[f.id] }));
    if (!f.playbook && !playbookData[f.id]) {
      setPlaybookLoading(true);
      setPlaybookFindingId(f.id);
      try {
        const account = accounts[0];
        let token = "";
        if (account) {
          try { const r = await instance.acquireTokenSilent({ ...loginRequest, account }); token = r.accessToken; } catch { }
        }
        const updated = await generatePlaybook(clientId, f.id, token);
        if (updated.playbook) {
          setPlaybookData(prev => ({ ...prev, [f.id]: updated.playbook! }));
          setPlaybookOpen(prev => ({ ...prev, [f.id]: true }));
          qc.invalidateQueries({ queryKey: ["findings-all"] });
        }
      } catch {
        setSnack("Failed to generate playbook");
      } finally {
        setPlaybookLoading(false);
        setPlaybookFindingId(null);
      }
    }
  };

  const [sortKey, setSortKey] = React.useState<string>("first_seen_at");
  const [sortDir, setSortDir] = React.useState<"asc" | "desc">("desc");
  const sortedFindings = React.useMemo(() => {
    const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const dir = sortDir === "asc" ? 1 : -1;
    return [...findings].sort((a, b) => {
      let av: any = (a as any)[sortKey];
      let bv: any = (b as any)[sortKey];
      if (sortKey === "severity") {
        av = SEV_RANK[(typeof a.severity === "object" ? (a.severity as any).value : a.severity) || "info"] ?? 99;
        bv = SEV_RANK[(typeof b.severity === "object" ? (b.severity as any).value : b.severity) || "info"] ?? 99;
      }
      if (sortKey === "first_seen_at") {
        av = a.first_seen_at || a.created_at;
        bv = b.first_seen_at || b.created_at;
      }
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av || "").localeCompare(String(bv || "")) * dir;
    });
  }, [findings, sortKey, sortDir]);
  const setSort = (k: string) => {
    if (sortKey === k) setSortDir(sortDir === "asc" ? "desc" : "asc");
    else { setSortKey(k); setSortDir("desc"); }
  };

  const sevCounts = findings.reduce((acc: Record<string, number>, f) => {
    const s = typeof f.severity === "object" ? (f.severity as any).value ?? f.severity : f.severity;
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>Findings</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            {scanId ? "Findings for selected scan (no deduplication)" : "Consolidated findings across all scans — deduplicated by vulnerability"}
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 160 }} disabled={!clientId}>
            <InputLabel sx={{ color: "text.secondary" }}>Project</InputLabel>
            <Select value={projectId} onChange={(e) => { setProjectId(e.target.value); setScanId(""); }} label="Project"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">All projects</MenuItem>
              {projects.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 180 }} disabled={!clientId}>
            <InputLabel sx={{ color: "text.secondary" }}>Scan</InputLabel>
            <Select value={scanId} onChange={(e) => setScanId(e.target.value)} label="Scan"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">All scans</MenuItem>
              {scans.map((s) => (
                <MenuItem key={s.id} value={s.id}>
                  {(s as any).name || (s as any).scan_type || s.id.slice(0, 8)}
                  {(s as any).findings_count ? ` (${(s as any).findings_count})` : ""}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 130 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Severity</InputLabel>
            <Select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} label="Severity"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">All</MenuItem>
              {["critical","high","medium","low","info"].map((s) => (
                <MenuItem key={s} value={s} sx={{ color: SEV_COLOR[s] }}>{s.charAt(0).toUpperCase() + s.slice(1)}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 130 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Status</InputLabel>
            <Select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} label="Status"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">All</MenuItem>
              <MenuItem value="open">Open</MenuItem>
              <MenuItem value="remediated">Remediated</MenuItem>
              <MenuItem value="accepted">Accepted</MenuItem>
              <MenuItem value="false_positive">False Positive</MenuItem>
            </Select>
          </FormControl>
          <Chip
            icon={showSuppressed ? <Visibility sx={{ fontSize: 14 }} /> : <VisibilityOff sx={{ fontSize: 14 }} />}
            label={showSuppressed ? "Suppressed shown" : "Show suppressed"}
            size="small"
            onClick={() => setShowSuppressed(v => !v)}
            variant={showSuppressed ? "filled" : "outlined"}
            sx={{
              cursor: "pointer",
              bgcolor: showSuppressed ? "rgba(255,255,255,0.1)" : "transparent",
              color: showSuppressed ? "text.primary" : "text.secondary",
              borderColor: "divider",
              "& .MuiChip-icon": { color: "inherit" },
            }}
          />
          <Button
            size="small"
            variant="outlined"
            startIcon={<FileDownload sx={{ fontSize: 16 }} />}
            disabled={!clientId}
            onClick={handleExport}
            sx={{
              color: "text.secondary",
              borderColor: "divider",
              textTransform: "none",
              "&:hover": { borderColor: "#34A853", color: "#34A853", bgcolor: "rgba(52,168,83,0.05)" },
            }}
          >
            Export CSV
          </Button>
        </Box>
      </Box>

      {/* MTTR strip — compact row shown when posture history is available */}
      {clientId && latestPosture && (
        <Box sx={{ display: "flex", gap: 1.5, mb: 2.5, flexWrap: "wrap", alignItems: "center" }}>
          <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mr: 0.5 }}>
            MTTR:
          </Typography>
          {[
            {
              label: "Critical",
              hours: latestPosture.mttr_critical_hours as number | null,
              prevHours: prevPosture?.mttr_critical_hours as number | null | undefined,
              sla: 24,
            },
            {
              label: "High",
              hours: latestPosture.mttr_high_hours as number | null,
              prevHours: prevPosture?.mttr_high_hours as number | null | undefined,
              sla: 168,
            },
          ].map(({ label, hours, prevHours, sla }) => {
            const withinSla = hours != null && hours < sla;
            const improving = hours != null && prevHours != null && hours < prevHours;
            const display =
              hours == null
                ? "—"
                : hours < 1
                ? `${Math.round(hours * 60)}m`
                : hours < 24
                ? `${hours.toFixed(1)}h`
                : `${(hours / 24).toFixed(1)}d`;
            return (
              <Tooltip
                key={label}
                title={
                  hours == null
                    ? `${label}: no data`
                    : `${label} MTTR: ${display} — SLA ${hours < sla ? "met" : "breached"} (target < ${sla}h)${improving ? " — Improving" : ""}`
                }
              >
                <Chip
                  size="small"
                  icon={
                    hours == null ? undefined : withinSla ? (
                      <CheckCircle sx={{ fontSize: "14px !important", color: "#34A853 !important" }} />
                    ) : (
                      <Cancel sx={{ fontSize: "14px !important", color: "#f44336 !important" }} />
                    )
                  }
                  label={`${label}: ${display}${improving ? " ↓" : ""}`}
                  sx={{
                    bgcolor: hours == null
                      ? "rgba(255,255,255,0.06)"
                      : withinSla
                      ? "rgba(52,168,83,0.12)"
                      : "rgba(244,67,54,0.12)",
                    color: hours == null
                      ? "text.secondary"
                      : withinSla
                      ? "#34A853"
                      : "#f44336",
                    fontSize: 11,
                    height: 22,
                    fontWeight: improving ? 700 : 400,
                  }}
                />
              </Tooltip>
            );
          })}
          {latestPosture.compliance_score != null && (
            <Chip
              size="small"
              label={`Compliance: ${(latestPosture.compliance_score as number).toFixed(1)}%`}
              sx={{
                bgcolor: "rgba(66,133,244,0.12)",
                color: "#82b1ff",
                fontSize: 11,
                height: 22,
              }}
            />
          )}
        </Box>
      )}

      {clientId && (
        <>
          {/* Section tabs */}
          <Tabs value={section} onChange={(_, v) => { setSection(v); setCategory(""); }}
            sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)", mb: 1.5,
              "& .MuiTab-root": { color: "text.secondary", textTransform: "none", fontWeight: 500 },
              "& .Mui-selected": { color: "#4285F4" }, "& .MuiTabs-indicator": { backgroundColor: "#4285F4" } }}>
            {visibleSections.map((s) => (
              <Tab key={s.key} value={s.key} label={`${s.label} (${s.total})`} />
            ))}
          </Tabs>

          {/* Category tile grid */}
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11, fontWeight: 600, letterSpacing: 0.5 }}>
              CATEGORIES — CLICK TO FILTER
            </Typography>
            {category && (
              <Button size="small" onClick={() => setCategory("")}
                sx={{ color: "#4285F4", fontSize: 11 }}>
                Clear category
              </Button>
            )}
          </Box>
          <Grid container spacing={1.5} sx={{ mb: 2 }}>
            {!effectiveCatData ? (
              [0, 1, 2, 3, 4, 5].map((i) => (
                <Grid key={i} size={{ xs: 6, sm: 4, md: 3, lg: 2 }}>
                  <Skeleton variant="rectangular" height={88}
                    sx={{ borderRadius: 2, bgcolor: "rgba(255,255,255,0.04)" }} />
                </Grid>
              ))
            ) : (
              (sectionData?.categories || []).map((c) => (
                <Grid key={c.key} size={{ xs: 6, sm: 4, md: 3, lg: 2 }}>
                  <CategoryTile cat={c}
                    active={category === c.key}
                    onClick={() => setCategory(category === c.key ? "" : c.key)} />
                </Grid>
              ))
            )}
          </Grid>

          {findings.length > 0 && (
            <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap", alignItems: "center" }}>
              {["critical","high","medium","low","info"].filter((s) => sevCounts[s]).map((s) => (
                <Chip key={s} label={`${s.charAt(0).toUpperCase() + s.slice(1)}: ${sevCounts[s]}`} size="small"
                  onClick={() => setSevFilter(sevFilter === s ? "" : s)}
                  sx={{ bgcolor: `${SEV_COLOR[s]}${sevFilter === s ? "40" : "20"}`, color: SEV_COLOR[s],
                    border: sevFilter === s ? `1px solid ${SEV_COLOR[s]}` : "none", cursor: "pointer" }} />
              ))}
              <Typography variant="caption" sx={{ color: "text.secondary", alignSelf: "center", ml: 1 }}>
                {findings.length} matching
              </Typography>
              <Box sx={{ flex: 1 }} />
              <Button
                size="small"
                variant="outlined"
                startIcon={<CleaningServices sx={{ fontSize: 16 }} />}
                disabled={cleanupBlankMutation.isPending}
                onClick={() => {
                  if (window.confirm("Delete all findings that have no title, description, or resource? This is used to tidy up empty rows after a scanner returned partial data.")) {
                    cleanupBlankMutation.mutate();
                  }
                }}
                sx={{
                  color: "text.secondary",
                  borderColor: "divider",
                  textTransform: "none",
                  "&:hover": { borderColor: "#EA4335", color: "#EA4335", bgcolor: "rgba(234,67,53,0.05)" },
                }}
              >
                Delete blank findings
              </Button>
            </Box>
          )}
        </>
      )}

      {!clientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "text.primary" }}>Select a client to view findings.</Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#4285F4" }} /></Box>
      ) : findings.length === 0 ? (
        <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <BugReport sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No findings found. Run a scan to discover security issues.
          </Typography>
        </Card>
      ) : (
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                  <TableCell><TableSortLabel active={sortKey === "severity"} direction={sortDir} onClick={() => setSort("severity")}
                    sx={{ color: "rgba(255,255,255,0.5) !important", "& .MuiTableSortLabel-icon": { color: "rgba(255,255,255,0.5) !important" } }}>SEVERITY</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "title"} direction={sortDir} onClick={() => setSort("title")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>TITLE</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "cve_id"} direction={sortDir} onClick={() => setSort("cve_id")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>CVE</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "cvss_score"} direction={sortDir} onClick={() => setSort("cvss_score")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>CVSS</TableSortLabel></TableCell>
                  <TableCell>RESOURCE</TableCell>
                  <TableCell><TableSortLabel active={sortKey === "status"} direction={sortDir} onClick={() => setSort("status")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>STATUS</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "first_seen_at"} direction={sortDir} onClick={() => setSort("first_seen_at")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>FOUND</TableSortLabel></TableCell>
                  <TableCell align="right" sx={{ width: 44 }} />
                  <TableCell align="right" sx={{ width: 220, whiteSpace: "nowrap" }} />
                </TableRow>
              </TableHead>
              <TableBody>
                {sortedFindings.map((f) => {
                  const sev = typeof f.severity === "object" ? (f.severity as any).value ?? f.severity : f.severity;
                  return (
                    <TableRow key={f.id}
                      sx={{ cursor: "pointer", "&:hover": { bgcolor: "rgba(255,255,255,0.03)" },
                        "& td": { borderColor: "divider", py: 1 } }}
                      onClick={() => setSelected(f)}>
                      <TableCell>
                        <Chip label={sev} size="small"
                          sx={{ bgcolor: `${SEV_COLOR[sev] || "#888"}20`, color: SEV_COLOR[sev] || "#888", fontSize: 10, height: 18 }} />
                      </TableCell>
                      <TableCell sx={{ color: "text.primary", maxWidth: 300 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                          <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {f.title}
                          </Typography>
                          {(() => {
                            const n = f.occurrence_count ?? f.seen_count ?? 1;
                            if (n > 1) return (
                              <Tooltip title={`Re-confirmed in ${n} scans — same issue, not a new finding`}>
                                <Chip label={`×${n}`} size="small"
                                  sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontSize: 10, height: 16, flexShrink: 0 }} />
                              </Tooltip>
                            );
                            if (f.duplicate_of_id) return (
                              <Tooltip title="Duplicate — links to an existing finding detected in a previous scan">
                                <Chip label="DUP" size="small"
                                  sx={{ bgcolor: "rgba(255,152,0,0.12)", color: "#ff9800", fontSize: 10, height: 16, flexShrink: 0 }} />
                              </Tooltip>
                            );
                            return null;
                          })()}
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: f.cve_id ? "#4285F4" : "text.secondary", fontSize: 12 }}>
                        {f.cve_id || "—"}
                      </TableCell>
                      <TableCell sx={{ color: f.cvss_score != null ? (f.cvss_score >= 9 ? "#f44336" : f.cvss_score >= 7 ? "#ff9800" : "white") : "rgba(255,255,255,0.3)", fontSize: 12 }}>
                        {f.cvss_score != null ? f.cvss_score.toFixed(1) : "—"}
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 12, maxWidth: 160 }}>
                        <Typography variant="caption" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>
                          {f.resource_id || f.resource_type || "—"}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={f.status || "open"} size="small"
                          sx={{ bgcolor: `${STATUS_COLOR[f.status || "open"] || "#888"}20`,
                            color: STATUS_COLOR[f.status || "open"] || "#888", fontSize: 10, height: 18 }} />
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>
                        {(() => {
                          const ts = f.first_seen_at || f.created_at;
                          return fromNow(ts);
                        })()}
                      </TableCell>
                      <TableCell align="right" sx={{ width: 44 }}>
                        <Tooltip title="Delete finding">
                          <IconButton
                            size="small"
                            onClick={(e) => { e.stopPropagation(); setPendingDelete(f); }}
                            sx={{
                              color: "text.secondary",
                              "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" },
                            }}
                          >
                            <DeleteOutlined sx={{ fontSize: 18 }} />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                      {/* Actions: Suppress + Playbook */}
                      <TableCell align="right" sx={{ width: 220, whiteSpace: "nowrap" }} onClick={(e) => e.stopPropagation()}>
                        <Box sx={{ display: "flex", gap: 0.5, justifyContent: "flex-end", alignItems: "center" }}>
                          {/* Playbook button */}
                          <Tooltip title={playbookData[f.id] || f.playbook ? "Toggle playbook" : "Generate AI playbook"}>
                            <Button
                              size="small"
                              variant="outlined"
                              startIcon={
                                playbookLoading && playbookFindingId === f.id
                                  ? <CircularProgress size={12} sx={{ color: "#FBBC04" }} />
                                  : <AutoAwesome sx={{ fontSize: 13 }} />
                              }
                              onClick={(e) => { e.stopPropagation(); handleGeneratePlaybook(f); }}
                              disabled={playbookLoading && playbookFindingId === f.id}
                              sx={{
                                fontSize: 10,
                                py: 0.25,
                                px: 0.75,
                                color: "#FBBC04",
                                borderColor: "rgba(251,188,4,0.3)",
                                textTransform: "none",
                                minWidth: 0,
                                "&:hover": { borderColor: "#FBBC04", bgcolor: "rgba(251,188,4,0.06)" },
                              }}
                            >
                              {playbookData[f.id] || f.playbook
                                ? (playbookOpen[f.id] ? "Hide" : "Playbook")
                                : "Playbook"}
                            </Button>
                          </Tooltip>

                          {/* Suppress / Unsuppress */}
                          {f.status === "false_positive" ? (
                            <Tooltip title="Unsuppress this finding">
                              <Button
                                size="small"
                                variant="outlined"
                                startIcon={<Visibility sx={{ fontSize: 13 }} />}
                                disabled={unsuppressMutation.isPending}
                                onClick={(e) => { e.stopPropagation(); unsuppressMutation.mutate(f.id); }}
                                sx={{
                                  fontSize: 10, py: 0.25, px: 0.75,
                                  color: "#4285F4", borderColor: "rgba(66,133,244,0.3)",
                                  textTransform: "none", minWidth: 0,
                                  "&:hover": { borderColor: "#4285F4", bgcolor: "rgba(66,133,244,0.06)" },
                                }}
                              >
                                Unsuppress
                              </Button>
                            </Tooltip>
                          ) : (
                            <Tooltip title="Mark as false positive / suppress">
                              <Button
                                size="small"
                                variant="outlined"
                                startIcon={<VisibilityOff sx={{ fontSize: 13 }} />}
                                onClick={(e) => { e.stopPropagation(); setSuppressTarget(f); setSuppressReason(""); }}
                                sx={{
                                  fontSize: 10, py: 0.25, px: 0.75,
                                  color: "text.secondary", borderColor: "divider",
                                  textTransform: "none", minWidth: 0,
                                  "&:hover": { borderColor: "rgba(255,255,255,0.3)", color: "text.primary" },
                                }}
                              >
                                Suppress
                              </Button>
                            </Tooltip>
                          )}
                        </Box>

                        {/* Playbook expansion panel */}
                        <Collapse in={!!(playbookOpen[f.id] && (playbookData[f.id] || f.playbook))} unmountOnExit>
                          <Box
                            sx={{
                              mt: 1, p: 1.25, borderRadius: 1,
                              bgcolor: "rgba(251,188,4,0.06)",
                              border: "1px solid rgba(251,188,4,0.2)",
                              textAlign: "left",
                              maxWidth: 420,
                              ml: "auto",
                            }}
                            onClick={(e) => e.stopPropagation()}
                          >
                            <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, mb: 0.75 }}>
                              <AutoAwesome sx={{ fontSize: 13, color: "#FBBC04" }} />
                              <Typography variant="caption" sx={{ color: "#FBBC04", fontWeight: 700, fontSize: 10 }}>
                                AI REMEDIATION PLAYBOOK
                              </Typography>
                              <Box sx={{ flex: 1 }} />
                              <Tooltip title="Regenerate playbook">
                                <IconButton
                                  size="small"
                                  onClick={() => {
                                    setPlaybookData(prev => { const n = { ...prev }; delete n[f.id]; return n; });
                                    handleGeneratePlaybook({ ...f, playbook: undefined });
                                  }}
                                  sx={{ color: "rgba(251,188,4,0.5)", "&:hover": { color: "#FBBC04" }, p: 0.25 }}
                                >
                                  <Refresh sx={{ fontSize: 14 }} />
                                </IconButton>
                              </Tooltip>
                            </Box>
                            <Typography
                              variant="body2"
                              sx={{ color: "text.secondary", fontSize: 11, whiteSpace: "pre-wrap", lineHeight: 1.6 }}
                            >
                              {playbookData[f.id] || f.playbook}
                            </Typography>
                          </Box>
                        </Collapse>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        </Card>
      )}

      {/* Detail / status update dialog */}
      <Dialog open={!!selected} onClose={() => setSelected(null)} maxWidth="md" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        {selected && (() => {
          const sev = typeof selected.severity === "object" ? (selected.severity as any).value ?? selected.severity : selected.severity;
          return (
            <>
              <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)", pb: 1.5 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Chip label={sev} size="small" sx={{ bgcolor: `${SEV_COLOR[sev]}20`, color: SEV_COLOR[sev], fontSize: 11 }} />
                  <Typography sx={{ fontWeight: 600 }}>{selected.title}</Typography>
                </Box>
              </DialogTitle>
              <DialogContent sx={{ mt: 1 }}>
                {selected.description && (
                  <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>{selected.description}</Typography>
                )}
                <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2 }}>
                  {selected.cve_id && <Chip label={selected.cve_id} size="small" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4" }} />}
                  {selected.cvss_score != null && <Chip label={`CVSS ${selected.cvss_score.toFixed(1)}`} size="small" sx={{ bgcolor: "rgba(255,255,255,0.08)", color: "text.primary" }} />}
                  {selected.control_id && <Chip label={selected.control_id} size="small" sx={{ bgcolor: "rgba(124,77,255,0.2)", color: "#34A853" }} />}
                </Box>
                {selected.resource_id && (
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 2 }}>
                    {selected.resource_type === "code_file" ? "File" : selected.resource_type === "host" || selected.resource_type === "ip" ? "Host" : "Resource"}: {selected.resource_id}
                  </Typography>
                )}
                {/* Dedup metadata row */}
                {(() => {
                  const n = selected.occurrence_count ?? selected.seen_count ?? 1;
                  const firstSeen = selected.first_seen_at || selected.created_at;
                  const lastSeen = selected.last_seen_at;
                  if (n <= 1 && !lastSeen) return null;
                  return (
                    <Box sx={{ display: "flex", gap: 1.5, flexWrap: "wrap", mb: 2 }}>
                      {n > 1 && (
                        <Chip
                          size="small"
                          label={`Confirmed in ${n} scans`}
                          sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", fontSize: 11, height: 22 }}
                        />
                      )}
                      {firstSeen && (
                        <Chip
                          size="small"
                          label={`First seen: ${fromNow(firstSeen)}`}
                          sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", fontSize: 11, height: 22 }}
                        />
                      )}
                      {lastSeen && lastSeen !== firstSeen && (
                        <Chip
                          size="small"
                          label={`Last confirmed: ${fromNow(lastSeen)}`}
                          sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", fontSize: 11, height: 22 }}
                        />
                      )}
                    </Box>
                  );
                })()}
                {selected.remediation && (
                  <Box sx={{ bgcolor: "rgba(0,230,118,0.08)", border: "1px solid rgba(0,230,118,0.2)", borderRadius: 1, p: 1.5, mb: 2 }}>
                    <Typography variant="caption" sx={{ color: "#00e676", fontWeight: 600, display: "block", mb: 0.5 }}>Remediation</Typography>
                    <Typography variant="body2" sx={{ color: "text.secondary" }}>{selected.remediation}</Typography>
                  </Box>
                )}
                <Box>
                  <Typography variant="caption" sx={{ color: "text.secondary", mb: 1, display: "block" }}>Update Status</Typography>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    {["open","remediated","accepted","false_positive"].map((s) => (
                      <Chip key={s} label={s.replace("_", " ")} size="small" clickable
                        onClick={() => updateMutation.mutate({ id: selected.id, data: { status: s } })}
                        sx={{ bgcolor: selected.status === s ? `${STATUS_COLOR[s]}40` : `${STATUS_COLOR[s]}15`,
                          color: STATUS_COLOR[s], border: selected.status === s ? `1px solid ${STATUS_COLOR[s]}` : "none",
                          cursor: "pointer" }} />
                    ))}
                  </Box>
                </Box>
              </DialogContent>
              <DialogActions sx={{ p: 2 }}>
                <Button
                  startIcon={<DeleteOutlined />}
                  onClick={() => setPendingDelete(selected)}
                  sx={{
                    color: "#EA4335", textTransform: "none",
                    "&:hover": { bgcolor: "rgba(234,67,53,0.08)" },
                  }}
                >
                  Delete
                </Button>
                <Box sx={{ flex: 1 }} />
                <Button onClick={() => setSelected(null)} sx={{ color: "text.secondary" }}>Close</Button>
              </DialogActions>
            </>
          );
        })()}
      </Dialog>

      {/* Confirm delete */}
      <Dialog open={!!pendingDelete} onClose={() => setPendingDelete(null)}
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>Delete finding?</DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            This permanently removes the finding from the database. If the same issue is detected again on the next scan it will be re-created.
          </Typography>
          {pendingDelete && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600 }}>{pendingDelete.title || "(no title)"}</Typography>
              {pendingDelete.resource_id && (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>{pendingDelete.resource_id}</Typography>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDelete(null)} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button
            variant="contained"
            color="error"
            disabled={deleteMutation.isPending}
            onClick={() => pendingDelete && deleteMutation.mutate(pendingDelete.id)}
            sx={{ bgcolor: "#EA4335", "&:hover": { bgcolor: "#c5362b" } }}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Suppress dialog */}
      <Dialog open={!!suppressTarget} onClose={() => { setSuppressTarget(null); setSuppressReason(""); }}
        maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>Suppress finding</DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>
            Suppressing marks this finding as a false positive and hides it from the default view. Provide a reason so your team understands why it was suppressed.
          </Typography>
          {suppressTarget && (
            <Box sx={{ mb: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600 }}>{suppressTarget.title || "(no title)"}</Typography>
            </Box>
          )}
          <TextField
            label="Reason for suppression"
            value={suppressReason}
            onChange={(e) => setSuppressReason(e.target.value)}
            multiline
            rows={3}
            fullWidth
            placeholder="e.g. Confirmed not exploitable in this environment, test artifact, accepted risk..."
            slotProps={{ inputLabel: { sx: { color: "text.secondary" } } }}
            sx={{
              "& .MuiOutlinedInput-root": {
                color: "text.primary",
                "& fieldset": { borderColor: "divider" },
                "&:hover fieldset": { borderColor: "rgba(255,255,255,0.3)" },
                "&.Mui-focused fieldset": { borderColor: "#4285F4" },
              },
            }}
          />
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => { setSuppressTarget(null); setSuppressReason(""); }} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button
            variant="contained"
            disabled={!suppressReason.trim() || suppressMutation.isPending}
            onClick={() => suppressTarget && suppressMutation.mutate({ finding: suppressTarget, reason: suppressReason })}
            sx={{ bgcolor: "rgba(255,255,255,0.1)", color: "text.primary", "&:hover": { bgcolor: "rgba(255,255,255,0.15)" } }}
          >
            Suppress
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={!!snack}
        autoHideDuration={3000}
        onClose={() => setSnack("")}
        message={snack}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
      />
    </Box>
  );
}
