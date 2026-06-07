/**
 * Reports — generates printable / exportable views over existing data.
 *
 * Five report types are supported:
 *   - Executive Summary  (one-pager: posture score, key counts, top issues)
 *   - Compliance         (per-framework control list with status + evidence)
 *   - Findings           (full findings table)
 *   - Risk Register      (full risks table)
 *   - Asset Inventory    (full assets table)
 *
 * Each report has CSV download and Print (browser PDF).
 */
import React, { useMemo, useRef, useState } from "react";
import {
  Box, Typography, Card, CardContent, Grid, Chip, Button,
  Select, MenuItem, FormControl, InputLabel, CircularProgress, Alert,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer, Divider,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  FormControlLabel, Checkbox,
} from "@mui/material";
import { Print, Download, Description, Email, Send } from "@mui/icons-material";
import { useQuery, useMutation } from "@tanstack/react-query";
import { toast } from "react-toastify";
import {
  clientsApi, projectsApi, findingsApi, risksApi, assetsApi,
  frameworksApi, riskOverviewApi, missionsApi, emailApi,
} from "../services/api";
import {
  Client, Project, Finding, Risk, Asset, FrameworkSummary,
  FrameworkDetail, ControlStatusEntry, RiskOverview, FrameworkCatalogEntry,
} from "../types";
import dayjs from "dayjs";
import { fmt, fmtDate } from "../utils/datetime";

type ReportType = "executive" | "compliance" | "findings" | "risks" | "assets";

const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50", info: "#9e9e9e",
};
const STATUS_COLOR: Record<string, string> = {
  compliant: "#00e676", non_compliant: "#f44336", partial: "#ff9800", not_applicable: "#9e9e9e",
};

function downloadCSV(filename: string, rows: Record<string, any>[]) {
  if (rows.length === 0) {
    alert("Nothing to export");
    return;
  }
  const headers = Object.keys(rows[0]);
  const escape = (v: any) => {
    if (v == null) return "";
    const s = typeof v === "string" ? v : JSON.stringify(v);
    if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };
  const csv = [
    headers.join(","),
    ...rows.map((r) => headers.map((h) => escape(r[h])).join(",")),
  ].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

export default function Reports() {
  const [clientId, setClientId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [reportType, setReportType] = useState<ReportType>("executive");
  const [framework, setFramework] = useState<string>("nist_csf");
  const printRef = useRef<HTMLDivElement>(null);

  const { data: clients = [] } = useQuery<Client[]>({
    queryKey: ["clients"], queryFn: clientsApi.list,
  });
  const client = clients.find((c) => c.id === clientId);
  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", clientId], queryFn: () => projectsApi.list(clientId),
    enabled: !!clientId,
  });
  const project = projects.find((p) => p.id === projectId);

  const { data: catalog = [] } = useQuery<FrameworkCatalogEntry[]>({
    queryKey: ["framework-catalog"], queryFn: frameworksApi.catalog,
  });

  // ── Executive summary feeds off the risk-overview endpoint ─────────────────
  const { data: overview, isLoading: overviewLoading } = useQuery<RiskOverview>({
    queryKey: ["risk-overview", clientId],
    queryFn: () => riskOverviewApi.get(clientId, 30),
    enabled: !!clientId && reportType === "executive",
  });
  const { data: fwSummaries = [] } = useQuery<FrameworkSummary[]>({
    queryKey: ["framework-summary", clientId],
    queryFn: () => frameworksApi.summary(clientId),
    enabled: !!clientId && reportType === "executive",
  });

  // ── Compliance ─────────────────────────────────────────────────────────────
  const { data: fwDetail, isLoading: fwLoading } = useQuery<FrameworkDetail>({
    queryKey: ["framework-detail", clientId, framework],
    queryFn: () => frameworksApi.forClient(clientId, framework),
    enabled: !!clientId && reportType === "compliance",
  });

  // ── Findings / Risks / Assets ──────────────────────────────────────────────
  const { data: findings = [], isLoading: findingsLoading } = useQuery<Finding[]>({
    queryKey: ["report-findings", clientId, projectId],
    queryFn: () => findingsApi.listAll(clientId, undefined, undefined, projectId || undefined),
    enabled: !!clientId && reportType === "findings",
  });
  const { data: risks = [], isLoading: risksLoading } = useQuery<Risk[]>({
    queryKey: ["report-risks", clientId, projectId],
    queryFn: () => risksApi.list(clientId, projectId || undefined),
    enabled: !!clientId && reportType === "risks",
  });
  const { data: assets = [], isLoading: assetsLoading } = useQuery<Asset[]>({
    queryKey: ["report-assets", clientId, projectId],
    queryFn: () => assetsApi.list(clientId, projectId ? { project_id: projectId } : {}),
    enabled: !!clientId && reportType === "assets",
  });

  const handlePrint = () => window.print();

  // ── Email this report ────────────────────────────────────────────────────
  const [emailOpen, setEmailOpen] = useState(false);
  const [emailTo, setEmailTo] = useState("");
  const [emailCc, setEmailCc] = useState("");
  const [emailSubject, setEmailSubject] = useState("");
  const [emailBody, setEmailBody] = useState("");
  const [attachReport, setAttachReport] = useState(true);

  const openEmailDialog = () => {
    const title = reportTitle;
    setEmailSubject(`${title}${client?.name ? ` — ${client.name}` : ""}`);
    setEmailBody(
      `Hi,\n\nPlease find ${attachReport ? "attached " : ""}the ${title}` +
      `${client?.name ? ` for ${client.name}` : ""}${project ? ` (${project.name})` : ""}.\n\n` +
      `Generated ${dayjs().format("DD MMM YYYY, HH:mm")}.\n\nRegards,`
    );
    setEmailOpen(true);
  };

  // Self-contained HTML snapshot of the rendered report, for the attachment.
  // Reuses the live DOM (inline sx styles carry severity/brand colours) and
  // wraps it in a light, paper-friendly stylesheet so it opens cleanly.
  const buildReportHtml = (): string => {
    const inner = printRef.current?.innerHTML || "";
    return (
      `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${reportTitle}</title>` +
      `<style>` +
      `body{font-family:Arial,Helvetica,sans-serif;color:#1a1a1a;background:#fff;margin:24px;}` +
      `table{border-collapse:collapse;width:100%;margin:8px 0;}` +
      `th,td{border:1px solid #e0e0e0;padding:6px 8px;text-align:left;font-size:13px;}` +
      `h1,h2,h3,h4,h5,h6{color:#111;margin:8px 0;}` +
      `.MuiChip-root{display:inline-block;padding:2px 10px;border-radius:11px;font-size:11px;font-weight:700;}` +
      `svg{vertical-align:middle;}` +
      `</style></head><body>${inner}</body></html>`
    );
  };

  const utf8ToBase64 = (s: string) => btoa(unescape(encodeURIComponent(s)));

  const sendMutation = useMutation({
    mutationFn: () => {
      const stamp = dayjs().format("YYYYMMDD-HHmm");
      const slug = (client?.slug || client?.name || "client").replace(/\W+/g, "-");
      const attachments = attachReport
        ? [{
            filename: `${slug}-${reportType}-${stamp}.html`,
            content_base64: utf8ToBase64(buildReportHtml()),
            mime: "text/html",
          }]
        : [];
      const bodyHtml =
        `<div style="font-family:Arial,Helvetica,sans-serif;color:#1a1a1a;white-space:pre-wrap">` +
        `${emailBody.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>`;
      return emailApi.send({
        to: emailTo,
        cc: emailCc || undefined,
        subject: emailSubject,
        body_text: emailBody,
        body_html: bodyHtml,
        attachments,
      });
    },
    onSuccess: () => {
      toast.success("Report emailed");
      setEmailOpen(false);
    },
    onError: (e: any) =>
      toast.error(e?.response?.data?.detail || "Failed to send email"),
  });

  const handleExportCSV = () => {
    const stamp = dayjs().format("YYYYMMDD-HHmm");
    const slug = (client?.slug || client?.name || "client").replace(/\W+/g, "-");
    if (reportType === "findings") {
      downloadCSV(`findings-${slug}-${stamp}.csv`, findings.map((f) => ({
        title: f.title,
        severity: typeof f.severity === "object" ? (f.severity as any).value : f.severity,
        status: f.status,
        cve_id: f.cve_id || "",
        cvss_score: f.cvss_score ?? "",
        resource_id: f.resource_id || "",
        resource_type: f.resource_type || "",
        framework: f.framework || "",
        control_id: f.control_id || "",
        first_seen_at: f.first_seen_at || f.created_at || "",
        seen_count: f.seen_count ?? 1,
      })));
    } else if (reportType === "risks") {
      downloadCSV(`risks-${slug}-${stamp}.csv`, risks.map((r) => ({
        title: r.title,
        risk_level: r.risk_level,
        likelihood: r.likelihood,
        impact: r.impact,
        risk_score: r.risk_score ?? "",
        category: r.category || "",
        owner: r.owner || "",
        status: r.status,
        due_date: r.due_date || "",
        created_at: r.created_at || "",
      })));
    } else if (reportType === "assets") {
      downloadCSV(`assets-${slug}-${stamp}.csv`, assets.map((a) => ({
        name: a.name,
        asset_type: a.asset_type || "",
        asset_class: a.asset_class || "",
        region: a.region || "",
        subscription_id: a.subscription_id || "",
        resource_group: a.resource_group || "",
        status: a.status,
        open_findings_count: a.open_findings_count,
        risks_count: a.risks_count,
        last_synced_at: a.last_synced_at || "",
      })));
    } else if (reportType === "compliance" && fwDetail) {
      downloadCSV(`compliance-${framework}-${slug}-${stamp}.csv`,
        fwDetail.controls.map((c: ControlStatusEntry) => ({
          control_id: c.control.control_id,
          domain: c.control.domain || "",
          title: c.control.title,
          status: c.status,
          derived: c.derived ? "yes" : "no",
          evidence: c.evidence || "",
          last_evaluated_at: c.last_evaluated_at || "",
          finding_count: c.finding_ids?.length || 0,
        })),
      );
    } else if (reportType === "executive" && overview) {
      downloadCSV(`executive-summary-${slug}-${stamp}.csv`, [
        {
          metric: "security_score",
          value: overview.security_score?.current ?? "",
          delta_7d: overview.security_score?.delta ?? "",
        },
        ...["critical", "high", "medium", "low", "info"].map((sev) => ({
          metric: `open_${sev}`,
          value: (overview.open_issues as any)[sev] ?? 0,
          delta_7d: (overview.open_issues?.deltas as any)?.[sev] ?? "",
        })),
        ...fwSummaries.map((fs) => ({
          metric: `framework_${fs.framework}_score`,
          value: fs.score,
          delta_7d: "",
        })),
      ]);
    }
  };

  const exportDisabled = !clientId
    || (reportType === "compliance" && !fwDetail)
    || (reportType === "findings" && findings.length === 0)
    || (reportType === "risks" && risks.length === 0)
    || (reportType === "assets" && assets.length === 0)
    || (reportType === "executive" && !overview);

  const reportTitle = useMemo(() => {
    const t: Record<ReportType, string> = {
      executive: "Executive Summary",
      compliance: `Compliance Report — ${catalog.find((c) => c.framework === framework)?.name || framework}`,
      findings: "Findings Report",
      risks: "Risk Register",
      assets: "Asset Inventory",
    };
    return t[reportType];
  }, [reportType, framework, catalog]);

  return (
    <Box>
      {/* Print-only stylesheet — hides chrome, shows ref'd report cleanly */}
      <style>{`
        @media print {
          @page { size: A4; margin: 12mm; }
          body { background: #fff !important; }
          .no-print { display: none !important; }

          /* Print brand/severity colours instead of letting the browser drop backgrounds */
          .print-area, .print-area * {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
          }
          .print-area { padding: 0 !important; max-width: 100% !important; color: #1a1a1a !important; }

          /* Paper-white surfaces (the portal canvas is dark) */
          .print-area .MuiCard-root, .print-area .MuiCardContent-root,
          .print-area .MuiPaper-root, .print-area .MuiTableContainer-root,
          .print-area .MuiTable-root {
            background: #fff !important;
            box-shadow: none !important;
            border-color: #e0e0e0 !important;
          }
          .print-area .MuiTableCell-root { border-color: #e0e0e0 !important; }

          /* Legible dark body text — the dark theme's light text would vanish on
             white. Chips, charts and .keep-color brand values are excluded so they
             keep their portal colours. */
          .print-area .MuiTypography-root:not(.keep-color),
          .print-area .MuiTableCell-root:not(.keep-color) {
            color: #1a1a1a !important;
          }

          .print-area .MuiCard-root { page-break-inside: avoid; }
        }
      `}</style>

      <Box className="no-print" sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>Reports</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Printable + exportable views over your security posture data
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1 }}>
          <Button variant="outlined" startIcon={<Download />} disabled={exportDisabled}
            onClick={handleExportCSV}
            sx={{ color: "#4285F4", borderColor: "rgba(66,133,244,0.5)" }}>
            Export CSV
          </Button>
          <Button variant="outlined" startIcon={<Email />} disabled={!clientId}
            onClick={openEmailDialog}
            sx={{ color: "#4285F4", borderColor: "rgba(66,133,244,0.5)" }}>
            Email Report
          </Button>
          <Button variant="contained" startIcon={<Print />} disabled={!clientId}
            onClick={handlePrint}
            sx={{ bgcolor: "#4285F4", color: "#000", "&:hover": { bgcolor: "#00b8d4" } }}>
            Print / PDF
          </Button>
        </Box>
      </Box>

      <Card className="no-print" sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
        <CardContent>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, sm: 3 }}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "text.secondary" }}>Report Type</InputLabel>
                <Select value={reportType} label="Report Type"
                  onChange={(e) => setReportType(e.target.value as ReportType)}
                  sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                  <MenuItem value="executive">Executive Summary</MenuItem>
                  <MenuItem value="compliance">Compliance Report</MenuItem>
                  <MenuItem value="findings">Findings Report</MenuItem>
                  <MenuItem value="risks">Risk Register</MenuItem>
                  <MenuItem value="assets">Asset Inventory</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 3 }}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "text.secondary" }}>Client</InputLabel>
                <Select value={clientId} label="Client"
                  onChange={(e) => { setClientId(e.target.value); setProjectId(""); }}
                  sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                  {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 3 }}>
              <FormControl fullWidth size="small" disabled={!clientId}>
                <InputLabel sx={{ color: "text.secondary" }}>Project</InputLabel>
                <Select value={projectId} label="Project" onChange={(e) => setProjectId(e.target.value)}
                  sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                  <MenuItem value="">All projects</MenuItem>
                  {projects.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
                </Select>
              </FormControl>
            </Grid>
            {reportType === "compliance" && (
              <Grid size={{ xs: 12, sm: 3 }}>
                <FormControl fullWidth size="small">
                  <InputLabel sx={{ color: "text.secondary" }}>Framework</InputLabel>
                  <Select value={framework} label="Framework" onChange={(e) => setFramework(e.target.value)}
                    sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                    {catalog.map((f) => (
                      <MenuItem key={f.framework} value={f.framework}>{f.name}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
            )}
          </Grid>
        </CardContent>
      </Card>

      {!clientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "text.primary" }}>
          Pick a client to generate a report.
        </Alert>
      ) : (
        <>
        <Dialog open={emailOpen} onClose={() => setEmailOpen(false)} fullWidth maxWidth="sm" className="no-print">
          <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <Email sx={{ color: "#4285F4" }} /> Email Report
          </DialogTitle>
          <DialogContent>
            <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
              <TextField label="To" size="small" fullWidth value={emailTo}
                onChange={(e) => setEmailTo(e.target.value)} autoFocus
                placeholder="ana@contoso.com, ciso@contoso.com"
                helperText="One or more addresses, comma or semicolon separated." />
              <TextField label="Cc (optional)" size="small" fullWidth value={emailCc}
                onChange={(e) => setEmailCc(e.target.value)} />
              <TextField label="Subject" size="small" fullWidth value={emailSubject}
                onChange={(e) => setEmailSubject(e.target.value)} />
              <TextField label="Message" size="small" fullWidth multiline minRows={5} value={emailBody}
                onChange={(e) => setEmailBody(e.target.value)} />
              <FormControlLabel
                control={<Checkbox checked={attachReport} onChange={(e) => setAttachReport(e.target.checked)} />}
                label={`Attach the ${reportTitle} (HTML)`} />
            </Box>
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={() => setEmailOpen(false)} sx={{ color: "text.secondary" }}>Cancel</Button>
            <Button variant="contained" startIcon={<Send />}
              disabled={!emailTo.trim() || sendMutation.isPending}
              onClick={() => sendMutation.mutate()}
              sx={{ bgcolor: "#4285F4", color: "#000", "&:hover": { bgcolor: "#00b8d4" } }}>
              {sendMutation.isPending ? "Sending…" : "Send"}
            </Button>
          </DialogActions>
        </Dialog>

        <Card className="print-area" ref={printRef as any}
          sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
              <Description sx={{ color: "#4285F4" }} />
              <Typography variant="h6" sx={{ color: "text.primary", fontWeight: 700 }}>{reportTitle}</Typography>
            </Box>
            <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 2 }}>
              {client?.name} {project ? `· ${project.name}` : ""} · Generated {fmt(new Date().toISOString())}
            </Typography>
            <Divider sx={{ borderColor: "divider", mb: 2 }} />

            {reportType === "executive" && (
              overviewLoading ? <CircularProgress sx={{ color: "#4285F4" }} /> :
              !overview ? <Alert severity="warning">No data yet — run a scan first.</Alert> :
              <ExecutiveBlock overview={overview} fwSummaries={fwSummaries} />
            )}

            {reportType === "compliance" && (
              fwLoading ? <CircularProgress sx={{ color: "#4285F4" }} /> :
              !fwDetail ? <Alert severity="warning">No control data — recompute on the Frameworks page.</Alert> :
              <ComplianceBlock detail={fwDetail} />
            )}

            {reportType === "findings" && (
              findingsLoading ? <CircularProgress sx={{ color: "#4285F4" }} /> :
              <FindingsBlock rows={findings} />
            )}

            {reportType === "risks" && (
              risksLoading ? <CircularProgress sx={{ color: "#4285F4" }} /> :
              <RisksBlock rows={risks} />
            )}

            {reportType === "assets" && (
              assetsLoading ? <CircularProgress sx={{ color: "#4285F4" }} /> :
              <AssetsBlock rows={assets} />
            )}
          </CardContent>
        </Card>
        </>
      )}

      {/* Workflow Outputs — recent runs across all scheduled workflows */}
      <WorkflowOutputsSection />
    </Box>
  );
}

function WorkflowOutputsSection() {
  const [expanded, setExpanded] = useState(false);
  const { data: runs = [], isLoading } = useQuery<any[]>({
    queryKey: ["mission-runs-recent"],
    queryFn: () => missionsApi.recentRuns(50),
  });
  return (
    <Card className="no-print" sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mt: 2 }}>
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, cursor: "pointer" }}
          onClick={() => setExpanded((v) => !v)}>
          <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 700 }}>
            Workflow Outputs
          </Typography>
          <Chip label={runs.length} size="small"
            sx={{ height: 18, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontSize: 10, fontWeight: 700 }} />
          <Box sx={{ flex: 1 }} />
          <Button size="small" sx={{ color: "text.secondary", fontSize: 11 }}>
            {expanded ? "Hide" : "Show recent runs"}
          </Button>
        </Box>
        {expanded && (
          <Box sx={{ mt: 1 }}>
            {isLoading ? (
              <CircularProgress size={20} sx={{ color: "#4285F4" }} />
            ) : runs.length === 0 ? (
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                No workflow runs yet — schedule one and click Run Now.
              </Typography>
            ) : (
              runs.map((run) => (
                <Box key={run.id} sx={{ borderTop: "1px solid rgba(255,255,255,0.06)", py: 1.25 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5, flexWrap: "wrap" }}>
                    <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600 }}>
                      {run.mission_name}
                    </Typography>
                    <Chip label={run.mission_type.replace(/_/g, " ")} size="small"
                      sx={{ height: 18, fontSize: 10, bgcolor: "rgba(66,133,244,0.08)", color: "#4285F4", textTransform: "capitalize" }} />
                    <Chip label={run.status} size="small"
                      sx={{ height: 18, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                        bgcolor: run.status === "success" ? "rgba(52,168,83,0.15)" : run.status === "failed" ? "rgba(234,67,53,0.15)" : "rgba(251,188,4,0.15)",
                        color: run.status === "success" ? "#34A853" : run.status === "failed" ? "#EA4335" : "#FBBC04" }} />
                    <Box sx={{ flex: 1 }} />
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>
                      {run.started_at ? fmtDate(run.started_at) : ""}
                    </Typography>
                  </Box>
                  {run.output && (
                    <Typography component="pre" sx={{
                      color: "text.secondary", fontSize: 12, whiteSpace: "pre-wrap",
                      wordBreak: "break-word", fontFamily: "inherit", m: 0, lineHeight: 1.4,
                    }}>
                      {run.output}
                    </Typography>
                  )}
                  {run.error && (
                    <Typography variant="caption" sx={{ color: "#EA4335", display: "block", mt: 0.5 }}>
                      Error: {run.error}
                    </Typography>
                  )}
                </Box>
              ))
            )}
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

// ── Report sections ──────────────────────────────────────────────────────────

function StatTile({ label, value, color = "#4285F4" }: { label: string; value: string | number; color?: string }) {
  return (
    <Card sx={{ bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 1, height: "100%" }}>
      <CardContent sx={{ "&:last-child": { pb: 2 } }}>
        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>{label}</Typography>
        <Typography className="keep-color" variant="h4" sx={{ color, fontWeight: 700, lineHeight: 1.2 }}>{value}</Typography>
      </CardContent>
    </Card>
  );
}

function ExecutiveBlock({ overview, fwSummaries }: { overview: RiskOverview; fwSummaries: FrameworkSummary[] }) {
  const score = overview.security_score?.current ?? 0;
  const oi = overview.open_issues || {} as any;
  return (
    <Box>
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 4 }}>
          <StatTile label="Security Score" value={`${score}%`}
            color={score >= 80 ? "#00e676" : score >= 60 ? "#ff9800" : "#f44336"} />
        </Grid>
        <Grid size={{ xs: 6, sm: 2 }}><StatTile label="Critical" value={oi.critical ?? 0} color={SEV_COLOR.critical} /></Grid>
        <Grid size={{ xs: 6, sm: 2 }}><StatTile label="High" value={oi.high ?? 0} color={SEV_COLOR.high} /></Grid>
        <Grid size={{ xs: 6, sm: 2 }}><StatTile label="Medium" value={oi.medium ?? 0} color={SEV_COLOR.medium} /></Grid>
        <Grid size={{ xs: 6, sm: 2 }}><StatTile label="Low" value={oi.low ?? 0} color={SEV_COLOR.low} /></Grid>
      </Grid>

      <Typography variant="subtitle2" sx={{ color: "text.primary", fontWeight: 700, mb: 1 }}>Framework Compliance</Typography>
      <TableContainer sx={{ mb: 3 }}>
        <Table size="small">
          <TableHead><TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11 } }}>
            <TableCell>FRAMEWORK</TableCell>
            <TableCell align="right">SCORE</TableCell>
            <TableCell align="right">COMPLIANT</TableCell>
            <TableCell align="right">NON-COMPLIANT</TableCell>
            <TableCell align="right">PARTIAL</TableCell>
            <TableCell align="right">N/A</TableCell>
          </TableRow></TableHead>
          <TableBody>
            {fwSummaries.map((fs) => (
              <TableRow key={fs.framework} sx={{ "& td": { color: "text.primary", borderColor: "divider" } }}>
                <TableCell>{fs.framework}</TableCell>
                <TableCell className="keep-color" align="right" sx={{ fontWeight: 700, color: fs.score >= 80 ? "#00e676" : fs.score >= 60 ? "#ff9800" : "#f44336" }}>
                  {fs.score}%
                </TableCell>
                <TableCell align="right">{fs.compliant}</TableCell>
                <TableCell align="right">{fs.non_compliant}</TableCell>
                <TableCell align="right">{fs.partial}</TableCell>
                <TableCell align="right">{fs.not_applicable}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Typography variant="subtitle2" sx={{ color: "text.primary", fontWeight: 700, mb: 1 }}>Top Issues (by frequency)</Typography>
      <TableContainer>
        <Table size="small">
          <TableHead><TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11 } }}>
            <TableCell>TITLE</TableCell>
            <TableCell>SEVERITY</TableCell>
            <TableCell align="right">COUNT</TableCell>
            <TableCell align="right">RESOURCES</TableCell>
          </TableRow></TableHead>
          <TableBody>
            {(overview.top_issues || []).slice(0, 10).map((t, i) => (
              <TableRow key={i} sx={{ "& td": { color: "text.primary", borderColor: "divider" } }}>
                <TableCell>{t.title}</TableCell>
                <TableCell>
                  <Chip label={t.severity} size="small" sx={{ bgcolor: `${SEV_COLOR[t.severity]}20`, color: SEV_COLOR[t.severity], height: 18, fontSize: 10 }} />
                </TableCell>
                <TableCell align="right">{t.count}</TableCell>
                <TableCell align="right">{t.affected_resources}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

function ComplianceBlock({ detail }: { detail: FrameworkDetail }) {
  const s = detail.summary;
  return (
    <Box>
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 6, sm: 2 }}><StatTile label="Score" value={`${s.score}%`}
          color={s.score >= 80 ? "#00e676" : s.score >= 60 ? "#ff9800" : "#f44336"} /></Grid>
        <Grid size={{ xs: 6, sm: 2 }}><StatTile label="Compliant" value={s.compliant} color={STATUS_COLOR.compliant} /></Grid>
        <Grid size={{ xs: 6, sm: 2 }}><StatTile label="Non-compliant" value={s.non_compliant} color={STATUS_COLOR.non_compliant} /></Grid>
        <Grid size={{ xs: 6, sm: 2 }}><StatTile label="Partial" value={s.partial} color={STATUS_COLOR.partial} /></Grid>
        <Grid size={{ xs: 6, sm: 2 }}><StatTile label="N/A" value={s.not_applicable} color={STATUS_COLOR.not_applicable} /></Grid>
        <Grid size={{ xs: 6, sm: 2 }}><StatTile label="Total" value={s.total} /></Grid>
      </Grid>

      <TableContainer>
        <Table size="small">
          <TableHead><TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11 } }}>
            <TableCell>CONTROL</TableCell>
            <TableCell>TITLE</TableCell>
            <TableCell>STATUS</TableCell>
            <TableCell align="right">FINDINGS</TableCell>
            <TableCell>EVIDENCE</TableCell>
          </TableRow></TableHead>
          <TableBody>
            {(detail.controls || []).map((c) => (
              <TableRow key={c.control.id} sx={{ "& td": { color: "text.primary", borderColor: "divider", verticalAlign: "top", py: 0.75 } }}>
                <TableCell sx={{ fontFamily: "monospace", fontSize: 11, whiteSpace: "nowrap" }}>{c.control.control_id}</TableCell>
                <TableCell sx={{ fontSize: 12, maxWidth: 360 }}>{c.control.title}</TableCell>
                <TableCell>
                  <Chip label={c.status.replace("_", " ")} size="small"
                    sx={{ bgcolor: `${STATUS_COLOR[c.status]}25`, color: STATUS_COLOR[c.status], height: 18, fontSize: 10 }} />
                </TableCell>
                <TableCell align="right">{c.finding_ids?.length ?? 0}</TableCell>
                <TableCell sx={{ fontSize: 11, color: "text.secondary", maxWidth: 280 }}>{c.evidence || ""}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

function FindingsBlock({ rows }: { rows: Finding[] }) {
  if (rows.length === 0) return <Alert severity="info">No findings.</Alert>;
  const sevCount: Record<string, number> = {};
  rows.forEach((f) => {
    const s = typeof f.severity === "object" ? (f.severity as any).value : f.severity;
    sevCount[s] = (sevCount[s] || 0) + 1;
  });
  return (
    <Box>
      <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
        {["critical", "high", "medium", "low", "info"].filter((s) => sevCount[s]).map((s) => (
          <Chip key={s} label={`${s}: ${sevCount[s]}`} size="small"
            sx={{ bgcolor: `${SEV_COLOR[s]}20`, color: SEV_COLOR[s] }} />
        ))}
        <Typography variant="caption" sx={{ color: "text.secondary", alignSelf: "center", ml: 1 }}>
          {rows.length} total
        </Typography>
      </Box>
      <TableContainer>
        <Table size="small">
          <TableHead><TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11 } }}>
            <TableCell>SEV</TableCell>
            <TableCell>TITLE</TableCell>
            <TableCell>CVE</TableCell>
            <TableCell>RESOURCE</TableCell>
            <TableCell>STATUS</TableCell>
            <TableCell>FOUND</TableCell>
          </TableRow></TableHead>
          <TableBody>
            {rows.map((f) => {
              const sev = typeof f.severity === "object" ? (f.severity as any).value : f.severity;
              const ts = f.first_seen_at || f.created_at;
              return (
                <TableRow key={f.id} sx={{ "& td": { color: "text.primary", borderColor: "divider" } }}>
                  <TableCell><Chip label={sev} size="small" sx={{ bgcolor: `${SEV_COLOR[sev]}20`, color: SEV_COLOR[sev], height: 18, fontSize: 10 }} /></TableCell>
                  <TableCell sx={{ maxWidth: 320, fontSize: 12 }}>{f.title}</TableCell>
                  <TableCell sx={{ color: "#4285F4", fontSize: 11 }}>{f.cve_id || "—"}</TableCell>
                  <TableCell sx={{ color: "text.secondary", fontSize: 11, maxWidth: 200 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>
                      {f.resource_id || "—"}
                    </span>
                  </TableCell>
                  <TableCell sx={{ fontSize: 11 }}>{f.status}</TableCell>
                  <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>{fmtDate(ts)}</TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

function RisksBlock({ rows }: { rows: Risk[] }) {
  if (rows.length === 0) return <Alert severity="info">No risks recorded.</Alert>;
  return (
    <TableContainer>
      <Table size="small">
        <TableHead><TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11 } }}>
          <TableCell>LEVEL</TableCell>
          <TableCell>TITLE</TableCell>
          <TableCell>CATEGORY</TableCell>
          <TableCell>OWNER</TableCell>
          <TableCell align="right">SCORE</TableCell>
          <TableCell>STATUS</TableCell>
          <TableCell>DUE</TableCell>
        </TableRow></TableHead>
        <TableBody>
          {rows.map((r) => (
            <TableRow key={r.id} sx={{ "& td": { color: "text.primary", borderColor: "divider" } }}>
              <TableCell><Chip label={r.risk_level} size="small" sx={{ bgcolor: `${SEV_COLOR[r.risk_level]}20`, color: SEV_COLOR[r.risk_level], height: 18, fontSize: 10 }} /></TableCell>
              <TableCell sx={{ maxWidth: 320, fontSize: 12 }}>{r.title}</TableCell>
              <TableCell sx={{ fontSize: 11 }}>{r.category || "—"}</TableCell>
              <TableCell sx={{ fontSize: 11 }}>{r.owner || "—"}</TableCell>
              <TableCell align="right">{r.risk_score ?? "—"}</TableCell>
              <TableCell sx={{ fontSize: 11 }}>{r.status}</TableCell>
              <TableCell sx={{ fontSize: 11 }}>{fmtDate(r.due_date)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

function AssetsBlock({ rows }: { rows: Asset[] }) {
  if (rows.length === 0) return <Alert severity="info">No assets discovered yet.</Alert>;
  return (
    <TableContainer>
      <Table size="small">
        <TableHead><TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11 } }}>
          <TableCell>NAME</TableCell>
          <TableCell>TYPE</TableCell>
          <TableCell>CLASS</TableCell>
          <TableCell>SCOPE</TableCell>
          <TableCell>REGION</TableCell>
          <TableCell>STATUS</TableCell>
          <TableCell align="right">FINDINGS</TableCell>
          <TableCell align="right">RISKS</TableCell>
        </TableRow></TableHead>
        <TableBody>
          {rows.map((a) => (
            <TableRow key={a.id} sx={{ "& td": { color: "text.primary", borderColor: "divider" } }}>
              <TableCell sx={{ fontSize: 12, maxWidth: 240 }}>{a.name}</TableCell>
              <TableCell sx={{ fontSize: 11, maxWidth: 200 }}>{a.asset_type || "—"}</TableCell>
              <TableCell sx={{ fontSize: 11 }}>{a.asset_class || "—"}</TableCell>
              <TableCell sx={{ fontSize: 11 }}>{a.subscription_id || a.account_id || a.project_id || "—"}</TableCell>
              <TableCell sx={{ fontSize: 11 }}>{a.region || "—"}</TableCell>
              <TableCell sx={{ fontSize: 11 }}>{a.status}</TableCell>
              <TableCell align="right" sx={{ color: a.open_findings_count > 0 ? "#f44336" : "text.secondary" }}>{a.open_findings_count}</TableCell>
              <TableCell align="right">{a.risks_count}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
