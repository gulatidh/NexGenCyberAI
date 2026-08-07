import React, { useState, useRef, useCallback } from "react";
import { useViewMode } from "../theme/ViewModeContext";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Button, Card, Grid, Chip,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  Select, MenuItem, FormControl, InputLabel, CircularProgress,
  Tabs, Tab, Stack, Tooltip, Divider, IconButton, Badge,
  Table, TableHead, TableRow, TableCell, TableBody,
  Accordion, AccordionSummary, AccordionDetails,
  TablePagination, Snackbar, Alert, ToggleButton, ToggleButtonGroup,
  Switch, FormControlLabel, LinearProgress,
} from "@mui/material";
import {
  PlayArrow, Add, Refresh, Visibility, DeleteOutlined, Replay, History, CompareArrows,
  ExpandMore, CloudUpload, Upload, Storage, Business, Link as LinkIcon,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { scansApi, connectorsApi, clientsApi, frameworksApi, assessmentsApi, findingsApi, apiClient } from "../services/api";
import { useNavigate, useLocation } from "react-router-dom";
import { Scan, Client, Connector, ScanType, FrameworkType, FrameworkCatalogEntry } from "../types";
import { toast } from "react-toastify";
import { fromNow } from "../utils/datetime";
import { CREDENTIAL_FIELDS } from "./Connections";

const STATUS_COLOR: Record<string, string> = {
  pending: "#ff9800", running: "#4285F4", completed: "#00e676",
  failed: "#f44336", cancelled: "rgba(255,255,255,0.3)",
};

const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b",
  low: "#4caf50", info: "#4285F4",
};

// ── Scanner catalog ──────────────────────────────────────────────────────────
type ScannerStatus = "live" | "soon";
type ScanCategory = "cloud" | "dast" | "sast" | "network" | "dependency" | "enterprise";
type ScannerDef = {
  id: string;
  name: string;
  connectorType: string;
  category: ScanCategory;
  status: ScannerStatus;
  description: string;
};

const CATEGORY_LABEL: Record<ScanCategory, string> = {
  cloud: "Cloud & Identity",
  dast: "DAST — Dynamic AppSec",
  sast: "SAST — Static AppSec",
  network: "Network & Infrastructure",
  dependency: "Dependency & Secret",
  enterprise: "Enterprise Scanners",
};

const CATEGORY_COLOR: Record<ScanCategory, string> = {
  cloud: "#4285F4",
  dast: "#FBBC04",
  sast: "#4285F4",
  network: "#34A853",
  dependency: "#EA4335",
  enterprise: "#9C27B0",
};

const SCANNERS: ScannerDef[] = [
  // DAST
  { id: "zap", name: "OWASP ZAP", connectorType: "web", category: "dast", status: "live",
    description: "Web app DAST — passive (unauth) and active (auth) profiles via GitHub Actions." },
  // SAST
  { id: "semgrep", name: "Semgrep", connectorType: "semgrep", category: "sast", status: "live",
    description: "Open-source static analysis with curated rule packs. Runs in GitHub Actions via semgrep/semgrep image." },
  { id: "codeql", name: "GitHub CodeQL", connectorType: "codeql", category: "sast", status: "live",
    description: "GitHub's semantic code analysis. Auto-detects language; runs the security-and-quality query suite in GitHub Actions." },
  { id: "checkov", name: "Checkov", connectorType: "checkov", category: "sast", status: "live",
    description: "IaC security scanner for Terraform, CloudFormation, Kubernetes, Helm, and Dockerfile. Finds misconfigurations before resources are deployed. Runs in GitHub Actions." },
  { id: "ai_code_review", name: "AI Code Review", connectorType: "ai_code_review", category: "sast", status: "live",
    description: "LLM-powered vulnerability discovery — triage, per-function analysis, self-critique, and cross-file taint tracing. Runs fully in-process; no GitHub Actions required." },
  { id: "sonarqube", name: "SonarQube", connectorType: "sonarqube", category: "sast", status: "soon",
    description: "Community Edition (self-hosted) or Enterprise (SonarCloud via Action). Workflow coming soon." },
  // Network
  { id: "nmap", name: "NMAP", connectorType: "nmap", category: "network", status: "live",
    description: "Service / port discovery on hosts or CIDR ranges with NSE safe + vuln scripts. Runs in GitHub Actions." },
  { id: "nuclei", name: "Nuclei", connectorType: "nuclei", category: "network", status: "live",
    description: "Template-based vulnerability scanner with 9,000+ PoC templates covering CVEs, default credentials, misconfigurations, and exposed panels. Every finding is confirmed. Runs in GitHub Actions." },
  { id: "sslyze", name: "SSLyze", connectorType: "sslyze", category: "network", status: "live",
    description: "TLS/SSL configuration auditor — detects deprecated protocols (SSL 2/3, TLS 1.0/1.1), weak ciphers, expired certs, Heartbleed, and ROBOT. Runs in GitHub Actions." },
  { id: "openvas", name: "OpenVAS / Greenbone", connectorType: "openvas", category: "network", status: "soon",
    description: "Open-source network vulnerability scanner. Workflow coming soon." },
  { id: "trivy", name: "Trivy", connectorType: "trivy", category: "network", status: "live",
    description: "Container image + filesystem + IaC scanner. Runs in GitHub Actions." },
  // Dependency / Secret
  { id: "owasp_dc", name: "OWASP Dependency-Check", connectorType: "owasp_dc", category: "dependency", status: "live",
    description: "SCA / CVE matching for application dependencies. Clones the repo and runs Dependency-Check in GitHub Actions (add an NVD API key to avoid rate-limits)." },
  { id: "gitleaks", name: "Gitleaks", connectorType: "gitleaks", category: "dependency", status: "live",
    description: "Secret scanner for git history. Runs in GitHub Actions." },
  { id: "trufflehog", name: "TruffleHog", connectorType: "trufflehog", category: "dependency", status: "live",
    description: "Secret scanner (git + filesystem) with verification. Runs in GitHub Actions." },
  // Enterprise Professional Scanners
  { id: "tenable", name: "Tenable.io", connectorType: "tenable", category: "enterprise", status: "live",
    description: "Industry-leading vulnerability management platform. Scans hosts, cloud assets, and containers via Tenable's REST API. Requires access_key + secret_key." },
  { id: "burp_enterprise", name: "Burp Suite Enterprise", connectorType: "burp_enterprise", category: "enterprise", status: "live",
    description: "PortSwigger's enterprise-grade DAST platform. Automated web app scanning with Burp's industry-standard crawler and attack engine. Requires host URL + API key." },
  { id: "snyk", name: "Snyk", connectorType: "snyk", category: "enterprise", status: "live",
    description: "SCA + code security platform. Scans all projects in your Snyk organisation for vulnerable dependencies, license issues, and code vulnerabilities. Requires API key + org_id." },
  { id: "rapid7", name: "Rapid7 InsightVM", connectorType: "rapid7", category: "enterprise", status: "live",
    description: "Rapid7's enterprise vulnerability management. Launches site scans, polls for results, and ingests prioritised vulnerabilities with remediation guidance. Requires host + credentials + site_id." },
  { id: "qualys", name: "Qualys VMDR", connectorType: "qualys", category: "enterprise", status: "live",
    description: "Qualys Vulnerability Management Detection and Response. Cloud-based scanning of IPs and CIDR ranges. Requires Qualys API URL + credentials." },
  { id: "invicti", name: "Invicti (Netsparker)", connectorType: "invicti", category: "enterprise", status: "live",
    description: "Enterprise DAST with proof-based scanning and low false-positive rates. Scans web applications and APIs. Requires API URL + API token." },
  { id: "acunetix", name: "Acunetix Enterprise", connectorType: "acunetix", category: "enterprise", status: "live",
    description: "Acunetix enterprise web vulnerability scanner. Creates targets, launches full scans, and ingests vulnerabilities via REST API. Requires host URL + API key." },
];

const CATEGORY_ORDER: ScanCategory[] = ["cloud", "dast", "sast", "network", "dependency", "enterprise"];

// Scanner groups for the top-level accordion sections
const PLATFORM_SCANNER_TYPES = new Set([
  "web", "nmap", "nuclei", "sslyze", "openvas", "trivy",
  "semgrep", "codeql", "checkov", "sonarqube",
  "owasp_dc", "gitleaks", "trufflehog", "ai_code_review",
]);
const ENTERPRISE_SCANNER_TYPES = new Set([
  "tenable", "burp_enterprise", "snyk", "rapid7", "qualys", "invicti", "acunetix",
]);

// ── Confidence chip colours ────────────────────────────────────────────────
function confidenceColor(pct: number): string {
  if (pct >= 85) return "#34A853";
  if (pct >= 60) return "#FBBC04";
  return "#EA4335";
}

// ── ScanImportPanel ───────────────────────────────────────────────────────
interface ImportPreview {
  detected_format: string;
  finding_count: number;
  avg_confidence: number;
  new_count: number;
  fixed_count: number;
  persisting_count: number;
  severity_breakdown: { critical: number; high: number; medium: number; low: number; info: number };
  findings: {
    confidence: number;
    severity: string;
    title: string;
    resource: string;
    cve_id?: string;
  }[];
}

interface ImportHistoryRow {
  id: string;
  scan_name: string;
  detected_format: string;
  finding_count: number;
  created_at: string;
}

interface ScanImportPanelProps {
  clientId: string;
}

function ScanImportPanel({ clientId }: ScanImportPanelProps) {
  const qc = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [toolHint, setToolHint] = useState("");
  const [importName, setImportName] = useState("");
  const [parsing, setParsing] = useState(false);
  const [committing, setCommitting] = useState(false);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const [successSnack, setSuccessSnack] = useState<string | null>(null);

  // Findings table pagination
  const [page, setPage] = useState(0);
  const ROWS_PER_PAGE = 10;

  const { data: historyData = [] } = useQuery<ImportHistoryRow[]>({
    queryKey: ["import-history", clientId],
    queryFn: () => scansApi.importHistory(clientId),
    enabled: !!clientId,
  });

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) {
      setSelectedFile(file);
      setPreview(null);
      setParseError(null);
    }
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null;
    setSelectedFile(file);
    setPreview(null);
    setParseError(null);
  };

  const clearPreview = () => {
    setPreview(null);
    setSelectedFile(null);
    setImportName("");
    setToolHint("");
    setParseError(null);
    setPage(0);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const handleParse = async () => {
    if (!selectedFile || !clientId) return;
    setParsing(true);
    setParseError(null);
    try {
      const result = await scansApi.parseScanImport(clientId, selectedFile, toolHint);
      setPreview(result as ImportPreview);
      setPage(0);
    } catch (e: any) {
      setParseError(e?.response?.data?.detail || e?.message || "Failed to parse file");
    } finally {
      setParsing(false);
    }
  };

  const handleCommit = async () => {
    if (!selectedFile || !clientId) return;
    setCommitting(true);
    try {
      const result: any = await scansApi.commitScanImport(clientId, selectedFile, toolHint, importName);
      const count = result?.finding_count ?? preview?.finding_count ?? 0;
      setSuccessSnack(`${count} findings imported`);
      qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
      qc.invalidateQueries({ queryKey: ["import-history", clientId] });
      clearPreview();
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || e?.message || "Import failed");
    } finally {
      setCommitting(false);
    }
  };

  const FILE_TYPE_CHIPS = ["SARIF", "Nessus", "Burp", "OpenVAS", "Qualys", "Checkmarx", "CSV", "JSON", "PDF"];

  return (
    <Box>
      {/* Drag-and-drop zone */}
      <Box
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        onDragLeave={handleDragLeave}
        onClick={() => !selectedFile && fileInputRef.current?.click()}
        sx={{
          border: `2px dashed ${dragOver ? "#4285F4" : "rgba(255,255,255,0.2)"}`,
          borderRadius: 2,
          p: 4,
          textAlign: "center",
          bgcolor: dragOver ? "rgba(66,133,244,0.08)" : "rgba(255,255,255,0.02)",
          cursor: selectedFile ? "default" : "pointer",
          transition: "border-color 0.15s, background-color 0.15s",
          "&:hover": !selectedFile ? { borderColor: "#4285F4", bgcolor: "rgba(66,133,244,0.04)" } : {},
        }}
      >
        <input
          ref={fileInputRef}
          type="file"
          hidden
          accept=".sarif,.json,.xml,.nessus,.csv,.pdf,.txt"
          onChange={handleFileChange}
        />
        <CloudUpload sx={{ fontSize: 40, color: dragOver ? "#4285F4" : "text.secondary", mb: 1 }} />
        {selectedFile ? (
          <Box>
            <Typography sx={{ color: "text.primary", fontWeight: 600, mb: 0.5 }}>
              {selectedFile.name}
            </Typography>
            <Typography variant="caption" sx={{ color: "text.secondary" }}>
              {(selectedFile.size / 1024).toFixed(1)} KB
            </Typography>
            <Box sx={{ mt: 1 }}>
              <Button
                size="small"
                variant="outlined"
                sx={{ borderColor: "divider", color: "text.secondary", fontSize: 11 }}
                onClick={(e) => { e.stopPropagation(); setSelectedFile(null); setPreview(null); setParseError(null); if (fileInputRef.current) fileInputRef.current.value = ""; }}
              >
                Change file
              </Button>
            </Box>
          </Box>
        ) : (
          <Box>
            <Typography sx={{ color: "text.secondary", mb: 0.5 }}>
              Drag and drop a scan file here, or click to browse
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, justifyContent: "center", mt: 1.5 }}>
              {FILE_TYPE_CHIPS.map((t) => (
                <Chip key={t} label={t} size="small"
                  sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", height: 20, fontSize: 10 }} />
              ))}
            </Box>
          </Box>
        )}
      </Box>

      {/* Tool hint + parse button */}
      <Box sx={{ display: "flex", gap: 2, mt: 2, alignItems: "flex-start", flexWrap: "wrap" }}>
        <FormControl size="small" sx={{ minWidth: 240 }}>
          <InputLabel sx={{ color: "text.secondary" }}>Source tool (optional hint for AI)</InputLabel>
          <Select
            value={toolHint}
            onChange={(e) => setToolHint(e.target.value)}
            label="Source tool (optional hint for AI)"
            sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
          >
            <MenuItem value="">Auto-detect</MenuItem>
            <MenuItem value="Nessus">Tenable Nessus</MenuItem>
            <MenuItem value="Burp Suite">Burp Suite</MenuItem>
            <MenuItem value="OpenVAS">OpenVAS / Greenbone</MenuItem>
            <MenuItem value="Qualys">Qualys VMDR</MenuItem>
            <MenuItem value="Checkmarx">Checkmarx</MenuItem>
            <MenuItem value="OWASP ZAP">OWASP ZAP</MenuItem>
            <MenuItem value="Rapid7">Rapid7 InsightVM</MenuItem>
            <MenuItem value="Other">Other</MenuItem>
          </Select>
        </FormControl>

        <Button
          variant="contained"
          disabled={!selectedFile || parsing || !clientId}
          onClick={handleParse}
          startIcon={parsing ? <CircularProgress size={16} sx={{ color: "inherit" }} /> : <Visibility />}
          sx={{ height: 40 }}
        >
          {parsing ? "Parsing…" : "Preview"}
        </Button>
      </Box>

      {parsing && (
        <Box sx={{ mt: 2, display: "flex", alignItems: "center", gap: 1.5 }}>
          <CircularProgress size={20} sx={{ color: "#4285F4" }} />
          <Typography variant="body2" sx={{ color: "text.secondary" }}>Parsing your scan file…</Typography>
        </Box>
      )}

      {parseError && (
        <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(234,67,53,0.08)", border: "1px solid rgba(234,67,53,0.3)", borderRadius: 1 }}>
          <Typography variant="body2" sx={{ color: "#EA4335" }}>{parseError}</Typography>
        </Box>
      )}

      {/* Preview results */}
      {preview && (
        <Box sx={{ mt: 3 }}>
          <Divider sx={{ borderColor: "divider", mb: 2 }} />

          {/* Header summary */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap", mb: 2 }}>
            <Chip label={`Detected: ${preview.detected_format}`} size="small"
              sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontWeight: 700 }} />
            <Chip label={`${preview.finding_count} findings`} size="small"
              sx={{ bgcolor: "rgba(255,255,255,0.08)", color: "text.primary", fontWeight: 700 }} />
            <Chip label={`Avg confidence: ${preview.avg_confidence}%`} size="small"
              sx={{ bgcolor: `${confidenceColor(preview.avg_confidence)}20`, color: confidenceColor(preview.avg_confidence), fontWeight: 700 }} />
          </Box>

          {/* Delta summary chips */}
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
            <Chip label={`New  ${preview.new_count}`} size="small"
              sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontWeight: 700 }} />
            <Chip label={`Fixed  ${preview.fixed_count}`} size="small"
              sx={{ bgcolor: "rgba(52,168,83,0.15)", color: "#34A853", fontWeight: 700 }} />
            <Chip label={`Persisting  ${preview.persisting_count}`} size="small"
              sx={{ bgcolor: "rgba(251,188,4,0.15)", color: "#FBBC04", fontWeight: 700 }} />
          </Box>

          {/* Severity breakdown bar */}
          <Box sx={{ mb: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.06)" }}>
            <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, display: "block", mb: 1 }}>SEVERITY BREAKDOWN</Typography>
            <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
              {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
                <Box key={sev} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                  <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: SEV_COLOR[sev] }} />
                  <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "capitalize" }}>{sev}:</Typography>
                  <Typography variant="caption" sx={{ color: "text.primary", fontWeight: 700 }}>
                    {preview.severity_breakdown[sev] ?? 0}
                  </Typography>
                </Box>
              ))}
            </Box>
            {/* Visual bar */}
            <Box sx={{ display: "flex", height: 6, borderRadius: 3, overflow: "hidden", mt: 1.5, bgcolor: "rgba(255,255,255,0.06)" }}>
              {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
                const count = preview.severity_breakdown[sev] ?? 0;
                const pct = preview.finding_count > 0 ? (count / preview.finding_count) * 100 : 0;
                return pct > 0 ? (
                  <Box key={sev} sx={{ width: `${pct}%`, bgcolor: SEV_COLOR[sev] }} />
                ) : null;
              })}
            </Box>
          </Box>

          {/* Findings table */}
          <Box sx={{ border: "1px solid rgba(255,255,255,0.08)", borderRadius: 1, overflow: "hidden", mb: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "rgba(255,255,255,0.04)", "& th": { borderColor: "rgba(255,255,255,0.08)", color: "text.secondary", fontSize: 11, fontWeight: 600, py: 1 } }}>
                  <TableCell sx={{ width: 80 }}>Confidence</TableCell>
                  <TableCell sx={{ width: 90 }}>Severity</TableCell>
                  <TableCell>Title</TableCell>
                  <TableCell>Resource</TableCell>
                  <TableCell sx={{ width: 110 }}>CVE</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {preview.findings.slice(page * ROWS_PER_PAGE, page * ROWS_PER_PAGE + ROWS_PER_PAGE).map((f, i) => {
                  const confColor = confidenceColor(f.confidence);
                  return (
                    <TableRow key={i} hover sx={{ "& td": { borderColor: "rgba(255,255,255,0.06)", fontSize: 12, py: 0.75 } }}>
                      <TableCell>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                          <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: confColor, flexShrink: 0 }} />
                          <Typography variant="caption" sx={{ color: confColor, fontWeight: 700 }}>{f.confidence}%</Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip label={f.severity} size="small"
                          sx={{ bgcolor: `${SEV_COLOR[f.severity] || "#888"}20`, color: SEV_COLOR[f.severity] || "#888", fontSize: 10, height: 18, fontWeight: 700 }} />
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" sx={{ color: "text.primary", display: "block", fontWeight: 500 }}>
                          {f.title}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" sx={{ color: "text.secondary" }}>{f.resource || "—"}</Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" sx={{ color: "#4285F4" }}>{f.cve_id || "—"}</Typography>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            <TablePagination
              component="div"
              count={preview.findings.length}
              page={page}
              onPageChange={(_, p) => setPage(p)}
              rowsPerPage={ROWS_PER_PAGE}
              rowsPerPageOptions={[ROWS_PER_PAGE]}
              sx={{ color: "text.secondary", "& .MuiToolbar-root": { minHeight: 40 }, fontSize: 12,
                "& .MuiTablePagination-selectIcon": { color: "text.secondary" } }}
            />
          </Box>

          {/* Import name + confirm */}
          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", alignItems: "center" }}>
            <TextField
              size="small"
              label="Import name (optional)"
              placeholder="e.g. Nessus scan - July 2026"
              value={importName}
              onChange={(e) => setImportName(e.target.value)}
              sx={{ flex: 1, minWidth: 240, "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
              
            />
            <Button
              variant="contained"
              disabled={committing}
              startIcon={committing ? <CircularProgress size={16} sx={{ color: "inherit" }} /> : <Upload />}
              onClick={handleCommit}
            >
              {committing ? "Importing…" : "Confirm Import"}
            </Button>
            <Button variant="outlined" sx={{ borderColor: "divider", color: "text.secondary" }} onClick={clearPreview}>
              Cancel
            </Button>
          </Box>
        </Box>
      )}

      {/* Recent imports history */}
      {historyData.length > 0 && (
        <Box sx={{ mt: 4 }}>
          <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, letterSpacing: 1, display: "block", mb: 1.5 }}>
            RECENT IMPORTS
          </Typography>
          <Box sx={{ border: "1px solid rgba(255,255,255,0.08)", borderRadius: 1, overflow: "hidden" }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "rgba(255,255,255,0.04)", "& th": { borderColor: "rgba(255,255,255,0.08)", color: "text.secondary", fontSize: 11, fontWeight: 600, py: 1 } }}>
                  <TableCell>Import name</TableCell>
                  <TableCell>Format</TableCell>
                  <TableCell>Findings</TableCell>
                  <TableCell>Date</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {historyData.map((row) => (
                  <TableRow key={row.id} hover sx={{ "& td": { borderColor: "rgba(255,255,255,0.06)", fontSize: 12, py: 0.75 } }}>
                    <TableCell>
                      <Typography variant="caption" sx={{ color: "text.primary", fontWeight: 500 }}>
                        {row.scan_name || "—"}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={row.detected_format || "—"} size="small"
                        sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontSize: 10, height: 18, fontWeight: 700 }} />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" sx={{ color: "text.primary" }}>{row.finding_count}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        {row.created_at ? new Date(row.created_at).toLocaleDateString() : "—"}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Box>
        </Box>
      )}

      <Snackbar
        open={!!successSnack}
        autoHideDuration={4000}
        onClose={() => setSuccessSnack(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      >
        <Alert severity="success" onClose={() => setSuccessSnack(null)} sx={{ fontWeight: 600 }}>
          {successSnack}
        </Alert>
      </Snackbar>
    </Box>
  );
}

// ── AssessmentTileCard ────────────────────────────────────────────────────
interface AssessmentTileCardProps {
  tile: any;
  versionMap: Map<string, any[]>;
  navigate: ReturnType<typeof useNavigate>;
  rescanMutation: any;
  setPendingDeleteScan: (tile: any) => void;
  setHistoryOpenForRoot: (root: string | null) => void;
}

function AssessmentTileCard({ tile, versionMap, navigate, rescanMutation, setPendingDeleteScan, setHistoryOpenForRoot }: AssessmentTileCardProps) {
  const location = useLocation();
  const scansBase = location.pathname.startsWith("/vulnerability") ? "/vulnerability/scans" : "/scans";
  const status = tile.status as string;
  const statusColor = STATUS_COLOR[status] || "rgba(255,255,255,0.3)";
  const cat = (tile.category as string) || "Other";
  const catColor = CATEGORY_COLOR[cat.toLowerCase() as ScanCategory] || "#4285F4";
  const dur = tile.duration_seconds != null
    ? (tile.duration_seconds >= 60 ? `${Math.round(tile.duration_seconds / 60)} min` : `${tile.duration_seconds}s`)
    : (status === "running" ? (tile.progress_message || "Running…") : "—");
  const agentRuns = (tile.agents_ran || []) as any[];
  const agentNames = Array.from(new Set(agentRuns.map((a: any) => a.agent_name || a.agent_type)));
  const anyAgentFailed = agentRuns.some((a: any) => /fail|error/i.test(String(a.status || "")));
  const root = tile.parent_scan_id || tile.id;
  const versions = versionMap.get(root) || [];
  const versionCount = versions.length;
  const isLive = versions[0]?.id === tile.id;

  return (
    <Card
      onClick={() => navigate(`${scansBase}/${tile.id}`)}
      sx={{
        bgcolor: "background.paper",
        border: `1px solid ${statusColor}40`,
        borderRadius: 2,
        cursor: "pointer",
        transition: "transform 0.12s, border-color 0.12s, background-color 0.12s",
        height: "100%",
        "&:hover": { borderColor: statusColor, bgcolor: "rgba(255,255,255,0.02)", transform: "translateY(-1px)" },
      }}>
      <Box sx={{ p: 2, position: "relative" }}>
        <Tooltip title="Delete assessment">
          <IconButton size="small" onClick={(e) => { e.stopPropagation(); setPendingDeleteScan(tile); }}
            sx={{ position: "absolute", top: 6, right: 6, color: "text.secondary", "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" } }}>
            <DeleteOutlined sx={{ fontSize: 16 }} />
          </IconButton>
        </Tooltip>
        <Tooltip title={status === "running" ? "Rescan disabled while a run is in progress" : "Rescan — keeps history of this assessment"}>
          <span>
            <IconButton size="small" disabled={status === "running" || rescanMutation.isPending}
              onClick={(e) => { e.stopPropagation(); rescanMutation.mutate(tile); }}
              sx={{ position: "absolute", top: 6, right: 32, color: "text.secondary", "&:hover": { color: "#4285F4", bgcolor: "rgba(66,133,244,0.08)" }, "&.Mui-disabled": { color: "text.secondary" } }}>
              <Replay sx={{ fontSize: 16 }} />
            </IconButton>
          </span>
        </Tooltip>
        {isLive && versionCount > 1 && (
          <Tooltip title={`${versionCount - 1} previous run${versionCount - 1 === 1 ? "" : "s"}`}>
            <IconButton size="small" onClick={(e) => { e.stopPropagation(); setHistoryOpenForRoot(root); }}
              sx={{ position: "absolute", top: 6, right: 58, color: "#FBBC04", bgcolor: "rgba(251,188,4,0.10)", "&:hover": { bgcolor: "rgba(251,188,4,0.22)" }, pr: 0.5 }}>
              <Badge badgeContent={versionCount}
                sx={{ "& .MuiBadge-badge": { fontSize: 9, height: 14, minWidth: 14, bgcolor: "#FBBC04", color: "#0d1117", fontWeight: 700 } }}>
                <History sx={{ fontSize: 16 }} />
              </Badge>
            </IconButton>
          </Tooltip>
        )}
        {tile.parent_scan_id && (
          <Tooltip title="View diff — compare with previous scan">
            <IconButton size="small" onClick={(e) => { e.stopPropagation(); navigate(`${scansBase}/${tile.id}/diff`); }}
              sx={{ position: "absolute", top: 6, right: 84, color: "#34A853", bgcolor: "rgba(52,168,83,0.10)", "&:hover": { bgcolor: "rgba(52,168,83,0.22)" } }}>
              <CompareArrows sx={{ fontSize: 16 }} />
            </IconButton>
          </Tooltip>
        )}
        <Chip label={status} size="small" sx={{
          position: "absolute", top: 12, right: tile.parent_scan_id ? 110 : 84,
          bgcolor: `${statusColor}20`, color: statusColor, fontWeight: 700, fontSize: 10, height: 20,
          textTransform: "uppercase", letterSpacing: 0.5,
        }} />
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, pr: 9 }}>
          <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: catColor, flexShrink: 0 }} />
          <Typography variant="caption" sx={{ color: catColor, fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1 }}>{cat}</Typography>
        </Box>
        <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 15, lineHeight: 1.25, mb: 0.5 }}>{tile.tile_name}</Typography>
        <Typography variant="caption" sx={{ color: status === "running" ? "#FBBC04" : "text.secondary", display: "block", mb: 0.5, fontWeight: status === "running" ? 600 : 400 }}>
          {tile.client_name && <span style={{ fontWeight: 600 }}>{tile.client_name}</span>}
          {tile.client_name && " · "}
          {tile.started_at ? fromNow(tile.started_at) : "Not started"} · {dur}
        </Typography>
        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", fontSize: 12, mb: 1.25, minHeight: 28 }}>
          {tile.name ? tile.name : ""}
          {tile.findings_count > 0
            ? `${tile.name ? " · " : ""}${tile.findings_count} finding${tile.findings_count === 1 ? "" : "s"}`
            : (tile.name ? "" : "No findings yet")}
          {tile.framework ? ` · ${tile.framework}` : ""}
        </Typography>
        <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", alignItems: "center" }}>
          {tile.summary?.critical > 0 && <Chip size="small" label={`${tile.summary.critical}C`} sx={{ bgcolor: "rgba(234,67,53,0.18)", color: "#EA4335", height: 18, fontSize: 10, fontWeight: 700 }} />}
          {tile.summary?.high > 0 && <Chip size="small" label={`${tile.summary.high}H`} sx={{ bgcolor: "rgba(255,112,67,0.18)", color: "#FF7043", height: 18, fontSize: 10, fontWeight: 700 }} />}
          {tile.summary?.medium > 0 && <Chip size="small" label={`${tile.summary.medium}M`} sx={{ bgcolor: "rgba(251,188,4,0.18)", color: "#FBBC04", height: 18, fontSize: 10, fontWeight: 700 }} />}
          {tile.has_verdict && <Chip size="small" label="AI verdict" sx={{ bgcolor: "rgba(66,133,244,0.18)", color: "#4285F4", height: 18, fontSize: 10, fontWeight: 700 }} />}
          {tile.summary?.tokens_used != null && (() => {
            const used = tile.summary.tokens_used as number;
            const pct = tile.summary.budget_pct as number;
            const label = `${(used / 1000).toFixed(0)}k tokens`;
            const color = pct >= 90 ? "#EA4335" : pct >= 70 ? "#FBBC04" : "#34A853";
            const bg = pct >= 90 ? "rgba(234,67,53,0.15)" : pct >= 70 ? "rgba(251,188,4,0.15)" : "rgba(52,168,83,0.15)";
            return <Tooltip title={`${used.toLocaleString()} tokens used`}><Chip size="small" label={label} sx={{ bgcolor: bg, color, height: 18, fontSize: 10, fontWeight: 700 }} /></Tooltip>;
          })()}
          <Box sx={{ flex: 1 }} />
          {agentNames.length > 0 && (
            <Tooltip title={`${anyAgentFailed ? "Some agent runs failed. " : ""}Agents: ${agentNames.join(", ")}`}>
              <Chip size="small" label={`${agentNames.length} agent${agentNames.length === 1 ? "" : "s"}`}
                sx={{ bgcolor: anyAgentFailed ? "rgba(234,67,53,0.18)" : "rgba(124,77,255,0.15)", color: anyAgentFailed ? "#EA4335" : "#9C27B0", height: 18, fontSize: 10, fontWeight: 700 }} />
            </Tooltip>
          )}
        </Box>
      </Box>
      {status === "running" && (
        <LinearProgress
          variant="indeterminate"
          sx={{
            height: 3,
            borderRadius: "0 0 8px 8px",
            bgcolor: "rgba(251,188,4,0.15)",
            "& .MuiLinearProgress-bar": { bgcolor: "#FBBC04" },
          }}
        />
      )}
    </Card>
  );
}

// ── Main Scans page ───────────────────────────────────────────────────────
export default function Scans() {
  const { canAct } = useViewMode();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const scansBase = location.pathname.startsWith("/vulnerability") ? "/vulnerability/scans" : "/scans";
  const connBase = location.pathname.startsWith("/vulnerability") ? "/platform/connections" : "/connections";
  const { clientId: selectedClientId, setClientId: setSelectedClientId } = useActiveClient();
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [open, setOpen] = useState(false);
  const [scanType, setScanType] = useState<ScanType>("full");
  const [connectorId, setConnectorId] = useState("");
  const [framework, setFramework] = useState<FrameworkType | "">("");
  const [scanName, setScanName] = useState("");
  const [category, setCategory] = useState<ScanCategory>("cloud");
  const [scannerId, setScannerId] = useState<string>("");
  const [viewScan, setViewScan] = useState<Scan | null>(null);
  // CodeQL binary-mode upload state
  const [codeqlMode, setCodeqlMode] = useState<"source" | "binary">("source");
  const [binaryFile, setBinaryFile] = useState<File | null>(null);
  // AI Code Review source mode: git repo vs zip archive upload
  const [acrMode, setAcrMode] = useState<"repo" | "archive">("repo");
  const [acrRepoUrl, setAcrRepoUrl] = useState("");
  const [acrGitToken, setAcrGitToken] = useState("");
  const [codeArchive, setCodeArchive] = useState<File | null>(null);
  // Top-level section accordion state
  const [sectionExpanded, setSectionExpanded] = useState<"platform" | "enterprise" | "import" | false>("platform");

  // Enterprise scanner dialog state
  const [enterpriseDialogOpen, setEnterpriseDialogOpen] = useState(false);
  const [enterpriseScanner, setEnterpriseScanner] = useState<ScannerDef | null>(null);
  // "pick" = choose which scanner, "configure" = connector/manual form
  const [enterpriseStep, setEnterpriseStep] = useState<"pick" | "configure">("pick");
  const [enterpriseMode, setEnterpriseMode] = useState<"saved" | "manual">("saved");
  const [enterpriseSelectedConnId, setEnterpriseSelectedConnId] = useState("");
  const [enterpriseManualCreds, setEnterpriseManualCreds] = useState<Record<string, string>>({});
  const [enterpriseScanName, setEnterpriseScanName] = useState("");
  const [enterpriseSaveConnector, setEnterpriseSaveConnector] = useState(true);
  const [enterpriseNewConnName, setEnterpriseNewConnName] = useState("");

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: frameworkCatalog = [] } = useQuery<FrameworkCatalogEntry[]>({
    queryKey: ["framework-catalog"],
    queryFn: frameworksApi.catalog,
  });
  const { data: connectors = [] } = useQuery<Connector[]>({
    queryKey: ["connectors", selectedClientId, selectedProjectId],
    queryFn: () => connectorsApi.list(selectedClientId, selectedProjectId || undefined),
    enabled: !!selectedClientId,
  });

  // Cross-client tile feed (default view). Refetches every 5s while any tile is still running.
  const { data: tilesData, refetch: refetchTiles } = useQuery<{ scans: any[] }>({
    queryKey: ["assessments-tiles"],
    queryFn: () => assessmentsApi.listAll(),
    retry: 1,
    refetchInterval: (q) => {
      const scans = (q.state.data as any)?.scans || [];
      if (!scans.some((s: any) => s.status === "running")) return false;
      // Slow down to 30s when cached data is stale (last success > 15s ago)
      // to avoid hammering the endpoint when requests are repeatedly failing.
      const ageMs = Date.now() - (q.state.dataUpdatedAt || 0);
      return ageMs < 15_000 ? 5000 : 30_000;
    },
  });

  // Group scans by version root (parent_scan_id ?? id).
  const { tiles, versionMap: _versionMap } = React.useMemo(() => {
    const allScans = (tilesData?.scans || []) as any[];
    const groups = new Map<string, any[]>();
    for (const t of allScans) {
      const root = t.parent_scan_id || t.id;
      if (!groups.has(root)) groups.set(root, []);
      groups.get(root)!.push(t);
    }
    groups.forEach((arr) => {
      arr.sort((a, b) => {
        const at = new Date(a.started_at || a.created_at || 0).getTime();
        const bt = new Date(b.started_at || b.created_at || 0).getTime();
        return bt - at;
      });
    });
    const latestIds = new Set<string>();
    groups.forEach((arr) => { if (arr[0]) latestIds.add(arr[0].id); });
    const filtered = allScans
      .filter((t) => latestIds.has(t.id))
      .filter((t) => {
        if (selectedClientId && t.client_id !== selectedClientId) return false;
        return true;
      });
    return { tiles: filtered, versionMap: groups };
  }, [tilesData, selectedClientId]);

  const { data: findings = [], isLoading: findingsLoading } = useQuery<any[]>({
    queryKey: ["findings", selectedClientId, viewScan?.id],
    queryFn: () => scansApi.findings(selectedClientId, viewScan!.id),
    enabled: !!viewScan && !!selectedClientId,
  });

  const [pendingDeleteFinding, setPendingDeleteFinding] = useState<any | null>(null);
  const deleteFindingMutation = useMutation({
    mutationFn: (findingId: string) => findingsApi.delete(selectedClientId, findingId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings", selectedClientId, viewScan?.id] });
      qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
      setPendingDeleteFinding(null);
      toast.success("Finding deleted");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Failed to delete finding"),
  });

  const [pendingDeleteScan, setPendingDeleteScan] = useState<any | null>(null);
  const deleteScanMutation = useMutation({
    mutationFn: (tile: any) => scansApi.delete(tile.client_id, tile.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
      setPendingDeleteScan(null);
      toast.success("Assessment deleted");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Failed to delete assessment"),
  });

  const startMutation = useMutation({
    mutationFn: (data: any) => scansApi.start(selectedClientId, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
      setOpen(false); setScanName(""); setAcrRepoUrl(""); setAcrGitToken(""); setAcrMode("repo");
      toast.success("Assessment started");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error starting assessment"),
  });

  const rescanMutation = useMutation({
    mutationFn: (tile: any) => scansApi.rescan(tile.client_id, tile.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
      toast.success("Rescan started");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Failed to rescan"),
  });

  const versionMap = _versionMap;
  const [historyOpenForRoot, setHistoryOpenForRoot] = useState<string | null>(null);

  // Helper to decide which top-level group a scanner belongs to
  const platformScanners = SCANNERS.filter((s) => PLATFORM_SCANNER_TYPES.has(s.connectorType));
  const enterpriseScanners = SCANNERS.filter((s) => ENTERPRISE_SCANNER_TYPES.has(s.connectorType));

  // ── Enterprise scanner dialog helpers ──────────────────────────────────────
  const openEnterpriseDialog = (scanner?: ScannerDef) => {
    if (scanner) {
      setEnterpriseScanner(scanner);
      setEnterpriseStep("configure");
    } else {
      setEnterpriseScanner(null);
      setEnterpriseStep("pick");
    }
    setEnterpriseMode("saved");
    setEnterpriseSelectedConnId("");
    setEnterpriseManualCreds({});
    setEnterpriseScanName("");
    setEnterpriseSaveConnector(true);
    setEnterpriseNewConnName("");
    setEnterpriseDialogOpen(true);
  };

  const closeEnterpriseDialog = () => {
    setEnterpriseDialogOpen(false);
    setEnterpriseScanner(null);
    setEnterpriseStep("pick");
    setEnterpriseMode("saved");
    setEnterpriseSelectedConnId("");
    setEnterpriseManualCreds({});
    setEnterpriseScanName("");
    setEnterpriseSaveConnector(true);
    setEnterpriseNewConnName("");
  };

  // Connectors for the currently selected enterprise scanner type
  const enterpriseConnectors = connectors.filter(
    (c) => enterpriseScanner && c.connector_type === enterpriseScanner.connectorType
  );

  const enterpriseStartMutation = useMutation({
    mutationFn: async () => {
      if (!enterpriseScanner) return;
      let resolvedConnectorId = enterpriseSelectedConnId;

      if (enterpriseMode === "manual") {
        // Optionally save the connector first
        if (enterpriseSaveConnector && enterpriseNewConnName.trim()) {
          try {
            const newConn = await connectorsApi.create(selectedClientId, {
              name: enterpriseNewConnName.trim(),
              connector_type: enterpriseScanner.connectorType,
              project_id: "",
              credentials: enterpriseManualCreds,
            });
            resolvedConnectorId = newConn.id;
            qc.invalidateQueries({ queryKey: ["connectors"] });
          } catch {
            // Failed to save — proceed with inline credentials
            resolvedConnectorId = "";
          }
        }
        return scansApi.start(selectedClientId, {
          scan_type: "full",
          connector_id: resolvedConnectorId || undefined,
          name: enterpriseScanName.trim() || undefined,
          credentials: resolvedConnectorId ? undefined : enterpriseManualCreds,
        });
      } else {
        return scansApi.start(selectedClientId, {
          scan_type: "full",
          connector_id: enterpriseSelectedConnId || undefined,
          name: enterpriseScanName.trim() || undefined,
        });
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
      closeEnterpriseDialog();
      toast.success("Assessment started");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error starting assessment"),
  });

  return (
    <Box>
      {/* ── Page header ─────────────────────────────────────────────────── */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>Assessments</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Every scan across all clients · click a tile for the AI verdict, findings, and agent runs
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <Button variant="outlined" startIcon={<Refresh />}
            onClick={() => refetchTiles()}
            sx={{ borderColor: "divider", color: "text.secondary" }}>Refresh</Button>
          <Tooltip title={!canAct ? "Read-only in Executive mode — switch to Analyst (top-right) to run scans." : ""}>
            <span>
              <Button
                variant="contained"
                startIcon={<Add />}
                disabled={clients.length === 0 || !canAct}
                onClick={() => setOpen(true)}
              >
                New Assessment
              </Button>
            </span>
          </Tooltip>
        </Box>
      </Box>

      {/* ── Top-level scanner / import groups ──────────────────────────── */}
      <Box sx={{ mb: 3 }}>
        {/* Group 1: Inbuilt Scanners */}
        <Accordion
          expanded={sectionExpanded === "platform"}
          onChange={(_, exp) => setSectionExpanded(exp ? "platform" : false)}
          sx={{
            bgcolor: "background.paper",
            border: "1px solid rgba(255,255,255,0.08)",
            borderRadius: "8px !important",
            mb: 1,
            "&:before": { display: "none" },
            boxShadow: "none",
          }}
        >
          <AccordionSummary expandIcon={<ExpandMore sx={{ color: "text.secondary" }} />} sx={{ minHeight: 52, px: 2.5 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, flex: 1, mr: 1 }}>
              <Storage sx={{ color: "#34A853", fontSize: 20 }} />
              <Box sx={{ flex: 1 }}>
                <Typography sx={{ fontWeight: 700, color: "text.primary", fontSize: 15 }}>Inbuilt Scanners</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  Built-in scanners: DAST, SAST, network, dependency, secrets, and AI code review
                  ({platformScanners.filter(s => s.status === "live").length} live)
                </Typography>
              </Box>
              <Chip
                label={`${platformScanners.filter(s => s.status === "live").length} live`}
                size="small"
                sx={{ bgcolor: "rgba(52,168,83,0.12)", color: "#34A853", fontWeight: 700, fontSize: 10 }}
              />
              <Button
                size="small"
                variant="outlined"
                startIcon={<Add sx={{ fontSize: 14 }} />}
                disabled={!canAct || clients.length === 0}
                onClick={(e) => { e.stopPropagation(); setOpen(true); setCategory("dast"); setScannerId(""); }}
                sx={{
                  borderColor: "#34A853", color: "#34A853", fontSize: 11, ml: 1,
                  "&:hover": { bgcolor: "rgba(52,168,83,0.08)" },
                  "&.Mui-disabled": { borderColor: "rgba(255,255,255,0.12)", color: "text.disabled" },
                }}
              >
                New Assessment
              </Button>
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ px: 2.5, pt: 0, pb: 2 }}>
            <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.5 }}>
              Click "New Assessment" to launch any of these scanners. Platform scanners run via GitHub Actions.
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {platformScanners.map((s) => (
                <Chip
                  key={s.id}
                  label={s.name}
                  size="small"
                  sx={{
                    bgcolor: s.status === "live" ? "rgba(52,168,83,0.12)" : "rgba(255,255,255,0.04)",
                    color: s.status === "live" ? "#34A853" : "text.secondary",
                    border: s.status === "live" ? "1px solid rgba(52,168,83,0.3)" : "1px solid transparent",
                    fontWeight: 600,
                  }}
                />
              ))}
            </Box>
            {/* Inbuilt assessments — full tiles */}
            {(() => {
              const platformTiles = tiles.filter((t) => !ENTERPRISE_SCANNER_TYPES.has(t.connector_type) && t.connector_type !== "upload");
              if (!platformTiles.length) return null;
              return (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", fontSize: 10, display: "block", mb: 1.5 }}>
                    Assessments ({platformTiles.length})
                  </Typography>
                  <Grid container spacing={1.5}>
                    {platformTiles.map((tile) => (
                      <Grid size={{ xs: 12, sm: 6, md: 4, lg: 3 }} key={tile.id}>
                        <AssessmentTileCard tile={tile} versionMap={versionMap} navigate={navigate}
                          rescanMutation={rescanMutation} setPendingDeleteScan={setPendingDeleteScan}
                          setHistoryOpenForRoot={setHistoryOpenForRoot} />
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              );
            })()}
          </AccordionDetails>
        </Accordion>

        {/* Group 2: Enterprise Integrations */}
        <Accordion
          expanded={sectionExpanded === "enterprise"}
          onChange={(_, exp) => setSectionExpanded(exp ? "enterprise" : false)}
          sx={{
            bgcolor: "background.paper",
            border: "1px solid rgba(255,255,255,0.08)",
            borderRadius: "8px !important",
            mb: 1,
            "&:before": { display: "none" },
            boxShadow: "none",
          }}
        >
          <AccordionSummary expandIcon={<ExpandMore sx={{ color: "text.secondary" }} />} sx={{ minHeight: 52, px: 2.5 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, flex: 1, mr: 1 }}>
              <Business sx={{ color: "#9C27B0", fontSize: 20 }} />
              <Box sx={{ flex: 1 }}>
                <Typography sx={{ fontWeight: 700, color: "text.primary", fontSize: 15 }}>Enterprise Integrations</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  Direct API integrations: Tenable, Burp Enterprise, Snyk, Rapid7, Qualys, Invicti, Acunetix
                  ({enterpriseScanners.filter(s => s.status === "live").length} live)
                </Typography>
              </Box>
              <Chip
                label={`${enterpriseScanners.filter(s => s.status === "live").length} live`}
                size="small"
                sx={{ bgcolor: "rgba(156,39,176,0.12)", color: "#9C27B0", fontWeight: 700, fontSize: 10 }}
              />
              <Button
                size="small"
                variant="outlined"
                startIcon={<Add sx={{ fontSize: 14 }} />}
                disabled={!canAct || clients.length === 0}
                onClick={(e) => { e.stopPropagation(); openEnterpriseDialog(); }}
                sx={{
                  borderColor: "#9C27B0", color: "#9C27B0", fontSize: 11, ml: 1,
                  "&:hover": { bgcolor: "rgba(156,39,176,0.08)" },
                  "&.Mui-disabled": { borderColor: "rgba(255,255,255,0.12)", color: "text.disabled" },
                }}
              >
                New Assessment
              </Button>
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ px: 2.5, pt: 0, pb: 2 }}>
            <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.5 }}>
              Click a scanner below or "New Assessment" to launch. Use saved connectors or enter credentials inline.
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {enterpriseScanners.map((s) => (
                <Chip
                  key={s.id}
                  label={s.name}
                  size="small"
                  onClick={() => canAct && selectedClientId && openEnterpriseDialog(s)}
                  sx={{
                    bgcolor: "rgba(156,39,176,0.12)",
                    color: "#9C27B0",
                    border: "1px solid rgba(156,39,176,0.3)",
                    fontWeight: 600,
                    cursor: canAct && selectedClientId ? "pointer" : "default",
                    "&:hover": canAct && selectedClientId ? { bgcolor: "rgba(156,39,176,0.22)" } : {},
                  }}
                />
              ))}
            </Box>
            {/* Enterprise assessments — full tiles */}
            {(() => {
              const entTiles = tiles.filter((t) => ENTERPRISE_SCANNER_TYPES.has(t.connector_type));
              if (!entTiles.length) return null;
              return (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", fontSize: 10, display: "block", mb: 1.5 }}>
                    Assessments ({entTiles.length})
                  </Typography>
                  <Grid container spacing={1.5}>
                    {entTiles.map((tile) => (
                      <Grid size={{ xs: 12, sm: 6, md: 4, lg: 3 }} key={tile.id}>
                        <AssessmentTileCard tile={tile} versionMap={versionMap} navigate={navigate}
                          rescanMutation={rescanMutation} setPendingDeleteScan={setPendingDeleteScan}
                          setHistoryOpenForRoot={setHistoryOpenForRoot} />
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              );
            })()}
          </AccordionDetails>
        </Accordion>

        {/* Group 3: Import Results */}
        <Accordion
          expanded={sectionExpanded === "import"}
          onChange={(_, exp) => setSectionExpanded(exp ? "import" : false)}
          sx={{
            bgcolor: "background.paper",
            border: "1px solid rgba(255,255,255,0.08)",
            borderRadius: "8px !important",
            mb: 1,
            "&:before": { display: "none" },
            boxShadow: "none",
          }}
        >
          <AccordionSummary expandIcon={<ExpandMore sx={{ color: "text.secondary" }} />} sx={{ minHeight: 52, px: 2.5 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <CloudUpload sx={{ color: "#4285F4", fontSize: 20 }} />
              <Box>
                <Typography sx={{ fontWeight: 700, color: "text.primary", fontSize: 15 }}>Import Results</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  Upload offline scan files — SARIF, Nessus, Burp, OpenVAS, Qualys, Checkmarx, CSV, JSON, PDF
                </Typography>
              </Box>
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ px: 2.5, pt: 0, pb: 3 }}>
            {!selectedClientId ? (
              <Box sx={{ p: 3, textAlign: "center", border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 1.5, color: "text.secondary" }}>
                <Typography variant="body2">Select a client from the top toolbar to import results.</Typography>
              </Box>
            ) : (
              <ScanImportPanel clientId={selectedClientId} />
            )}
            {/* Import assessments — full tiles */}
            {(() => {
              const importTiles = tiles.filter((t) => t.connector_type === "upload");
              if (!importTiles.length) return null;
              return (
                <Box sx={{ mt: 3 }}>
                  <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", fontSize: 10, display: "block", mb: 1.5 }}>
                    Imported Assessments ({importTiles.length})
                  </Typography>
                  <Grid container spacing={1.5}>
                    {importTiles.map((tile) => (
                      <Grid size={{ xs: 12, sm: 6, md: 4, lg: 3 }} key={tile.id}>
                        <AssessmentTileCard tile={tile} versionMap={versionMap} navigate={navigate}
                          rescanMutation={rescanMutation} setPendingDeleteScan={setPendingDeleteScan}
                          setHistoryOpenForRoot={setHistoryOpenForRoot} />
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              );
            })()}
          </AccordionDetails>
        </Accordion>
      </Box>

      {/* ── Start scan dialog — category → scanner cascade ──────────────── */}
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle>
          Start New Scan
          <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>
            Pick a category, choose a scanner, then point it at a connector.
          </Typography>
        </DialogTitle>
        <DialogContent dividers sx={{ borderColor: "divider" }}>
          {/* Client picker */}
          <FormControl fullWidth size="small" sx={{ mb: 2 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Client</InputLabel>
            <Select
              value={selectedClientId}
              onChange={(e) => {
                setSelectedClientId(e.target.value);
                localStorage.setItem("owlet-active-client", e.target.value);
                setSelectedProjectId("");
                setConnectorId("");
                setScannerId("");
              }}
              label="Client"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
            >
              {clients.map((c) => (
                <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>
              ))}
              {clients.length === 0 && (
                <MenuItem value="" disabled>No clients you can access — ask an admin for a grant</MenuItem>
              )}
            </Select>
          </FormControl>

          {!selectedClientId ? (
            <Box sx={{
              p: 3, textAlign: "center", border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 1.5,
              color: "text.secondary",
            }}>
              <Typography variant="body2">Pick a client above to continue.</Typography>
            </Box>
          ) : (
          <>
          {/* Category tabs */}
          <Tabs
            value={category}
            onChange={(_, v) => { setCategory(v as ScanCategory); setScannerId(""); setConnectorId(""); }}
            sx={{
              mb: 2,
              borderBottom: "1px solid rgba(255,255,255,0.08)",
              "& .MuiTab-root": { color: "text.secondary", textTransform: "none", fontWeight: 600, minHeight: 40 },
              "& .Mui-selected": { color: CATEGORY_COLOR[category] },
              "& .MuiTabs-indicator": { backgroundColor: CATEGORY_COLOR[category] },
            }}
          >
            {CATEGORY_ORDER.map((c) => (
              <Tab key={c} value={c} label={CATEGORY_LABEL[c]} />
            ))}
          </Tabs>

          {category === "cloud" ? (
            // Cloud & Identity keeps the existing scan-type / framework form.
            <Grid container spacing={2} sx={{ mt: 0.5 }}>
              <Grid size={{ xs: 12 }}>
                <TextField fullWidth size="small" label="Scan name (optional)"
                  value={scanName} onChange={(e) => setScanName(e.target.value)}
                  placeholder='e.g. "Weekly Azure prod compliance"'
                  
                  sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <FormControl fullWidth size="small">
                  <InputLabel sx={{ color: "text.secondary" }}>Scan Type</InputLabel>
                  <Select value={scanType} onChange={(e) => setScanType(e.target.value as ScanType)} label="Scan Type"
                    sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                    <MenuItem value="vulnerability">Vulnerability Assessment</MenuItem>
                    <MenuItem value="configuration">Configuration Review</MenuItem>
                    <MenuItem value="compliance">Compliance Assessment</MenuItem>
                    <MenuItem value="full">Full Assessment (all)</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <FormControl fullWidth size="small">
                  <InputLabel sx={{ color: "text.secondary" }}>Connector (optional)</InputLabel>
                  <Select value={connectorId} onChange={(e) => setConnectorId(e.target.value)} label="Connector"
                    sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                    <MenuItem value="">All connectors</MenuItem>
                    {connectors
                      .filter((c) => !SCANNERS.some((s) => s.connectorType === c.connector_type))
                      .map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
                  </Select>
                </FormControl>
              </Grid>
              <Grid size={{ xs: 12 }}>
                <FormControl fullWidth size="small">
                  <InputLabel sx={{ color: "text.secondary" }}>Framework</InputLabel>
                  <Select value={framework} onChange={(e) => setFramework(e.target.value as FrameworkType)} label="Framework"
                    sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                    <MenuItem value="">None</MenuItem>
                    {frameworkCatalog.map((f) => (
                      <MenuItem key={f.framework} value={f.framework}>
                        {f.name} ({f.total_controls})
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          ) : (
            // Scanner-driven categories (DAST/SAST/Network/Dependency/Enterprise)
            <Box>
              <Stack spacing={1} sx={{ mb: 2 }}>
                {SCANNERS.filter((s) => s.category === category).map((s) => {
                  const isPicked = scannerId === s.id;
                  const isLive = s.status === "live";
                  return (
                    <Card
                      key={s.id}
                      onClick={() => isLive && setScannerId(s.id)}
                      sx={{
                        bgcolor: isPicked ? "rgba(66,133,244,0.08)" : "transparent",
                        border: `1px solid ${isPicked ? CATEGORY_COLOR[category] : "rgba(255,255,255,0.1)"}`,
                        borderRadius: 2, p: 1.5, cursor: isLive ? "pointer" : "not-allowed",
                        opacity: isLive ? 1 : 0.55,
                        transition: "all 0.15s",
                        "&:hover": isLive ? { borderColor: CATEGORY_COLOR[category], bgcolor: "rgba(255,255,255,0.03)" } : {},
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
                        <Typography sx={{ fontWeight: 600, fontSize: 14, color: "text.primary" }}>{s.name}</Typography>
                        <Chip
                          label={isLive ? "Live" : "Coming soon"}
                          size="small"
                          sx={{
                            bgcolor: isLive ? "rgba(52,168,83,0.15)" : "rgba(255,255,255,0.06)",
                            color: isLive ? "#34A853" : "text.secondary",
                            fontWeight: 700, fontSize: 10, height: 20,
                          }}
                        />
                      </Box>
                      <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {s.description}
                      </Typography>
                    </Card>
                  );
                })}
              </Stack>

              {/* Per-scanner config: connector picker + name */}
              {scannerId && (
                <Grid container spacing={2}>
                  <Grid size={{ xs: 12 }}>
                    <TextField fullWidth size="small" label="Scan name (optional)"
                      value={scanName} onChange={(e) => setScanName(e.target.value)}
                      
                      sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
                  </Grid>
                  {scannerId !== "ai_code_review" && (
                    <Grid size={{ xs: 12 }}>
                      <FormControl fullWidth size="small">
                        <InputLabel sx={{ color: "text.secondary" }}>Connector</InputLabel>
                        <Select value={connectorId} onChange={(e) => setConnectorId(e.target.value)} label="Connector"
                          sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                          {(() => {
                            const def = SCANNERS.find((s) => s.id === scannerId);
                            const matching = connectors.filter((c) => c.connector_type === def?.connectorType);
                            if (matching.length === 0) {
                              return <MenuItem disabled value="">No {def?.name} connector configured — create one under Connectors first</MenuItem>;
                            }
                            return matching.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>);
                          })()}
                        </Select>
                      </FormControl>
                    </Grid>
                  )}
                  {/* AI Code Review — pick git repo mode vs archive upload. */}
                  {scannerId === "ai_code_review" && (
                    <>
                      <Grid size={{ xs: 12 }}>
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
                          SOURCE MODE
                        </Typography>
                        <Box sx={{ display: "flex", gap: 1 }}>
                          {([
                            { id: "repo",    label: "Git repo",       hint: "The connector's repo_url is cloned and analysed. Best for CI/CD integration." },
                            { id: "archive", label: "Upload archive",  hint: "Upload a .zip or .tar.gz of your source code. No git credentials needed." },
                          ] as const).map((opt) => {
                            const picked = acrMode === opt.id;
                            return (
                              <Tooltip key={opt.id} title={opt.hint}>
                                <Card
                                  onClick={() => { setAcrMode(opt.id); if (opt.id === "repo") setCodeArchive(null); }}
                                  sx={{
                                    flex: 1, p: 1.25, cursor: "pointer",
                                    bgcolor: picked ? "rgba(66,133,244,0.08)" : "transparent",
                                    border: `1px solid ${picked ? "#4285F4" : "rgba(255,255,255,0.1)"}`,
                                    borderRadius: 1.5,
                                    "&:hover": { borderColor: "#4285F4" },
                                  }}
                                >
                                  <Typography sx={{ color: "text.primary", fontSize: 13, fontWeight: 600 }}>{opt.label}</Typography>
                                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.25 }}>
                                    {opt.hint}
                                  </Typography>
                                </Card>
                              </Tooltip>
                            );
                          })}
                        </Box>
                      </Grid>
                      {acrMode === "repo" && (
                        <>
                          <Grid size={{ xs: 12 }}>
                            <TextField
                              fullWidth size="small" label="Repository URL"
                              placeholder="https://github.com/owner/repo"
                              value={acrRepoUrl}
                              onChange={(e) => setAcrRepoUrl(e.target.value)}
                              slotProps={{ input: { sx: { color: "text.primary" } } }}
                            />
                          </Grid>
                          <Grid size={{ xs: 12 }}>
                            <TextField
                              fullWidth size="small" type="password"
                              label="Access Token (optional — required for private repos)"
                              placeholder="ghp_xxxxxxxxxxxx"
                              value={acrGitToken}
                              onChange={(e) => setAcrGitToken(e.target.value)}
                              helperText="GitHub PAT or GitLab token with repo read access. Not stored after the scan runs."
                              slotProps={{ input: { sx: { color: "text.primary" } } }}
                            />
                          </Grid>
                        </>
                      )}
                      {acrMode === "archive" && (
                        <Grid size={{ xs: 12 }}>
                          <Box sx={{ p: 1.5, border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 1.5 }}>
                            <Button
                              component="label" size="small" variant="outlined"
                              sx={{ borderColor: "divider", color: "text.secondary" }}
                            >
                              {codeArchive ? "Change archive" : "Choose code archive"}
                              <input hidden type="file" accept=".zip,.tar.gz,.tgz,.tar"
                                onChange={(e) => setCodeArchive(e.target.files?.[0] || null)} />
                            </Button>
                            {codeArchive ? (
                              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>
                                <b>{codeArchive.name}</b> · {(codeArchive.size / 1024 / 1024).toFixed(2)} MB
                              </Typography>
                            ) : (
                              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>
                                Accepts .zip, .tar.gz, or .tar archives of your source code.
                              </Typography>
                            )}
                          </Box>
                        </Grid>
                      )}
                    </>
                  )}
                  {/* CodeQL-only: pick source-repo mode vs upload-binary mode. */}
                  {scannerId === "codeql" && (
                    <>
                      <Grid size={{ xs: 12 }}>
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
                          SCAN MODE
                        </Typography>
                        <Box sx={{ display: "flex", gap: 1 }}>
                          {([
                            { id: "source", label: "Source repo", hint: "Workflow clones the connector's repo_url and runs the security-and-quality suite." },
                            { id: "binary", label: "Upload binary", hint: "Upload a JAR / WAR / EAR / ZIP / tar.gz. Workflow runs CodeQL with --build-mode=none (JVM / .NET). 500 MB max. Auto-deleted after 30 days." },
                          ] as const).map((opt) => {
                            const picked = codeqlMode === opt.id;
                            return (
                              <Tooltip key={opt.id} title={opt.hint}>
                                <Card
                                  onClick={() => { setCodeqlMode(opt.id); if (opt.id === "source") setBinaryFile(null); }}
                                  sx={{
                                    flex: 1, p: 1.25, cursor: "pointer",
                                    bgcolor: picked ? "rgba(66,133,244,0.08)" : "transparent",
                                    border: `1px solid ${picked ? "#4285F4" : "rgba(255,255,255,0.1)"}`,
                                    borderRadius: 1.5,
                                    "&:hover": { borderColor: "#4285F4" },
                                  }}
                                >
                                  <Typography sx={{ color: "text.primary", fontSize: 13, fontWeight: 600 }}>{opt.label}</Typography>
                                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.25 }}>
                                    {opt.hint}
                                  </Typography>
                                </Card>
                              </Tooltip>
                            );
                          })}
                        </Box>
                      </Grid>
                      {codeqlMode === "binary" && (
                        <Grid size={{ xs: 12 }}>
                          <Box sx={{ p: 1.5, border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 1.5 }}>
                            <Button
                              component="label" size="small" variant="outlined"
                              sx={{ borderColor: "divider", color: "text.secondary" }}
                            >
                              {binaryFile ? "Change file" : "Choose binary archive"}
                              <input hidden type="file"
                                accept=".jar,.war,.ear,.zip,.tar,.tar.gz,.tgz,.dll,.exe"
                                onChange={(e) => setBinaryFile(e.target.files?.[0] || null)} />
                            </Button>
                            {binaryFile ? (
                              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>
                                <b>{binaryFile.name}</b> · {(binaryFile.size / 1024 / 1024).toFixed(2)} MB
                              </Typography>
                            ) : (
                              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>
                                Accepts JAR / WAR / EAR / ZIP / tar.gz / DLL / EXE up to 500 MB.
                              </Typography>
                            )}
                          </Box>
                        </Grid>
                      )}
                    </>
                  )}
                </Grid>
              )}
            </Box>
          )}
          </>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => { setOpen(false); setAcrRepoUrl(""); setAcrGitToken(""); setAcrMode("repo"); }} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button variant="contained" startIcon={<PlayArrow />}
            disabled={
              startMutation.isPending ||
              (category !== "cloud" && scannerId !== "ai_code_review" && (!scannerId || !connectorId)) ||
              (scannerId === "codeql" && codeqlMode === "binary" && !binaryFile) ||
              (scannerId === "ai_code_review" && acrMode === "archive" && !codeArchive) ||
              (scannerId === "ai_code_review" && acrMode === "repo" && !acrRepoUrl.trim())
            }
            onClick={async () => {
              const isBinary = scannerId === "codeql" && codeqlMode === "binary" && binaryFile;
              const isAcrArchive = scannerId === "ai_code_review" && acrMode === "archive" && codeArchive;
              if (isBinary) {
                try {
                  const created = await scansApi.start(selectedClientId, {
                    scan_type: scanType,
                    connector_id: connectorId || undefined,
                    framework: framework || undefined,
                    name: scanName || undefined,
                    defer_dispatch: true,
                  });
                  const fd = new FormData();
                  fd.append("file", binaryFile);
                  await apiClient.post(
                    `/clients/${selectedClientId}/scans/${created.id}/upload-binary`,
                    fd,
                    { headers: { "Content-Type": "multipart/form-data" } }
                  );
                  qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
                  setOpen(false); setScanName(""); setBinaryFile(null);
                  toast.success(`Uploaded ${binaryFile.name} — scan starting`);
                } catch (e: any) {
                  toast.error(e?.response?.data?.detail || "Binary upload failed");
                }
              } else if (isAcrArchive) {
                try {
                  const created = await scansApi.start(selectedClientId, {
                    scan_type: scanType,
                    connector_id: connectorId || undefined,
                    framework: framework || undefined,
                    name: scanName || undefined,
                    defer_dispatch: true,
                  });
                  const fd = new FormData();
                  fd.append("file", codeArchive);
                  await apiClient.post(
                    `/clients/${selectedClientId}/scans/${created.id}/upload-code/`,
                    fd,
                    { headers: { "Content-Type": "multipart/form-data" } }
                  );
                  qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
                  setOpen(false); setScanName(""); setCodeArchive(null); setAcrMode("repo");
                  toast.success(`Uploaded ${codeArchive.name} — AI code review starting`);
                } catch (e: any) {
                  toast.error(e?.response?.data?.detail || "Code archive upload failed");
                }
              } else {
                const isAcrRepo = scannerId === "ai_code_review" && acrMode === "repo";
                startMutation.mutate({
                  scan_type: scanType,
                  connector_id: isAcrRepo ? undefined : (connectorId || undefined),
                  framework: framework || undefined,
                  name: scanName || undefined,
                  ...(isAcrRepo && acrRepoUrl.trim() ? { repo_url: acrRepoUrl.trim() } : {}),
                  ...(isAcrRepo && acrGitToken.trim() ? { git_token: acrGitToken.trim() } : {}),
                });
              }
            }}>
            {startMutation.isPending ? <CircularProgress size={18} /> : "Start Scan"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Enterprise scanner dialog ──────────────────────────────────────── */}
      <Dialog
        open={enterpriseDialogOpen}
        onClose={closeEnterpriseDialog}
        maxWidth="sm"
        fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}
      >
        <DialogTitle sx={{ pb: 1 }}>
          {enterpriseStep === "pick" ? (
            <>
              <Typography variant="h6" sx={{ fontWeight: 700 }}>Select Enterprise Scanner</Typography>
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                Choose which scanner to launch a new assessment with.
              </Typography>
            </>
          ) : (
            <>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                <Business sx={{ color: "#9C27B0" }} />
                <Box>
                  <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1.2 }}>
                    {enterpriseScanner?.name}
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    New Assessment
                  </Typography>
                </Box>
              </Box>
            </>
          )}
        </DialogTitle>
        <DialogContent dividers sx={{ borderColor: "divider" }}>
          {enterpriseStep === "pick" ? (
            /* ── Scanner picker grid ── */
            <Grid container spacing={1.5} sx={{ mt: 0.5 }}>
              {enterpriseScanners.map((s) => (
                <Grid size={{ xs: 12, sm: 6 }} key={s.id}>
                  <Card
                    onClick={() => {
                      setEnterpriseScanner(s);
                      setEnterpriseStep("configure");
                      setEnterpriseMode("saved");
                      setEnterpriseSelectedConnId("");
                      setEnterpriseManualCreds({});
                      setEnterpriseNewConnName(`${s.name} — ${new Date().toLocaleDateString()}`);
                    }}
                    sx={{
                      bgcolor: "transparent",
                      border: "1px solid rgba(255,255,255,0.1)",
                      borderRadius: 2, p: 1.5, cursor: "pointer",
                      transition: "all 0.15s",
                      "&:hover": { borderColor: "#9C27B0", bgcolor: "rgba(156,39,176,0.06)" },
                    }}
                  >
                    <Typography sx={{ fontWeight: 600, fontSize: 14, color: "text.primary", mb: 0.5 }}>
                      {s.name}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                      {s.description.slice(0, 90)}{s.description.length > 90 ? "…" : ""}
                    </Typography>
                  </Card>
                </Grid>
              ))}
            </Grid>
          ) : (
            /* ── Configure step ── */
            <Box sx={{ mt: 0.5 }}>
              {/* Client selector */}
              <FormControl fullWidth size="small" sx={{ mb: 2 }}>
                <InputLabel sx={{ color: "text.secondary" }}>Client</InputLabel>
                <Select
                  value={selectedClientId}
                  onChange={(e) => {
                    setSelectedClientId(e.target.value);
                    localStorage.setItem("owlet-active-client", e.target.value);
                    setEnterpriseSelectedConnId("");
                  }}
                  label="Client"
                  sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                >
                  {clients.map((c) => (
                    <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>
                  ))}
                  {clients.length === 0 && (
                    <MenuItem value="" disabled>No clients — ask an admin for a grant</MenuItem>
                  )}
                </Select>
              </FormControl>

              {/* Mode toggle */}
              <Box sx={{ mb: 2 }}>
                <ToggleButtonGroup
                  value={enterpriseMode}
                  exclusive
                  onChange={(_, v) => { if (v) { setEnterpriseMode(v); setEnterpriseSelectedConnId(""); setEnterpriseManualCreds({}); } }}
                  size="small"
                  fullWidth
                  sx={{
                    "& .MuiToggleButton-root": {
                      color: "text.secondary", borderColor: "rgba(255,255,255,0.12)",
                      textTransform: "none", fontWeight: 600, fontSize: 13,
                    },
                    "& .Mui-selected": { color: "#9C27B0", bgcolor: "rgba(156,39,176,0.1) !important" },
                  }}
                >
                  <ToggleButton value="saved">
                    <LinkIcon sx={{ fontSize: 16, mr: 0.75 }} />
                    Use Saved Connector
                  </ToggleButton>
                  <ToggleButton value="manual">
                    <Add sx={{ fontSize: 16, mr: 0.75 }} />
                    Enter Manually
                  </ToggleButton>
                </ToggleButtonGroup>
              </Box>

              {/* ── Saved connector mode ── */}
              {enterpriseMode === "saved" && (
                <Box>
                  {enterpriseConnectors.length === 0 ? (
                    <Box
                      sx={{
                        p: 2.5, borderRadius: 1.5, textAlign: "center",
                        border: "1px dashed rgba(255,255,255,0.2)",
                        bgcolor: "rgba(255,255,255,0.02)",
                      }}
                    >
                      <Typography sx={{ color: "text.secondary", fontSize: 14, mb: 1 }}>
                        No saved connectors for {enterpriseScanner?.name} yet.
                      </Typography>
                      <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.5 }}>
                        Switch to "Enter Manually" or configure one in Connections first.
                      </Typography>
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={() => navigate(`${connBase}#scanner`)}
                        sx={{ borderColor: "#9C27B0", color: "#9C27B0", fontSize: 12 }}
                      >
                        Go to Scanner Connectors
                      </Button>
                    </Box>
                  ) : (
                    <Box>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, display: "block", mb: 1, letterSpacing: 0.5 }}>
                        SELECT CONNECTOR
                      </Typography>
                      <Stack spacing={1} sx={{ mb: 2 }}>
                        {enterpriseConnectors.map((conn) => {
                          const isPicked = enterpriseSelectedConnId === conn.id;
                          return (
                            <Box
                              key={conn.id}
                              onClick={() => setEnterpriseSelectedConnId(conn.id)}
                              sx={{
                                p: 1.5, borderRadius: 1.5, cursor: "pointer",
                                border: `1px solid ${isPicked ? "#9C27B0" : "rgba(255,255,255,0.1)"}`,
                                bgcolor: isPicked ? "rgba(156,39,176,0.08)" : "rgba(255,255,255,0.02)",
                                "&:hover": { borderColor: "#9C27B0", bgcolor: "rgba(156,39,176,0.05)" },
                              }}
                            >
                              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                <Typography sx={{ fontWeight: 600, fontSize: 13, color: "text.primary" }}>
                                  {conn.name}
                                </Typography>
                                <Chip
                                  size="small"
                                  label={conn.status === "active" ? "Active" : conn.status}
                                  sx={{
                                    height: 18, fontSize: 10, fontWeight: 700,
                                    bgcolor: conn.status === "active" ? "rgba(0,230,118,0.12)" : "rgba(255,255,255,0.06)",
                                    color: conn.status === "active" ? "#00e676" : "text.secondary",
                                  }}
                                />
                              </Box>
                              {conn.created_at && (
                                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                  Added {new Date(conn.created_at).toLocaleDateString()}
                                </Typography>
                              )}
                            </Box>
                          );
                        })}
                      </Stack>
                    </Box>
                  )}
                </Box>
              )}

              {/* ── Manual credentials mode ── */}
              {enterpriseMode === "manual" && enterpriseScanner && (
                <Box>
                  {(() => {
                    const fields = CREDENTIAL_FIELDS[enterpriseScanner.connectorType as keyof typeof CREDENTIAL_FIELDS] || [];
                    return (
                      <Grid container spacing={1.5}>
                        {fields.map(({ key, label, secret, placeholder, help }) => (
                          <Grid size={{ xs: 12 }} key={key}>
                            <TextField
                              fullWidth size="small" label={label}
                              type={secret ? "password" : "text"}
                              placeholder={placeholder}
                              helperText={help}
                              value={enterpriseManualCreds[key] || ""}
                              onChange={(e) => setEnterpriseManualCreds({ ...enterpriseManualCreds, [key]: e.target.value })}
                              slotProps={{
                                formHelperText: { sx: { color: "text.secondary", fontSize: 11 } },
                              }}
                              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                            />
                          </Grid>
                        ))}
                      </Grid>
                    );
                  })()}

                  {/* Save connector toggle */}
                  <Box
                    sx={{
                      mt: 2, p: 1.5, borderRadius: 1.5,
                      border: "1px solid rgba(255,255,255,0.08)",
                      bgcolor: "rgba(255,255,255,0.02)",
                    }}
                  >
                    <FormControlLabel
                      control={
                        <Switch
                          checked={enterpriseSaveConnector}
                          onChange={(e) => setEnterpriseSaveConnector(e.target.checked)}
                          size="small"
                          sx={{ "& .MuiSwitch-switchBase.Mui-checked": { color: "#9C27B0" }, "& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track": { bgcolor: "#9C27B0" } }}
                        />
                      }
                      label={
                        <Typography sx={{ fontSize: 13, color: "text.primary", fontWeight: 600 }}>
                          Save connector for future use
                        </Typography>
                      }
                    />
                    {enterpriseSaveConnector && (
                      <TextField
                        fullWidth size="small" label="Connector name"
                        value={enterpriseNewConnName}
                        onChange={(e) => setEnterpriseNewConnName(e.target.value)}
                        sx={{ mt: 1.5, "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      />
                    )}
                  </Box>
                </Box>
              )}

              {/* Scan name */}
              <TextField
                fullWidth size="small" label="Scan name (optional)"
                value={enterpriseScanName}
                onChange={(e) => setEnterpriseScanName(e.target.value)}
                placeholder={`${enterpriseScanner?.name || "Enterprise"} — ${new Date().toLocaleDateString()}`}
                sx={{ mt: 2, "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
              />
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button
            onClick={() => {
              if (enterpriseStep === "configure" && !enterpriseScanner) {
                closeEnterpriseDialog();
              } else if (enterpriseStep === "configure") {
                setEnterpriseStep("pick");
                setEnterpriseScanner(null);
              } else {
                closeEnterpriseDialog();
              }
            }}
            sx={{ color: "text.secondary" }}
          >
            {enterpriseStep === "configure" ? "Back" : "Cancel"}
          </Button>
          {enterpriseStep === "configure" && (
            <Button
              variant="contained"
              startIcon={enterpriseStartMutation.isPending ? <CircularProgress size={16} sx={{ color: "inherit" }} /> : <PlayArrow />}
              disabled={
                !selectedClientId ||
                enterpriseStartMutation.isPending ||
                (enterpriseMode === "saved" && !enterpriseSelectedConnId && enterpriseConnectors.length > 0)
              }
              onClick={() => enterpriseStartMutation.mutate()}
              sx={{ bgcolor: "#9C27B0", "&:hover": { bgcolor: "#7b1fa2" } }}
            >
              {enterpriseStartMutation.isPending ? "Starting…" : "Launch Scan"}
            </Button>
          )}
        </DialogActions>
      </Dialog>

      {/* ── Findings dialog ────────────────────────────────────────────────── */}
      <Dialog open={!!viewScan} onClose={() => setViewScan(null)} maxWidth="md" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <Box>
            <Typography variant="h6">Scan Findings</Typography>
            {viewScan && (
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {viewScan.scan_type} · {viewScan.framework || "No framework"} · {fromNow(viewScan.started_at)}
              </Typography>
            )}
          </Box>
          {viewScan && (
            <Chip label={viewScan.status} size="small"
              sx={{ bgcolor: `${STATUS_COLOR[viewScan.status]}20`, color: STATUS_COLOR[viewScan.status] }} />
          )}
        </DialogTitle>
        <Divider sx={{ borderColor: "divider" }} />
        <DialogContent sx={{ p: 0 }}>
          {findingsLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}>
              <CircularProgress sx={{ color: "#4285F4" }} />
            </Box>
          ) : findings.length === 0 ? (
            <Box sx={{ p: 4, textAlign: "center", color: "text.secondary" }}>
              No findings recorded for this scan.
            </Box>
          ) : (
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { borderColor: "divider", color: "text.secondary", fontSize: 11, fontWeight: 600 } }}>
                  <TableCell>Severity</TableCell>
                  <TableCell>Title</TableCell>
                  <TableCell>Resource</TableCell>
                  <TableCell>CVE</TableCell>
                  <TableCell>CVSS</TableCell>
                  <TableCell align="right" sx={{ width: 44 }} />
                </TableRow>
              </TableHead>
              <TableBody>
                {findings.map((f: any) => (
                  <TableRow key={f.id} hover sx={{ "& td": { borderColor: "divider", color: "text.primary", fontSize: 12 } }}>
                    <TableCell>
                      <Chip label={f.severity} size="small"
                        sx={{ bgcolor: `${SEV_COLOR[f.severity] || "#888"}20`, color: SEV_COLOR[f.severity] || "#888", fontSize: 10, height: 18 }} />
                    </TableCell>
                    <TableCell sx={{ maxWidth: 300 }}>
                      <Typography variant="caption" sx={{ display: "block", fontWeight: 600 }}>{f.title}</Typography>
                      {f.description && (
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.3 }}>
                          {f.description.slice(0, 120)}{f.description.length > 120 ? "…" : ""}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell><Typography variant="caption" sx={{ color: "text.secondary" }}>{f.resource_id || "—"}</Typography></TableCell>
                    <TableCell><Typography variant="caption" sx={{ color: "#4285F4" }}>{f.cve_id || "—"}</Typography></TableCell>
                    <TableCell><Typography variant="caption">{f.cvss_score ?? "—"}</Typography></TableCell>
                    <TableCell align="right" sx={{ width: 44 }}>
                      <Tooltip title="Delete finding">
                        <IconButton
                          size="small"
                          onClick={(e) => { e.stopPropagation(); setPendingDeleteFinding(f); }}
                          sx={{
                            color: "text.secondary",
                            "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" },
                          }}
                        >
                          <DeleteOutlined sx={{ fontSize: 18 }} />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setViewScan(null)} sx={{ color: "text.secondary" }}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* ── Version history dialog ─────────────────────────────────────────── */}
      <Dialog open={!!historyOpenForRoot} onClose={() => setHistoryOpenForRoot(null)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <History sx={{ color: "#FBBC04" }} />
            <Typography component="span" sx={{ fontWeight: 700 }}>Assessment history</Typography>
          </Box>
        </DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          {historyOpenForRoot && (() => {
            const versions = versionMap.get(historyOpenForRoot) || [];
            return (
              <Box>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
                  {versions.length} run{versions.length === 1 ? "" : "s"} — the <b>LIVE</b> version's findings show in the global view.
                  Click "Set as Live" on any version to promote it.
                </Typography>
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.3)", display: "block", mb: 1.5, fontSize: 11 }}>
                  Previous findings are never deleted — they become active again if you restore an older version.
                </Typography>
                {versions.map((v: any, idx: number) => {
                  const isLive = v.is_live === true || (v.is_live === undefined && idx === 0);
                  const versionNum = versions.length - idx;
                  const vStatus = (v.status || "").toLowerCase();
                  const vColor = STATUS_COLOR[vStatus] || "rgba(255,255,255,0.4)";
                  return (
                    <Box
                      key={v.id}
                      sx={{
                        display: "flex", alignItems: "center", gap: 1.5, p: 1.25, mb: 0.75,
                        borderRadius: 1,
                        bgcolor: isLive ? "rgba(52,168,83,0.06)" : "rgba(255,255,255,0.03)",
                        border: `1px solid ${isLive ? "rgba(52,168,83,0.3)" : "rgba(255,255,255,0.06)"}`,
                      }}
                    >
                      <Chip
                        label={isLive ? `v${versionNum} · LIVE` : `v${versionNum}`}
                        size="small"
                        sx={{
                          height: 22, fontSize: 10, fontWeight: 700, letterSpacing: 0.5, minWidth: 78,
                          bgcolor: isLive ? "rgba(52,168,83,0.2)" : "rgba(255,255,255,0.06)",
                          color: isLive ? "#34A853" : "text.secondary",
                        }} />
                      <Box
                        sx={{ flex: 1, minWidth: 0, cursor: "pointer", "&:hover": { opacity: 0.8 } }}
                        onClick={() => { setHistoryOpenForRoot(null); navigate(`${scansBase}/${v.id}`); }}
                      >
                        <Typography variant="body2" sx={{ color: "text.primary", fontSize: 13, fontWeight: 500 }}>
                          {v.started_at ? new Date(v.started_at).toLocaleString() : (v.created_at ? new Date(v.created_at).toLocaleString() : "—")}
                        </Typography>
                        <Typography variant="caption" sx={{ color: "text.secondary" }}>
                          {v.findings_count || 0} finding{(v.findings_count || 0) === 1 ? "" : "s"}
                          {v.duration_seconds != null
                            ? ` · ${v.duration_seconds >= 60 ? Math.round(v.duration_seconds / 60) + " min" : v.duration_seconds + "s"}`
                            : ""}
                        </Typography>
                      </Box>
                      <Chip label={vStatus} size="small"
                        sx={{ height: 18, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                          bgcolor: `${vColor}25`, color: vColor }} />
                      {!isLive && (
                        <Tooltip title="Promote this version to live — its findings become the active set">
                          <Button
                            size="small"
                            variant="outlined"
                            onClick={(e) => {
                              e.stopPropagation();
                              scansApi.setLive(v.client_id || "", v.id).then(() => {
                                qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
                                qc.invalidateQueries({ queryKey: ["scans-for-findings"] });
                                qc.invalidateQueries({ queryKey: ["findings-all"] });
                                setHistoryOpenForRoot(null);
                                toast.success(`v${versionNum} is now the live version`);
                              }).catch(() => toast.error("Failed to set live version"));
                            }}
                            sx={{ fontSize: 11, py: 0.25, px: 1, minWidth: 0, borderColor: "#34A853", color: "#34A853",
                              whiteSpace: "nowrap", "&:hover": { bgcolor: "rgba(52,168,83,0.08)" } }}
                          >
                            Set as Live
                          </Button>
                        </Tooltip>
                      )}
                    </Box>
                  );
                })}
              </Box>
            );
          })()}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setHistoryOpenForRoot(null)} sx={{ color: "text.secondary" }}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* ── Confirm assessment delete ──────────────────────────────────────── */}
      <Dialog open={!!pendingDeleteScan} onClose={() => setPendingDeleteScan(null)}
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>Delete assessment?</DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            This permanently removes the scan and every finding, agent run, and AI verdict tied to it. It does NOT delete the connector or affect future scans.
          </Typography>
          {pendingDeleteScan && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600 }}>{pendingDeleteScan.tile_name}</Typography>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {pendingDeleteScan.scan_type} · {pendingDeleteScan.findings_count ?? 0} finding{pendingDeleteScan.findings_count === 1 ? "" : "s"}
                {pendingDeleteScan.framework ? ` · ${pendingDeleteScan.framework}` : ""}
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDeleteScan(null)} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button
            variant="contained"
            disabled={deleteScanMutation.isPending}
            onClick={() => pendingDeleteScan && deleteScanMutation.mutate(pendingDeleteScan)}
            sx={{ bgcolor: "#EA4335", "&:hover": { bgcolor: "#c5362b" } }}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Confirm finding delete ─────────────────────────────────────────── */}
      <Dialog open={!!pendingDeleteFinding} onClose={() => setPendingDeleteFinding(null)}
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>Delete finding?</DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            This permanently removes the finding. If the same issue is detected on the next scan it will be re-created.
          </Typography>
          {pendingDeleteFinding && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600 }}>{pendingDeleteFinding.title || "(no title)"}</Typography>
              {pendingDeleteFinding.resource_id && (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>{pendingDeleteFinding.resource_id}</Typography>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDeleteFinding(null)} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button
            variant="contained"
            disabled={deleteFindingMutation.isPending}
            onClick={() => pendingDeleteFinding && deleteFindingMutation.mutate(pendingDeleteFinding.id)}
            sx={{ bgcolor: "#EA4335", "&:hover": { bgcolor: "#c5362b" } }}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
