import React, { useState } from "react";
import {
  Box, Typography, Card, Chip, CircularProgress, TextField,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  Collapse, IconButton, Alert, Tooltip, Divider,
  FormControl, InputLabel, Select, MenuItem,
  Dialog, DialogTitle, DialogContent,
} from "@mui/material";
import { BugReport, ExpandMore, ExpandLess, Shield, Calculate } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { clientsApi, cveApi } from "../services/api";
import { Client, CveImpact } from "../types";
import { fromNow } from "../utils/datetime";

const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50", info: "#4285F4",
};
const CLASS_COLOR: Record<string, string> = {
  vm: "#4285F4", storage: "#ff9800", network: "#34A853", database: "#00e676",
  identity: "#f06292", keyvault: "#ffd54f", other: "#9e9e9e",
};

function MitreBadge({ t }: { t: any }) {
  return (
    <Tooltip title={`${t.tactic || ""} · Confidence: ${t.confidence || "unknown"}`}>
      <Chip
        label={`${t.technique_id || ""} ${t.technique_name || ""}`}
        size="small"
        sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontSize: 10, height: 20, mr: 0.5, mb: 0.5 }}
      />
    </Tooltip>
  );
}

function CVEDetailRow({ clientId, cveId }: { clientId: string; cveId: string; onClose: () => void }) {
  const { data, isLoading } = useQuery<any>({
    queryKey: ["cve-detail", clientId, cveId],
    queryFn: () => cveApi.get(clientId, cveId),
    enabled: !!clientId && !!cveId,
  });

  return (
    <Box sx={{ bgcolor: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2, mb: 1 }}>
      {isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", p: 2 }}>
          <CircularProgress size={24} sx={{ color: "#4285F4" }} />
        </Box>
      ) : !data ? (
        <Typography sx={{ color: "text.secondary" }}>No detail available.</Typography>
      ) : (
        <>
          {/* Header */}
          <Box sx={{ mb: 1.5 }}>
            <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600, mb: 0.5 }}>{data.title}</Typography>
            <Typography variant="caption" sx={{ color: "text.secondary" }}>{data.description?.slice(0, 300)}{data.description?.length > 300 ? "…" : ""}</Typography>
          </Box>

          {/* MITRE techniques */}
          {data.mitre_techniques?.length > 0 && (
            <Box sx={{ mb: 1.5 }}>
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
                <Shield sx={{ fontSize: 12, mr: 0.5, verticalAlign: "middle" }} />
                MITRE ATT&CK Techniques
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap" }}>
                {data.mitre_techniques.map((t: any, i: number) => <MitreBadge key={i} t={t} />)}
              </Box>
            </Box>
          )}

          <Divider sx={{ borderColor: "rgba(255,255,255,0.06)", my: 1.5 }} />

          {/* Affected assets */}
          <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, display: "block", mb: 1 }}>
            AFFECTED ASSETS ({data.assets?.length ?? 0})
          </Typography>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
            {(data.assets || []).map((asset: any) => (
              <Box key={asset.resource_id}
                sx={{ bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1, p: 1.5, border: "1px solid rgba(255,255,255,0.06)" }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5, flexWrap: "wrap" }}>
                  <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600 }}>
                    {asset.asset_name}
                  </Typography>
                  {asset.asset_class && (
                    <Chip label={asset.asset_class} size="small"
                      sx={{ bgcolor: `${CLASS_COLOR[asset.asset_class] || "#888"}20`, color: CLASS_COLOR[asset.asset_class] || "#888", fontSize: 10, height: 16 }} />
                  )}
                  {asset.region && (
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>{asset.region}</Typography>
                  )}
                </Box>
                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                  {(asset.findings || []).map((f: any) => (
                    <Tooltip key={f.id} title={f.title}>
                      <Chip label={f.severity} size="small"
                        sx={{ bgcolor: `${SEV_COLOR[f.severity] || "#888"}20`, color: SEV_COLOR[f.severity] || "#888", fontSize: 10, height: 18 }} />
                    </Tooltip>
                  ))}
                </Box>
              </Box>
            ))}
          </Box>
        </>
      )}
    </Box>
  );
}

export default function CVEPivot() {
  const [clientId, setClientId] = useState("");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [impactCve, setImpactCve] = useState<string | null>(null);

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });

  const { data: cves = [], isLoading } = useQuery<any[]>({
    queryKey: ["cve-list", clientId, search],
    queryFn: () => cveApi.list(clientId, search || undefined),
    enabled: !!clientId,
  });

  const { data: impactData, isLoading: impactLoading } = useQuery<CveImpact>({
    queryKey: ["cve-impact", clientId, impactCve],
    queryFn: () => cveApi.impact(clientId, impactCve!),
    enabled: !!impactCve && !!clientId,
  });

  const toggle = (cveId: string) => setExpanded((prev) => (prev === cveId ? null : cveId));

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>CVE Blast Radius</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Select a client to see every CVE across all scans — click any row to see which assets are affected.
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Account</InputLabel>
            <Select value={clientId} onChange={(e) => { setClientId(e.target.value); setExpanded(null); }} label="Account"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <TextField
            size="small"
            placeholder="Search CVE-…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            sx={{ minWidth: 200,
              "& .MuiOutlinedInput-root": { color: "text.primary", "& fieldset": { borderColor: "divider" } },
              "& input::placeholder": { color: "text.secondary" } }}
          />
        </Box>
      </Box>

      {!clientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "text.primary" }}>
          Select a client to view its CVE blast-radius report.
        </Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      ) : cves.length === 0 ? (
        <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <BugReport sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            {search ? `No CVEs matching "${search}".` : "No CVE-tagged findings for this client yet. Run a scan with CVE detection (Tenable, Qualys, Rapid7, Nessus import) to populate this view."}
          </Typography>
        </Card>
      ) : (
        <>
          <Typography variant="caption" sx={{ color: "text.secondary", mb: 1, display: "block" }}>
            {cves.length} unique CVEs · sorted by CVSS score
          </Typography>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                    <TableCell sx={{ width: 32 }} />
                    <TableCell>CVE ID</TableCell>
                    <TableCell>MAX SEVERITY</TableCell>
                    <TableCell align="right">CVSS</TableCell>
                    <TableCell align="right">ASSETS AFFECTED</TableCell>
                    <TableCell align="right">FINDINGS</TableCell>
                    <TableCell align="right">DAYS OPEN</TableCell>
                    <TableCell>PERSISTING</TableCell>
                    <TableCell>LAST SEEN</TableCell>
                    <TableCell sx={{ width: 40 }}>IMPACT</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {cves.map((cve) => {
                    const isOpen = expanded === cve.cve_id;
                    const sev = cve.max_severity || "info";
                    return (
                      <React.Fragment key={cve.cve_id}>
                        <TableRow
                          onClick={() => toggle(cve.cve_id)}
                          sx={{
                            cursor: "pointer",
                            bgcolor: isOpen ? "rgba(66,133,244,0.05)" : "transparent",
                            "&:hover": { bgcolor: "rgba(255,255,255,0.03)" },
                            "& td": { borderColor: isOpen ? "transparent" : "divider", py: 1 },
                          }}
                        >
                          <TableCell sx={{ pl: 1 }}>
                            <IconButton size="small" sx={{ color: "text.secondary", p: 0.25 }}>
                              {isOpen ? <ExpandLess fontSize="small" /> : <ExpandMore fontSize="small" />}
                            </IconButton>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" sx={{ color: "#4285F4", fontFamily: "monospace", fontWeight: 600 }}>
                              {cve.cve_id}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip label={sev} size="small"
                              sx={{ bgcolor: `${SEV_COLOR[sev] || "#888"}20`, color: SEV_COLOR[sev] || "#888", fontSize: 10, height: 18 }} />
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2" sx={{
                              fontWeight: 700,
                              color: cve.max_cvss >= 9 ? "#f44336" : cve.max_cvss >= 7 ? "#ff9800" : cve.max_cvss >= 4 ? "#ffeb3b" : "rgba(255,255,255,0.5)",
                            }}>
                              {cve.max_cvss > 0 ? cve.max_cvss.toFixed(1) : "—"}
                            </Typography>
                          </TableCell>
                          <TableCell align="right" sx={{ color: cve.affected_assets > 0 ? "text.primary" : "text.secondary", fontWeight: 600 }}>
                            {cve.affected_assets}
                          </TableCell>
                          <TableCell align="right" sx={{ color: "text.secondary" }}>
                            {cve.finding_count}
                          </TableCell>
                          <TableCell align="right" sx={{
                            fontSize: 12, fontWeight: 600,
                            color: cve.days_open > 90 ? "#f44336" : cve.days_open > 30 ? "#ff9800" : "#4caf50",
                          }}>
                            {cve.days_open != null ? cve.days_open : "—"}
                          </TableCell>
                          <TableCell>
                            {cve.is_persisting ? (
                              <Chip label="Persisting" size="small"
                                sx={{ bgcolor: "rgba(255,152,0,0.15)", color: "#ff9800", fontSize: 10, height: 18 }} />
                            ) : <Typography sx={{ color: "text.disabled", fontSize: 12 }}>—</Typography>}
                          </TableCell>
                          <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>
                            {fromNow(cve.last_seen)}
                          </TableCell>
                          <TableCell onClick={(e) => e.stopPropagation()}>
                            <Tooltip title="View remediation impact">
                              <IconButton
                                size="small"
                                sx={{ color: "#4285F4", p: 0.25 }}
                                onClick={() => setImpactCve(cve.cve_id)}
                              >
                                <Calculate fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          </TableCell>
                        </TableRow>
                        <TableRow sx={{ "& td": { py: 0, borderColor: "divider" } }}>
                          <TableCell colSpan={10} sx={{ p: 0 }}>
                            <Collapse in={isOpen} timeout="auto" unmountOnExit>
                              <Box sx={{ p: 2 }}>
                                <CVEDetailRow clientId={clientId} cveId={cve.cve_id} onClose={() => setExpanded(null)} />
                              </Box>
                            </Collapse>
                          </TableCell>
                        </TableRow>
                      </React.Fragment>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          </Card>
        </>
      )}

      {/* Impact Dialog */}
      <Dialog
        open={!!impactCve}
        onClose={() => setImpactCve(null)}
        maxWidth="md"
        fullWidth
        sx={{ "& .MuiDialog-paper": { bgcolor: "#0d1117", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 2 } }}
      >
        <DialogTitle sx={{ color: "text.primary", fontWeight: 700, borderBottom: "1px solid rgba(255,255,255,0.08)", pb: 1.5 }}>
          Remediation Impact — {impactCve}
        </DialogTitle>
        <DialogContent sx={{ pt: 2 }}>
          {impactLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
              <CircularProgress sx={{ color: "#4285F4" }} />
            </Box>
          ) : !impactData ? (
            <Typography sx={{ color: "text.secondary" }}>No impact data available.</Typography>
          ) : (
            <Box>
              {/* Priority note */}
              {impactData.priority_note && (
                <Chip
                  label={impactData.priority_note}
                  sx={{
                    mb: 2,
                    bgcolor: impactData.max_cvss >= 9 ? "rgba(244,67,54,0.15)" : "rgba(255,152,0,0.15)",
                    color: impactData.max_cvss >= 9 ? "#f44336" : "#ff9800",
                    fontSize: 12, height: 28, fontWeight: 600,
                  }}
                />
              )}

              {/* Summary stats */}
              <Box sx={{ display: "flex", gap: 3, mb: 2, flexWrap: "wrap" }}>
                <Box>
                  <Typography variant="h5" sx={{ color: "#4caf50", fontWeight: 700 }}>{impactData.total_open_findings}</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>findings patched</Typography>
                </Box>
                <Box>
                  <Typography variant="h5" sx={{ color: "#4285F4", fontWeight: 700 }}>{impactData.affected_assets}</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>assets affected</Typography>
                </Box>
                <Box>
                  <Typography variant="h5" sx={{ color: "#ff9800", fontWeight: 700 }}>{impactData.total_risk_points_freed}</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>risk points freed</Typography>
                </Box>
                <Box>
                  <Typography variant="h5" sx={{ color: impactData.max_cvss >= 9 ? "#f44336" : impactData.max_cvss >= 7 ? "#ff9800" : "white", fontWeight: 700 }}>
                    {impactData.max_cvss.toFixed(1)}
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>max CVSS</Typography>
                </Box>
              </Box>

              {/* Per-asset table */}
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1, fontWeight: 600 }}>
                PER-ASSET BREAKDOWN
              </Typography>
              <TableContainer sx={{ maxHeight: 320 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                      <TableCell>ASSET NAME</TableCell>
                      <TableCell align="right">FINDINGS</TableCell>
                      <TableCell align="right">RISK POINTS</TableCell>
                      <TableCell align="right">CVSS</TableCell>
                      <TableCell>SEVERITIES</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(impactData.per_asset || []).map((pa) => (
                      <TableRow key={pa.resource_id} sx={{ "& td": { borderColor: "divider", py: 1 } }}>
                        <TableCell sx={{ color: "text.primary", maxWidth: 240 }}>
                          <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {pa.asset_name || pa.resource_id}
                          </Typography>
                        </TableCell>
                        <TableCell align="right" sx={{ color: "text.primary", fontWeight: 600 }}>{pa.finding_count}</TableCell>
                        <TableCell align="right" sx={{ color: "#ff9800", fontWeight: 600 }}>{pa.risk_points_freed}</TableCell>
                        <TableCell align="right" sx={{ fontSize: 12, color: pa.max_cvss >= 9 ? "#f44336" : pa.max_cvss >= 7 ? "#ff9800" : "white" }}>
                          {pa.max_cvss > 0 ? pa.max_cvss.toFixed(1) : "—"}
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                            {Array.from(new Set(pa.severities || [])).map((s: string) => (
                              <Chip key={s} label={s} size="small"
                                sx={{ bgcolor: `${SEV_COLOR[s] || "#888"}20`, color: SEV_COLOR[s] || "#888", fontSize: 10, height: 16 }} />
                            ))}
                          </Box>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </DialogContent>
      </Dialog>
    </Box>
  );
}
