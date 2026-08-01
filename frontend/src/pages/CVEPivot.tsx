import React, { useState } from "react";
import {
  Box, Typography, Card, Chip, CircularProgress, TextField,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  Collapse, IconButton, Alert, Tooltip, Divider,
  FormControl, InputLabel, Select, MenuItem,
} from "@mui/material";
import { BugReport, ExpandMore, ExpandLess, Shield } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { clientsApi, cveApi } from "../services/api";
import { Client } from "../types";
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

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });

  const { data: cves = [], isLoading } = useQuery<any[]>({
    queryKey: ["cve-list", clientId, search],
    queryFn: () => cveApi.list(clientId, search || undefined),
    enabled: !!clientId,
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
            <InputLabel sx={{ color: "text.secondary" }}>Client</InputLabel>
            <Select value={clientId} onChange={(e) => { setClientId(e.target.value); setExpanded(null); }} label="Client"
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
                    <TableCell>LAST SEEN</TableCell>
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
                          <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>
                            {fromNow(cve.last_seen)}
                          </TableCell>
                        </TableRow>
                        <TableRow sx={{ "& td": { py: 0, borderColor: "divider" } }}>
                          <TableCell colSpan={7} sx={{ p: 0 }}>
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
    </Box>
  );
}
