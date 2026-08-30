import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Button, FormControl,
  InputLabel, Select, MenuItem, CircularProgress, Alert,
  List, ListItem, ListItemIcon, ListItemText, Chip, Divider,
} from "@mui/material";
import {
  Download, VerifiedUser, CheckCircleOutlined, RadioButtonUnchecked,
  FolderZip, BugReport, Shield, Build, SmartToy, Assessment,
} from "@mui/icons-material";
import { useActiveClient } from "../contexts/ClientContext";
import { useQuery } from "@tanstack/react-query";
import { apiClient, frameworksApi } from "../services/api";

export default function EvidencePackage() {
  const { clientId } = useActiveClient();
  const [framework, setFramework] = useState("nist_csf");
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data: catalog = [] } = useQuery<any[]>({
    queryKey: ["frameworks-all"],
    queryFn: frameworksApi.catalogAll,
    staleTime: 5 * 60 * 1000,
  });

  const download = async () => {
    if (!clientId) return;
    setDownloading(true);
    setError(null);
    try {
      const { msalInstance } = await import("../auth/AuthProvider");
      const { loginRequest } = await import("../auth/msalConfig");
      await msalInstance.initialize();
      const account = msalInstance.getActiveAccount() ?? msalInstance.getAllAccounts()[0];
      let token = "";
      if (account) {
        try {
          const resp = await msalInstance.acquireTokenSilent({ ...loginRequest, account });
          token = resp.accessToken;
        } catch {
          // proceed; backend will 401 with a clear message
        }
      }
      const base = apiClient.defaults.baseURL || "";
      const url = `${base}/clients/${clientId}/evidence/package?framework=${framework}`;
      const res = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `evidence-${framework}-${new Date().toISOString().slice(0, 10)}.zip`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e: any) {
      setError(e.message || "Download failed");
    } finally {
      setDownloading(false);
    }
  };

  const files = [
    {
      name: "00_summary.json",
      label: "Summary",
      icon: <Assessment sx={{ fontSize: 18, color: "#4285F4" }} />,
      desc: "Client name, selected framework, generation timestamp, open and remediated finding counts.",
      alwaysPopulated: true,
    },
    {
      name: "01_findings.csv",
      label: "Findings",
      icon: <BugReport sx={{ fontSize: 18, color: "#EA4335" }} />,
      desc: "All open and remediated findings — title, severity, status, CVE ID, CVSS score, resource, control ID, framework. Up to 5,000 rows.",
      alwaysPopulated: true,
      note: "Populated as long as at least one scan has been run for this account.",
    },
    {
      name: "02_control_deficiencies.json",
      label: "Control Deficiencies",
      icon: <Shield sx={{ fontSize: 18, color: "#FBBC04" }} />,
      desc: "Framework control gaps identified by the Compliance Monitor agent — control ID, gap description, remediation guidance.",
      alwaysPopulated: false,
      prereq: "Run the Compliance Monitor agent (AI Buddies) at least once.",
    },
    {
      name: "03_remediation_actions.json",
      label: "Remediation Actions",
      icon: <Build sx={{ fontSize: 18, color: "#34A853" }} />,
      desc: "Priority-banded remediation tasks from the Remediation Planner agent — title, priority, band, assignee, due date.",
      alwaysPopulated: false,
      prereq: "Run the Remediation Planner agent (AI Buddies) at least once.",
    },
    {
      name: "04_agent_runs.json",
      label: "Agent Run Log",
      icon: <SmartToy sx={{ fontSize: 18, color: "#9C27B0" }} />,
      desc: "Last 50 completed agent runs — agent type, status, start and completion timestamps.",
      alwaysPopulated: false,
      prereq: "At least one AI Buddies agent must have been run to completion.",
    },
    {
      name: "05_framework_assessments.json",
      label: "Framework Assessments",
      icon: <VerifiedUser sx={{ fontSize: 18, color: "#00BCD4" }} />,
      desc: "Last 10 framework assessment scores per framework — overall score and assessment date.",
      alwaysPopulated: false,
      prereq: "Recompute framework compliance on the Frameworks page, or run the Compliance Monitor agent.",
    },
  ];

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>Evidence Package</Typography>
        <Typography variant="body2" sx={{ color: "text.secondary" }}>
          Download a ZIP containing findings, control gaps, remediation actions, and agent logs
          for compliance audit evidence collection.
        </Typography>
      </Box>

      {!clientId ? (
        <Alert severity="info">Select a client from the top bar to generate an evidence package.</Alert>
      ) : (
        <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap", alignItems: "flex-start" }}>
          {/* Left: generate card */}
          <Card sx={{ flex: "0 0 340px" }}>
            <CardContent sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                <FolderZip sx={{ color: "primary.main", fontSize: 32 }} />
                <Box>
                  <Typography sx={{ fontWeight: 700 }}>Generate Evidence Package</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    Downloads as a ZIP · scoped to active account
                  </Typography>
                </Box>
              </Box>

              <FormControl fullWidth size="small">
                <InputLabel>Framework</InputLabel>
                <Select value={framework} label="Framework" onChange={(e) => setFramework(e.target.value)}>
                  {(catalog as any[]).map((f) => (
                    <MenuItem key={f.framework} value={f.framework}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        {f.name}
                        {f.is_custom && (
                          <Chip label="Custom" size="small"
                            sx={{ height: 16, fontSize: 9, bgcolor: "rgba(156,39,176,0.15)", color: "#ce93d8" }} />
                        )}
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                The selected framework filters control deficiencies and scopes the summary header.
                All findings are always included regardless of framework.
              </Typography>

              {error && <Alert severity="error">{error}</Alert>}

              <Button
                variant="contained" size="large"
                startIcon={downloading ? <CircularProgress size={18} color="inherit" /> : <Download />}
                onClick={download} disabled={downloading}
              >
                {downloading ? "Preparing download…" : "Download Evidence Package"}
              </Button>
            </CardContent>
          </Card>

          {/* Right: what's in the ZIP */}
          <Card sx={{ flex: 1, minWidth: 300 }}>
            <CardContent>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>
                What's inside the ZIP
              </Typography>
              <List dense disablePadding>
                {files.map((f, i) => (
                  <React.Fragment key={f.name}>
                    {i > 0 && <Divider sx={{ my: 0.75, borderColor: "rgba(255,255,255,0.06)" }} />}
                    <ListItem disableGutters alignItems="flex-start" sx={{ gap: 1 }}>
                      <ListItemIcon sx={{ minWidth: 28, mt: 0.25 }}>
                        {f.alwaysPopulated
                          ? <CheckCircleOutlined sx={{ fontSize: 16, color: "#34A853" }} />
                          : <RadioButtonUnchecked sx={{ fontSize: 16, color: "text.disabled" }} />}
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, mb: 0.25 }}>
                            {f.icon}
                            <Typography sx={{ fontSize: 12.5, fontWeight: 700, color: "text.primary" }}>
                              {f.label}
                            </Typography>
                            <Typography sx={{ fontSize: 10, color: "text.disabled", fontFamily: "monospace" }}>
                              {f.name}
                            </Typography>
                          </Box>
                        }
                        secondary={
                          <Box>
                            <Typography sx={{ fontSize: 11.5, color: "text.secondary", lineHeight: 1.4 }}>
                              {f.desc}
                            </Typography>
                            {!f.alwaysPopulated && f.prereq && (
                              <Typography sx={{ fontSize: 11, color: "#FBBC04", mt: 0.5, lineHeight: 1.3 }}>
                                ⚠ {f.prereq}
                              </Typography>
                            )}
                            {f.alwaysPopulated && f.note && (
                              <Typography sx={{ fontSize: 11, color: "text.disabled", mt: 0.25 }}>
                                {f.note}
                              </Typography>
                            )}
                          </Box>
                        }
                      />
                    </ListItem>
                  </React.Fragment>
                ))}
              </List>
            </CardContent>
          </Card>
        </Box>
      )}
    </Box>
  );
}
