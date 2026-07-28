import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Button, FormControl,
  InputLabel, Select, MenuItem, CircularProgress, Alert,
} from "@mui/material";
import { Download, VerifiedUser } from "@mui/icons-material";
import { useActiveClient } from "../contexts/ClientContext";
import { apiClient } from "../services/api";

const FRAMEWORKS = [
  { value: "nist_csf",   label: "NIST CSF 2.0" },
  { value: "iso_27001",  label: "ISO/IEC 27001:2022" },
  { value: "pci_dss",    label: "PCI DSS v4.0" },
  { value: "cis_v8",     label: "CIS Controls v8" },
  { value: "gdpr",       label: "GDPR" },
];

export default function EvidencePackage() {
  const { clientId } = useActiveClient();
  const [framework, setFramework] = useState("nist_csf");
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const download = async () => {
    if (!clientId) return;
    setDownloading(true);
    setError(null);
    try {
      const token = (apiClient.defaults.headers.common?.["Authorization"] as string) || "";
      const base = apiClient.defaults.baseURL || "";
      const url = `${base}/clients/${clientId}/evidence/package?framework=${framework}`;
      const res = await fetch(url, { headers: { Authorization: token } });
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

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>Evidence Package</Typography>
        <Typography variant="body2" sx={{ color: "text.secondary" }}>
          Download a ZIP containing findings, control deficiencies, remediation actions,
          agent logs, and framework assessments for compliance audits.
        </Typography>
      </Box>

      {!clientId ? (
        <Alert severity="info">Select a client from the top bar to generate an evidence package.</Alert>
      ) : (
        <Card sx={{ maxWidth: 520 }}>
          <CardContent sx={{ display: "flex", flexDirection: "column", gap: 2.5 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <VerifiedUser sx={{ color: "primary.main", fontSize: 36 }} />
              <Box>
                <Typography sx={{ fontWeight: 700 }}>Generate Evidence Package</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  Scoped to the active client · Downloads as a ZIP file
                </Typography>
              </Box>
            </Box>

            <FormControl fullWidth size="small">
              <InputLabel>Framework</InputLabel>
              <Select value={framework} label="Framework" onChange={(e) => setFramework(e.target.value)}>
                {FRAMEWORKS.map((f) => (
                  <MenuItem key={f.value} value={f.value}>{f.label}</MenuItem>
                ))}
              </Select>
            </FormControl>

            {error && <Alert severity="error">{error}</Alert>}

            <Button
              variant="contained" size="large" startIcon={downloading ? <CircularProgress size={18} color="inherit" /> : <Download />}
              onClick={download} disabled={downloading}
            >
              {downloading ? "Preparing download…" : "Download Evidence Package"}
            </Button>

            <Typography variant="caption" sx={{ color: "text.secondary" }}>
              Package contents: findings.csv · control_deficiencies.json ·
              remediation_actions.json · agent_runs.json · framework_assessments.json
            </Typography>
          </CardContent>
        </Card>
      )}
    </Box>
  );
}
