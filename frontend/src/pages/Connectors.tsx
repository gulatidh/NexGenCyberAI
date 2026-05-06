import React, { useState } from "react";
import {
  Box, Typography, Button, Card, CardContent, Grid, Chip,
  Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, Select, MenuItem, FormControl, InputLabel,
  CircularProgress, Alert,
} from "@mui/material";
import { Add, PlayArrow, CheckCircle, Error, HourglassEmpty, Cable } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { connectorsApi, clientsApi } from "../services/api";
import { Connector, ConnectorType, Client } from "../types";
import { toast } from "react-toastify";

const CONNECTOR_ICONS: Record<ConnectorType, string> = {
  azure: "☁️ Azure", aws: "🟠 AWS", gcp: "🔵 GCP",
  onprem: "🖥️ On-Premises", servicenow: "🟣 ServiceNow",
  okta: "🔑 Okta", entraid: "🆔 Entra ID",
  containers: "🐳 Containers", github: "🐙 GitHub", jira: "📋 Jira",
};

const CREDENTIAL_FIELDS: Record<ConnectorType, Array<{ key: string; label: string; secret?: boolean }>> = {
  azure: [
    { key: "tenant_id", label: "Tenant ID" },
    { key: "client_id", label: "Client ID" },
    { key: "client_secret", label: "Client Secret", secret: true },
    { key: "subscription_id", label: "Subscription ID" },
  ],
  aws: [
    { key: "access_key_id", label: "Access Key ID" },
    { key: "secret_access_key", label: "Secret Access Key", secret: true },
    { key: "role_arn", label: "Role ARN (optional)" },
  ],
  gcp: [
    { key: "project_id", label: "Project ID" },
    { key: "service_account_json", label: "Service Account JSON", secret: true },
  ],
  onprem: [
    { key: "nessus_url", label: "Nessus URL" },
    { key: "nessus_api_key", label: "API Key", secret: true },
    { key: "nessus_secret_key", label: "Secret Key", secret: true },
  ],
  servicenow: [
    { key: "instance_url", label: "Instance URL (https://xxx.service-now.com)" },
    { key: "username", label: "Username" },
    { key: "password", label: "Password", secret: true },
  ],
  okta: [
    { key: "domain", label: "Okta Domain (xxx.okta.com)" },
    { key: "api_token", label: "API Token", secret: true },
  ],
  entraid: [
    { key: "tenant_id", label: "Tenant ID" },
    { key: "client_id", label: "App Registration Client ID" },
    { key: "client_secret", label: "Client Secret", secret: true },
  ],
  containers: [
    { key: "api_server", label: "Kubernetes API Server URL" },
    { key: "token", label: "Bearer Token", secret: true },
  ],
  github: [
    { key: "token", label: "Personal Access Token", secret: true },
    { key: "org", label: "Organisation" },
  ],
  jira: [
    { key: "url", label: "Jira URL" },
    { key: "email", label: "Email" },
    { key: "api_token", label: "API Token", secret: true },
  ],
};

const STATUS_PROPS: Record<string, any> = {
  active: { icon: <CheckCircle sx={{ fontSize: 16 }} />, color: "#00e676", label: "Active" },
  error: { icon: <Error sx={{ fontSize: 16 }} />, color: "#f44336", label: "Error" },
  pending: { icon: <HourglassEmpty sx={{ fontSize: 16 }} />, color: "#ff9800", label: "Pending" },
  inactive: { icon: <Cable sx={{ fontSize: 16 }} />, color: "rgba(255,255,255,0.3)", label: "Inactive" },
};

export default function Connectors() {
  const qc = useQueryClient();
  const [selectedClientId, setSelectedClientId] = useState("");
  const [open, setOpen] = useState(false);
  const [connectorType, setConnectorType] = useState<ConnectorType>("azure");
  const [connName, setConnName] = useState("");
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [testResults, setTestResults] = useState<Record<string, any>>({});

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: connectors = [], isLoading } = useQuery<Connector[]>({
    queryKey: ["connectors", selectedClientId],
    queryFn: () => connectorsApi.list(selectedClientId),
    enabled: !!selectedClientId,
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => connectorsApi.create(selectedClientId, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["connectors"] }); setOpen(false); toast.success("Connector added"); },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error"),
  });

  const testMutation = useMutation({
    mutationFn: ({ clientId, connId }: any) => connectorsApi.test(clientId, connId),
    onSuccess: (data, vars) => { setTestResults(prev => ({ ...prev, [vars.connId]: data })); qc.invalidateQueries({ queryKey: ["connectors"] }); },
    onError: (e: any, vars) => setTestResults(prev => ({ ...prev, [vars.connId]: { success: false, message: e.message } })),
  });

  const credFields = CREDENTIAL_FIELDS[connectorType] || [];

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Connectors</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>Connect cloud platforms, identity providers, and SaaS tools</Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1 }}>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Select Client</InputLabel>
            <Select value={selectedClientId} onChange={(e) => setSelectedClientId(e.target.value)} label="Select Client"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <Button variant="contained" startIcon={<Add />} disabled={!selectedClientId} onClick={() => setOpen(true)}
            sx={{ bgcolor: "#00e5ff", color: "#000", "&:hover": { bgcolor: "#00b8d4" } }}>
            Add Connector
          </Button>
        </Box>
      </Box>

      {!selectedClientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(0,229,255,0.1)", color: "white" }}>Select a client to view and manage its connectors.</Alert>
      ) : isLoading ? (
        <CircularProgress sx={{ color: "#00e5ff" }} />
      ) : connectors.length === 0 ? (
        <Card sx={{ bgcolor: "#161b22", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
          <Cable sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
          <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>No connectors. Add one to start scanning.</Typography>
        </Card>
      ) : (
        <Grid container spacing={2}>
          {connectors.map((conn) => {
            const sp = STATUS_PROPS[conn.status] || STATUS_PROPS.inactive;
            const tr = testResults[conn.id];
            return (
              <Grid size={{ xs: 12, sm: 6, md: 4 }} key={conn.id}>
                <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
                      <Typography sx={{ color: "white", fontWeight: 600 }}>{conn.name}</Typography>
                      <Chip size="small" icon={sp.icon} label={sp.label}
                        sx={{ bgcolor: `${sp.color}20`, color: sp.color, fontSize: 11 }} />
                    </Box>
                    <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)", mb: 1.5 }}>
                      {CONNECTOR_ICONS[conn.connector_type] || conn.connector_type}
                    </Typography>
                    {conn.error_message && (
                      <Typography variant="caption" sx={{ color: "#f44336", display: "block", mb: 1 }}>{conn.error_message}</Typography>
                    )}
                    {tr && (
                      <Alert severity={tr.success ? "success" : "error"} sx={{ py: 0, mb: 1, fontSize: 11 }}>{tr.message}</Alert>
                    )}
                    <Button size="small" variant="outlined" startIcon={<PlayArrow />}
                      onClick={() => testMutation.mutate({ clientId: selectedClientId, connId: conn.id })}
                      disabled={testMutation.isPending}
                      sx={{ borderColor: "#00e5ff", color: "#00e5ff", fontSize: 11 }}>
                      Test Connection
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}

      {/* Add Connector Dialog */}
      <Dialog open={open} onClose={() => setOpen(false)} slotProps={{ paper: { sx: { bgcolor: "#161b22", color: "white", minWidth: 520 } } }}>
        <DialogTitle>Add Connector</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 0.5 }}>
            <Grid size={{ xs: 12, sm: 6 }}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Type</InputLabel>
                <Select value={connectorType} onChange={(e) => { setConnectorType(e.target.value as ConnectorType); setCredentials({}); }}
                  label="Type" sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                  {Object.entries(CONNECTOR_ICONS).map(([k, v]) => <MenuItem key={k} value={k}>{v}</MenuItem>)}
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label="Connector Name" value={connName} onChange={(e) => setConnName(e.target.value)}
                slotProps={{ inputLabel: { sx: { color: 'rgba(255,255,255,0.5)' } }, htmlInput: { style: { color: 'white' } } }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
            </Grid>
            {credFields.map(({ key, label, secret }) => (
              <Grid size={{ xs: 12 }} key={key}>
                <TextField fullWidth size="small" label={label} type={secret ? "password" : "text"}
                  value={credentials[key] || ""} onChange={(e) => setCredentials({ ...credentials, [key]: e.target.value })}
                  slotProps={{ inputLabel: { sx: { color: 'rgba(255,255,255,0.5)' } }, htmlInput: { style: { color: 'white' } } }}
                  sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
              </Grid>
            ))}
          </Grid>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setOpen(false)} sx={{ color: "rgba(255,255,255,0.5)" }}>Cancel</Button>
          <Button variant="contained" disabled={!connName || createMutation.isPending}
            onClick={() => createMutation.mutate({ name: connName, connector_type: connectorType, credentials })}
            sx={{ bgcolor: "#00e5ff", color: "#000" }}>
            {createMutation.isPending ? <CircularProgress size={18} /> : "Save"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
