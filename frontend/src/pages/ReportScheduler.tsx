import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Button, Dialog, DialogTitle, DialogContent,
  DialogActions, TextField, Select, MenuItem, FormControl, InputLabel,
  Table, TableBody, TableCell, TableHead, TableRow, IconButton, Chip, Alert,
} from "@mui/material";
import { Add, Delete, Schedule, Email } from "@mui/icons-material";

const STORAGE_KEY = "aegis-report-schedules";

interface ScheduleEntry {
  id: string;
  name: string;
  reportType: string;
  frequency: string;
  recipients: string;
  nextRun: string;
  enabled: boolean;
}

const REPORT_TYPES = ["Executive Summary", "VAPT Report", "Compliance Heatmap", "Risk Register", "Finding Summary"];
const FREQUENCIES  = ["Daily", "Weekly", "Bi-weekly", "Monthly", "Quarterly"];

function load(): ScheduleEntry[] {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"); } catch { return []; }
}
function save(items: ScheduleEntry[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
}

function nextRunDate(freq: string): string {
  const d = new Date();
  if (freq === "Daily")     d.setDate(d.getDate() + 1);
  else if (freq === "Weekly")  d.setDate(d.getDate() + 7);
  else if (freq === "Bi-weekly") d.setDate(d.getDate() + 14);
  else if (freq === "Monthly")  d.setMonth(d.getMonth() + 1);
  else                          d.setMonth(d.getMonth() + 3);
  return d.toISOString().split("T")[0];
}

const BLANK: Omit<ScheduleEntry, "id" | "nextRun" | "enabled"> = {
  name: "", reportType: REPORT_TYPES[0], frequency: "Weekly", recipients: "",
};

export default function ReportScheduler() {
  const [schedules, setSchedules] = useState<ScheduleEntry[]>(load);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ ...BLANK });
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  const handleAdd = () => {
    if (!form.name.trim()) { setError("Name is required."); return; }
    if (!form.recipients.trim()) { setError("At least one recipient email is required."); return; }
    const entry: ScheduleEntry = {
      id: crypto.randomUUID(),
      ...form,
      nextRun: nextRunDate(form.frequency),
      enabled: true,
    };
    const updated = [...schedules, entry];
    setSchedules(updated);
    save(updated);
    setOpen(false);
    setForm({ ...BLANK });
    setError("");
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleDelete = (id: string) => {
    const updated = schedules.filter(s => s.id !== id);
    setSchedules(updated);
    save(updated);
  };

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Report Scheduler</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
            Schedule recurring report delivery to stakeholders via email.
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<Add />} size="small" onClick={() => setOpen(true)}
          sx={{ bgcolor: "#4285F4", "&:hover": { bgcolor: "#3367D6" } }}>
          New Schedule
        </Button>
      </Box>

      <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
        Email delivery requires SMTP configuration in the platform settings. Schedules are stored in your browser.
      </Alert>

      {saved && <Alert severity="success" sx={{ mb: 2, borderRadius: 2 }}>Schedule saved.</Alert>}

      {schedules.length === 0 ? (
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent sx={{ textAlign: "center", py: 6 }}>
            <Schedule sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
            <Typography variant="body2" sx={{ color: "text.secondary" }}>
              No schedules yet. Click "New Schedule" to create your first recurring report.
            </Typography>
          </CardContent>
        </Card>
      ) : (
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent sx={{ p: 0 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { fontWeight: 700, fontSize: 12, bgcolor: "rgba(255,255,255,0.03)", color: "text.secondary", borderBottom: "1px solid rgba(255,255,255,0.1)" } }}>
                  <TableCell>Name</TableCell>
                  <TableCell>Report Type</TableCell>
                  <TableCell>Frequency</TableCell>
                  <TableCell>Recipients</TableCell>
                  <TableCell>Next Run</TableCell>
                  <TableCell />
                </TableRow>
              </TableHead>
              <TableBody>
                {schedules.map(s => (
                  <TableRow key={s.id} sx={{ "&:hover": { bgcolor: "rgba(255,255,255,0.03)" } }}>
                    <TableCell sx={{ fontSize: 13, fontWeight: 600 }}>{s.name}</TableCell>
                    <TableCell sx={{ fontSize: 12 }}>{s.reportType}</TableCell>
                    <TableCell>
                      <Chip label={s.frequency} size="small" sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontWeight: 700, fontSize: 10, height: 20 }} />
                    </TableCell>
                    <TableCell sx={{ fontSize: 12, color: "text.secondary", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {s.recipients}
                    </TableCell>
                    <TableCell sx={{ fontSize: 12, color: "text.secondary" }}>{s.nextRun}</TableCell>
                    <TableCell padding="none">
                      <IconButton size="small" onClick={() => handleDelete(s.id)} sx={{ color: "text.secondary" }}>
                        <Delete sx={{ fontSize: 16 }} />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ fontWeight: 700 }}>New Report Schedule</DialogTitle>
        <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2, pt: "12px !important" }}>
          {error && <Alert severity="error" sx={{ borderRadius: 1 }}>{error}</Alert>}
          <TextField label="Schedule Name" size="small" fullWidth value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
          <FormControl size="small" fullWidth>
            <InputLabel>Report Type</InputLabel>
            <Select value={form.reportType} label="Report Type" onChange={e => setForm(f => ({ ...f, reportType: e.target.value as string }))}>
              {REPORT_TYPES.map(r => <MenuItem key={r} value={r}>{r}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" fullWidth>
            <InputLabel>Frequency</InputLabel>
            <Select value={form.frequency} label="Frequency" onChange={e => setForm(f => ({ ...f, frequency: e.target.value as string }))}>
              {FREQUENCIES.map(fr => <MenuItem key={fr} value={fr}>{fr}</MenuItem>)}
            </Select>
          </FormControl>
          <TextField label="Recipients (comma-separated emails)" size="small" fullWidth multiline rows={2}
            value={form.recipients} placeholder="ciso@example.com, board@example.com"
            onChange={e => setForm(f => ({ ...f, recipients: e.target.value }))} />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button onClick={() => { setOpen(false); setError(""); }} variant="outlined" size="small"
            sx={{ borderColor: "rgba(255,255,255,0.2)", color: "text.secondary" }}>Cancel</Button>
          <Button onClick={handleAdd} variant="contained" size="small"
            startIcon={<Email />} sx={{ bgcolor: "#4285F4", "&:hover": { bgcolor: "#3367D6" } }}>
            Save Schedule
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
