import React, { useState } from "react";
import {
  Box, Typography, Card, Chip, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  FormControl, InputLabel, Select, MenuItem, Button, Alert,
  Dialog, DialogTitle, DialogContent, DialogActions, LinearProgress,
} from "@mui/material";
import { Warning } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { clientsApi, risksApi, projectsApi } from "../services/api";
import { Client, Risk, Project } from "../types";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
dayjs.extend(relativeTime);

const LEVEL_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50",
};
const STATUS_COLOR: Record<string, string> = {
  open: "#ff9800", mitigated: "#00e676", accepted: "#7c4dff", closed: "rgba(255,255,255,0.3)",
};

export default function Risks() {
  const qc = useQueryClient();
  const [clientId, setClientId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [levelFilter, setLevelFilter] = useState("");
  const [selected, setSelected] = useState<Risk | null>(null);

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", clientId],
    queryFn: () => projectsApi.list(clientId),
    enabled: !!clientId,
  });
  const { data: risks = [], isLoading } = useQuery<Risk[]>({
    queryKey: ["risks", clientId, projectId],
    queryFn: () => risksApi.list(clientId, projectId || undefined),
    enabled: !!clientId,
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: any) => risksApi.update(clientId, id, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["risks"] }); setSelected(null); },
  });

  const filtered = levelFilter ? risks.filter((r) => {
    const lv = typeof r.risk_level === "object" ? (r.risk_level as any).value ?? r.risk_level : r.risk_level;
    return lv === levelFilter;
  }) : risks;

  const levelCounts = risks.reduce((acc: Record<string, number>, r) => {
    const lv = typeof r.risk_level === "object" ? (r.risk_level as any).value ?? r.risk_level : r.risk_level;
    acc[lv] = (acc[lv] || 0) + 1;
    return acc;
  }, {});

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Risk Register</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            Prioritised risks with mitigation tracking
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1 }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client</InputLabel>
            <Select value={clientId} onChange={(e) => { setClientId(e.target.value); setProjectId(""); }} label="Client"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 160 }} disabled={!clientId}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Project</InputLabel>
            <Select value={projectId} onChange={(e) => setProjectId(e.target.value)} label="Project"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All projects</MenuItem>
              {projects.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
            </Select>
          </FormControl>
        </Box>
      </Box>

      {clientId && !isLoading && risks.length > 0 && (
        <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
          {["critical","high","medium","low"].filter((l) => levelCounts[l]).map((l) => (
            <Chip key={l} label={`${l.charAt(0).toUpperCase() + l.slice(1)}: ${levelCounts[l]}`} size="small"
              onClick={() => setLevelFilter(levelFilter === l ? "" : l)}
              sx={{ bgcolor: `${LEVEL_COLOR[l]}${levelFilter === l ? "40" : "20"}`, color: LEVEL_COLOR[l],
                border: levelFilter === l ? `1px solid ${LEVEL_COLOR[l]}` : "none", cursor: "pointer" }} />
          ))}
          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", alignSelf: "center", ml: 1 }}>
            {filtered.length} risks
          </Typography>
        </Box>
      )}

      {!clientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(0,229,255,0.1)", color: "white" }}>Select a client to view the risk register.</Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#00e5ff" }} /></Box>
      ) : filtered.length === 0 ? (
        <Card sx={{ bgcolor: "#161b22", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <Warning sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
          <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>
            No risks yet. Run an AI risk assessment from the Agents page.
          </Typography>
        </Card>
      ) : (
        <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
                  <TableCell>RISK LEVEL</TableCell>
                  <TableCell>TITLE</TableCell>
                  <TableCell>SCORE</TableCell>
                  <TableCell>CATEGORY</TableCell>
                  <TableCell>LIKELIHOOD / IMPACT</TableCell>
                  <TableCell>STATUS</TableCell>
                  <TableCell>ADDED</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filtered.map((r) => {
                  const lv = typeof r.risk_level === "object" ? (r.risk_level as any).value ?? r.risk_level : r.risk_level;
                  const score = r.risk_score ?? 0;
                  const scoreColor = score >= 7 ? "#f44336" : score >= 5 ? "#ff9800" : score >= 3 ? "#ffeb3b" : "#4caf50";
                  return (
                    <TableRow key={r.id}
                      sx={{ cursor: "pointer", "&:hover": { bgcolor: "rgba(255,255,255,0.03)" },
                        "& td": { borderColor: "rgba(255,255,255,0.05)", py: 1 } }}
                      onClick={() => setSelected(r)}>
                      <TableCell>
                        <Chip label={lv} size="small"
                          sx={{ bgcolor: `${LEVEL_COLOR[lv] || "#888"}20`, color: LEVEL_COLOR[lv] || "#888", fontSize: 10, height: 18 }} />
                      </TableCell>
                      <TableCell sx={{ color: "white", maxWidth: 300 }}>
                        <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {r.title}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <Typography variant="body2" sx={{ color: scoreColor, fontWeight: 700, minWidth: 28 }}>
                            {score.toFixed(1)}
                          </Typography>
                          <LinearProgress variant="determinate" value={Math.min(score * 10, 100)}
                            sx={{ width: 50, height: 4, borderRadius: 2, bgcolor: "rgba(255,255,255,0.1)",
                              "& .MuiLinearProgress-bar": { bgcolor: scoreColor, borderRadius: 2 } }} />
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }}>
                        {r.category || "—"}
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }}>
                        {r.likelihood ?? "—"} / {r.impact ?? "—"}
                      </TableCell>
                      <TableCell>
                        <Chip label={r.status || "open"} size="small"
                          sx={{ bgcolor: `${STATUS_COLOR[r.status || "open"] || "#888"}20`,
                            color: STATUS_COLOR[r.status || "open"] || "#888", fontSize: 10, height: 18 }} />
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.4)", fontSize: 11 }}>
                        {r.created_at ? dayjs(r.created_at).fromNow() : "—"}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        </Card>
      )}

      {/* Detail dialog */}
      <Dialog open={!!selected} onClose={() => setSelected(null)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "#161b22", color: "white" } } }}>
        {selected && (() => {
          const lv = typeof selected.risk_level === "object" ? (selected.risk_level as any).value ?? selected.risk_level : selected.risk_level;
          return (
            <>
              <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)", pb: 1.5 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Chip label={lv} size="small" sx={{ bgcolor: `${LEVEL_COLOR[lv]}20`, color: LEVEL_COLOR[lv], fontSize: 11 }} />
                  <Typography sx={{ fontWeight: 600 }}>{selected.title}</Typography>
                </Box>
              </DialogTitle>
              <DialogContent sx={{ mt: 1 }}>
                {selected.description && (
                  <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.7)", mb: 2 }}>{selected.description}</Typography>
                )}
                <Box sx={{ display: "flex", gap: 2, mb: 2 }}>
                  <Box sx={{ flex: 1, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, p: 1.5, textAlign: "center" }}>
                    <Typography variant="h5" sx={{ color: selected.risk_score != null && selected.risk_score >= 7 ? "#f44336" : "#ff9800", fontWeight: 700 }}>
                      {(selected.risk_score ?? 0).toFixed(1)}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>Risk Score</Typography>
                  </Box>
                  <Box sx={{ flex: 1, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, p: 1.5, textAlign: "center" }}>
                    <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>{selected.likelihood ?? "—"}</Typography>
                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>Likelihood (1-5)</Typography>
                  </Box>
                  <Box sx={{ flex: 1, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, p: 1.5, textAlign: "center" }}>
                    <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>{selected.impact ?? "—"}</Typography>
                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>Impact (1-5)</Typography>
                  </Box>
                </Box>
                {selected.mitigation_plan && (
                  <Box sx={{ bgcolor: "rgba(0,230,118,0.08)", border: "1px solid rgba(0,230,118,0.2)", borderRadius: 1, p: 1.5, mb: 2 }}>
                    <Typography variant="caption" sx={{ color: "#00e676", fontWeight: 600, display: "block", mb: 0.5 }}>Mitigation Plan</Typography>
                    <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.8)" }}>{selected.mitigation_plan}</Typography>
                  </Box>
                )}
                <Box>
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", mb: 1, display: "block" }}>Update Status</Typography>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    {["open","mitigated","accepted","closed"].map((s) => (
                      <Chip key={s} label={s} size="small" clickable
                        onClick={() => updateMutation.mutate({ id: selected.id, data: { status: s } })}
                        sx={{ bgcolor: selected.status === s ? `${STATUS_COLOR[s]}40` : `${STATUS_COLOR[s]}15`,
                          color: STATUS_COLOR[s], border: selected.status === s ? `1px solid ${STATUS_COLOR[s]}` : "none",
                          cursor: "pointer" }} />
                    ))}
                  </Box>
                </Box>
              </DialogContent>
              <DialogActions sx={{ p: 2 }}>
                <Button onClick={() => setSelected(null)} sx={{ color: "rgba(255,255,255,0.5)" }}>Close</Button>
              </DialogActions>
            </>
          );
        })()}
      </Dialog>
    </Box>
  );
}
