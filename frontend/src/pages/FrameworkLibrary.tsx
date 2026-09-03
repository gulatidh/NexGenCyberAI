import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Grid, Chip, Button, IconButton,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  CircularProgress, Tooltip, Alert, Divider,
} from "@mui/material";
import {
  Policy, LibraryAdd, Add, Delete, Edit, Close, Refresh,
  VerifiedUser, Security, Gavel, Lock, AccountBalance, CloudQueue, AutoAwesome,
  SmartToy,
} from "@mui/icons-material";
import FrameworkAdvisor from "../components/FrameworkAdvisor";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { customFrameworksApi } from "../services/api";
import { toast } from "react-toastify";
import { FrameworkDetail } from "./CustomFrameworks";

// ── Standard framework metadata ───────────────────────────────────────────────

const STANDARD_FRAMEWORKS = [
  {
    key: "nist_csf",
    label: "NIST CSF 2.0",
    description: "NIST Cybersecurity Framework 2.0 — Govern, Identify, Protect, Detect, Respond, Recover.",
    color: "#1565C0",
    Icon: Security,
    controls: 106,
    family: "NIST",
  },
  {
    key: "nist_800_53",
    label: "NIST 800-53 Rev 5",
    description: "Security and Privacy Controls for Information Systems and Organizations.",
    color: "#1565C0",
    Icon: Security,
    controls: null,
    family: "NIST",
  },
  {
    key: "nist_ai_rmf",
    label: "NIST AI RMF 1.0",
    description: "NIST AI Risk Management Framework (AI 100-1) — Govern, Map, Measure, Manage AI risks across the AI lifecycle.",
    color: "#1565C0",
    Icon: SmartToy,
    controls: 56,
    family: "NIST",
  },
  {
    key: "nist_ai_200_1",
    label: "NIST AI 200-1",
    description: "AI Use Taxonomy — classifies AI systems by use case, deployment context, stakeholder roles, data & model types, risk tier, and governance requirements.",
    color: "#1565C0",
    Icon: SmartToy,
    controls: 28,
    family: "NIST",
  },
  {
    key: "nist_ai_200_2",
    label: "NIST AI 200-2",
    description: "TEVV Framework — Testing, Evaluation, Verification, and Validation of AI systems covering functional, adversarial, bias, risk, and regulatory dimensions.",
    color: "#1565C0",
    Icon: SmartToy,
    controls: 41,
    family: "NIST",
  },
  {
    key: "cis_v8",
    label: "CIS Controls v8",
    description: "18 CIS Critical Security Controls with Implementation Groups for every organisation size.",
    color: "#6A1B9A",
    Icon: VerifiedUser,
    controls: 153,
    family: "CIS",
  },
  {
    key: "iso_27001",
    label: "ISO/IEC 27001:2022",
    description: "International standard for information security management systems (ISMS).",
    color: "#2E7D32",
    Icon: AccountBalance,
    controls: 97,
    family: "Standards",
  },
  {
    key: "pci_dss",
    label: "PCI DSS v4.0",
    description: "Payment Card Industry Data Security Standard for cardholder data protection.",
    color: "#2E7D32",
    Icon: Lock,
    controls: 92,
    family: "Standards",
  },
  {
    key: "gdpr",
    label: "GDPR",
    description: "EU General Data Protection Regulation — data privacy and protection requirements.",
    color: "#2E7D32",
    Icon: Gavel,
    controls: 67,
    family: "Standards",
  },
  {
    key: "soc2",
    label: "SOC 2",
    description: "AICPA Trust Services Criteria — security, availability, processing integrity, confidentiality, privacy.",
    color: "#2E7D32",
    Icon: VerifiedUser,
    controls: null,
    family: "Standards",
  },
  {
    key: "gcc_im8",
    label: "GCC IM8 (Singapore)",
    description: "Singapore Government Commercial Cloud Instruction Manual 8 Reform 2025 — cybersecurity baseline for GCC workloads.",
    color: "#C62828",
    Icon: CloudQueue,
    controls: 137,
    family: "Standards",
  },
];

// ── Standard controls browser dialog ─────────────────────────────────────────

function StandardControlsBrowser({
  fw,
  onClose,
}: {
  fw: { key: string; label: string; color: string };
  onClose: () => void;
}) {
  const [page, setPage] = useState(1);
  const { data, isLoading } = useQuery({
    queryKey: ["fw-controls-browse", fw.key, page],
    queryFn: () => customFrameworksApi.pickerControls({ framework: fw.key, page }),
    staleTime: 60_000,
  });

  const controls: any[] = data?.controls ?? data ?? [];
  const hasMore = controls.length === 100;

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="md"
      slotProps={{ paper: { sx: { maxHeight: "80vh" } } }}>
      <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: fw.color, flexShrink: 0 }} />
        <Typography sx={{ fontWeight: 700, flex: 1 }}>{fw.label} — Control Catalog</Typography>
        <IconButton size="small" onClick={onClose}><Close fontSize="small" /></IconButton>
      </DialogTitle>
      <DialogContent dividers sx={{ p: 0 }}>
        {isLoading ? (
          <Box sx={{ display: "flex", justifyContent: "center", p: 6 }}>
            <CircularProgress size={28} />
          </Box>
        ) : controls.length === 0 ? (
          <Box sx={{ p: 4, textAlign: "center" }}>
            <Typography sx={{ color: "text.secondary" }}>
              No controls loaded for this framework. Seed the framework data first via the backend.
            </Typography>
          </Box>
        ) : (
          controls.map((c: any, idx: number) => (
            <Box key={c.id}>
              {idx > 0 && <Divider />}
              <Box sx={{ px: 2.5, py: 1.5, display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.25 }}>
                    <Typography variant="caption"
                      sx={{ fontFamily: "monospace", fontWeight: 700, color: fw.color, flexShrink: 0 }}>
                      {c.control_id}
                    </Typography>
                    {c.domain && (
                      <Chip label={c.domain} size="small"
                        sx={{ height: 16, fontSize: 9, bgcolor: `${fw.color}18`, color: fw.color }} />
                    )}
                    {c.weight >= 2 && (
                      <Chip
                        label={c.weight === 3 ? "Critical" : "Important"}
                        size="small"
                        sx={{ height: 16, fontSize: 9,
                          bgcolor: c.weight === 3 ? "#EA433520" : "#FBBC0420",
                          color: c.weight === 3 ? "#EA4335" : "#FBBC04" }} />
                    )}
                  </Box>
                  <Typography sx={{ fontSize: 13, fontWeight: 600 }}>{c.title}</Typography>
                  {c.description && (
                    <Typography variant="caption" sx={{ color: "text.secondary", lineHeight: 1.4 }}>
                      {c.description}
                    </Typography>
                  )}
                </Box>
              </Box>
            </Box>
          ))
        )}
      </DialogContent>
      {(hasMore || page > 1) && (
        <DialogActions sx={{ justifyContent: "center", py: 1.5 }}>
          <Button size="small" disabled={page === 1} onClick={() => setPage(p => p - 1)}>Prev</Button>
          <Typography variant="caption" sx={{ mx: 1, color: "text.secondary" }}>Page {page}</Typography>
          <Button size="small" disabled={!hasMore} onClick={() => setPage(p => p + 1)}>Next</Button>
        </DialogActions>
      )}
    </Dialog>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

interface CustomFrameworkSummary {
  id: string;
  name: string;
  slug: string;
  description?: string;
  control_count: number;
}

export default function FrameworkLibrary() {
  const qc = useQueryClient();

  // Standard framework browser
  const [browseKey, setBrowseKey] = useState<string | null>(null);

  // Custom framework detail
  const [selectedCf, setSelectedCf] = useState<string | null>(null);

  // Framework Advisor
  const [advisorOpen, setAdvisorOpen] = useState(false);

  // Create dialog
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");

  // Edit dialog
  const [editOpen, setEditOpen] = useState(false);
  const [editId, setEditId] = useState("");
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");

  const { data: customs = [], isLoading, refetch } = useQuery<CustomFrameworkSummary[]>({
    queryKey: ["custom-frameworks"],
    queryFn: () => customFrameworksApi.list(),
  });

  const createMut = useMutation({
    mutationFn: () => customFrameworksApi.create({ name: newName.trim(), description: newDesc.trim() || undefined }),
    onSuccess: (created) => {
      qc.invalidateQueries({ queryKey: ["custom-frameworks"] });
      toast.success(`"${created.name}" created`);
      setCreateOpen(false);
      setNewName(""); setNewDesc("");
      setSelectedCf(created.id);
    },
    onError: () => toast.error("Failed to create policy"),
  });

  const renameMut = useMutation({
    mutationFn: () => customFrameworksApi.update(editId, { name: editName.trim(), description: editDesc.trim() || undefined }),
    onSuccess: (updated) => {
      qc.invalidateQueries({ queryKey: ["custom-frameworks"] });
      toast.success(`Renamed to "${updated.name}"`);
      setEditOpen(false);
    },
    onError: () => toast.error("Failed to rename policy"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => customFrameworksApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["custom-frameworks"] });
      toast.success("Policy deleted");
    },
    onError: () => toast.error("Failed to delete policy"),
  });

  const handleEditOpen = (e: React.MouseEvent, cf: CustomFrameworkSummary) => {
    e.stopPropagation();
    setEditId(cf.id); setEditName(cf.name); setEditDesc(cf.description || "");
    setEditOpen(true);
  };

  const handleDelete = (e: React.MouseEvent, id: string, name: string) => {
    e.stopPropagation();
    if (window.confirm(`Delete "${name}"? This cannot be undone.`)) deleteMut.mutate(id);
  };

  // ── Show detail builder when custom framework selected ────────────────────
  if (selectedCf) {
    return (
      <Box>
        <FrameworkDetail cfId={selectedCf} onBack={() => setSelectedCf(null)} />
      </Box>
    );
  }

  const browseFw = browseKey ? STANDARD_FRAMEWORKS.find(f => f.key === browseKey) : null;

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Framework Library</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Browse standard control frameworks and manage your custom compliance policies.
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
          <IconButton onClick={() => refetch()} size="small"><Refresh /></IconButton>
          <Button
            variant="outlined"
            startIcon={<AutoAwesome />}
            onClick={() => setAdvisorOpen(true)}
            sx={{ borderColor: "#7C3AED", color: "#7C3AED", "&:hover": { borderColor: "#6d35d9", bgcolor: "rgba(124,58,237,0.06)" } }}
          >
            Framework Advisor
          </Button>
          <Button variant="contained" startIcon={<Add />} onClick={() => setCreateOpen(true)}>
            New Custom Policy
          </Button>
        </Box>
      </Box>

      {/* Standard frameworks */}
      <Typography variant="subtitle2"
        sx={{ fontWeight: 700, color: "text.secondary", textTransform: "uppercase",
          letterSpacing: 0.8, fontSize: 11, mb: 1.5 }}>
        Standard Frameworks
      </Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {STANDARD_FRAMEWORKS.map((fw) => {
          const IconComp = fw.Icon;
          return (
            <Grid key={fw.key} size={{ xs: 12, sm: 6, md: 4 }}>
              <Card variant="outlined"
                onClick={() => setBrowseKey(fw.key)}
                sx={{ cursor: "pointer", height: "100%", transition: "all 0.15s",
                  "&:hover": { boxShadow: 4, borderColor: fw.color } }}>
                <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                  <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                    <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                      <IconComp sx={{ color: fw.color, fontSize: 26 }} />
                    </Box>
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, mb: 0.25 }}>
                        <Typography sx={{ fontWeight: 700, fontSize: 14, lineHeight: 1.2 }}>{fw.label}</Typography>
                        <Chip label={fw.family} size="small"
                          sx={{ height: 16, fontSize: 9, bgcolor: `${fw.color}15`, color: fw.color, fontWeight: 700 }} />
                      </Box>
                      <Typography variant="caption" sx={{ color: "text.secondary", lineHeight: 1.4 }}>
                        {fw.description}
                      </Typography>
                      {fw.controls && (
                        <Box sx={{ mt: 1 }}>
                          <Chip label={`${fw.controls} controls`} size="small" variant="outlined"
                            sx={{ fontSize: 10, height: 18 }} />
                        </Box>
                      )}
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          );
        })}
      </Grid>

      {/* Custom policies */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
        <Typography variant="subtitle2"
          sx={{ fontWeight: 700, color: "text.secondary", textTransform: "uppercase",
            letterSpacing: 0.8, fontSize: 11 }}>
          Custom Policies
        </Typography>
        <Chip label={customs.length} size="small"
          sx={{ height: 16, fontSize: 10, bgcolor: "rgba(124,77,255,0.12)", color: "#9C27B0" }} />
      </Box>

      {isLoading && <CircularProgress size={22} />}

      {!isLoading && customs.length === 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          No custom policies yet. Click <strong>New Custom Policy</strong> to build one by combining controls from standard frameworks.
        </Alert>
      )}

      <Grid container spacing={2}>
        {customs.map((cf) => (
          <Grid key={cf.id} size={{ xs: 12, sm: 6, md: 4 }}>
            <Card variant="outlined"
              onClick={() => setSelectedCf(cf.id)}
              sx={{ cursor: "pointer", height: "100%", transition: "all 0.15s",
                "&:hover": { boxShadow: 4, borderColor: "#9C27B0" } }}>
              <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                    <LibraryAdd sx={{ color: "#9C27B0", fontSize: 26 }} />
                  </Box>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, mb: 0.25 }}>
                      <Typography sx={{ fontWeight: 700, fontSize: 14, lineHeight: 1.2 }}>{cf.name}</Typography>
                      <Chip label="Custom" size="small"
                        sx={{ height: 16, fontSize: 9, bgcolor: "rgba(124,77,255,0.12)", color: "#9C27B0", fontWeight: 700 }} />
                    </Box>
                    {cf.description && (
                      <Typography variant="caption" sx={{ color: "text.secondary", lineHeight: 1.4 }}>
                        {cf.description}
                      </Typography>
                    )}
                    <Box sx={{ display: "flex", gap: 0.75, mt: 1, alignItems: "center" }}>
                      <Chip label={`${cf.control_count} controls`} size="small" variant="outlined"
                        sx={{ fontSize: 10, height: 18 }} />
                      <Chip label={cf.slug} size="small"
                        sx={{ fontSize: 9, height: 16, fontFamily: "monospace", bgcolor: "action.hover" }} />
                    </Box>
                  </Box>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5, flexShrink: 0 }}>
                    <Tooltip title="Rename policy">
                      <IconButton size="small" onClick={(e) => handleEditOpen(e, cf)}
                        sx={{ color: "text.secondary" }}>
                        <Edit sx={{ fontSize: 16 }} />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete policy">
                      <IconButton size="small" onClick={(e) => handleDelete(e, cf.id, cf.name)}
                        sx={{ color: "error.main" }}>
                        <Delete sx={{ fontSize: 16 }} />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Standard framework controls browser */}
      {browseFw && (
        <StandardControlsBrowser
          fw={browseFw}
          onClose={() => setBrowseKey(null)}
        />
      )}

      {/* Create dialog */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle sx={{ fontWeight: 700 }}>New Custom Policy</DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2, mt: 0.5 }}>
            After creating, you'll be taken to the builder to add domains, select controls from
            existing frameworks, and define your own custom controls.
          </Alert>
          <TextField fullWidth label="Policy name" value={newName} autoFocus
            onChange={(e) => setNewName(e.target.value)}
            placeholder="e.g. MAS TRM, Accenture Security Baseline" sx={{ mb: 2 }} />
          <TextField fullWidth label="Description (optional)" value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)} multiline rows={2}
            placeholder="Describe what this policy covers and who it applies to" />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button variant="contained" disabled={!newName.trim() || createMut.isPending}
            onClick={() => createMut.mutate()}
            startIcon={createMut.isPending ? <CircularProgress size={14} /> : <Add />}>
            Create & Build
          </Button>
        </DialogActions>
      </Dialog>

      {/* Rename dialog */}
      <Dialog open={editOpen} onClose={() => setEditOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle sx={{ fontWeight: 700 }}>Rename Policy</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Policy name" value={editName} autoFocus
            onChange={(e) => setEditName(e.target.value)} sx={{ mb: 2, mt: 1 }} />
          <TextField fullWidth label="Description (optional)" value={editDesc}
            onChange={(e) => setEditDesc(e.target.value)} multiline rows={2}
            placeholder="Describe what this policy covers and who it applies to" />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setEditOpen(false)}>Cancel</Button>
          <Button variant="contained" disabled={!editName.trim() || renameMut.isPending}
            onClick={() => renameMut.mutate()}
            startIcon={renameMut.isPending ? <CircularProgress size={14} /> : <Edit />}>
            Save
          </Button>
        </DialogActions>
      </Dialog>

      <FrameworkAdvisor open={advisorOpen} onClose={() => setAdvisorOpen(false)} />
    </Box>
  );
}
