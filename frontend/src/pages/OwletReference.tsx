import React, { useState, useRef, useEffect } from "react";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress, Alert,
  Button, TextField, Divider, Tooltip, IconButton, Paper,
  Table, TableBody, TableCell, TableHead, TableRow, TableContainer,
  List, ListItem, Snackbar,
} from "@mui/material";
import {
  Hub, Warning, VerifiedUser, SmartToy, Search, Devices,
  Cable, FactCheck, BugReport, Edit, Save, Cancel, Lock,
  AutoStories, History, OpenInNew,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { systemKbApi, adminApi } from "../services/api";

// ── Section icon map ─────────────────────────────────────────────────────────

const ICON_MAP: Record<string, React.ReactNode> = {
  Hub: <Hub />,
  Warning: <Warning />,
  VerifiedUser: <VerifiedUser />,
  SmartToy: <SmartToy />,
  Search: <Search />,
  Devices: <Devices />,
  Cable: <Cable />,
  FactCheck: <FactCheck />,
  BugReport: <BugReport />,
};

const SECTION_COLOR: Record<string, string> = {
  overview: "#4285F4",
  risk_management: "#EA4335",
  compliance: "#34A853",
  ai_agents: "#9C27B0",
  scanning: "#FF7043",
  asset_management: "#00ACC1",
  integrations: "#607D8B",
  audit_intelligence: "#1565C0",
  threat_intelligence: "#E91E63",
};

// ── Simple markdown renderer ──────────────────────────────────────────────────

function renderInline(text: string): React.ReactNode {
  // Handle **bold** and `code` inline
  const parts: React.ReactNode[] = [];
  const regex = /(`[^`]+`|\*\*[^*]+\*\*)/g;
  let last = 0;
  let match: RegExpExecArray | null;
  let idx = 0;
  while ((match = regex.exec(text)) !== null) {
    if (match.index > last) {
      parts.push(<React.Fragment key={idx++}>{text.slice(last, match.index)}</React.Fragment>);
    }
    const tok = match[0];
    if (tok.startsWith("`")) {
      parts.push(
        <code key={idx++} style={{
          background: "rgba(255,255,255,0.08)", padding: "1px 5px",
          borderRadius: 3, fontFamily: "monospace", fontSize: "0.85em",
        }}>
          {tok.slice(1, -1)}
        </code>
      );
    } else {
      parts.push(<strong key={idx++}>{tok.slice(2, -2)}</strong>);
    }
    last = match.index + tok.length;
  }
  if (last < text.length) {
    parts.push(<React.Fragment key={idx++}>{text.slice(last)}</React.Fragment>);
  }
  return parts.length === 0 ? text : <>{parts}</>;
}

interface ParsedTable {
  type: "table";
  headers: string[];
  rows: string[][];
}
interface ParsedHeading {
  type: "h1" | "h2" | "h3";
  text: string;
}
interface ParsedList {
  type: "list";
  items: string[];
}
interface ParsedParagraph {
  type: "paragraph";
  text: string;
}
type ParsedBlock = ParsedTable | ParsedHeading | ParsedList | ParsedParagraph;

function parseMarkdown(md: string): ParsedBlock[] {
  const lines = md.split("\n");
  const blocks: ParsedBlock[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Headings
    if (line.startsWith("### ")) {
      blocks.push({ type: "h3", text: line.slice(4).trim() });
      i++;
      continue;
    }
    if (line.startsWith("## ")) {
      blocks.push({ type: "h2", text: line.slice(3).trim() });
      i++;
      continue;
    }
    if (line.startsWith("# ")) {
      blocks.push({ type: "h1", text: line.slice(2).trim() });
      i++;
      continue;
    }

    // Tables — collect consecutive | lines
    if (line.trim().startsWith("|")) {
      const tableLines: string[] = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) {
        tableLines.push(lines[i]);
        i++;
      }
      const parseRow = (l: string) =>
        l.split("|").slice(1, -1).map((c) => c.trim());
      const headers = parseRow(tableLines[0]);
      const rows: string[][] = [];
      for (let j = 2; j < tableLines.length; j++) {
        rows.push(parseRow(tableLines[j]));
      }
      blocks.push({ type: "table", headers, rows });
      continue;
    }

    // List items
    if (line.trim().startsWith("- ")) {
      const items: string[] = [];
      while (i < lines.length && lines[i].trim().startsWith("- ")) {
        items.push(lines[i].trim().slice(2));
        i++;
      }
      blocks.push({ type: "list", items });
      continue;
    }

    // Empty line
    if (line.trim() === "") {
      i++;
      continue;
    }

    // Paragraph
    blocks.push({ type: "paragraph", text: line.trim() });
    i++;
  }

  return blocks;
}

function SimpleMarkdown({ content }: { content: string }) {
  const blocks = parseMarkdown(content);
  return (
    <Box>
      {blocks.map((block, idx) => {
        if (block.type === "h1") {
          return (
            <Typography key={idx} variant="h5" sx={{ fontWeight: 700, mt: idx === 0 ? 0 : 3, mb: 1.5 }}>
              {block.text}
            </Typography>
          );
        }
        if (block.type === "h2") {
          return (
            <Typography key={idx} variant="h6" sx={{ fontWeight: 700, mt: 2.5, mb: 1, color: "text.primary" }}>
              {block.text}
            </Typography>
          );
        }
        if (block.type === "h3") {
          return (
            <Typography key={idx} variant="subtitle1" sx={{ fontWeight: 700, mt: 2, mb: 0.75, color: "text.primary" }}>
              {block.text}
            </Typography>
          );
        }
        if (block.type === "table") {
          return (
            <TableContainer key={idx} component={Paper} variant="outlined"
              sx={{ mb: 2, mt: 1, "& .MuiPaper-root": { bgcolor: "rgba(255,255,255,0.03)" } }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ "& th": { fontWeight: 700, fontSize: 12, color: "text.secondary", borderColor: "divider" } }}>
                    {block.headers.map((h, i) => <TableCell key={i}>{h}</TableCell>)}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {block.rows.map((row, ri) => (
                    <TableRow key={ri} sx={{ "& td": { fontSize: 12, borderColor: "divider" } }}>
                      {row.map((cell, ci) => (
                        <TableCell key={ci}>{renderInline(cell)}</TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          );
        }
        if (block.type === "list") {
          return (
            <List key={idx} dense disablePadding sx={{ mb: 1, pl: 1 }}>
              {block.items.map((item, ii) => (
                <ListItem key={ii} disableGutters sx={{ py: 0.25, alignItems: "flex-start" }}>
                  <Box sx={{ width: 6, height: 6, bgcolor: "text.secondary", borderRadius: "50%", mt: 1, mr: 1.5, flexShrink: 0 }} />
                  <Typography variant="body2" sx={{ color: "text.secondary" }}>
                    {renderInline(item)}
                  </Typography>
                </ListItem>
              ))}
            </List>
          );
        }
        // paragraph
        return (
          <Typography key={idx} variant="body2" sx={{ color: "text.secondary", mb: 0.75, lineHeight: 1.7 }}>
            {renderInline(block.text)}
          </Typography>
        );
      })}
    </Box>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

interface KBEntry {
  section_key: string;
  section_title: string;
  icon_name?: string;
  content: string;
  version: number;
  last_updated_by?: string;
  last_updated_at?: string;
}

export default function OwletReference() {
  const qc = useQueryClient();
  const { data: me } = useQuery<any>({ queryKey: ["my-access"], queryFn: adminApi.me, retry: 0, staleTime: 60_000 });
  const isAdmin = !!me?.is_admin;
  const [activeKey, setActiveKey] = useState<string>("");
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editContent, setEditContent] = useState("");
  const [snack, setSnack] = useState("");
  const sectionRefs = useRef<Record<string, HTMLDivElement | null>>({});

  const { data: entries = [], isLoading, error } = useQuery<KBEntry[]>({
    queryKey: ["system-kb"],
    queryFn: () => systemKbApi.list(),
    staleTime: 60_000,
  });

  const saveMutation = useMutation({
    mutationFn: ({ key, content }: { key: string; content: string }) =>
      systemKbApi.update(key, { content }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["system-kb"] });
      setEditingKey(null);
      setSnack("Section saved successfully.");
    },
    onError: () => setSnack("Failed to save. Check your permissions."),
  });

  useEffect(() => {
    if (entries.length > 0 && !activeKey) {
      setActiveKey(entries[0].section_key);
    }
  }, [entries, activeKey]);

  const scrollTo = (key: string) => {
    setActiveKey(key);
    const el = sectionRefs.current[key];
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const startEdit = (entry: KBEntry) => {
    setEditContent(entry.content);
    setEditingKey(entry.section_key);
  };

  const cancelEdit = () => {
    setEditingKey(null);
    setEditContent("");
  };

  const saveEdit = (key: string) => {
    saveMutation.mutate({ key, content: editContent });
  };

  if (isLoading) {
    return <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress /></Box>;
  }

  if (error) {
    return <Alert severity="error" sx={{ mt: 2 }}>Failed to load Owlet Reference. Check your connection.</Alert>;
  }

  return (
    <Box>
      {/* Page header */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 0.5 }}>
          <AutoStories sx={{ color: "#1565C0", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Owlet Reference</Typography>
          {isAdmin ? (
            <Chip label="Admin" size="small" sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontSize: 10, fontWeight: 700 }} />
          ) : (
            <Chip icon={<Lock sx={{ fontSize: "12px !important" }} />} label="Read-only" size="small"
              sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", fontSize: 10 }} />
          )}
        </Box>
        <Typography variant="body2" sx={{ color: "text.secondary" }}>
          Technical reference for the Owlet ecosystem — capabilities, logic, and architecture. Admin-editable. Injected into the Aegis Assistant.
        </Typography>
      </Box>

      <Box sx={{ display: "flex", gap: 3, alignItems: "flex-start" }}>
        {/* Left sidebar nav */}
        <Box sx={{
          width: 220, flexShrink: 0, position: "sticky", top: 16,
          maxHeight: "calc(100vh - 120px)", overflowY: "auto",
        }}>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent sx={{ p: 1.5, "&:last-child": { pb: 1.5 } }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, fontSize: 10,
                textTransform: "uppercase", letterSpacing: 1, pl: 1, display: "block", mb: 1 }}>
                Sections
              </Typography>
              {entries.map((entry) => {
                const color = SECTION_COLOR[entry.section_key] || "#888";
                const isActive = activeKey === entry.section_key;
                return (
                  <Box key={entry.section_key}
                    onClick={() => scrollTo(entry.section_key)}
                    sx={{
                      display: "flex", alignItems: "center", gap: 1, px: 1, py: 0.75,
                      borderRadius: 1, cursor: "pointer", mb: 0.25,
                      bgcolor: isActive ? `${color}18` : "transparent",
                      borderLeft: isActive ? `3px solid ${color}` : "3px solid transparent",
                      "&:hover": { bgcolor: isActive ? `${color}18` : "rgba(255,255,255,0.04)" },
                      transition: "all 0.15s",
                    }}>
                    <Box sx={{ color: isActive ? color : "text.secondary", fontSize: 16, display: "flex" }}>
                      {ICON_MAP[entry.icon_name || ""] || <Hub sx={{ fontSize: 16 }} />}
                    </Box>
                    <Typography variant="caption" sx={{
                      color: isActive ? color : "text.secondary",
                      fontWeight: isActive ? 700 : 400, fontSize: 12, lineHeight: 1.3,
                    }}>
                      {entry.section_title}
                    </Typography>
                  </Box>
                );
              })}
            </CardContent>
          </Card>

          {/* Admin hint */}
          {isAdmin && (
            <Box sx={{ mt: 1.5, p: 1.5, bgcolor: "rgba(66,133,244,0.06)", borderRadius: 1.5,
              border: "1px solid rgba(66,133,244,0.2)" }}>
              <Typography variant="caption" sx={{ color: "#4285F4", fontSize: 11, display: "block", fontWeight: 600, mb: 0.25 }}>
                Admin Mode
              </Typography>
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, lineHeight: 1.4 }}>
                Click Edit on any section to update its content. Changes are reflected in the Aegis Assistant immediately.
              </Typography>
            </Box>
          )}
        </Box>

        {/* Main content */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          {entries.length === 0 ? (
            <Alert severity="info">No reference sections found. The database may still be seeding on first startup.</Alert>
          ) : (
            <Box sx={{ display: "flex", flexDirection: "column", gap: 2.5 }}>
              {entries.map((entry) => {
                const color = SECTION_COLOR[entry.section_key] || "#4285F4";
                const isEditing = editingKey === entry.section_key;
                const isSaving = saveMutation.isPending && saveMutation.variables?.key === entry.section_key;

                return (
                  <Card key={entry.section_key}
                    ref={(el) => { sectionRefs.current[entry.section_key] = el; }}
                    sx={{
                      bgcolor: "background.paper",
                      border: `1px solid rgba(255,255,255,0.08)`,
                      borderLeft: `4px solid ${color}`,
                      borderRadius: 2,
                      scrollMarginTop: 16,
                    }}>
                    <CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}>
                      {/* Section header */}
                      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 2 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                          <Box sx={{
                            width: 36, height: 36, borderRadius: 1.5,
                            bgcolor: `${color}18`, display: "flex", alignItems: "center", justifyContent: "center",
                            color, flexShrink: 0,
                          }}>
                            {ICON_MAP[entry.icon_name || ""] || <Hub />}
                          </Box>
                          <Box>
                            <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1.2 }}>
                              {entry.section_title}
                            </Typography>
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 0.25 }}>
                              <Chip label={`v${entry.version}`} size="small"
                                sx={{ height: 16, fontSize: 9, bgcolor: `${color}18`, color }} />
                              {entry.last_updated_by && (
                                <Typography variant="caption" sx={{ color: "text.disabled", fontSize: 10 }}>
                                  Updated by {entry.last_updated_by}
                                  {entry.last_updated_at
                                    ? ` · ${new Date(entry.last_updated_at).toLocaleDateString()}`
                                    : ""}
                                </Typography>
                              )}
                            </Box>
                          </Box>
                        </Box>

                        {/* Admin controls */}
                        {isAdmin && (
                          <Box sx={{ display: "flex", gap: 0.5, flexShrink: 0 }}>
                            {isEditing ? (
                              <>
                                <Button size="small" variant="contained"
                                  startIcon={isSaving ? <CircularProgress size={12} /> : <Save />}
                                  onClick={() => saveEdit(entry.section_key)}
                                  disabled={isSaving}
                                  sx={{ bgcolor: "#34A853", "&:hover": { bgcolor: "#2d9247" }, fontSize: 11 }}>
                                  Save
                                </Button>
                                <Button size="small" variant="outlined" startIcon={<Cancel />}
                                  onClick={cancelEdit} sx={{ fontSize: 11 }}>
                                  Cancel
                                </Button>
                              </>
                            ) : (
                              <Tooltip title="Edit section content">
                                <IconButton size="small" onClick={() => startEdit(entry)}
                                  sx={{ color: "text.secondary", "&:hover": { color } }}>
                                  <Edit fontSize="small" />
                                </IconButton>
                              </Tooltip>
                            )}
                          </Box>
                        )}
                      </Box>

                      <Divider sx={{ mb: 2, borderColor: "rgba(255,255,255,0.06)" }} />

                      {/* Content */}
                      {isEditing ? (
                        <Box>
                          <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>
                            Edit in Markdown. Tables, headings (#/##/###), bold (**text**), code (`text`), and list items (- item) are all supported.
                          </Typography>
                          <TextField
                            fullWidth multiline minRows={20} maxRows={50}
                            value={editContent}
                            onChange={(e) => setEditContent(e.target.value)}
                            sx={{
                              "& .MuiInputBase-root": {
                                fontFamily: "monospace", fontSize: 12, lineHeight: 1.6,
                              },
                            }}
                          />
                        </Box>
                      ) : (
                        <SimpleMarkdown content={entry.content} />
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </Box>
          )}
        </Box>
      </Box>

      <Snackbar open={!!snack} autoHideDuration={4000} onClose={() => setSnack("")}
        message={snack} anchorOrigin={{ vertical: "bottom", horizontal: "center" }} />
    </Box>
  );
}
