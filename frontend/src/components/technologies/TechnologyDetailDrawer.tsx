import React from "react";
import {
  Drawer, Box, Typography, IconButton, Chip, CircularProgress, Tabs, Tab,
  Table, TableHead, TableRow, TableCell, TableBody,
} from "@mui/material";
import { Close } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { technologiesApi } from "../../services/api";
import type { TechnologyDetail } from "../../types";

interface Props {
  clientId: string;
  technologyName: string | null;
  onClose: () => void;
}

const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50", info: "#4285F4",
};

export default function TechnologyDetailDrawer({ clientId, technologyName, onClose }: Props) {
  const [tab, setTab] = React.useState(0);
  const { data, isLoading } = useQuery<TechnologyDetail>({
    queryKey: ["technology-detail", clientId, technologyName],
    queryFn: () => technologiesApi.detail(clientId, technologyName as string),
    enabled: !!clientId && !!technologyName,
  });

  React.useEffect(() => { setTab(0); }, [technologyName]);

  return (
    <Drawer anchor="right" open={!!technologyName} onClose={onClose}
      slotProps={{ paper: { sx: { bgcolor: "background.default", color: "text.primary", width: { xs: "100%", sm: 560 }, p: 0 } } }}>
      {!technologyName ? null : (
        <Box>
          <Box sx={{ p: 2.5, borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
              <Box>
                <Typography variant="caption" sx={{ color: "text.secondary", fontFamily: "monospace" }}>
                  TECHNOLOGY
                </Typography>
                <Typography variant="h6" sx={{ color: "text.primary", fontWeight: 600, mt: 0.5, wordBreak: "break-word" }}>
                  {technologyName}
                </Typography>
              </Box>
              <IconButton size="small" onClick={onClose} sx={{ color: "text.secondary" }}>
                <Close />
              </IconButton>
            </Box>
            {data && (
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 1 }}>
                <Chip label={data.category} size="small" sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontSize: 10 }} />
                <Chip label={data.subcategory} size="small" sx={{ bgcolor: "rgba(124,77,255,0.15)", color: "#34A853", fontSize: 10 }} />
                <Chip label={data.type} size="small" sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", fontSize: 10 }} />
              </Box>
            )}
          </Box>

          {isLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", py: 8 }}>
              <CircularProgress sx={{ color: "#4285F4" }} />
            </Box>
          ) : !data ? (
            <Box sx={{ p: 3 }}>
              <Typography sx={{ color: "text.secondary" }}>No data available.</Typography>
            </Box>
          ) : (
            <>
              {/* Summary stats */}
              <Box sx={{ display: "flex", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                {[
                  ["Resources", data.resources_count],
                  ["Versions", data.versions_detected.length],
                  ["Open findings", data.open_findings.length],
                  ["Exposure", data.exposure_level],
                ].map(([label, val]) => (
                  <Box key={label as string} sx={{ flex: 1, p: 2, textAlign: "center", borderRight: "1px solid rgba(255,255,255,0.08)", "&:last-child": { borderRight: 0 } }}>
                    <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 600 }}>
                      {(label as string).toUpperCase()}
                    </Typography>
                    <Typography sx={{ color: "text.primary", fontSize: 18, fontWeight: 700, mt: 0.5, textTransform: "capitalize" }}>
                      {val}
                    </Typography>
                  </Box>
                ))}
              </Box>

              {/* Tabs */}
              <Tabs value={tab} onChange={(_, v) => setTab(v)} variant="fullWidth"
                sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)",
                  "& .MuiTab-root": { color: "text.secondary", textTransform: "none", fontSize: 12 },
                  "& .Mui-selected": { color: "#4285F4" }, "& .MuiTabs-indicator": { backgroundColor: "#4285F4" } }}>
                <Tab label="Overview" />
                <Tab label="Findings" />
                <Tab label="Assets" />
                <Tab label="Policies" />
              </Tabs>

              <Box sx={{ p: 2.5, overflowY: "auto", maxHeight: "calc(100vh - 300px)" }}>
                {tab === 0 && (
                  <Box>
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600 }}>OWNER</Typography>
                      <Typography variant="body2" sx={{ color: "text.primary", mt: 0.5 }}>{data.owner}</Typography>
                    </Box>
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600 }}>VERSIONS DETECTED</Typography>
                      <Box sx={{ display: "flex", gap: 0.5, mt: 0.5, flexWrap: "wrap" }}>
                        {data.versions_detected.map((v) => (
                          <Chip key={v.version} label={`${v.version} (${v.asset_count})`} size="small"
                            sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.primary", fontSize: 11 }} />
                        ))}
                      </Box>
                    </Box>
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600 }}>REGIONS</Typography>
                      <Box sx={{ display: "flex", gap: 0.5, mt: 0.5, flexWrap: "wrap" }}>
                        {data.regions.length === 0 ? <Typography variant="caption" sx={{ color: "text.secondary" }}>—</Typography> :
                          data.regions.map((r) => (
                            <Chip key={r} label={r} size="small" sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.primary", fontSize: 10 }} />
                          ))}
                      </Box>
                    </Box>
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600 }}>SUBSCRIPTIONS</Typography>
                      <Box sx={{ display: "flex", gap: 0.5, mt: 0.5, flexWrap: "wrap" }}>
                        {data.subscriptions.length === 0 ? <Typography variant="caption" sx={{ color: "text.secondary" }}>—</Typography> :
                          data.subscriptions.map((s) => (
                            <Chip key={s} label={s} size="small" sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.primary", fontSize: 10, fontFamily: "monospace" }} />
                          ))}
                      </Box>
                    </Box>
                  </Box>
                )}

                {tab === 1 && (
                  <Box>
                    {data.open_findings.length === 0 ? (
                      <Typography sx={{ color: "text.secondary", textAlign: "center", py: 4 }}>
                        No open findings.
                      </Typography>
                    ) : (
                      data.open_findings.map((f) => (
                        <Box key={f.id} sx={{ p: 1.5, borderRadius: 1, bgcolor: "rgba(255,255,255,0.03)", mb: 1 }}>
                          <Box sx={{ display: "flex", gap: 1, alignItems: "flex-start" }}>
                            <Chip label={f.severity} size="small"
                              sx={{ bgcolor: `${SEV_COLOR[f.severity] || "#888"}20`, color: SEV_COLOR[f.severity] || "#888", fontSize: 9, height: 18, flexShrink: 0 }} />
                            <Typography variant="body2" sx={{ color: "text.primary", fontSize: 12.5 }}>{f.title}</Typography>
                          </Box>
                          {f.cve_id && (
                            <Typography variant="caption" sx={{ color: "#4285F4", fontFamily: "monospace", fontSize: 11, ml: 1, mt: 0.5, display: "block" }}>
                              {f.cve_id}{f.cvss_score ? ` · CVSS ${f.cvss_score.toFixed(1)}` : ""}
                            </Typography>
                          )}
                        </Box>
                      ))
                    )}
                  </Box>
                )}

                {tab === 2 && (
                  <Box>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
                      Active ({data.assets.length})
                    </Typography>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 10, borderColor: "divider" } }}>
                          <TableCell>NAME</TableCell>
                          <TableCell>REGION</TableCell>
                          <TableCell>STATUS</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {data.assets.map((a) => (
                          <TableRow key={a.id} sx={{ "& td": { color: "text.primary", fontSize: 11, borderColor: "divider" } }}>
                            <TableCell sx={{ maxWidth: 220 }}>
                              <Typography variant="caption" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>
                                {a.name}
                              </Typography>
                            </TableCell>
                            <TableCell sx={{ color: "rgba(255,255,255,0.6) !important", fontSize: 11 }}>{a.region || "—"}</TableCell>
                            <TableCell>
                              <Chip label={a.status} size="small" sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.primary", fontSize: 9, height: 16 }} />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>

                    {data.stale_assets && data.stale_assets.length > 0 && (
                      <Box sx={{ mt: 2 }}>
                        <Typography variant="caption" sx={{ color: "#ff9800", display: "block", mb: 0.5, fontWeight: 600 }}>
                          Stale / decommissioned ({data.stale_count ?? data.stale_assets.length}) — excluded from analysis
                        </Typography>
                        <Table size="small">
                          <TableBody>
                            {data.stale_assets.map((a) => (
                              <TableRow key={a.id} sx={{ "& td": { color: "text.secondary", fontSize: 11, borderColor: "divider" } }}>
                                <TableCell sx={{ maxWidth: 220 }}>
                                  <Typography variant="caption" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>
                                    {a.name}
                                  </Typography>
                                </TableCell>
                                <TableCell sx={{ color: "rgba(255,255,255,0.45) !important", fontSize: 11 }}>{a.region || "—"}</TableCell>
                                <TableCell>
                                  <Chip label={a.status} size="small" sx={{ bgcolor: "transparent", color: "#ff9800", border: "1px solid rgba(255,152,0,0.4)", fontSize: 9, height: 16 }} />
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </Box>
                    )}
                  </Box>
                )}

                {tab === 3 && (
                  <Box>
                    {data.policies.length === 0 ? (
                      <Typography sx={{ color: "text.secondary", textAlign: "center", py: 4 }}>
                        No related policies.
                      </Typography>
                    ) : (
                      data.policies.map((p, i) => (
                        <Box key={i} sx={{ p: 1.5, borderRadius: 1, bgcolor: "rgba(255,255,255,0.03)", mb: 1 }}>
                          <Box sx={{ display: "flex", justifyContent: "space-between", gap: 1 }}>
                            <Typography variant="body2" sx={{ color: "text.primary", fontSize: 12.5 }}>{p.name}</Typography>
                            <Chip label={p.status} size="small"
                              sx={{ bgcolor: p.status === "passing" ? "rgba(0,230,118,0.15)" : "rgba(244,67,54,0.15)",
                                color: p.status === "passing" ? "#00e676" : "#f44336", fontSize: 9, height: 18 }} />
                          </Box>
                          <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>
                            {p.framework.replace(/_/g, " ").toUpperCase()} · {p.control_id}
                          </Typography>
                        </Box>
                      ))
                    )}
                  </Box>
                )}
              </Box>
            </>
          )}
        </Box>
      )}
    </Drawer>
  );
}
