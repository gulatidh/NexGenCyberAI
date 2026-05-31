/**
 * Sync — admin-triggered, on-demand sync of every external feed.
 *
 * Each feed (EPSS, CISA KEV, NVD recent CVEs, framework/standards
 * recompute) renders as a tile showing its last-sync timestamp and
 * cached item count, with its own "Sync" button. A top-level "Sync all"
 * button fires every feed sequentially.
 *
 * Page is admin-only — non-admins see an "access required" alert
 * (matches the Admin page guard).
 */
import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Button, Chip, Alert,
  CircularProgress, Grid, LinearProgress, Tooltip,
} from "@mui/material";
import {
  Sync, AdminPanelSettings, CheckCircleOutlined, ScheduleOutlined,
  ShieldOutlined, CloudDownload, Policy, ErrorOutlined,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { adminApi } from "../services/api";
import { MyAccess } from "../types";
import { fromNow } from "../utils/datetime";

interface SyncFeed {
  id: string;
  name: string;
  category: "threat_intel" | "cve" | "framework" | "threat_library";
  description: string;
  source_url: string;
  item_label: string;
  count: number;
  last_synced_at: string | null;
  schedule_cron?: string | null;
  schedule_label?: string | null;
  next_run_at?: string | null;
  extra?: Record<string, any>;
}

interface FeedResult {
  ok: boolean;
  id?: string;
  count?: number;
  error?: string;
}

const CATEGORY_COLOR: Record<string, string> = {
  threat_intel: "#EA4335",
  cve: "#4285F4",
  framework: "#34A853",
  threat_library: "#9C27B0",
};
const CATEGORY_LABEL: Record<string, string> = {
  threat_intel: "Threat Intel",
  cve: "External CVE",
  framework: "Framework",
  threat_library: "Threat Library",
};
const CATEGORY_ICON: Record<string, React.ReactNode> = {
  threat_intel: <ShieldOutlined sx={{ fontSize: 22 }} />,
  cve: <CloudDownload sx={{ fontSize: 22 }} />,
  framework: <Policy sx={{ fontSize: 22 }} />,
  threat_library: <ShieldOutlined sx={{ fontSize: 22 }} />,
};

function FeedTile({
  feed, syncing, onSync, lastResult,
}: {
  feed: SyncFeed;
  syncing: boolean;
  onSync: () => void;
  lastResult?: FeedResult;
}) {
  const color = CATEGORY_COLOR[feed.category] || "#4285F4";
  const synced = !!feed.last_synced_at;
  const hasError = lastResult && !lastResult.ok;

  return (
    <Card sx={{
      bgcolor: "#1E1E1E",
      border: `1px solid ${hasError ? "#EA433580" : synced ? `${color}40` : "rgba(255,255,255,0.08)"}`,
      borderRadius: 2, height: "100%",
    }}>
      <CardContent sx={{ display: "flex", flexDirection: "column", height: "100%" }}>
        <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5, mb: 2 }}>
          <Box sx={{
            width: 44, height: 44, borderRadius: 1.5, bgcolor: `${color}18`,
            display: "flex", alignItems: "center", justifyContent: "center",
            color, flexShrink: 0,
          }}>
            {CATEGORY_ICON[feed.category]}
          </Box>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Chip
              label={CATEGORY_LABEL[feed.category]}
              size="small"
              sx={{
                height: 18, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                letterSpacing: 0.5, bgcolor: `${color}20`, color, mb: 0.5,
              }} />
            <Typography sx={{ color: "white", fontWeight: 700, fontSize: 15, lineHeight: 1.3 }}>
              {feed.name}
            </Typography>
            <Tooltip title={feed.source_url}>
              <Typography component="a" href={feed.source_url} target="_blank" rel="noreferrer"
                sx={{
                  color: "rgba(255,255,255,0.45)", fontSize: 11, textDecoration: "none",
                  display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  "&:hover": { color },
                }}>
                {feed.source_url.replace(/^https?:\/\//, "")}
              </Typography>
            </Tooltip>
          </Box>
          <Chip
            icon={syncing
              ? <CircularProgress size={12} sx={{ color: `${color} !important`, ml: 0.5 }} />
              : hasError
                ? <ErrorOutlined sx={{ fontSize: 12, color: "#EA4335 !important" }} />
                : synced
                  ? <CheckCircleOutlined sx={{ fontSize: 12, color: `${color} !important` }} />
                  : <ScheduleOutlined sx={{ fontSize: 12, color: "rgba(255,255,255,0.5) !important" }} />}
            label={syncing ? "Syncing" : hasError ? "Error" : synced ? "Synced" : "Pending"}
            size="small"
            sx={{
              bgcolor: hasError ? "rgba(234,67,53,0.15)" : synced ? `${color}18` : "rgba(255,255,255,0.05)",
              color: hasError ? "#EA4335" : synced ? color : "rgba(255,255,255,0.6)",
              fontSize: 10, fontWeight: 700, height: 20, textTransform: "uppercase", letterSpacing: 0.5,
            }} />
        </Box>

        <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.7)", fontSize: 12.5, lineHeight: 1.5, mb: 1.5 }}>
          {feed.description}
        </Typography>

        <Box sx={{ flex: 1 }} />

        <Box sx={{ display: "flex", alignItems: "baseline", gap: 1, mb: 0.5 }}>
          <Typography sx={{ color, fontSize: 26, fontWeight: 700, lineHeight: 1 }}>
            {feed.count.toLocaleString()}
          </Typography>
          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
            {feed.item_label}
          </Typography>
        </Box>
        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", display: "block" }}>
          {feed.last_synced_at ? `Last sync ${fromNow(feed.last_synced_at)}` : "Never synced"}
        </Typography>
        {feed.schedule_label && (
          <Tooltip title={feed.next_run_at ? `Next run ${fromNow(feed.next_run_at)}` : feed.schedule_label}>
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", display: "flex", alignItems: "center", gap: 0.5, mb: 1.5 }}>
              <ScheduleOutlined sx={{ fontSize: 12 }} />
              {feed.schedule_label}
              {feed.next_run_at && (
                <Box component="span" sx={{ color: "rgba(255,255,255,0.55)" }}>
                  · next {fromNow(feed.next_run_at)}
                </Box>
              )}
            </Typography>
          </Tooltip>
        )}
        {!feed.schedule_label && <Box sx={{ mb: 1.5 }} />}

        {hasError && lastResult?.error && (
          <Typography variant="caption" sx={{ color: "#EA4335", display: "block", mb: 1 }}>
            {lastResult.error}
          </Typography>
        )}

        <Button
          variant="outlined"
          size="small"
          startIcon={syncing ? <CircularProgress size={14} sx={{ color }} /> : <Sync />}
          disabled={syncing}
          onClick={onSync}
          sx={{
            color, borderColor: `${color}60`, textTransform: "none", fontWeight: 600,
            "&:hover": { borderColor: color, bgcolor: `${color}10` },
            "&.Mui-disabled": { borderColor: `${color}30`, color: `${color}80` },
          }}
        >
          {syncing ? "Syncing…" : "Sync"}
        </Button>
      </CardContent>
    </Card>
  );
}

export default function ThreatIntel() {
  const qc = useQueryClient();
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [allSyncing, setAllSyncing] = useState(false);
  const [results, setResults] = useState<Record<string, FeedResult>>({});

  const { data: me, isLoading: meLoading } = useQuery<MyAccess>({
    queryKey: ["my-access"],
    queryFn: adminApi.me,
  });
  const canAdmin = !!(me?.is_admin || me?.is_admin_anywhere);

  const { data: feeds = [], isLoading } = useQuery<SyncFeed[]>({
    queryKey: ["sync-feeds"],
    queryFn: adminApi.listSyncFeeds,
    enabled: canAdmin,
  });

  const syncOne = useMutation({
    mutationFn: (feedId: string) => adminApi.refreshSyncFeed(feedId),
    onMutate: (feedId: string) => { setSyncingId(feedId); },
    onSuccess: (result: FeedResult, feedId: string) => {
      setResults((prev) => ({ ...prev, [feedId]: result }));
    },
    onError: (err: any, feedId: string) => {
      setResults((prev) => ({
        ...prev,
        [feedId]: { ok: false, error: err?.response?.data?.detail || err?.message || "Sync failed" },
      }));
    },
    onSettled: () => {
      setSyncingId(null);
      qc.invalidateQueries({ queryKey: ["sync-feeds"] });
    },
  });

  const syncAll = useMutation({
    mutationFn: () => adminApi.refreshAllSyncFeeds(),
    onMutate: () => { setAllSyncing(true); },
    onSuccess: (resp: { results: FeedResult[] }) => {
      const next: Record<string, FeedResult> = {};
      for (const r of resp.results || []) {
        if (r.id) next[r.id] = r;
      }
      setResults((prev) => ({ ...prev, ...next }));
    },
    onSettled: () => {
      setAllSyncing(false);
      qc.invalidateQueries({ queryKey: ["sync-feeds"] });
    },
  });

  if (meLoading) {
    return <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#4285F4" }} /></Box>;
  }
  if (!canAdmin) {
    return (
      <Box sx={{ maxWidth: 640, mx: "auto", mt: 6 }}>
        <Alert severity="warning" icon={<AdminPanelSettings />}
          sx={{ bgcolor: "rgba(255,152,0,0.08)", color: "white", border: "1px solid rgba(255,152,0,0.3)" }}>
          <Typography sx={{ fontWeight: 600, mb: 0.5 }}>Admin access required</Typography>
          External feed sync is restricted to administrators.
        </Alert>
      </Box>
    );
  }

  const anySynced = feeds.some((f) => f.last_synced_at);

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Sync</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            On-demand sync for external CVEs, threat intel, and framework catalogs
          </Typography>
        </Box>
        <Button
          variant="contained"
          size="large"
          startIcon={allSyncing ? <CircularProgress size={18} sx={{ color: "white" }} /> : <Sync />}
          disabled={allSyncing || !!syncingId}
          onClick={() => syncAll.mutate()}
          sx={{
            bgcolor: "#4285F4", color: "white", textTransform: "none", fontWeight: 700,
            "&:hover": { bgcolor: "#1a73e8" },
            "&.Mui-disabled": { bgcolor: "rgba(66,133,244,0.4)", color: "rgba(255,255,255,0.7)" },
          }}
        >
          {allSyncing ? "Syncing all…" : anySynced ? "Sync all feeds" : "Run first sync"}
        </Button>
      </Box>

      {allSyncing && (
        <Box sx={{ mb: 2 }}>
          <LinearProgress sx={{
            bgcolor: "rgba(66,133,244,0.1)",
            "& .MuiLinearProgress-bar": { bgcolor: "#4285F4" },
          }} />
          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", mt: 0.5, display: "block" }}>
            Running every feed sequentially. EPSS download is the longest (~10MB compressed).
          </Typography>
        </Box>
      )}

      {!anySynced && !allSyncing && (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.08)", color: "white", border: "1px solid rgba(66,133,244,0.3)", mb: 2 }}>
          <Typography sx={{ fontWeight: 600, mb: 0.25 }}>No external data synced yet</Typography>
          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.75)" }}>
            Until you run the first sync, EPSS and KEV factors in the Risk Priority Score are marked <code>unknown</code> and dropped from the multiplication. Click <i>Sync all feeds</i> or use the per-tile <i>Sync</i> button to populate each cache.
          </Typography>
        </Alert>
      )}

      {isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      ) : (
        <Grid container spacing={2}>
          {feeds.map((feed) => (
            <Grid key={feed.id} size={{ xs: 12, md: 6 }}>
              <FeedTile
                feed={feed}
                syncing={syncingId === feed.id || allSyncing}
                onSync={() => syncOne.mutate(feed.id)}
                lastResult={results[feed.id]}
              />
            </Grid>
          ))}
        </Grid>
      )}

      <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mt: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 700, mb: 1 }}>
            How sync works
          </Typography>
          <Box component="ul" sx={{ pl: 2.5, color: "rgba(255,255,255,0.75)", fontSize: 13, lineHeight: 1.7, m: 0 }}>
            <li><b>Auto-scheduled in the background</b> via APScheduler on the API process (EPSS/KEV daily, NVD every 6h, ATT&CK/CAPEC weekly). The "Sync" button on each tile still works for an immediate refresh — useful when an upstream feed has just published an update.</li>
            <li><b>Outbound HTTPS</b> to public feeds (FIRST.org, cisa.gov, nvd.nist.gov, github.com/mitre). No credentials required.</li>
            <li><b>Cached on disk</b> at <code>backend/data/</code> (and the <code>threat_library</code> table for ATT&CK/CAPEC) so a process restart doesn't require re-downloading.</li>
            <li><b>RPS picks up changes immediately</b> — every subsequent finding render uses the refreshed cache. No need to re-run scans.</li>
            <li><b>Wiz / CrowdStrike Spotlight reachability</b> is separate and live — it queries the provider per finding when configured via env vars.</li>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}
