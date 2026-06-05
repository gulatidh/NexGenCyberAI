/**
 * Clickable CAPEC / ATT&CK chip with a lazy-fetched description tooltip.
 *
 * The chip itself is rendered like the inline chips on the Threat Model
 * detail page. On hover (after a short delay) it fetches the entry from
 * `GET /threat-models/library/{source}/{source_id}` and shows
 * `name + short description + CWEs` inside a Tooltip body.
 *
 * If the entry isn't in the cache (sync hasn't run yet) the chip still
 * renders, the tooltip just shows a "run Sync" hint.
 */
import React, { useState } from "react";
import { Box, Chip, CircularProgress, Tooltip, Typography } from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { threatModelsApi } from "../services/api";

interface Props {
  source: "capec" | "attack";
  sourceId: string;
  label?: string;
  sx?: any;
}

interface LibraryEntry {
  source: string;
  source_id: string;
  name?: string | null;
  description?: string | null;
  category?: string | null;
  severity_default?: string | null;
  mitigation_hint?: string | null;
  related_cwes?: string[];
  extra?: Record<string, any>;
}

export default function ThreatLibraryChip({ source, sourceId, label, sx }: Props) {
  const [open, setOpen] = useState(false);

  const { data, isLoading, error } = useQuery<LibraryEntry>({
    queryKey: ["threat-library", source, sourceId],
    queryFn: () => threatModelsApi.libraryEntry(source, sourceId),
    enabled: open,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });

  const tooltipBody = (
    <Box sx={{ minWidth: 220, maxWidth: 360, p: 0.5 }}>
      {isLoading && (
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <CircularProgress size={12} sx={{ color: "#4285F4" }} />
          <Typography variant="caption">Loading {sourceId}…</Typography>
        </Box>
      )}
      {error && (
        <Typography variant="caption" sx={{ color: "#FBBC04" }}>
          {sourceId} not cached. Run <b>Settings → Sync → {source === "capec" ? "MITRE CAPEC" : "MITRE ATT&CK"}</b> to populate.
        </Typography>
      )}
      {data && (
        <>
          <Typography sx={{ fontSize: 12, fontWeight: 700, mb: 0.5 }}>
            {data.source_id} · {data.name}
          </Typography>
          {data.category && (
            <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5, textTransform: "capitalize" }}>
              {data.category.replace(/_/g, " ")}
            </Typography>
          )}
          {data.description && (
            <Typography variant="caption" sx={{ display: "block", color: "text.secondary", lineHeight: 1.4, mb: 0.5 }}>
              {data.description.length > 320
                ? `${data.description.slice(0, 320)}…`
                : data.description}
            </Typography>
          )}
          {!!(data.related_cwes && data.related_cwes.length) && (
            <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
              CWEs: {data.related_cwes.join(", ")}
            </Typography>
          )}
        </>
      )}
    </Box>
  );

  return (
    <Tooltip
      title={tooltipBody}
      enterDelay={250}
      onOpen={() => setOpen(true)}
      placement="top"
      arrow
    >
      <Chip
        label={label || sourceId}
        size="small"
        sx={{
          height: 16, fontSize: 9.5, cursor: "help",
          ...(source === "capec"
            ? { bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }
            : { bgcolor: "rgba(124,77,255,0.15)", color: "#9C27B0" }),
          ...sx,
        }}
      />
    </Tooltip>
  );
}
