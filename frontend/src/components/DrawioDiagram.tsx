/**
 * Embedded diagrams.net viewer for threat-model DFDs.
 *
 * The backend renders `components` + `data_flows` as mxGraph XML via
 * `services/drawio_renderer.py`. This component takes that XML, loads
 * the diagrams.net embed iframe, and posts the XML in via the embed
 * protocol's `load` action.
 *
 * Listens for the iframe's `init` event before posting — racing the
 * load message early causes diagrams.net to silently drop it.
 */
import React, { useEffect, useRef, useState } from "react";
import { Box, CircularProgress, Typography } from "@mui/material";
import { Warning } from "@mui/icons-material";

const EMBED_BASE =
  "https://embed.diagrams.net/?embed=1&proto=json&spin=0" +
  "&saveAndExit=0&noSaveBtn=1&noExitBtn=1&toolbar=zoom%20pages";

const PROVIDER_LIBS: Record<string, string> = {
  aws:     "aws4;general",
  azure:   "azure2;general",
  gcp:     "gcp2;general",
  on_prem: "cisco;network;general",
  generic: "general",
};

function embedUrl(cloudProvider?: string): string {
  const libs = PROVIDER_LIBS[cloudProvider || "generic"] ?? "general";
  return `${EMBED_BASE}&ui=dark&libraries=1&libs=${encodeURIComponent(libs)}`;
}

interface Props {
  xml: string;
  className?: string;
  height?: number | string;
  cloudProvider?: string;
}

export default function DrawioDiagram({ xml, className, height = 620, cloudProvider }: Props) {
  const EMBED_URL = embedUrl(cloudProvider);
  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!xml) {
      setError("No diagram XML to render.");
      return;
    }
    setError(null);
    setLoaded(false);

    function handleMessage(ev: MessageEvent) {
      const iframe = iframeRef.current;
      if (!iframe || !iframe.contentWindow) return;
      if (ev.source !== iframe.contentWindow) return;
      try {
        const msg = typeof ev.data === "string" ? JSON.parse(ev.data) : ev.data;
        if (!msg || typeof msg !== "object") return;
        if (msg.event === "init") {
          iframe.contentWindow.postMessage(
            JSON.stringify({ action: "load", xml, autosave: 0 }),
            "*",
          );
          setLoaded(true);
        }
      } catch {
        // diagrams.net sometimes posts non-JSON pings; ignore
      }
    }

    window.addEventListener("message", handleMessage);
    return () => window.removeEventListener("message", handleMessage);
  }, [xml]);

  if (error) {
    return (
      <Box className={className} sx={{
        display: "flex", alignItems: "center", justifyContent: "center", gap: 1,
        p: 4, border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 2,
        color: "text.secondary",
      }}>
        <Warning sx={{ fontSize: 24 }} />
        <Typography variant="body2">{error}</Typography>
      </Box>
    );
  }

  return (
    <Box
      className={className}
      sx={{
        position: "relative",
        border: "1px solid rgba(255,255,255,0.06)",
        borderRadius: 2,
        overflow: "hidden",
        bgcolor: "background.paper",
      }}
    >
      {!loaded && (
        <Box sx={{
          position: "absolute", inset: 0, display: "flex", alignItems: "center",
          justifyContent: "center", zIndex: 1, color: "text.secondary",
          gap: 1.5,
        }}>
          <CircularProgress size={20} sx={{ color: "#4285F4" }} />
          <Typography variant="body2">Loading draw.io viewer…</Typography>
        </Box>
      )}
      <iframe
        ref={iframeRef}
        src={EMBED_URL}
        title="Threat Model DFD (draw.io)"
        style={{
          width: "100%",
          height: typeof height === "number" ? `${height}px` : height,
          border: 0,
          display: "block",
        }}
      />
    </Box>
  );
}
