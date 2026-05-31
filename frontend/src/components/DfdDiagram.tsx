/**
 * Mermaid DFD renderer for threat-model diagrams.
 *
 * The threat-modeler service emits a `dfd_mermaid` string in `flowchart TD`
 * syntax. This component renders it to inline SVG. Mermaid is loaded once
 * lazily; subsequent renders just re-invoke `mermaid.render()`.
 *
 * Empty / invalid diagrams fall back to a small placeholder so the page
 * doesn't crash if the LLM returned a bad mermaid block.
 */
import React, { useEffect, useRef, useState } from "react";
import { Box, CircularProgress, Typography } from "@mui/material";
import { ImageNotSupported } from "@mui/icons-material";

let _mermaidInstance: any = null;
let _initPromise: Promise<any> | null = null;

async function loadMermaid(): Promise<any> {
  if (_mermaidInstance) return _mermaidInstance;
  if (!_initPromise) {
    _initPromise = (async () => {
      const m = (await import("mermaid")).default;
      m.initialize({
        startOnLoad: false,
        theme: "dark",
        themeVariables: {
          // Map onto our Google-vibrant palette so the diagram doesn't
          // clash with the rest of the UI.
          primaryColor: "#1E1E1E",
          primaryTextColor: "#FFFFFF",
          primaryBorderColor: "#4285F4",
          lineColor: "rgba(255,255,255,0.55)",
          tertiaryColor: "#161b22",
          background: "#1E1E1E",
          mainBkg: "#1E1E1E",
          clusterBkg: "rgba(66,133,244,0.06)",
          clusterBorder: "rgba(66,133,244,0.5)",
        },
        flowchart: {
          curve: "basis",
          htmlLabels: true,
          padding: 12,
        },
        securityLevel: "loose",
      });
      _mermaidInstance = m;
      return m;
    })();
  }
  return _initPromise;
}

interface Props {
  source: string;
  className?: string;
}

export default function DfdDiagram({ source, className }: Props) {
  const ref = useRef<HTMLDivElement | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function render() {
      if (!source || !source.trim()) {
        if (!cancelled) {
          setError("No diagram available — generator did not emit a DFD.");
          setLoading(false);
        }
        return;
      }
      try {
        setLoading(true);
        setError(null);
        const mermaid = await loadMermaid();
        const id = `dfd-${Math.random().toString(36).slice(2)}`;
        const { svg } = await mermaid.render(id, source);
        if (!cancelled && ref.current) {
          ref.current.innerHTML = svg;
          setLoading(false);
        }
      } catch (exc: any) {
        if (!cancelled) {
          setError(exc?.message || "Failed to render the diagram.");
          setLoading(false);
        }
      }
    }
    render();
    return () => { cancelled = true; };
  }, [source]);

  if (error) {
    return (
      <Box className={className} sx={{
        display: "flex", alignItems: "center", justifyContent: "center", gap: 1,
        p: 4, border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 2,
        color: "rgba(255,255,255,0.5)",
      }}>
        <ImageNotSupported sx={{ fontSize: 24 }} />
        <Typography variant="body2">{error}</Typography>
      </Box>
    );
  }

  return (
    <Box
      className={className}
      sx={{
        position: "relative", overflow: "auto",
        bgcolor: "#1E1E1E",
        borderRadius: 2,
        border: "1px solid rgba(255,255,255,0.06)",
        p: 2, minHeight: 200,
        "& svg": { maxWidth: "100%", height: "auto", display: "block", mx: "auto" },
        "& .nodeLabel, & .edgeLabel": { color: "white !important" },
        "& .cluster rect": { rx: 8, ry: 8 },
      }}
    >
      {loading && (
        <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
          <CircularProgress size={20} sx={{ color: "#4285F4" }} />
        </Box>
      )}
      <Box ref={ref} sx={{ display: loading ? "none" : "block" }} />
    </Box>
  );
}
