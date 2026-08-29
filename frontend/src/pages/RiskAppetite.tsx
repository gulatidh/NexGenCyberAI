import React, { useState, useCallback } from "react";
import {
  Box, Typography, Card, CardContent, Grid, Slider, Button, Alert, Divider, Chip,
} from "@mui/material";
import { Tune, Save } from "@mui/icons-material";

const STORAGE_KEY = "aegis-risk-appetite";

const DIMENSIONS = [
  {
    key: "financial",
    label: "Financial Impact Tolerance",
    desc: "Maximum acceptable financial loss from a single risk event.",
    marks: [
      { value: 1, label: "< $10K" },
      { value: 2, label: "$10K–$100K" },
      { value: 3, label: "$100K–$1M" },
      { value: 4, label: "$1M–$10M" },
      { value: 5, label: "> $10M" },
    ],
  },
  {
    key: "operational",
    label: "Operational Disruption Tolerance",
    desc: "Acceptable downtime or business process interruption threshold.",
    marks: [
      { value: 1, label: "< 1 hour" },
      { value: 2, label: "1–8 hours" },
      { value: 3, label: "8–24 hours" },
      { value: 4, label: "1–7 days" },
      { value: 5, label: "> 7 days" },
    ],
  },
  {
    key: "reputational",
    label: "Reputational Risk Tolerance",
    desc: "Acceptable level of public exposure or brand damage.",
    marks: [
      { value: 1, label: "None" },
      { value: 2, label: "Minimal" },
      { value: 3, label: "Moderate" },
      { value: 4, label: "Significant" },
      { value: 5, label: "Severe" },
    ],
  },
  {
    key: "compliance",
    label: "Compliance Deviation Tolerance",
    desc: "Acceptable gap from full compliance with applicable frameworks.",
    marks: [
      { value: 1, label: "Zero tolerance" },
      { value: 2, label: "Minor gaps" },
      { value: 3, label: "Partial gaps" },
      { value: 4, label: "Significant gaps" },
      { value: 5, label: "Unconstrained" },
    ],
  },
];

function loadAppetite(): Record<string, number> {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}"); } catch { return {}; }
}

const MATRIX_LABELS: Record<number, { label: string; color: string }> = {
  1:  { label: "Very Low",  color: "#34A853" },
  2:  { label: "Low",       color: "#81C784" },
  3:  { label: "Moderate",  color: "#FBBC04" },
  4:  { label: "High",      color: "#FF7043" },
  5:  { label: "Very High", color: "#EA4335" },
};

function MatrixCell({ consequence, likelihood, threshold }: { consequence: number; likelihood: number; threshold: number }) {
  const score = consequence * likelihood;
  const fill =
    score <= 4  ? "#34A853" :
    score <= 9  ? "#FBBC04" :
    score <= 15 ? "#FF7043" :
                  "#EA4335";
  const isThreshold = consequence === threshold || likelihood === threshold;
  return (
    <Box sx={{ width: 40, height: 40, bgcolor: fill + "33", border: isThreshold ? `2px solid ${fill}` : "1px solid rgba(255,255,255,0.08)",
      display: "flex", alignItems: "center", justifyContent: "center", borderRadius: 0.5, flexShrink: 0 }}>
      <Typography variant="caption" sx={{ fontWeight: 700, color: fill, fontSize: 11 }}>{score}</Typography>
    </Box>
  );
}

export default function RiskAppetite() {
  const [values, setValues] = useState<Record<string, number>>(() => {
    const saved = loadAppetite();
    const defaults: Record<string, number> = {};
    DIMENSIONS.forEach(d => { defaults[d.key] = saved[d.key] ?? 3; });
    return defaults;
  });
  const [saved, setSaved] = useState(false);

  const avgThreshold = Math.round(Object.values(values).reduce((a, b) => a + b, 0) / DIMENSIONS.length);

  const handleSave = useCallback(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(values));
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  }, [values]);

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Risk Appetite</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
            Configure organisation risk tolerance bands for the 5×5 GCC IM8 matrix.
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<Save />} size="small" onClick={handleSave}
          sx={{ bgcolor: "#4285F4", "&:hover": { bgcolor: "#3367D6" } }}>
          Save Preferences
        </Button>
      </Box>

      {saved && <Alert severity="success" sx={{ mb: 3, borderRadius: 2 }}>Risk appetite preferences saved.</Alert>}

      <Grid container spacing={2}>
        {/* Sliders */}
        <Grid size={{ xs: 12, md: 7 }}>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
                <Tune sx={{ color: "#4285F4" }} />
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Tolerance Settings</Typography>
              </Box>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {DIMENSIONS.map(dim => {
                  const v = values[dim.key];
                  const info = MATRIX_LABELS[v];
                  return (
                    <Box key={dim.key}>
                      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
                        <Typography variant="body2" sx={{ fontWeight: 700 }}>{dim.label}</Typography>
                        <Chip label={info.label} size="small"
                          sx={{ bgcolor: info.color + "22", color: info.color, fontWeight: 700, fontSize: 11 }} />
                      </Box>
                      <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.5 }}>
                        {dim.desc}
                      </Typography>
                      <Slider
                        value={v}
                        min={1} max={5} step={1}
                        marks={dim.marks}
                        onChange={(_, val) => setValues(prev => ({ ...prev, [dim.key]: val as number }))}
                        sx={{
                          color: info.color,
                          "& .MuiSlider-mark": { bgcolor: "rgba(255,255,255,0.2)" },
                          "& .MuiSlider-markLabel": { fontSize: 10, color: "text.secondary" },
                        }}
                      />
                    </Box>
                  );
                })}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Live matrix preview */}
        <Grid size={{ xs: 12, md: 5 }}>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>5×5 Matrix Preview</Typography>
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 2 }}>
                Tolerance level {avgThreshold} — cells at or above this band are in your accepted risk zone.
              </Typography>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5, alignItems: "flex-start" }}>
                {[5, 4, 3, 2, 1].map(consequence => (
                  <Box key={consequence} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                    <Typography variant="caption" sx={{ color: "text.secondary", width: 12, textAlign: "right", flexShrink: 0 }}>{consequence}</Typography>
                    {[1, 2, 3, 4, 5].map(likelihood => (
                      <MatrixCell key={likelihood} consequence={consequence} likelihood={likelihood} threshold={avgThreshold} />
                    ))}
                  </Box>
                ))}
                <Box sx={{ display: "flex", gap: 0.5, mt: 0.5, ml: "20px" }}>
                  {[1, 2, 3, 4, 5].map(l => (
                    <Box key={l} sx={{ width: 40, textAlign: "center" }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>{l}</Typography>
                    </Box>
                  ))}
                </Box>
                <Box sx={{ ml: "20px", mt: 0.5 }}>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>← Likelihood →</Typography>
                </Box>
              </Box>

              <Divider sx={{ my: 2, borderColor: "rgba(255,255,255,0.08)" }} />
              <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75 }}>
                {[
                  { range: "1–4",   label: "Low",           color: "#34A853" },
                  { range: "5–9",   label: "Medium",        color: "#FBBC04" },
                  { range: "10–15", label: "Medium-High",   color: "#FF7043" },
                  { range: "16–25", label: "High–Critical", color: "#EA4335" },
                ].map(band => (
                  <Box key={band.range} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <Box sx={{ width: 14, height: 14, bgcolor: band.color + "33", border: `1.5px solid ${band.color}`, borderRadius: 0.5, flexShrink: 0 }} />
                    <Typography variant="caption">{band.range} — {band.label}</Typography>
                  </Box>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
