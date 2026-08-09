import { Box, Typography } from "@mui/material";

interface Stat {
  label: string;
  value: number | string;
  color: string;
  sub?: string;
}

export default function StatRow({ stats, sx }: { stats: Stat[]; sx?: object }) {
  return (
    <Box sx={{ display: "flex", gap: 1.5, flexWrap: "wrap", mb: 3, ...sx }}>
      {stats.map((s) => (
        <Box
          key={s.label}
          sx={{
            bgcolor: "background.paper",
            border: "1px solid", borderColor: "divider",
            borderRadius: 2, px: 2.5, py: 1.5,
            display: "flex", flexDirection: "column", gap: 0.25, minWidth: 100,
          }}
        >
          <Typography sx={{ fontSize: 22, fontWeight: 800, color: s.color, lineHeight: 1 }}>
            {s.value ?? 0}
          </Typography>
          <Typography sx={{ fontSize: 11, color: "text.secondary", fontWeight: 500 }}>
            {s.label}
          </Typography>
          {s.sub && (
            <Typography sx={{ fontSize: 10, color: s.color, fontWeight: 600 }}>{s.sub}</Typography>
          )}
        </Box>
      ))}
    </Box>
  );
}

// V3 page title — Space Grotesk + colour bar. Drop-in for <Typography variant="h5">
export function PageTitle({ title, description, color }: { title: string; description: string; color: string }) {
  return (
    <>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
        <Box sx={{ width: 3, height: 20, borderRadius: 2, bgcolor: color, flexShrink: 0 }} />
        <Typography sx={{
          fontFamily: "'Space Grotesk', sans-serif",
          fontSize: 22, fontWeight: 700, letterSpacing: "-0.02em",
        }}>
          {title}
        </Typography>
      </Box>
      <Typography sx={{ color: "text.secondary", fontSize: 13, pl: "11px" }}>
        {description}
      </Typography>
    </>
  );
}
