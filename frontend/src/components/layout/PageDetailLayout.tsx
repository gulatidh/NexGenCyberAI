/**
 * PageDetailLayout — reusable two-panel layout for detail pages.
 *
 * Left panel (220px): mini sidebar with entity header + nav items.
 * Right panel (flex 1): scrollable content area.
 *
 * Usage:
 *   <PageDetailLayout
 *     entityName="My Scan"
 *     entityType="Assessment"
 *     navItems={NAV_ITEMS}
 *     activeId={tab}
 *     onSelect={(id) => id === "help" ? navigate("/help") : setTab(id)}
 *   >
 *     {tab === "findings" && <FindingsContent />}
 *     ...
 *   </PageDetailLayout>
 */
import React from "react";
import { Box, Typography, Avatar, Divider, Chip, useTheme } from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";

export interface DetailNavItem {
  id: string;
  label: string;
  Icon: SvgIconComponent;
  color: string;
  badge?: number | string;
}

interface Props {
  entityName: string;
  entityType: string;
  avatarColor?: string;
  navItems: DetailNavItem[];
  activeId: string;
  onSelect: (id: string) => void;
  children: React.ReactNode;
  /** If true (e.g. print mode), skip the sidebar so content renders full-width */
  fullWidth?: boolean;
}

export default function PageDetailLayout({
  entityName, entityType, avatarColor = "#4285F4",
  navItems, activeId, onSelect, children, fullWidth = false,
}: Props) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const sidebarBg  = isDark ? "#0F1825" : "#F0F4FA";
  const activeBase = isDark ? "rgba(66,133,244,0.10)" : "rgba(26,115,232,0.08)";

  if (fullWidth) {
    return <>{children}</>;
  }

  return (
    <Box sx={{ display: "flex", minHeight: "calc(100vh - 112px)", bgcolor: "background.default" }}>
      {/* ── Left mini sidebar ──────────────────────────────────────── */}
      <Box sx={{
        width: 220, flexShrink: 0,
        bgcolor: sidebarBg,
        borderRight: "1px solid", borderColor: "divider",
        display: "flex", flexDirection: "column",
        position: "sticky", top: 0, alignSelf: "flex-start",
        maxHeight: "calc(100vh - 112px)", overflowY: "auto",
      }}>
        {/* Entity mini-header */}
        <Box sx={{ p: 2, display: "flex", alignItems: "center", gap: 1.5 }}>
          <Avatar sx={{
            bgcolor: avatarColor, width: 34, height: 34,
            fontSize: 15, fontWeight: 700, borderRadius: 1.5, flexShrink: 0,
          }}>
            {entityName.charAt(0).toUpperCase()}
          </Avatar>
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="body2" sx={{
              fontWeight: 700, lineHeight: 1.2,
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}>
              {entityName}
            </Typography>
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>
              {entityType}
            </Typography>
          </Box>
        </Box>
        <Divider />

        {/* Nav items */}
        <Box sx={{ pt: 0.5, pb: 2 }}>
          {navItems.map(({ id, label, Icon, color, badge }) => {
            const isActive = activeId === id;
            return (
              <Box
                key={id}
                onClick={() => onSelect(id)}
                sx={{
                  display: "flex", alignItems: "center", gap: 1.5,
                  px: 2, py: 1.25, cursor: "pointer",
                  borderLeft: "3px solid",
                  borderColor: isActive ? color : "transparent",
                  bgcolor: isActive ? `${color}12` : "transparent",
                  "&:hover": {
                    bgcolor: isActive ? `${color}12`
                      : isDark ? "rgba(255,255,255,0.04)" : "rgba(0,0,0,0.04)",
                  },
                  transition: "all .12s ease",
                }}
              >
                <Box sx={{
                  display: "flex", alignItems: "center", justifyContent: "center",
                  flexShrink: 0,
                }}>
                  <Icon sx={{ fontSize: 17, color }} />
                </Box>
                <Typography variant="body2" sx={{
                  flex: 1, fontSize: 13,
                  color: isActive ? "text.primary" : "text.secondary",
                  fontWeight: isActive ? 600 : 400,
                }}>
                  {label}
                </Typography>
                {badge !== undefined && badge !== 0 && (
                  <Chip
                    label={badge}
                    size="small"
                    sx={{
                      height: 18, fontSize: 10, minWidth: 24,
                      bgcolor: isActive ? `${color}22`
                        : isDark ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.06)",
                      color: isActive ? color : "text.secondary",
                    }}
                  />
                )}
              </Box>
            );
          })}
        </Box>
      </Box>

      {/* ── Right content panel ────────────────────────────────────── */}
      <Box sx={{ flex: 1, overflow: "auto", p: 3 }}>
        {children}
      </Box>
    </Box>
  );
}
