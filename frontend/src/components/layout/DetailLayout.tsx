/**
 * DetailLayout — thin chrome for detail pages.
 * Just top bar (MegaMenuBar) + full-height content, no product sidebar.
 * PageDetailLayout inside the Outlet provides its own inner tab sidebar.
 */
import React from "react";
import { Outlet } from "react-router-dom";
import { Box } from "@mui/material";
import MegaMenuBar from "./MegaMenuBar";
import AppControls from "./AppControls";
import OwletLogo from "../OwletLogo";
import AssistantWidget from "../AssistantWidget";

interface Props { color?: string; }

export default function DetailLayout({ color = "#4285F4" }: Props) {
  return (
    <>
      <Box sx={{ display: "flex", flexDirection: "column", height: "100vh", bgcolor: "background.default" }}>
        <Box sx={{
          height: 52, flexShrink: 0,
          bgcolor: "background.paper",
          borderBottom: "1px solid", borderColor: "divider",
          zIndex: 1200,
        }}>
          <MegaMenuBar brand={<OwletLogo height={30} />} trailing={<AppControls avatarColor={color} />} />
        </Box>
        <Box sx={{ flexGrow: 1, overflow: "auto" }}>
          <Outlet />
        </Box>
      </Box>
      <AssistantWidget />
    </>
  );
}
