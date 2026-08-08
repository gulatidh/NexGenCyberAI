import React from "react";
import { Outlet } from "react-router-dom";
import { Box } from "@mui/material";
import AssistantWidget from "../AssistantWidget";
import OwletLogo from "../OwletLogo";
import MegaMenuBar from "./MegaMenuBar";
import AppControls from "./AppControls";

export interface ProductNavItem {
  label: string;
  icon: React.ReactNode;
  path: string;
}

export interface ProductDef {
  name: string;
  abbrev: string;
  icon: React.ReactNode;
  color: string;
  bgColor: string;
  basePath: string;
  nav: ProductNavItem[];
}

interface Props {
  product: ProductDef;
}

export default function ProductLayout({ product }: Props) {
  return (
    <>
      <Box sx={{ display: "flex", flexDirection: "column", height: "100vh", bgcolor: "background.default" }}>

        {/* ── Top bar with mega menu ────────────────────────────────────── */}
        <Box sx={{
          height: 52, flexShrink: 0,
          bgcolor: "background.paper",
          borderBottom: "1px solid", borderColor: "divider",
          zIndex: 1200,
        }}>
          <MegaMenuBar
            brand={<OwletLogo height={30} />}
            trailing={<AppControls avatarColor={product.color} />}
          />
        </Box>

        {/* ── Main content — full width ─────────────────────────────────── */}
        <Box sx={{ flexGrow: 1, overflow: "auto", p: 3 }}>
          <Outlet />
        </Box>

      </Box>
      <AssistantWidget />
    </>
  );
}
