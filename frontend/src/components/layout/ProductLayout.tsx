import React from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { Box, Typography } from "@mui/material";
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
  const navigate = useNavigate();
  const { pathname } = useLocation();

  // product.nav paths are relative to basePath (e.g. "/scans" → "/vulnerability/scans")
  const fullPath = (rel: string) => product.basePath + rel;
  const isActive = (rel: string) => {
    const fp = fullPath(rel);
    return pathname === fp || pathname.startsWith(fp + "/");
  };

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

        {/* ── Content row: section mini-nav + page content ─────────────── */}
        <Box sx={{ display: "flex", flexGrow: 1, overflow: "hidden" }}>

          {/* Section mini-nav (same visual pattern as AppLayout + PageDetailLayout) */}
          {product.nav.length > 0 && (
            <Box sx={{
              width: 178, flexShrink: 0,
              bgcolor: (theme) => theme.palette.mode !== "light" ? "#0F1825" : "#F0F4FA",
              borderRight: "1px solid", borderColor: "divider",
              display: "flex", flexDirection: "column",
              overflowY: "auto",
            }}>
              {/* Product/section label */}
              <Box sx={{ px: 2, py: 1.5, borderBottom: "1px solid", borderColor: "divider" }}>
                <Box sx={{
                  display: "inline-flex", alignItems: "center", gap: 0.75,
                  px: 1.25, py: 0.5, borderRadius: 1,
                  bgcolor: `${product.color}22`,
                }}>
                  <Box sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: product.color }} />
                  <Typography sx={{
                    fontSize: 9.5, fontWeight: 700, letterSpacing: 0.8,
                    textTransform: "uppercase", color: product.color, lineHeight: 1,
                  }}>
                    {product.name}
                  </Typography>
                </Box>
              </Box>
              {/* Nav items */}
              <Box sx={{ pt: 0.5, pb: 2 }}>
                {product.nav.map(item => {
                  const active = isActive(item.path);
                  return (
                    <Box
                      key={item.path}
                      onClick={() => navigate(fullPath(item.path))}
                      sx={{
                        display: "flex", alignItems: "center", gap: 1.25,
                        px: 1.5, py: 1, cursor: "pointer",
                        borderLeft: "3px solid",
                        borderColor: active ? product.color : "transparent",
                        bgcolor: active ? `${product.color}12` : "transparent",
                        "&:hover": {
                          bgcolor: active ? `${product.color}12` : "rgba(128,128,128,0.06)",
                        },
                        transition: "all .12s ease",
                      }}
                    >
                      <Box sx={{
                        width: 26, height: 26, borderRadius: 1.25,
                        bgcolor: `${product.color}22`,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        flexShrink: 0,
                        color: product.color,
                        "& svg": { fontSize: "14px !important" },
                      }}>
                        {item.icon}
                      </Box>
                      <Typography sx={{
                        fontSize: 12.5,
                        color: active ? "text.primary" : "text.secondary",
                        fontWeight: active ? 600 : 400,
                        lineHeight: 1.3, flex: 1,
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                      }}>
                        {item.label}
                      </Typography>
                    </Box>
                  );
                })}
              </Box>
            </Box>
          )}

          {/* Page content */}
          <Box sx={{ flexGrow: 1, overflow: "auto", p: 3 }}>
            <Outlet />
          </Box>
        </Box>

      </Box>
      <AssistantWidget />
    </>
  );
}
