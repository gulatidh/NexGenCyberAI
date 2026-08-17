/**
 * Product definitions — top-level sections shown in MegaMenuBar.
 *
 * Single source of truth: nav items are auto-derived from each section page's
 * card list via navFromCards(). Adding a card to a section page automatically
 * adds it to the sidebar — no separate update needed here.
 */
import React from "react";
import { GridView, Psychology } from "@mui/icons-material";
import { ProductDef, ProductNavItem } from "../components/layout/ProductLayout";
import { CardDef } from "../components/SectionPage";
import { SETUP_SECTION } from "../pages/SetupPage";
import { DISCOVER_SECTION } from "../pages/DiscoverPage";
import { ANALYSE_SECTION } from "../pages/AnalysePage";
import { RESPOND_SECTION } from "../pages/RespondPage";
import { REPORT_SECTION } from "../pages/ReportPage";
import { AUTOMATE_SECTION } from "../pages/AutomatePage";

// Converts a section's card list into sidebar nav items.
// Routes that don't start with basePath are treated as absolute cross-section links.
function navFromCards(cards: CardDef[], basePath: string): ProductNavItem[] {
  return cards.map(card => {
    const isAbsolute = !card.route.startsWith(basePath);
    const path = isAbsolute ? card.route : card.route.slice(basePath.length) || "";
    return {
      label: card.name,
      icon: card.icon ?? <GridView />,
      path,
      ...(card.group ? { group: card.group } : {}),
      ...(isAbsolute ? { absolute: true as const } : {}),
    };
  });
}

export const PLATFORM: ProductDef = {
  name: "Setup",
  abbrev: "ST",
  icon: <GridView />,
  color: "#2563eb",
  bgColor: "#EFF6FF",
  basePath: "/platform",
  nav: [
    { label: "Overview", icon: <GridView />, path: "" },
    ...navFromCards(SETUP_SECTION.cards, "/platform"),
  ],
};

export const DISCOVER_PRODUCT: ProductDef = {
  name: "Discover",
  abbrev: "DC",
  icon: <GridView />,
  color: "#0f766e",
  bgColor: "#ECFDF5",
  basePath: "/discover",
  nav: [
    { label: "Overview", icon: <GridView />, path: "" },
    ...navFromCards(DISCOVER_SECTION.cards, "/discover"),
  ],
};

export const ANALYSE_PRODUCT: ProductDef = {
  name: "Analyse",
  abbrev: "AN",
  icon: <GridView />,
  color: "#b45309",
  bgColor: "#FFFBEB",
  basePath: "/analyse",
  nav: [
    { label: "Overview", icon: <GridView />, path: "" },
    ...navFromCards(ANALYSE_SECTION.cards, "/analyse"),
  ],
};

export const RESPOND_PRODUCT: ProductDef = {
  name: "Respond",
  abbrev: "RE",
  icon: <GridView />,
  color: "#b91c1c",
  bgColor: "#FEF2F2",
  basePath: "/respond",
  nav: [
    { label: "Overview", icon: <GridView />, path: "" },
    ...navFromCards(RESPOND_SECTION.cards, "/respond"),
  ],
};

export const REPORT_PRODUCT: ProductDef = {
  name: "Report",
  abbrev: "RP",
  icon: <GridView />,
  color: "#15803d",
  bgColor: "#F0FDF4",
  basePath: "/report",
  nav: [
    { label: "Overview", icon: <GridView />, path: "" },
    ...navFromCards(REPORT_SECTION.cards, "/report"),
  ],
};

export const AUTOMATE_PRODUCT: ProductDef = {
  name: "Automate",
  abbrev: "AT",
  icon: <Psychology />,
  color: "#4338ca",
  bgColor: "#EEF2FF",
  basePath: "/automate",
  nav: [
    { label: "Overview", icon: <GridView />, path: "" },
    ...navFromCards(AUTOMATE_SECTION.cards, "/automate"),
  ],
};

export const ALL_PRODUCTS = [
  PLATFORM,
  REPORT_PRODUCT,
  DISCOVER_PRODUCT,
  ANALYSE_PRODUCT,
  RESPOND_PRODUCT,
  AUTOMATE_PRODUCT,
];
