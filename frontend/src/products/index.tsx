/**
 * Product definitions — 5 top-level sections shown in MegaMenuBar.
 */
import React from "react";
import {
  Radar, Assessment, BugReport, Shield, GppBad,
  PlaylistAddCheck, SmartToy, TrendingUp,
  Security, FindInPage, Policy, Description,
  Hub, Search, MenuBook, AccountTree, DeviceHub,
  People, Storage, Cable, SyncAlt, Tune, Settings as SettingsIcon,
  Devices, HelpOutlined, AutoFixHigh, AltRoute, Psychology,
  GridView,
} from "@mui/icons-material";
import { ProductDef } from "../components/layout/ProductLayout";

export const DISCOVER_PRODUCT: ProductDef = {
  name: "Discover",
  abbrev: "DC",
  icon: <BugReport />,
  color: "#0f766e",
  bgColor: "#ECFDF5",
  basePath: "/discover",
  nav: [
    { label: "Overview",       icon: <GridView />,   path: "" },
    { label: "Assessments",    icon: <BugReport />,  path: "/scans" },
    { label: "Findings",       icon: <FindInPage />, path: "/findings" },
    { label: "Assets",         icon: <Storage />,    path: "/assets" },
    { label: "Technologies",   icon: <Devices />,    path: "/technologies" },
    { label: "AI Scan",        icon: <SmartToy />,   path: "/ai-scan" },
    { label: "CVE Blast",      icon: <Radar />,      path: "/cve-pivot" },
    { label: "Posture Trends", icon: <TrendingUp />, path: "/posture" },
  ],
};

export const ANALYSE_PRODUCT: ProductDef = {
  name: "Analyse",
  abbrev: "AN",
  icon: <Assessment />,
  color: "#b45309",
  bgColor: "#FFFBEB",
  basePath: "/analyse",
  nav: [
    { label: "Overview",      icon: <GridView />,   path: "" },
    { label: "Risk Register", icon: <Security />,   path: "/risks" },
    { label: "Risk Overview", icon: <Assessment />, path: "/risk-overview" },
    { label: "AI Risk",       icon: <SmartToy />,   path: "/ai-analysis" },
    { label: "Attack Paths",  icon: <AltRoute />,   path: "/attack-paths" },
    { label: "AI Threat Intelligence", icon: <DeviceHub />,  path: "/threat-models" },
    { label: "Compliance Heatmap",    icon: <Policy />,     path: "/compliance-heatmap" },
    { label: "Ask Your Data", icon: <Search />,     path: "/nl-query" },
  ],
};

export const RESPOND_PRODUCT: ProductDef = {
  name: "Respond",
  abbrev: "RE",
  icon: <Shield />,
  color: "#b91c1c",
  bgColor: "#FEF2F2",
  basePath: "/respond",
  nav: [
    { label: "Overview",        icon: <GridView />,         path: "" },
    { label: "Threat Intel",    icon: <Radar />,            path: "/threats" },
    { label: "Control Gaps",    icon: <GppBad />,           path: "/gaps" },
    { label: "Remediation",     icon: <PlaylistAddCheck />, path: "/remediation" },
    { label: "AI Remediations", icon: <AutoFixHigh />,      path: "/remediation-jobs" },
    { label: "CTEM",            icon: <AccountTree />,      path: "/ctem" },
    { label: "VAPT Reports",    icon: <Description />,      path: "/vapt-reports" },
    { label: "Security Docs",   icon: <MenuBook />,         path: "/security-docs" },
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
    { label: "Overview",       icon: <GridView />,   path: "" },
    { label: "AI Buddies",     icon: <SmartToy />,   path: "/agents" },
    { label: "AI Workflows",   icon: <Hub />,        path: "/workflows" },
    { label: "Reports",        icon: <Assessment />, path: "/reports" },
    { label: "Knowledge Base", icon: <MenuBook />,   path: "/knowledge" },
    { label: "AI Guardrails",  icon: <Shield />,     path: "/ai-guardrails" },
  ],
};

export const PLATFORM: ProductDef = {
  name: "Setup",
  abbrev: "ST",
  icon: <Tune />,
  color: "#37474F",
  bgColor: "#ECEFF1",
  basePath: "/platform",
  nav: [
    { label: "Overview",             icon: <GridView />,    path: "" },
    { label: "Accounts",             icon: <People />,      path: "/clients" },
    { label: "Assets",               icon: <Storage />,     path: "/assets" },
    { label: "Technology Inventory", icon: <Devices />,     path: "/assets/technologies" },
    { label: "Connectors",           icon: <Cable />,       path: "/connections" },
    { label: "Ticket Sync",          icon: <SyncAlt />,     path: "/ticket-sync" },
    { label: "Settings",             icon: <SettingsIcon />,path: "/settings" },
    { label: "Help",                 icon: <HelpOutlined />,path: "/help" },
  ],
};

export const ALL_PRODUCTS = [
  PLATFORM,
  DISCOVER_PRODUCT,
  ANALYSE_PRODUCT,
  RESPOND_PRODUCT,
  AUTOMATE_PRODUCT,
];
