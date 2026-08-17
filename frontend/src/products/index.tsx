/**
 * Product definitions — top-level sections shown in MegaMenuBar.
 * nav items: no group → rendered at top (Overview); group → rendered under that section header.
 */
import React from "react";
import {
  Radar, Assessment, BugReport, Shield, GppBad,
  PlaylistAddCheck, SmartToy, TrendingUp,
  Security, FindInPage, Policy, Description,
  Hub, Search, MenuBook, AccountTree, DeviceHub,
  People, Storage, Cable, SyncAlt, Tune, Settings as SettingsIcon,
  Devices, HelpOutlined, AutoFixHigh, AltRoute, Psychology,
  GridView, FolderZip, LibraryAdd, Webhook, VpnKey,
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
    { label: "Overview",            icon: <GridView />,   path: "" },
    // Scanning
    { label: "Assessments",         icon: <BugReport />,  path: "/scans",        group: "Scanning" },
    { label: "Findings",            icon: <FindInPage />, path: "/findings",     group: "Scanning" },
    { label: "AI Assisted Scan",    icon: <SmartToy />,   path: "/ai-scan",      group: "Scanning" },
    { label: "Posture Trends",      icon: <TrendingUp />, path: "/posture",      group: "Scanning" },
    // Assets & CVE
    { label: "Asset Inventory",     icon: <Storage />,    path: "/assets",       group: "Assets & CVE" },
    { label: "Technologies",        icon: <Devices />,    path: "/technologies", group: "Assets & CVE" },
    { label: "CVE Blast Radius",    icon: <Radar />,      path: "/cve-pivot",    group: "Assets & CVE" },
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
    { label: "Overview",               icon: <GridView />,   path: "" },
    // Risk
    { label: "Risk Register",          icon: <Security />,   path: "/risks",               group: "Risk" },
    { label: "Risk Overview",          icon: <Assessment />, path: "/risk-overview",        group: "Risk" },
    { label: "AI Risk Analysis",       icon: <SmartToy />,   path: "/ai-analysis",          group: "Risk" },
    { label: "Attack Paths",           icon: <AltRoute />,   path: "/attack-paths",         group: "Risk" },
    // Intelligence
    { label: "AI Threat Intelligence", icon: <DeviceHub />,  path: "/threat-models",        group: "Intelligence" },
    { label: "Compliance Heatmap",     icon: <Policy />,     path: "/compliance-heatmap",   group: "Intelligence" },
    { label: "Ask Your Data",          icon: <Search />,     path: "/nl-query",             group: "Intelligence" },
    { label: "Comparison",             icon: <Assessment />, path: "/comparison",           group: "Intelligence" },
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
    { label: "Overview",          icon: <GridView />,         path: "" },
    // Threat Intelligence
    { label: "Threat Register",   icon: <Radar />,            path: "/threats",          group: "Threat Intelligence" },
    { label: "Control Gaps",      icon: <GppBad />,           path: "/gaps",             group: "Threat Intelligence" },
    { label: "CTEM Programs",     icon: <AccountTree />,      path: "/ctem",             group: "Threat Intelligence" },
    // Remediation
    { label: "Remediation",       icon: <PlaylistAddCheck />, path: "/remediation",      group: "Remediation" },
    { label: "AI Remediations",   icon: <AutoFixHigh />,      path: "/remediation-jobs", group: "Remediation" },
    { label: "VAPT Reports",      icon: <Description />,      path: "/vapt-reports",     group: "Remediation" },
    { label: "Security Docs",     icon: <MenuBook />,         path: "/security-docs",    group: "Remediation" },
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
    // AI Agents
    { label: "AI Buddies",     icon: <SmartToy />,   path: "/agents",       group: "AI Agents" },
    { label: "AI Workflows",   icon: <Hub />,        path: "/workflows",    group: "AI Agents" },
    { label: "AI Assisted Scan", icon: <BugReport />, path: "/ai-scan",     group: "AI Agents" },
    // Knowledge
    { label: "Knowledge Base", icon: <MenuBook />,   path: "/knowledge",    group: "Knowledge" },
    { label: "Reports",        icon: <Assessment />, path: "/reports",      group: "Knowledge" },
    { label: "Ask Your Data",  icon: <Search />,     path: "/nl-query",     group: "Knowledge" },
    { label: "AI Guardrails",  icon: <Shield />,     path: "/ai-guardrails",group: "Knowledge" },
    { label: "Webhooks",       icon: <Webhook />,    path: "/webhooks",     group: "Knowledge" },
    { label: "API Keys",       icon: <VpnKey />,     path: "/api-keys",     group: "Knowledge" },
  ],
};

export const REPORT_PRODUCT: ProductDef = {
  name: "Report",
  abbrev: "RP",
  icon: <Description />,
  color: "#15803d",
  bgColor: "#F0FDF4",
  basePath: "/report",
  nav: [
    { label: "Overview",           icon: <GridView />,    path: "" },
    // Pen Testing
    { label: "VAPT Reports",       icon: <Description />, path: "/vapt-reports",      group: "Pen Testing" },
    { label: "Evidence Package",   icon: <FolderZip />,   path: "/evidence",          group: "Pen Testing" },
    { label: "Reports",            icon: <Assessment />,  path: "/reports",           group: "Pen Testing" },
    // Compliance
    { label: "Frameworks",         icon: <Policy />,      path: "/frameworks",        group: "Compliance" },
    { label: "Custom Standards",   icon: <LibraryAdd />,  path: "/custom-frameworks", group: "Compliance" },
    { label: "Control Gaps",       icon: <GppBad />,      path: "/gaps",              group: "Compliance" },
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
    { label: "Overview",             icon: <GridView />,     path: "" },
    // Environment
    { label: "Accounts",             icon: <People />,       path: "/clients",              group: "Environment" },
    { label: "Asset Inventory",      icon: <Storage />,      path: "/assets",               group: "Environment" },
    { label: "Technology Inventory", icon: <Devices />,      path: "/assets/technologies",  group: "Environment" },
    { label: "Connectors",           icon: <Cable />,        path: "/connections",          group: "Environment" },
    { label: "Ticket Sync",          icon: <SyncAlt />,      path: "/ticket-sync",          group: "Environment" },
    // Design
    { label: "AI Settings",          icon: <SmartToy />,     path: "/ai-settings",          group: "Design" },
    { label: "Settings",             icon: <SettingsIcon />, path: "/settings",             group: "Design" },
    { label: "Help",                 icon: <HelpOutlined />, path: "/help",                 group: "Design" },
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
