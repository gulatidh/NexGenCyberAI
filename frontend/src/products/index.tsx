/**
 * Product definitions for Monitara v2.
 * Each product maps to a route prefix and a set of sub-nav items.
 */
import React from "react";
import {
  Radar, Assessment, BugReport, Shield, GppBad,
  PlaylistAddCheck, SmartToy, Psychology, TrendingUp,
  Security, FindInPage, Policy, LibraryAdd, Description,
  Hub, Search, MenuBook, VerifiedUser, AccountTree, DeviceHub,
  People, Storage, Cable, SyncAlt, Tune, Settings as SettingsIcon,
  Devices, HelpOutlined, AutoFixHigh,
} from "@mui/icons-material";
import { ProductDef } from "../components/layout/ProductLayout";

export const THREAT_INTEL: ProductDef = {
  name: "Threat Intelligence",
  abbrev: "TI",
  icon: <Radar />,
  color: "#1565C0",
  bgColor: "#E3F2FD",
  basePath: "/threat-intel",
  nav: [
    { label: "Threat Register",  icon: <Radar />,     path: "/register" },
    { label: "Threat Models",    icon: <DeviceHub />, path: "/threat-models" },
    { label: "Attack Paths",     icon: <Hub />,       path: "/attack-paths" },
  ],
};

export const RISK_MANAGER: ProductDef = {
  name: "Risk Manager",
  abbrev: "RM",
  icon: <Assessment />,
  color: "#1565C0",
  bgColor: "#E3F2FD",
  basePath: "/risk",
  nav: [
    { label: "Risk Overview", icon: <Assessment />, path: "/overview" },
    { label: "Risk Register", icon: <Security />, path: "/register" },
  ],
};

export const VULN_MGMT: ProductDef = {
  name: "Vulnerability Management",
  abbrev: "VM",
  icon: <BugReport />,
  color: "#00695C",
  bgColor: "#E0F2F1",
  basePath: "/vulnerability",
  nav: [
    { label: "Assessments", icon: <BugReport />, path: "/scans" },
    { label: "Findings", icon: <FindInPage />, path: "/findings" },
    { label: "Posture Trends", icon: <TrendingUp />, path: "/posture" },
  ],
};

export const PEN_TEST: ProductDef = {
  name: "Pen Testing",
  abbrev: "PT",
  icon: <Shield />,
  color: "#00695C",
  bgColor: "#E0F2F1",
  basePath: "/vapt",
  nav: [
    { label: "VAPT Reports", icon: <Description />, path: "/reports" },
  ],
};

export const COMPLIANCE_MONITOR: ProductDef = {
  name: "Compliance Monitor",
  abbrev: "CM",
  icon: <GppBad />,
  color: "#6A1B9A",
  bgColor: "#F3E5F5",
  basePath: "/compliance",
  nav: [
    { label: "Control Deficiencies", icon: <GppBad />, path: "/deficiencies" },
    { label: "Frameworks", icon: <Policy />, path: "/frameworks" },
    { label: "Custom Policy",    icon: <LibraryAdd />, path: "/custom-frameworks" },
    { label: "Evidence Package", icon: <VerifiedUser />, path: "/evidence" },
  ],
};

export const GOVERNANCE: ProductDef = {
  name: "Governance",
  abbrev: "GR",
  icon: <PlaylistAddCheck />,
  color: "#6A1B9A",
  bgColor: "#F3E5F5",
  basePath: "/governance",
  nav: [
    { label: "CTEM Programs", icon: <AccountTree />, path: "/ctem" },
    { label: "Remediation Tracker", icon: <PlaylistAddCheck />, path: "/remediation" },
    { label: "AI Remediations", icon: <AutoFixHigh />, path: "/remediation-jobs" },
  ],
};

export const AI_ADVISOR: ProductDef = {
  name: "AI Security Advisor",
  abbrev: "AI",
  icon: <SmartToy />,
  color: "#E65100",
  bgColor: "#FBE9E7",
  basePath: "/ai-advisor",
  nav: [
    { label: "AI Buddies", icon: <SmartToy />, path: "/agents" },
    { label: "Workflows", icon: <Hub />, path: "/workflows" },
  ],
};

export const INTELLIGENCE: ProductDef = {
  name: "Smart Intelligence",
  abbrev: "IG",
  icon: <Psychology />,
  color: "#E65100",
  bgColor: "#FBE9E7",
  basePath: "/intelligence",
  nav: [
    { label: "Ask Your Data", icon: <Search />, path: "/nl-query" },
    { label: "Security Docs", icon: <Description />, path: "/security-docs" },
    { label: "Reports", icon: <Assessment />, path: "/reports" },
    { label: "Knowledge Base", icon: <MenuBook />, path: "/knowledge" },
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
    { label: "Clients",              icon: <People />,        path: "/clients" },
    { label: "Assets",               icon: <Storage />,        path: "/assets" },
    { label: "Technology Inventory", icon: <Devices />,        path: "/assets/technologies" },
    { label: "Connections",          icon: <Cable />,          path: "/connections" },
    { label: "Ticket Sync",          icon: <SyncAlt />,        path: "/ticket-sync" },
    { label: "Settings",             icon: <SettingsIcon />,   path: "/settings" },
    { label: "Help",                 icon: <HelpOutlined />,    path: "/help" },
  ],
};

export const ALL_PRODUCTS = [
  THREAT_INTEL, RISK_MANAGER,
  VULN_MGMT, PEN_TEST,
  COMPLIANCE_MONITOR, GOVERNANCE,
  AI_ADVISOR, INTELLIGENCE,
  PLATFORM,
];
