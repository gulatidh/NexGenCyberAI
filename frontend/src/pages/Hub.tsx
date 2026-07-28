import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, Card, CardActionArea, Avatar,
  List, ListItemButton, ListItemText, Divider,
  FormControl, Select, MenuItem, InputLabel,
} from "@mui/material";
import {
  Shield, BugReport, VerifiedUser, Psychology,
  Radar, Assessment, GppBad, PlaylistAddCheck,
  SmartToy, Search, MenuBook, TrendingUp, Cable, Settings,
} from "@mui/icons-material";
import { useMsal } from "@azure/msal-react";
import { useQuery } from "@tanstack/react-query";
import { adminApi, clientsApi } from "../services/api";
import { MyAccess, Client } from "../types";
import { useActiveClient } from "../contexts/ClientContext";

// ── Product catalogue ────────────────────────────────────────────────────────

interface Product {
  abbrev: string;
  name: string;
  description: string;
  route: string;
  icon: React.ReactNode;
  color: string;
  bgColor: string;
}

interface Category {
  id: string;
  label: string;
  color: string;
  products: Product[];
}

const CATEGORIES: Category[] = [
  {
    id: "threat-risk",
    label: "Threat & Risk",
    color: "#1565C0",
    products: [
      {
        abbrev: "TI",
        name: "Threat Intelligence",
        description: "MITRE ATT&CK mapped threats and attack path analysis",
        route: "/threat-intel",
        icon: <Radar />,
        color: "#1565C0",
        bgColor: "#E3F2FD",
      },
      {
        abbrev: "RM",
        name: "Risk Manager",
        description: "FAIR-scored risk register and ALE exposure dashboard",
        route: "/risk",
        icon: <Assessment />,
        color: "#1565C0",
        bgColor: "#E3F2FD",
      },
    ],
  },
  {
    id: "vulnerability",
    label: "Vulnerability",
    color: "#00695C",
    products: [
      {
        abbrev: "VM",
        name: "Vulnerability Management",
        description: "Scans, findings, posture trends, and scan import",
        route: "/vulnerability",
        icon: <BugReport />,
        color: "#00695C",
        bgColor: "#E0F2F1",
      },
      {
        abbrev: "PT",
        name: "Pen Testing",
        description: "VAPT reports with retest lifecycle and PDF/DOCX export",
        route: "/vapt",
        icon: <Shield />,
        color: "#00695C",
        bgColor: "#E0F2F1",
      },
    ],
  },
  {
    id: "compliance",
    label: "Compliance",
    color: "#6A1B9A",
    products: [
      {
        abbrev: "CM",
        name: "Compliance Monitor",
        description: "Framework control gaps, custom standards, and evidence packages",
        route: "/compliance",
        icon: <GppBad />,
        color: "#6A1B9A",
        bgColor: "#F3E5F5",
      },
      {
        abbrev: "GR",
        name: "Governance",
        description: "CTEM programs, remediation tracker, and security scorecard",
        route: "/governance",
        icon: <PlaylistAddCheck />,
        color: "#6A1B9A",
        bgColor: "#F3E5F5",
      },
    ],
  },
  {
    id: "ai-intelligence",
    label: "AI & Intelligence",
    color: "#E65100",
    products: [
      {
        abbrev: "AI",
        name: "AI Security Advisor",
        description: "AI agents, workflows, and 60+ advisory specialist catalog",
        route: "/ai-advisor",
        icon: <SmartToy />,
        color: "#E65100",
        bgColor: "#FBE9E7",
      },
      {
        abbrev: "IG",
        name: "Smart Intelligence",
        description: "Natural language queries, security doc RAG, and knowledge base",
        route: "/intelligence",
        icon: <Psychology />,
        color: "#E65100",
        bgColor: "#FBE9E7",
      },
    ],
  },
];

// ── Client picker ────────────────────────────────────────────────────────────

function ClientPicker() {
  const { clientId, setClientId } = useActiveClient();
  const { data: clients = [], isLoading } = useQuery<Client[]>({
    queryKey: ["clients"],
    queryFn: () => clientsApi.list(),
    staleTime: 60_000,
  });

  return (
    <Box sx={{ px: 1.5, py: 1 }}>
      <FormControl fullWidth size="small">
        <InputLabel sx={{ fontSize: 12 }}>Active Client</InputLabel>
        <Select
          label="Active Client"
          value={clientId || ""}
          onChange={(e) => setClientId(e.target.value as string)}
          disabled={isLoading || clients.length === 0}
          sx={{
            fontSize: 13,
            bgcolor: "background.default",
            "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" },
          }}
        >
          {clients.length === 0 && (
            <MenuItem value="" disabled>
              <em>{isLoading ? "Loading…" : "No clients yet"}</em>
            </MenuItem>
          )}
          {clients.map((c) => (
            <MenuItem key={c.id} value={c.id} sx={{ fontSize: 13 }}>{c.name}</MenuItem>
          ))}
        </Select>
      </FormControl>
    </Box>
  );
}

// ── Subcomponents ────────────────────────────────────────────────────────────

function ProductCard({ product }: { product: Product }) {
  const navigate = useNavigate();
  return (
    <Card
      elevation={0}
      sx={{
        border: "1px solid rgba(0,0,0,0.09)",
        borderRadius: 2,
        overflow: "hidden",
        transition: "box-shadow .18s ease, transform .18s ease",
        "&:hover": {
          boxShadow: "0 4px 20px rgba(0,0,0,0.12)",
          transform: "translateY(-2px)",
        },
      }}
    >
      <CardActionArea
        onClick={() => navigate(product.route)}
        sx={{ display: "flex", alignItems: "center", gap: 0, p: 0 }}
      >
        {/* Left icon block */}
        <Box sx={{
          width: 72, flexShrink: 0, alignSelf: "stretch",
          bgcolor: product.bgColor,
          display: "flex", flexDirection: "column",
          alignItems: "center", justifyContent: "center", gap: 0.5,
          borderRight: `1px solid rgba(0,0,0,0.06)`,
        }}>
          <Box sx={{ color: product.color, "& svg": { fontSize: 22 } }}>
            {product.icon}
          </Box>
          <Typography sx={{ fontSize: 11, fontWeight: 800, color: product.color, letterSpacing: 0.5 }}>
            {product.abbrev}
          </Typography>
        </Box>

        {/* Right text block */}
        <Box sx={{ px: 2, py: 1.5, flexGrow: 1, textAlign: "left" }}>
          <Typography sx={{ fontWeight: 700, fontSize: 14, color: "text.primary", lineHeight: 1.3, mb: 0.4 }}>
            {product.name}
          </Typography>
          <Typography sx={{ fontSize: 12, color: "text.secondary", lineHeight: 1.4 }}>
            {product.description}
          </Typography>
        </Box>
      </CardActionArea>
    </Card>
  );
}

function CategorySection({ category, active }: { category: Category; active: boolean }) {
  return (
    <Box id={`cat-${category.id}`} sx={{ mb: 4, scrollMarginTop: 24 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
        <Box sx={{ width: 4, height: 20, borderRadius: 2, bgcolor: category.color }} />
        <Typography sx={{ fontWeight: 700, fontSize: 15, color: "text.primary" }}>
          {category.label}
        </Typography>
      </Box>
      <Box sx={{
        display: "grid",
        gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr", lg: "1fr 1fr 1fr" },
        gap: 1.5,
      }}>
        {category.products.map((p) => (
          <ProductCard key={p.abbrev} product={p} />
        ))}
      </Box>
    </Box>
  );
}

// ── Main Hub page ─────────────────────────────────────────────────────────────

export default function Hub() {
  const { accounts } = useMsal();
  const [activeCategory, setActiveCategory] = useState("threat-risk");
  const { data: me } = useQuery<MyAccess>({
    queryKey: ["my-access"], queryFn: adminApi.me, retry: 0, staleTime: 60_000,
  });

  const displayName = accounts[0]?.name?.split(" ")[0]
    || accounts[0]?.username?.split("@")[0]
    || "there";

  const scrollTo = (id: string) => {
    setActiveCategory(id);
    document.getElementById(`cat-${id}`)?.scrollIntoView({ behavior: "smooth" });
  };

  const NAV_EXTRA = [
    { label: "Clients",            icon: <VerifiedUser sx={{ fontSize: 16 }} />, route: "/clients" },
    { label: "Connections",        icon: <Cable       sx={{ fontSize: 16 }} />, route: "/connections" },
    { label: "Reports",            icon: <TrendingUp  sx={{ fontSize: 16 }} />, route: "/reports" },
    { label: "Knowledge Base",     icon: <MenuBook    sx={{ fontSize: 16 }} />, route: "/knowledge" },
    { label: "Search Data",        icon: <Search      sx={{ fontSize: 16 }} />, route: "/intelligence/nl-query" },
    { label: "Settings",           icon: <Settings    sx={{ fontSize: 16 }} />, route: "/settings" },
  ];

  const navigate = useNavigate();

  return (
    <Box sx={{ display: "flex", height: "100%", bgcolor: "background.default" }}>

      {/* Left sidebar */}
      <Box sx={{
        width: 220, flexShrink: 0,
        bgcolor: "background.paper",
        borderRight: "1px solid", borderColor: "divider",
        display: "flex", flexDirection: "column",
        py: 2,
      }}>
        {/* Logo */}
        <Box sx={{ px: 2, mb: 2.5 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            <Box sx={{
              width: 36, height: 36, borderRadius: 1.5,
              background: "linear-gradient(135deg, #1565C0, #0288D1)",
              display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <Shield sx={{ color: "#fff", fontSize: 20 }} />
            </Box>
            <Box>
              <Typography sx={{ fontWeight: 800, fontSize: 15, color: "text.primary", lineHeight: 1.1 }}>
                Monitara
              </Typography>
              <Typography sx={{ fontSize: 10.5, color: "text.secondary", lineHeight: 1 }}>
                Security Platform
              </Typography>
            </Box>
          </Box>
        </Box>

        <Divider />

        {/* Client picker */}
        <ClientPicker />

        <Divider sx={{ mb: 1 }} />

        {/* Category nav */}
        <Typography sx={{ px: 2, pb: 0.5, fontSize: 10, fontWeight: 700, color: "text.secondary", textTransform: "uppercase", letterSpacing: 1 }}>
          Products
        </Typography>
        <List dense disablePadding sx={{ px: 1 }}>
          {CATEGORIES.map((cat) => (
            <ListItemButton
              key={cat.id}
              selected={activeCategory === cat.id}
              onClick={() => scrollTo(cat.id)}
              sx={{
                borderRadius: 1.5, mb: 0.25,
                "&.Mui-selected": {
                  bgcolor: `${cat.color}12`,
                  borderLeft: `3px solid ${cat.color}`,
                  pl: "11px",
                  "& .MuiListItemText-primary": { color: cat.color, fontWeight: 700 },
                },
              }}
            >
              <ListItemText
                primary={cat.label}
                slotProps={{ primary: { sx: { fontSize: 13 } } }}
              />
            </ListItemButton>
          ))}
        </List>

        <Divider sx={{ my: 1.5 }} />

        {/* Extra nav items */}
        <Typography sx={{ px: 2, pb: 0.5, fontSize: 10, fontWeight: 700, color: "text.secondary", textTransform: "uppercase", letterSpacing: 1 }}>
          Quick Access
        </Typography>
        <List dense disablePadding sx={{ px: 1 }}>
          {NAV_EXTRA.map((item) => (
            <ListItemButton
              key={item.label}
              onClick={() => navigate(item.route)}
              sx={{ borderRadius: 1.5, mb: 0.25, gap: 1 }}
            >
              <Box sx={{ color: "text.secondary" }}>{item.icon}</Box>
              <ListItemText primary={item.label} slotProps={{ primary: { sx: { fontSize: 13 } } }} />
            </ListItemButton>
          ))}
        </List>

        {/* User footer */}
        <Box sx={{ mt: "auto", pt: 2, px: 2, borderTop: "1px solid", borderColor: "divider" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            <Avatar sx={{ width: 30, height: 30, fontSize: 12, bgcolor: "#1565C0" }}>
              {(accounts[0]?.name || "U").charAt(0).toUpperCase()}
            </Avatar>
            <Box sx={{ minWidth: 0 }}>
              <Typography noWrap sx={{ fontSize: 12, fontWeight: 600, color: "text.primary" }}>
                {accounts[0]?.name || accounts[0]?.username || "User"}
              </Typography>
              {me?.is_admin && (
                <Typography sx={{ fontSize: 10, color: "#1565C0", fontWeight: 600 }}>Admin</Typography>
              )}
            </Box>
          </Box>
        </Box>
      </Box>

      {/* Main content */}
      <Box sx={{ flexGrow: 1, overflow: "auto", px: { xs: 2, md: 4 }, py: 3 }}>
        {/* Welcome */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, color: "text.primary", mb: 0.5 }}>
            Hi, {displayName}
          </Typography>
          <Typography sx={{ color: "text.secondary", fontSize: 14 }}>
            Select a product to get started, or use Quick Access links on the left.
          </Typography>
        </Box>

        {/* Category sections */}
        {CATEGORIES.map((cat) => (
          <CategorySection key={cat.id} category={cat} active={activeCategory === cat.id} />
        ))}

        {/* Bottom hint */}
        <Box sx={{ mt: 2, p: 2, borderRadius: 2, bgcolor: "background.paper", border: "1px solid", borderColor: "divider" }}>
          <Typography sx={{ fontSize: 12.5, color: "text.secondary" }}>
            <strong style={{ color: "#1565C0" }}>Configure</strong> — AI providers, webhooks, API keys, and administration are in{" "}
            <Box component="span"
              onClick={() => navigate("/settings")}
              sx={{ color: "#1565C0", fontWeight: 600, cursor: "pointer", textDecoration: "underline" }}>
              Configure
            </Box>.
            &nbsp;
            <Box component="span"
              onClick={() => navigate("/clients")}
              sx={{ color: "#1565C0", fontWeight: 600, cursor: "pointer", textDecoration: "underline" }}>
              Clients & Projects
            </Box>{" "}
            manage your multi-tenant data containers.
          </Typography>
        </Box>
      </Box>
    </Box>
  );
}
