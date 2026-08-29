import React, { Suspense, lazy } from "react";
import { useSearchParams } from "react-router-dom";
import { Box, Tabs, Tab, CircularProgress, Typography } from "@mui/material";
import { Cable, Webhook, VpnKey } from "@mui/icons-material";

const Connections  = lazy(() => import("./Connections"));
const Webhooks     = lazy(() => import("./Webhooks"));
const APIKeysPage  = lazy(() => import("./APIKeysPage"));

const TABS = [
  { value: "connectors", label: "Connectors", Icon: Cable,   Component: Connections  },
  { value: "webhooks",   label: "Webhooks",   Icon: Webhook, Component: Webhooks     },
  { value: "api-keys",   label: "API Keys",   Icon: VpnKey,  Component: APIKeysPage  },
];

function TabLoader() {
  return (
    <Box sx={{ display: "flex", justifyContent: "center", pt: 6 }}>
      <CircularProgress size={32} />
    </Box>
  );
}

export default function IntegrationsHub() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab") ?? "connectors";
  const active = TABS.find(t => t.value === raw) ? raw : "connectors";

  const handleChange = (_: React.SyntheticEvent, val: string) => {
    setParams({ tab: val }, { replace: true });
  };

  const ActiveComponent = TABS.find(t => t.value === active)!.Component;

  return (
    <Box>
      <Box sx={{ mb: 2 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>Integrations</Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
          Platform connectors, scanners, AI providers, webhooks, and API keys — all in one hub.
        </Typography>
      </Box>

      <Box sx={{ borderBottom: 1, borderColor: "divider", mb: 3 }}>
        <Tabs value={active} onChange={handleChange} textColor="inherit"
          sx={{ "& .MuiTabs-indicator": { backgroundColor: "#4285F4" } }}>
          {TABS.map(t => (
            <Tab key={t.value} value={t.value} label={t.label}
              icon={<t.Icon sx={{ fontSize: 16 }} />} iconPosition="start"
              sx={{ fontSize: 13, fontWeight: 600, minHeight: 44, textTransform: "none",
                color: active === t.value ? "#4285F4" : "text.secondary" }} />
          ))}
        </Tabs>
      </Box>

      <Suspense fallback={<TabLoader />}>
        <ActiveComponent />
      </Suspense>
    </Box>
  );
}
