/**
 * Stale Assets — assets not seen in the latest connector sync (status
 * stale/deleted). These are intentionally kept out of the main Asset
 * Inventory, assessments, threat models, technology inventory, and reports
 * so they don't inflate the active footprint or create false impressions.
 * They are NOT deleted: if a future sync sees them again they auto-reactivate.
 */
import React, { useState } from "react";
import {
  Box, Typography, Card, Chip, CircularProgress, Alert, Tooltip, Button,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  FormControl, InputLabel, Select, MenuItem,
} from "@mui/material";
import { History, ArrowBack } from "@mui/icons-material";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { clientsApi, assetsApi } from "../services/api";
import { Client, Asset } from "../types";
import { fromNow } from "../utils/datetime";

const STATUS_COLOR: Record<string, string> = {
  active: "#00e676",
  stale: "#ff9800",
  deleted: "rgba(255,255,255,0.4)",
};

export default function StaleAssets() {
  const navigate = useNavigate();
  const [clientId, setClientId] = useState("");

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });

  const { data: assets = [], isLoading } = useQuery<Asset[]>({
    queryKey: ["stale-assets", clientId],
    queryFn: () => assetsApi.list(clientId, { status: "archived" }),
    enabled: !!clientId,
  });

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
        <History sx={{ color: "#ff9800", fontSize: 28 }} />
        <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Stale Assets</Typography>
        <Button size="small" startIcon={<ArrowBack />} onClick={() => navigate("/assets")}
          sx={{ color: "rgba(255,255,255,0.6)", ml: "auto" }}>
          Back to Asset Inventory
        </Button>
      </Box>

      <Alert severity="info" sx={{ mb: 2, bgcolor: "rgba(255,152,0,0.08)", color: "rgba(255,255,255,0.85)", border: "1px solid rgba(255,152,0,0.3)" }}>
        These assets were <b>not seen in the latest connector sync</b>, so they're treated as decommissioned /
        out of scope and <b>excluded from assessments, threat models, technology inventory, and reports</b>.
        They aren't deleted — if a future sync detects them again they automatically return to the active inventory.
      </Alert>

      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
        <FormControl size="small" sx={{ minWidth: 220 }}>
          <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client</InputLabel>
          <Select value={clientId} onChange={(e) => setClientId(e.target.value)} label="Client"
            sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
            {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
          </Select>
        </FormControl>
      </Box>

      {!clientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "white" }}>
          Select a client to review its stale assets.
        </Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 6 }}><CircularProgress sx={{ color: "#ff9800" }} /></Box>
      ) : assets.length === 0 ? (
        <Alert severity="success" sx={{ bgcolor: "rgba(52,168,83,0.1)", color: "white" }}>
          No stale assets — the inventory is fully current. 🎉
        </Alert>
      ) : (
        <Card sx={{ bgcolor: "#1E1E1E" }}>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  {["Name", "Type", "Class", "Region", "Status", "Last seen"].map((h) => (
                    <TableCell key={h} sx={{ color: "rgba(255,255,255,0.6)", fontWeight: 600, borderColor: "rgba(255,255,255,0.1)" }}>{h}</TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {assets.map((a) => (
                  <TableRow key={a.id} hover sx={{ "&:hover": { bgcolor: "rgba(255,255,255,0.03)" } }}>
                    <TableCell sx={{ color: "white", borderColor: "rgba(255,255,255,0.06)" }}>
                      {a.name || a.external_id || a.id}
                    </TableCell>
                    <TableCell sx={{ color: "rgba(255,255,255,0.7)", borderColor: "rgba(255,255,255,0.06)" }}>{a.asset_type || "—"}</TableCell>
                    <TableCell sx={{ color: "rgba(255,255,255,0.7)", borderColor: "rgba(255,255,255,0.06)" }}>{a.asset_class || "—"}</TableCell>
                    <TableCell sx={{ color: "rgba(255,255,255,0.7)", borderColor: "rgba(255,255,255,0.06)" }}>{a.region || "—"}</TableCell>
                    <TableCell sx={{ borderColor: "rgba(255,255,255,0.06)" }}>
                      <Chip label={a.status} size="small"
                        sx={{ bgcolor: "transparent", color: STATUS_COLOR[a.status] || "rgba(255,255,255,0.5)",
                          border: `1px solid ${STATUS_COLOR[a.status] || "rgba(255,255,255,0.3)"}`, textTransform: "capitalize" }} />
                    </TableCell>
                    <TableCell sx={{ color: "rgba(255,255,255,0.5)", borderColor: "rgba(255,255,255,0.06)" }}>
                      <Tooltip title={a.last_synced_at || ""}>
                        <span>{a.last_synced_at ? fromNow(a.last_synced_at) : "—"}</span>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Card>
      )}
    </Box>
  );
}
