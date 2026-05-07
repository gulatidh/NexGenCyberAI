import React, { useState, useEffect, useCallback } from "react";
import {
  IconButton, Badge, Popover, Box, Typography, Chip, Button,
  List, ListItem, Divider, Tooltip,
} from "@mui/material";
import { Notifications, NotificationsNone, Delete, CheckCircle, Error, Warning, Info } from "@mui/icons-material";
import {
  getNotifications, subscribeNotifications, markAllRead, clearNotifications,
  unreadCount, AppNotification,
} from "../../services/notifications";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
dayjs.extend(relativeTime);

const TYPE_ICON: Record<string, React.ReactNode> = {
  success: <CheckCircle sx={{ fontSize: 16, color: "#00e676" }} />,
  error: <Error sx={{ fontSize: 16, color: "#f44336" }} />,
  warning: <Warning sx={{ fontSize: 16, color: "#ff9800" }} />,
  info: <Info sx={{ fontSize: 16, color: "#00e5ff" }} />,
};

const TYPE_COLOR: Record<string, string> = {
  success: "#00e676", error: "#f44336", warning: "#ff9800", info: "#00e5ff",
};

export default function NotificationBell() {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [count, setCount] = useState(0);

  const refresh = useCallback(() => {
    setNotifications(getNotifications());
    setCount(unreadCount());
  }, []);

  useEffect(() => {
    refresh();
    return subscribeNotifications(refresh);
  }, [refresh]);

  const handleOpen = (e: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(e.currentTarget);
    markAllRead();
  };

  const handleClose = () => setAnchorEl(null);

  return (
    <>
      <Tooltip title="Notifications & Activity Log">
        <IconButton onClick={handleOpen} size="small" sx={{ mr: 1 }}>
          <Badge badgeContent={count} color="error" max={99}>
            {count > 0
              ? <Notifications sx={{ color: "#00e5ff", fontSize: 22 }} />
              : <NotificationsNone sx={{ color: "rgba(255,255,255,0.5)", fontSize: 22 }} />}
          </Badge>
        </IconButton>
      </Tooltip>

      <Popover
        open={Boolean(anchorEl)}
        anchorEl={anchorEl}
        onClose={handleClose}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
        slotProps={{ paper: { sx: { bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 2, width: 400, maxHeight: 520 } } }}
      >
        <Box sx={{ p: 1.5, display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          <Typography sx={{ color: "white", fontWeight: 600, fontSize: 14 }}>
            Activity Log
          </Typography>
          <Box sx={{ display: "flex", gap: 0.5 }}>
            <Chip label={`${notifications.length} events`} size="small"
              sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.5)", fontSize: 10, height: 20 }} />
            {notifications.length > 0 && (
              <Tooltip title="Clear all">
                <IconButton size="small" onClick={() => { clearNotifications(); }} sx={{ color: "rgba(255,255,255,0.4)" }}>
                  <Delete sx={{ fontSize: 16 }} />
                </IconButton>
              </Tooltip>
            )}
          </Box>
        </Box>

        {notifications.length === 0 ? (
          <Box sx={{ p: 4, textAlign: "center" }}>
            <NotificationsNone sx={{ fontSize: 40, color: "rgba(255,255,255,0.2)", mb: 1 }} />
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>
              No activity yet. Operations will appear here.
            </Typography>
          </Box>
        ) : (
          <List sx={{ p: 0, overflow: "auto", maxHeight: 440 }}>
            {notifications.map((n, i) => (
              <React.Fragment key={n.id}>
                <ListItem sx={{ py: 1, px: 1.5, alignItems: "flex-start", gap: 1,
                  bgcolor: n.read ? "transparent" : "rgba(0,229,255,0.03)" }}>
                  <Box sx={{ mt: 0.2, flexShrink: 0 }}>{TYPE_ICON[n.type] || TYPE_ICON.info}</Box>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Typography sx={{ color: "white", fontSize: 12, fontWeight: 500, wordBreak: "break-word" }}>
                      {n.message}
                    </Typography>
                    {n.detail && (
                      <Typography sx={{ color: "rgba(255,255,255,0.5)", fontSize: 11, mt: 0.2, wordBreak: "break-word" }}>
                        {n.detail}
                      </Typography>
                    )}
                    <Typography sx={{ color: "rgba(255,255,255,0.3)", fontSize: 10, mt: 0.3 }}>
                      {dayjs(n.timestamp).fromNow()}
                    </Typography>
                  </Box>
                  <Chip label={n.type} size="small"
                    sx={{ bgcolor: `${TYPE_COLOR[n.type]}15`, color: TYPE_COLOR[n.type], fontSize: 9, height: 16, flexShrink: 0 }} />
                </ListItem>
                {i < notifications.length - 1 && <Divider sx={{ borderColor: "rgba(255,255,255,0.05)" }} />}
              </React.Fragment>
            ))}
          </List>
        )}
      </Popover>
    </>
  );
}
