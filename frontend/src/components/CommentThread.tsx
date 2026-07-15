import React, { useState } from "react";
import {
  Box, Typography, Avatar, IconButton, TextField, Button,
  Collapse, Divider, CircularProgress, Tooltip,
} from "@mui/material";
import { ExpandMore, ExpandLess, Edit, Delete, Check, Close } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { commentsApi } from "../services/api";
import { toast } from "react-toastify";
import { fmt } from "../utils/datetime";
import { useMsal } from "@azure/msal-react";

export interface CommentThreadProps {
  clientId: string;
  entityType: "finding" | "risk" | "remediation_action" | "threat_entry";
  entityId: string;
}

interface Comment {
  id: string;
  body: string;
  author_name?: string;
  author_email?: string;
  created_at?: string;
  updated_at?: string;
}

function initials(name?: string): string {
  if (!name) return "?";
  const parts = name.trim().split(" ");
  if (parts.length === 1) return parts[0][0].toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function CommentItem({
  comment, currentEmail, clientId, onDeleted, onEdited,
}: {
  comment: Comment;
  currentEmail: string;
  clientId: string;
  onDeleted: () => void;
  onEdited: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(comment.body);

  const editMut = useMutation({
    mutationFn: () => commentsApi.update(clientId, comment.id, draft),
    onSuccess: () => { setEditing(false); onEdited(); toast.success("Comment updated"); },
    onError: () => toast.error("Update failed"),
  });

  const deleteMut = useMutation({
    mutationFn: () => commentsApi.delete(clientId, comment.id),
    onSuccess: () => { onDeleted(); toast.success("Comment deleted"); },
    onError: () => toast.error("Delete failed"),
  });

  const isOwn = comment.author_email === currentEmail;
  const ini = initials(comment.author_name || comment.author_email);

  return (
    <Box sx={{ display: "flex", gap: 1.5, mb: 1.5 }}>
      <Avatar sx={{ width: 28, height: 28, fontSize: 11, fontWeight: 700, bgcolor: "#4285F4", flexShrink: 0 }}>
        {ini}
      </Avatar>
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.25 }}>
          <Typography variant="caption" sx={{ fontWeight: 600 }}>
            {comment.author_name || comment.author_email || "Unknown"}
          </Typography>
          {comment.created_at && (
            <Typography variant="caption" sx={{ color: "text.secondary" }}>
              {fmt(comment.created_at)}
            </Typography>
          )}
          {comment.updated_at && comment.updated_at !== comment.created_at && (
            <Typography variant="caption" sx={{ color: "text.secondary", fontStyle: "italic" }}>(edited)</Typography>
          )}
        </Box>

        {editing ? (
          <Box>
            <TextField
              fullWidth size="small" multiline minRows={2}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              sx={{ mb: 0.75 }}
            />
            <Box sx={{ display: "flex", gap: 0.75 }}>
              <Button size="small" variant="contained"
                onClick={() => editMut.mutate()} disabled={!draft.trim() || editMut.isPending}
                startIcon={editMut.isPending ? <CircularProgress size={12} color="inherit" /> : <Check />}>
                Save
              </Button>
              <Button size="small" onClick={() => { setEditing(false); setDraft(comment.body); }}
                startIcon={<Close />}>
                Cancel
              </Button>
            </Box>
          </Box>
        ) : (
          <Box sx={{ display: "flex", alignItems: "flex-start", gap: 0.5 }}>
            <Typography variant="body2" sx={{ flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              {comment.body}
            </Typography>
            {isOwn && (
              <Box sx={{ display: "flex", flexShrink: 0 }}>
                <Tooltip title="Edit">
                  <IconButton size="small" onClick={() => setEditing(true)}>
                    <Edit sx={{ fontSize: 13 }} />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Delete">
                  <IconButton size="small" color="error"
                    onClick={() => deleteMut.mutate()} disabled={deleteMut.isPending}>
                    <Delete sx={{ fontSize: 13 }} />
                  </IconButton>
                </Tooltip>
              </Box>
            )}
          </Box>
        )}
      </Box>
    </Box>
  );
}

export default function CommentThread({ clientId, entityType, entityId }: CommentThreadProps) {
  const qc = useQueryClient();
  const { accounts } = useMsal();
  const currentEmail = accounts[0]?.username || "";
  const [expanded, setExpanded] = useState(false);
  const [newBody, setNewBody] = useState("");

  const queryKey = ["comments", clientId, entityType, entityId];

  const { data: comments = [], isLoading } = useQuery<Comment[]>({
    queryKey,
    queryFn: () => commentsApi.list(clientId, entityType, entityId),
    enabled: !!clientId && expanded,
  });

  const postMut = useMutation({
    mutationFn: () =>
      commentsApi.create(clientId, { entity_type: entityType, entity_id: entityId, body: newBody.trim() }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey });
      setNewBody("");
    },
    onError: () => toast.error("Post failed"),
  });

  const invalidate = () => qc.invalidateQueries({ queryKey });

  return (
    <Box sx={{ mt: 1.5 }}>
      <Divider sx={{ mb: 1 }} />
      <Box
        sx={{ display: "flex", alignItems: "center", gap: 0.5, cursor: "pointer", userSelect: "none", mb: expanded ? 1.5 : 0 }}
        onClick={() => setExpanded((v) => !v)}
      >
        <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700 }}>
          Comments {expanded ? "" : `(${comments.length || "…"})`}
        </Typography>
        {expanded ? <ExpandLess sx={{ fontSize: 16, color: "text.secondary" }} /> : <ExpandMore sx={{ fontSize: 16, color: "text.secondary" }} />}
      </Box>

      <Collapse in={expanded}>
        {isLoading && <CircularProgress size={16} sx={{ mb: 1 }} />}

        {!isLoading && comments.length === 0 && (
          <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>
            No comments yet.
          </Typography>
        )}

        {comments.map((c) => (
          <CommentItem
            key={c.id}
            comment={c}
            currentEmail={currentEmail}
            clientId={clientId}
            onDeleted={invalidate}
            onEdited={invalidate}
          />
        ))}

        {/* New comment form */}
        <Box sx={{ display: "flex", gap: 1, mt: 1 }}>
          <TextField
            fullWidth size="small" multiline minRows={1}
            placeholder="Add a comment…"
            value={newBody}
            onChange={(e) => setNewBody(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && e.ctrlKey) postMut.mutate(); }}
          />
          <Button
            variant="contained" size="small"
            disabled={!newBody.trim() || postMut.isPending}
            onClick={() => postMut.mutate()}
          >
            {postMut.isPending ? <CircularProgress size={14} color="inherit" /> : "Post"}
          </Button>
        </Box>
      </Collapse>
    </Box>
  );
}
