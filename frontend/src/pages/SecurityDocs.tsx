import React, { useRef, useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, Button, Alert, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  TextField, Chip, IconButton, Tooltip, Divider,
} from "@mui/material";
import { Upload, Delete, Description, QuestionAnswer } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { documentsApi } from "../services/api";
import { toast } from "react-toastify";
import { fmt } from "../utils/datetime";

const SUGGESTION_CHIPS = [
  "What are our password requirements?",
  "What is our incident response process?",
  "What data classifications do we use?",
];

interface SecurityDocument {
  id: string;
  filename: string;
  size?: number;
  chunk_count?: number;
  uploaded_at?: string;
}

interface QueryResult {
  answer: string;
  sources?: string[];
}

function fmtBytes(n?: number): string {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export default function SecurityDocs() {
  const qc = useQueryClient();
  const { clientId } = useActiveClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [question, setQuestion] = useState("");
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null);
  const [querying, setQuerying] = useState(false);

  const { data: docs = [], isLoading } = useQuery<SecurityDocument[]>({
    queryKey: ["security-docs", clientId],
    queryFn: () => documentsApi.list(clientId),
    enabled: !!clientId,
  });

  const deleteMut = useMutation({
    mutationFn: (docId: string) => documentsApi.delete(clientId, docId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["security-docs", clientId] });
      toast.success("Document deleted");
    },
    onError: () => toast.error("Delete failed"),
  });

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !clientId) return;
    setUploading(true);
    try {
      await documentsApi.upload(clientId, file);
      qc.invalidateQueries({ queryKey: ["security-docs", clientId] });
      toast.success(`Uploaded ${file.name}`);
    } catch {
      toast.error("Upload failed");
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const handleAsk = async (q: string) => {
    if (!q.trim() || !clientId) return;
    setQuerying(true);
    setQueryResult(null);
    try {
      const res = await documentsApi.query(clientId, q.trim());
      setQueryResult(res);
    } catch {
      toast.error("Query failed");
    } finally {
      setQuerying(false);
    }
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Security Documents</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Upload policy and procedure documents and ask questions powered by AI
          </Typography>
        </Box>
        <Box>
          <input
            ref={fileRef}
            type="file"
            accept=".pdf,.docx,.txt"
            style={{ display: "none" }}
            onChange={handleFileChange}
          />
          <Button
            variant="contained"
            startIcon={uploading ? <CircularProgress size={16} color="inherit" /> : <Upload />}
            onClick={() => fileRef.current?.click()}
            disabled={!clientId || uploading}
          >
            {uploading ? "Uploading…" : "Upload Document"}
          </Button>
        </Box>
      </Box>

      {!clientId && <Alert severity="info">Select a client to manage their security documents.</Alert>}

      {clientId && isLoading && <CircularProgress size={24} />}

      {clientId && !isLoading && docs.length === 0 && (
        <Card variant="outlined" sx={{ p: 4, textAlign: "center", mb: 3 }}>
          <Description sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No documents uploaded yet. Upload a PDF, DOCX, or TXT file to get started.
          </Typography>
        </Card>
      )}

      {clientId && !isLoading && docs.length > 0 && (
        <TableContainer component={Card} variant="outlined" sx={{ mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                {["Filename", "Size", "Chunks", "Uploaded", ""].map((h) => (
                  <TableCell key={h} sx={{ fontWeight: 700, fontSize: 11 }}>{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {docs.map((doc) => (
                <TableRow key={doc.id} hover>
                  <TableCell>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Description fontSize="small" sx={{ color: "text.secondary" }} />
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>{doc.filename}</Typography>
                    </Box>
                  </TableCell>
                  <TableCell sx={{ fontSize: 12, color: "text.secondary" }}>{fmtBytes(doc.size)}</TableCell>
                  <TableCell sx={{ fontSize: 12, color: "text.secondary" }}>{doc.chunk_count ?? "—"}</TableCell>
                  <TableCell sx={{ fontSize: 12, color: "text.secondary" }}>
                    {doc.uploaded_at ? fmt(doc.uploaded_at) : "—"}
                  </TableCell>
                  <TableCell>
                    <Tooltip title="Delete">
                      <IconButton size="small" color="error" onClick={() => deleteMut.mutate(doc.id)}>
                        <Delete fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Ask a Question section */}
      {clientId && (
        <Card variant="outlined" sx={{ p: 2.5 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
            <QuestionAnswer sx={{ color: "#4285F4" }} />
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Ask Your Documents</Typography>
          </Box>
          <Box sx={{ display: "flex", gap: 1, mb: 1.5, flexWrap: "wrap" }}>
            {SUGGESTION_CHIPS.map((chip) => (
              <Chip
                key={chip}
                label={chip}
                size="small"
                variant="outlined"
                clickable
                onClick={() => { setQuestion(chip); handleAsk(chip); }}
                sx={{ fontSize: 12 }}
              />
            ))}
          </Box>
          <Box sx={{ display: "flex", gap: 1 }}>
            <TextField
              fullWidth size="small"
              placeholder="Ask a question about your security policies…"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") handleAsk(question); }}
            />
            <Button
              variant="contained"
              onClick={() => handleAsk(question)}
              disabled={!question.trim() || querying}
              startIcon={querying ? <CircularProgress size={16} color="inherit" /> : undefined}
            >
              Ask
            </Button>
          </Box>

          {queryResult && (
            <Box sx={{ mt: 2, p: 2, bgcolor: "action.hover", borderRadius: 1 }}>
              <Typography variant="body2" sx={{ mb: 1.5, whiteSpace: "pre-wrap" }}>
                {queryResult.answer}
              </Typography>
              {queryResult.sources && queryResult.sources.length > 0 && (
                <>
                  <Divider sx={{ mb: 1 }} />
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.75 }}>
                    Sources:
                  </Typography>
                  <Box sx={{ display: "flex", gap: 0.75, flexWrap: "wrap" }}>
                    {queryResult.sources.map((src, i) => (
                      <Chip key={i} label={src} size="small" variant="outlined" sx={{ fontSize: 11 }} />
                    ))}
                  </Box>
                </>
              )}
            </Box>
          )}
        </Card>
      )}
    </Box>
  );
}
