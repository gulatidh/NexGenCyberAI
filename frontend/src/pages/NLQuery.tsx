import React, { useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import { useMutation } from "@tanstack/react-query";
import {
  Box, Typography, TextField, Button, Alert, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer, TablePagination,
  Card, CardContent, Chip, Collapse,
} from "@mui/material";
import { Send, Search, ExpandMore, ExpandLess } from "@mui/icons-material";
import { nlQueryApi } from "../services/api";

// ── Types ────────────────────────────────────────────────────────────────────

interface QueryResult {
  question: string;
  sql: string;
  columns: string[];
  rows: any[][];
  summary: string;
  row_count: number;
}

// ── Suggestion chips ──────────────────────────────────────────────────────────

const SUGGESTIONS = [
  "Show all critical open findings",
  "Which findings have no assignee?",
  "Show remediation actions due this week",
  "Top 10 findings by CVSS score",
  "Count open findings by severity",
];

// ── Main page ─────────────────────────────────────────────────────────────────

export default function NLQuery() {
  const { clientId } = useActiveClient();
  const [question, setQuestion] = useState("");
  const [result, setResult] = useState<QueryResult | null>(null);
  const [showSql, setShowSql] = useState(false);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  const queryMutation = useMutation({
    mutationFn: (q: string) => nlQueryApi.query(clientId, q),
    onSuccess: (data: QueryResult) => {
      setResult(data);
      setShowSql(false);
      setPage(0);
    },
  });

  const handleAsk = () => {
    const q = question.trim();
    if (!q || !clientId) return;
    queryMutation.mutate(q);
  };

  const handleSuggestion = (s: string) => {
    setQuestion(s);
    if (clientId) queryMutation.mutate(s);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) handleAsk();
  };

  return (
    <Box>
      {/* Page header */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>
          Natural Language Query
        </Typography>
        <Typography variant="body2" sx={{ color: "text.secondary" }}>
          Ask your security data anything in plain English
        </Typography>
      </Box>

      {!clientId && (
        <Alert severity="info" sx={{ mb: 3 }}>
          Select a client to start querying their security data.
        </Alert>
      )}

      {/* Suggestion chips */}
      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
        {SUGGESTIONS.map((s) => (
          <Chip
            key={s}
            label={s}
            size="small"
            icon={<Search sx={{ fontSize: "14px !important" }} />}
            clickable
            disabled={!clientId}
            onClick={() => handleSuggestion(s)}
            sx={{
              bgcolor: "rgba(66,133,244,0.1)",
              color: "#82b1ff",
              border: "1px solid rgba(66,133,244,0.25)",
              fontSize: 12,
              "&:hover": { bgcolor: "rgba(66,133,244,0.2)" },
            }}
          />
        ))}
      </Box>

      {/* Input area */}
      <Box sx={{ display: "flex", gap: 1.5, mb: 3, alignItems: "flex-start" }}>
        <TextField
          multiline
          minRows={2}
          maxRows={6}
          fullWidth
          placeholder="e.g. Show me all critical findings that are still open..."
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={!clientId}
          sx={{
            "& .MuiOutlinedInput-root": {
              "& fieldset": { borderColor: "divider" },
              "&:hover fieldset": { borderColor: "#4285F4" },
            },
          }}
        />
        <Button
          variant="contained"
          startIcon={
            queryMutation.isPending ? (
              <CircularProgress size={16} sx={{ color: "#fff" }} />
            ) : (
              <Send sx={{ fontSize: 18 }} />
            )
          }
          disabled={!clientId || !question.trim() || queryMutation.isPending}
          onClick={handleAsk}
          sx={{
            bgcolor: "#4285F4",
            "&:hover": { bgcolor: "#1a73e8" },
            textTransform: "none",
            minWidth: 90,
            height: 56,
            flexShrink: 0,
          }}
        >
          Ask
        </Button>
      </Box>

      {/* Error */}
      {queryMutation.isError && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {(queryMutation.error as any)?.response?.data?.detail ||
            ((queryMutation.error as Error).message === "Network Error"
              ? "Could not reach the server — check that the backend is running and an AI provider is configured in AI Settings."
              : (queryMutation.error as Error).message) ||
            "Query failed — please try rephrasing."}
        </Alert>
      )}

      {/* Loading */}
      {queryMutation.isPending && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      )}

      {/* Results */}
      {result && !queryMutation.isPending && (
        <Box>
          {/* Summary */}
          <Card variant="outlined" sx={{ mb: 2 }}>
            <CardContent sx={{ pb: "16px !important" }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, display: "block", mb: 0.5 }}>
                RESULT SUMMARY
              </Typography>
              <Typography variant="body1" sx={{ color: "text.primary", mb: 1 }}>
                {result.summary}
              </Typography>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {result.row_count} row{result.row_count !== 1 ? "s" : ""} returned
              </Typography>
            </CardContent>
          </Card>

          {/* SQL toggle */}
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              gap: 0.5,
              mb: 1,
              cursor: "pointer",
              width: "fit-content",
            }}
            onClick={() => setShowSql((v) => !v)}
          >
            <Typography variant="caption" sx={{ color: "#4285F4", fontWeight: 600 }}>
              {showSql ? "Hide SQL" : "Show SQL"}
            </Typography>
            {showSql ? (
              <ExpandLess sx={{ fontSize: 16, color: "#4285F4" }} />
            ) : (
              <ExpandMore sx={{ fontSize: 16, color: "#4285F4" }} />
            )}
          </Box>
          <Collapse in={showSql}>
            <Box
              sx={{
                bgcolor: "#0d1117",
                border: "1px solid rgba(255,255,255,0.1)",
                borderRadius: 1,
                p: 2,
                mb: 2,
                fontFamily: "monospace",
                fontSize: 12,
                color: "#e6edf3",
                overflowX: "auto",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {result.sql}
            </Box>
          </Collapse>

          {/* Data table */}
          {result.rows.length > 0 ? (
            <Card variant="outlined">
              <TableContainer sx={{ maxHeight: "50vh", overflow: "auto" }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      {result.columns.map((col) => (
                        <TableCell
                          key={col}
                          sx={{
                            fontWeight: 700,
                            fontSize: 11,
                            bgcolor: "background.paper",
                            color: "text.secondary",
                            textTransform: "uppercase",
                            letterSpacing: 0.5,
                            whiteSpace: "nowrap",
                          }}
                        >
                          {col}
                        </TableCell>
                      ))}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {result.rows.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage).map((row, ri) => (
                      <TableRow key={ri} hover>
                        {row.map((cell, ci) => (
                          <TableCell key={ci} sx={{ fontSize: 12, color: "text.primary" }}>
                            {cell == null ? (
                              <Typography variant="caption" sx={{ color: "text.disabled" }}>
                                —
                              </Typography>
                            ) : String(cell)}
                          </TableCell>
                        ))}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              <TablePagination
                component="div"
                count={result.rows.length}
                page={page}
                onPageChange={(_, p) => setPage(p)}
                rowsPerPage={rowsPerPage}
                onRowsPerPageChange={(e) => { setRowsPerPage(parseInt(e.target.value, 10)); setPage(0); }}
                rowsPerPageOptions={[10, 25, 50, 100]}
                sx={{ borderTop: "1px solid", borderColor: "divider", color: "text.secondary", "& .MuiTablePagination-selectLabel, & .MuiTablePagination-displayedRows": { fontSize: 12 } }}
              />
            </Card>
          ) : (
            <Card
              variant="outlined"
              sx={{ p: 4, textAlign: "center", borderStyle: "dashed" }}
            >
              <Typography sx={{ color: "text.secondary" }}>
                The query returned no rows.
              </Typography>
            </Card>
          )}
        </Box>
      )}
    </Box>
  );
}
