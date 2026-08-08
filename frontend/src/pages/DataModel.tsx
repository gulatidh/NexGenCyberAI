/**
 * /data-model — Interactive Relationship Explorer
 *
 * Full 11-node ontology always visible. Click an entity node (no anchor)
 * → right panel shows record list. Pick a record → anchor set; connected
 * entity nodes highlight. Click a highlighted node → its records sprout
 * as sub-nodes. Click a sub-node → it becomes the new anchor (cascade).
 */
import { useState, useEffect } from "react";
import {
  Box, Typography, TextField, InputAdornment,
  List, ListItemButton, ListItemText,
  Chip, CircularProgress, alpha, useTheme, IconButton,
} from "@mui/material";
import { Search, Close } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { dataModelApi } from "../services/api";
import { useActiveClient } from "../contexts/ClientContext";

// ── Static ontology data ──────────────────────────────────────────────────────

interface ONode {
  entity: string; label: string;
  cx: number; cy: number; labelX: number; labelW: number; color: string;
}
interface OEdge {
  from: string; to: string;
  x1: number; y1: number; x2: number; y2: number; dashed?: boolean;
}
interface SubNode {
  id: string; entity: string; label: string; detail?: string; severity?: string | null;
}
interface AnchorRecord {
  id: string; label: string; entityKey: string; detail?: string;
}

const ONT_NODES: ONode[] = [
  { entity:"Client",      label:"Client",             cx: 70,  cy:300, labelX: 35,   labelW: 70,  color:"#2563eb" },
  { entity:"Asset",       label:"Asset",              cx:250,  cy:190, labelX:215,   labelW: 70,  color:"#2563eb" },
  { entity:"Control",     label:"Control",            cx:250,  cy:470, labelX:213.5, labelW: 73,  color:"#7c3aed" },
  { entity:"DataFlow",    label:"Data Flow",          cx:440,  cy: 90, labelX:396.5, labelW: 87,  color:"#7c3aed" },
  { entity:"Finding",     label:"Finding",            cx:440,  cy:280, labelX:403.5, labelW: 73,  color:"#0f766e" },
  { entity:"SmartIntel",  label:"Smart Intelligence", cx:440,  cy:560, labelX:365,   labelW:150,  color:"#4338ca" },
  { entity:"Risk",        label:"Risk",               cx:640,  cy:220, labelX:605,   labelW: 70,  color:"#b45309" },
  { entity:"Evidence",    label:"Evidence",           cx:640,  cy:470, labelX:600,   labelW: 80,  color:"#15803d" },
  { entity:"AttackPath",  label:"Attack Path",        cx:830,  cy:130, labelX:779.5, labelW:101,  color:"#b45309" },
  { entity:"Technique",   label:"MITRE Technique",    cx:830,  cy:300, labelX:765.5, labelW:129,  color:"#b91c1c" },
  { entity:"Remediation", label:"Remediation",        cx:830,  cy:420, labelX:779.5, labelW:101,  color:"#b91c1c" },
  { entity:"Report",      label:"Report",             cx:1020, cy:300, labelX:985,   labelW: 70,  color:"#15803d" },
];

const ONT_EDGES: OEdge[] = [
  { from:"Client",      to:"Asset",       x1: 70, y1:300, x2:250,  y2:190 },
  { from:"Asset",       to:"DataFlow",    x1:250, y1:190, x2:440,  y2: 90 },
  { from:"Asset",       to:"Finding",     x1:250, y1:190, x2:440,  y2:280 },
  { from:"Finding",     to:"Risk",        x1:440, y1:280, x2:640,  y2:220 },
  { from:"Risk",        to:"AttackPath",  x1:640, y1:220, x2:830,  y2:130 },
  { from:"DataFlow",    to:"Technique",   x1:440, y1: 90, x2:830,  y2:300 },
  { from:"AttackPath",  to:"Technique",   x1:830, y1:130, x2:830,  y2:300 },
  { from:"Risk",        to:"Remediation", x1:640, y1:220, x2:830,  y2:420 },
  { from:"Technique",   to:"Remediation", x1:830, y1:300, x2:830,  y2:420 },
  { from:"Control",     to:"Evidence",    x1:250, y1:470, x2:640,  y2:470 },
  { from:"Remediation", to:"Evidence",    x1:830, y1:420, x2:640,  y2:470 },
  { from:"Finding",     to:"Report",      x1:440, y1:280, x2:1020, y2:300 },
  { from:"Remediation", to:"Report",      x1:830, y1:420, x2:1020, y2:300 },
  { from:"Evidence",    to:"Report",      x1:640, y1:470, x2:1020, y2:300 },
  { from:"SmartIntel",  to:"Asset",       x1:440, y1:560, x2:250,  y2:190, dashed:true },
  { from:"SmartIntel",  to:"Finding",     x1:440, y1:560, x2:440,  y2:280, dashed:true },
  { from:"SmartIntel",  to:"Risk",        x1:440, y1:560, x2:640,  y2:220, dashed:true },
  { from:"SmartIntel",  to:"Control",     x1:440, y1:560, x2:250,  y2:470, dashed:true },
];

// ontology entity name → API entity key (empty = not queryable)
const TO_KEY: Record<string, string> = {
  Asset:"asset", Finding:"finding", Risk:"risk", Control:"control",
  Remediation:"remediation", Technique:"technique", Report:"report",
  Evidence:"report", AttackPath:"risk", SmartIntel:"finding",
  DataFlow:"", Client:"",
};

// Primary ontology node name for each API key (used to drive expand from panel)
const KEY_TO_NODE: Record<string, string> = {
  asset:"Asset", finding:"Finding", risk:"Risk", control:"Control",
  remediation:"Remediation", technique:"Technique", report:"Report",
};

const LISTABLE = new Set(["asset","finding","risk","remediation"]);

const SEV_COLOR: Record<string,string> = {
  critical:"#b91c1c", high:"#ea580c", medium:"#d97706", low:"#16a34a", info:"#0284c7",
};

const ENT_ICON: Record<string,string> = {
  finding:"⚠", risk:"◈", asset:"⬡", remediation:"⚙", control:"⬟",
  technique:"⬡", report:"▤",
};

// ── Sub-node layout ────────────────────────────────────────────────────────────

const GRAPH_CX = 560;
const GRAPH_CY = 300;
const SUB_R = 88;
const MAX_VIS = 5;

function subPositions(cx: number, cy: number, n: number): {x:number; y:number}[] {
  if (!n) return [];
  const base = Math.atan2(cy - GRAPH_CY, cx - GRAPH_CX);
  const spread = Math.min(Math.PI * 0.7, n * 0.42);
  return Array.from({length: n}, (_, i) => {
    const t = n === 1 ? 0 : i/(n-1) - 0.5;
    return {
      x: Math.round(cx + SUB_R * Math.cos(base + t * spread)),
      y: Math.round(cy + SUB_R * Math.sin(base + t * spread)),
    };
  });
}

// ── Main component ────────────────────────────────────────────────────────────

export default function DataModel() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const { clientId } = useActiveClient();

  const [listKey, setListKey] = useState<string|null>(null);
  const [search, setSearch]   = useState("");
  const [anchor, setAnchor]   = useState<AnchorRecord|null>(null);
  // Set of ontology entity NAMES currently sprouted (e.g. "Finding", "Risk")
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  // Connection records grouped by API entity key
  const [connByKey, setConnByKey] = useState<Record<string, SubNode[]>>({});

  const edgeCol  = isDark ? "#3a4250" : "#c3c9d4";
  const raisedBg = isDark ? "#141b25" : "#f2f4f8";
  const lineBdr  = isDark ? "#232b36" : "#e6e9ef";

  // Reset search when entity type tab changes
  useEffect(() => { setSearch(""); }, [listKey]);

  // ── Queries ────────────────────────────────────────────────────────────────

  const { data: listData, isLoading: listLoading } = useQuery({
    queryKey: ["dm-list", clientId, listKey, search],
    queryFn: () =>
      clientId && listKey
        ? dataModelApi.list(clientId, listKey, search || undefined)
        : Promise.resolve({ items: [] }),
    enabled: !!clientId && !!listKey && !anchor,
    staleTime: 30_000,
  });

  const { data: connData, isLoading: connLoading } = useQuery({
    queryKey: ["dm-conn", clientId, anchor?.entityKey, anchor?.id],
    queryFn: () =>
      clientId && anchor
        ? dataModelApi.connections(clientId, anchor.entityKey, anchor.id)
        : Promise.resolve(null),
    enabled: !!clientId && !!anchor,
    staleTime: 60_000,
  });

  // Group connections by entity key when data arrives
  useEffect(() => {
    if (!connData?.nodes) { setConnByKey({}); return; }
    const g: Record<string, SubNode[]> = {};
    for (const n of connData.nodes as SubNode[]) {
      if (!g[n.entity]) g[n.entity] = [];
      g[n.entity].push(n);
    }
    setConnByKey(g);
    setExpanded(new Set());
  }, [connData]);

  // ── Handlers ───────────────────────────────────────────────────────────────

  function handleNodeClick(entityName: string) {
    const key = TO_KEY[entityName];

    if (!anchor) {
      // No anchor: open/toggle list panel
      if (LISTABLE.has(key)) setListKey(k => k === key ? null : key);
      return;
    }
    // Clicking the anchor entity type → clear anchor
    if (key && key === anchor.entityKey) {
      clearAll(); return;
    }
    // Toggle sprout for this node
    const subnodes = connByKey[key] ?? [];
    if (!key || !subnodes.length) return;
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(entityName) ? next.delete(entityName) : next.add(entityName);
      return next;
    });
  }

  function handleSelectRecord(item: {id:string; label:string; detail?:string}) {
    if (!listKey) return;
    setAnchor({id: item.id, label: item.label, entityKey: listKey, detail: item.detail});
    setListKey(null);
  }

  function handleSubNodeClick(sn: SubNode, e: React.MouseEvent) {
    e.stopPropagation();
    setAnchor({id: sn.id, label: sn.label, entityKey: sn.entity, detail: sn.detail});
    setExpanded(new Set());
    setConnByKey({});
  }

  function clearAll() {
    setAnchor(null); setExpanded(new Set()); setConnByKey({}); setListKey(null);
  }

  // ── SVG layer helpers ──────────────────────────────────────────────────────

  function SubLayer({n}: {n: ONode}) {
    if (!expanded.has(n.entity)) return null;
    const key = TO_KEY[n.entity];
    if (!key) return null;
    const all = connByKey[key] ?? [];
    const vis = all.slice(0, MAX_VIS);
    const extra = all.length - MAX_VIS;
    const totalPos = vis.length + (extra > 0 ? 1 : 0);
    const pos = subPositions(n.cx, n.cy, totalPos);

    return (
      <g>
        {pos.map((p, i) => (
          <path key={`e${i}`}
            d={`M ${n.cx} ${n.cy} Q ${(n.cx+p.x)/2} ${(n.cy+p.y)/2 - 14} ${p.x} ${p.y}`}
            fill="none" stroke={n.color} strokeWidth={1.5} strokeOpacity={0.5} strokeLinecap="round"
          />
        ))}
        {vis.map((sn, i) => {
          const p = pos[i];
          const sc = sn.severity ? SEV_COLOR[sn.severity] : undefined;
          return (
            <g key={sn.id} style={{cursor:"pointer"}} onClick={ev => handleSubNodeClick(sn, ev)}>
              {sc && <circle cx={p.x} cy={p.y} r={22} fill="none" stroke={sc} strokeWidth={2} opacity={0.6}/>}
              <circle cx={p.x} cy={p.y} r={17} fill={isDark?"#1a2232":"#fff"} stroke={n.color} strokeWidth={2}/>
              <text x={p.x} y={p.y} textAnchor="middle" dominantBaseline="middle"
                fontSize={10} fontWeight={700} fill={n.color}>{ENT_ICON[sn.entity]??"●"}</text>
              <text x={p.x} y={p.y+28} textAnchor="middle" fontSize={8} fill={isDark?"#9ca3af":"#4b5563"}>
                {sn.label.length>14 ? sn.label.slice(0,12)+"…" : sn.label}
              </text>
            </g>
          );
        })}
        {extra > 0 && (() => {
          const p = pos[pos.length-1];
          return (
            <g key="more">
              <circle cx={p.x} cy={p.y} r={17} fill={alpha(n.color, 0.1)} stroke={n.color} strokeWidth={1.5} strokeDasharray="3 2"/>
              <text x={p.x} y={p.y} textAnchor="middle" dominantBaseline="middle"
                fontSize={9} fontWeight={700} fill={n.color}>+{extra}</text>
            </g>
          );
        })()}
      </g>
    );
  }

  function OntNode({n}: {n: ONode}) {
    const key = TO_KEY[n.entity];
    const isAnchorEnt = !!anchor && !!key && key === anchor.entityKey;
    const isListEnt   = !anchor && listKey === key && !!key;
    const isExp       = expanded.has(n.entity);
    const hasConn     = !!key && (connByKey[key]?.length ?? 0) > 0;
    const clickable   = !!key && (LISTABLE.has(key) || !!anchor);
    const dim         = !!anchor && !isAnchorEnt && !hasConn;

    const r  = isAnchorEnt ? 14 : isExp ? 12 : 9;
    const sw = isListEnt ? 2.5 : isExp ? 2.5 : 1.8;

    return (
      <g style={{cursor: clickable?"pointer":"default", opacity: dim?0.22:1, transition:"opacity 0.2s"}}
         onClick={() => handleNodeClick(n.entity)}>
        {/* Halo */}
        {(hasConn || isAnchorEnt) && (
          <circle cx={n.cx} cy={n.cy} r={r+7} fill="none" stroke={n.color} strokeWidth={1} opacity={isAnchorEnt?0.45:0.2}/>
        )}
        {/* List selection dashed ring */}
        {isListEnt && (
          <circle cx={n.cx} cy={n.cy} r={r+5} fill="none" stroke="#4338ca" strokeWidth={1.5} strokeDasharray="4 2" opacity={0.6}/>
        )}
        {/* Main circle */}
        <circle cx={n.cx} cy={n.cy} r={r}
          fill={isAnchorEnt ? n.color : raisedBg}
          stroke={n.color} strokeWidth={sw}
          style={{transition:"r 0.18s, fill 0.18s"}}/>
        {/* Inner dot / anchor star */}
        {isAnchorEnt
          ? <text x={n.cx} y={n.cy} textAnchor="middle" dominantBaseline="middle" fontSize={10} fill="#fff" fontWeight={700}>✦</text>
          : <circle cx={n.cx} cy={n.cy} r={4} fill={n.color}/>
        }
        {/* Label pill */}
        <rect x={n.labelX} y={n.cy+14} width={n.labelW} height={20} rx={10}
          fill={isAnchorEnt||isExp ? n.color : raisedBg}
          stroke={isAnchorEnt||isExp ? n.color : lineBdr} strokeWidth={1}
          style={{transition:"fill 0.18s"}}/>
        <text x={n.cx} y={n.cy+27} textAnchor="middle" dominantBaseline="middle"
          fontFamily="monospace" fontSize={10} fontWeight={isAnchorEnt||isExp?700:500}
          fill={isAnchorEnt||isExp?"#fff":theme.palette.text.primary}
          style={{transition:"fill 0.18s"}}>
          {n.label}
        </text>
        {/* Anchor record name */}
        {isAnchorEnt && anchor && (
          <text x={n.cx} y={n.cy+44} textAnchor="middle" fontSize={8.5} fill={n.color} fontWeight={500}>
            {anchor.label.length>16 ? anchor.label.slice(0,14)+"…" : anchor.label}
          </text>
        )}
      </g>
    );
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  const showList   = !anchor && !!listKey;
  const showAnchor = !!anchor;
  const anchorColor = ONT_NODES.find(n => TO_KEY[n.entity] === anchor?.entityKey)?.color ?? "#6b7280";

  return (
    <Box sx={{display:"flex", flexDirection:"column", gap:2.5}}>

      {/* Header */}
      <Box sx={{display:"flex", alignItems:"flex-start", justifyContent:"space-between"}}>
        <Box>
          <Typography variant="h5" sx={{fontWeight:700, mb:0.25}}>Relationship Explorer</Typography>
          <Typography sx={{fontSize:13, color:"text.secondary"}}>
            {!anchor
              ? "Click an entity node to select a record as anchor."
              : `Anchor: ${anchor.label} · Click highlighted nodes to sprout connections.`}
          </Typography>
        </Box>
        {anchor && (
          <IconButton size="small" onClick={clearAll} title="Clear anchor"><Close fontSize="small"/></IconButton>
        )}
      </Box>

      <Box sx={{display:"flex", gap:2, alignItems:"flex-start"}}>

        {/* ── Graph ── */}
        <Box sx={{
          flex:1, minWidth:0,
          bgcolor:"background.paper",
          border:"1px solid", borderColor:"divider",
          borderRadius:2, p:2, overflowX:"auto",
        }}>
          {connLoading && (
            <Box sx={{display:"flex", alignItems:"center", gap:1, mb:1}}>
              <CircularProgress size={13}/>
              <Typography sx={{fontSize:11, color:"text.secondary"}}>Loading connections…</Typography>
            </Box>
          )}

          <svg viewBox="0 0 1120 660" style={{width:"100%", minWidth:520, height:"auto", display:"block"}}>
            <defs>
              <marker id="dm-arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill={edgeCol}/>
              </marker>
            </defs>

            {/* Layer 1 — base edges */}
            <g>
              {ONT_EDGES.map((e, i) => {
                const litFrom = TO_KEY[e.from] === anchor?.entityKey;
                const litTo   = TO_KEY[e.to]   === anchor?.entityKey;
                const lit     = litFrom || litTo;
                return (
                  <line key={i} x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2}
                    stroke={lit ? "#4338ca" : edgeCol}
                    strokeWidth={lit ? 2 : 1.4}
                    opacity={anchor && !lit ? 0.18 : 1}
                    strokeDasharray={e.dashed ? "3 4" : undefined}
                    markerEnd="url(#dm-arr)"
                    style={{transition:"stroke 0.2s, opacity 0.2s"}}
                  />
                );
              })}
            </g>

            {/* Layer 2 — sprouted sub-nodes */}
            <g>
              {ONT_NODES.map(n => <SubLayer key={`sl-${n.entity}`} n={n}/>)}
            </g>

            {/* Layer 3 — entity type nodes (always on top) */}
            <g>
              {ONT_NODES.map(n => <OntNode key={n.entity} n={n}/>)}
            </g>
          </svg>

          {/* Legend */}
          <Box sx={{display:"flex", flexWrap:"wrap", gap:2, mt:1.5, pt:1.5, borderTop:"1px solid", borderColor:"divider"}}>
            {[
              ["●  click to list records", !anchor],
              ["✦  anchor record", true],
              ["bright ring  expanded node", true],
              ["sub-node  click to pivot", true],
            ].map(([txt]) => (
              <Typography key={txt as string} sx={{fontSize:10, color:"text.disabled"}}>{txt as string}</Typography>
            ))}
          </Box>
        </Box>

        {/* ── Right panel ── */}
        {(showList || showAnchor) && (
          <Box sx={{
            width:260, flexShrink:0,
            border:"1px solid", borderColor:"divider",
            borderRadius:2, bgcolor:"background.paper",
            display:"flex", flexDirection:"column",
            maxHeight:600, overflow:"hidden",
          }}>

            {/* LIST PANEL */}
            {showList && (
              <>
                <Box sx={{p:1.5, borderBottom:"1px solid", borderColor:"divider",
                  display:"flex", alignItems:"center", justifyContent:"space-between"}}>
                  <Box sx={{display:"flex", alignItems:"center", gap:1}}>
                    <Box sx={{width:8, height:8, borderRadius:"50%",
                      bgcolor: ONT_NODES.find(n=>TO_KEY[n.entity]===listKey)?.color ?? "#6b7280"}}/>
                    <Typography sx={{fontSize:13, fontWeight:700, textTransform:"capitalize"}}>
                      Select {listKey}
                    </Typography>
                  </Box>
                  <IconButton size="small" onClick={() => setListKey(null)}><Close fontSize="small"/></IconButton>
                </Box>

                <Box sx={{p:1.25}}>
                  <TextField size="small" fullWidth placeholder="Search…"
                    value={search} onChange={e => setSearch(e.target.value)}
                    slotProps={{input:{startAdornment:
                      <InputAdornment position="start"><Search sx={{fontSize:15}}/></InputAdornment>
                    }}}
                    sx={{"& .MuiInputBase-root":{fontSize:12}}}
                  />
                </Box>

                <Box sx={{flex:1, overflow:"auto"}}>
                  {listLoading
                    ? <Box sx={{display:"flex",justifyContent:"center",py:3}}><CircularProgress size={20}/></Box>
                    : (listData?.items ?? []).length === 0
                      ? <Typography sx={{fontSize:12, color:"text.disabled", textAlign:"center", py:3}}>No records found</Typography>
                      : <List dense disablePadding>
                          {(listData?.items ?? []).map((item: {id:string; label:string; detail?:string}) => (
                            <ListItemButton key={item.id} onClick={() => handleSelectRecord(item)} sx={{py:0.75, px:1.5}}>
                              <ListItemText
                                primary={<Typography sx={{fontSize:12, fontWeight:500, lineHeight:1.3}}>{item.label}</Typography>}
                                secondary={item.detail
                                  ? <Typography sx={{fontSize:10, color:"text.disabled"}}>{item.detail}</Typography>
                                  : undefined}
                              />
                            </ListItemButton>
                          ))}
                        </List>
                  }
                </Box>
              </>
            )}

            {/* ANCHOR PANEL */}
            {showAnchor && (
              <>
                <Box sx={{p:1.5, borderBottom:"1px solid", borderColor:"divider"}}>
                  <Box sx={{display:"flex", alignItems:"center", justifyContent:"space-between", mb:0.75}}>
                    <Chip label={anchor!.entityKey} size="small" sx={{
                      fontSize:10, height:18, textTransform:"capitalize",
                      bgcolor: alpha(anchorColor, 0.12), color: anchorColor,
                    }}/>
                    <IconButton size="small" onClick={clearAll}><Close fontSize="small"/></IconButton>
                  </Box>
                  <Typography sx={{fontSize:13, fontWeight:700, lineHeight:1.3}}>{anchor!.label}</Typography>
                  {anchor!.detail && (
                    <Typography sx={{fontSize:11, color:"text.secondary", mt:0.25}}>{anchor!.detail}</Typography>
                  )}
                </Box>

                <Box sx={{p:1.5, flex:1, overflow:"auto"}}>
                  <Typography sx={{fontSize:10, color:"text.secondary", mb:1, textTransform:"uppercase", letterSpacing:"0.05em"}}>
                    Connections
                  </Typography>

                  {connLoading && <CircularProgress size={16}/>}

                  {!connLoading && Object.keys(connByKey).length === 0 && (
                    <Typography sx={{fontSize:12, color:"text.disabled"}}>No connections found</Typography>
                  )}

                  {Object.entries(connByKey).map(([ent, nodes]) => {
                    const color = ONT_NODES.find(n => TO_KEY[n.entity] === ent)?.color ?? "#6b7280";
                    const primName = KEY_TO_NODE[ent];
                    const isExp = primName ? expanded.has(primName) : false;
                    return (
                      <Box key={ent}
                        onClick={() => { if (primName) handleNodeClick(primName); }}
                        sx={{
                          display:"flex", alignItems:"center", justifyContent:"space-between",
                          py:0.75, px:1, mb:0.5, borderRadius:1, cursor:"pointer",
                          bgcolor: isExp ? alpha(color, 0.1) : "action.hover",
                          "&:hover": {bgcolor: alpha(color, 0.14)},
                          border:"1px solid", borderColor: isExp ? alpha(color, 0.35) : "transparent",
                        }}
                      >
                        <Box sx={{display:"flex", alignItems:"center", gap:1}}>
                          <Box sx={{width:8, height:8, borderRadius:"50%", bgcolor:color}}/>
                          <Typography sx={{fontSize:12, textTransform:"capitalize"}}>{ent}</Typography>
                        </Box>
                        <Box sx={{display:"flex", alignItems:"center", gap:0.75}}>
                          <Typography sx={{fontSize:12, fontWeight:700}}>{nodes.length}</Typography>
                          <Typography sx={{fontSize:10, color:"text.secondary"}}>{isExp?"▾":"▸"}</Typography>
                        </Box>
                      </Box>
                    );
                  })}

                  <Typography sx={{fontSize:10, color:"text.disabled", mt:2, lineHeight:1.6}}>
                    Click a row (or the node in the graph) to sprout its records. Click any sub-node to pivot to it.
                  </Typography>
                </Box>
              </>
            )}
          </Box>
        )}
      </Box>
    </Box>
  );
}
