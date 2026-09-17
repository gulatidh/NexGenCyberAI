import { useEffect } from "react";
import { useMsal, useIsAuthenticated } from "@azure/msal-react";
import { useNavigate } from "react-router-dom";
import { loginRequest } from "../auth/msalConfig";

/* ─── CSS ─────────────────────────────────────────────────────────────────── */
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root {
  --ink:#0a0f14; --ink-mid:#1d2730; --ink-soft:#2d3a45;
  --paper:#f0f2f4; --card:#ffffff;
  --amber:#e8a33d; --amber-deep:#c77f1e; --amber-pale:#fdf4e3;
  --teal:#3e9d89; --teal-dark:#2f6f62; --teal-pale:#e6f4f1;
  --violet:#7c6fe0;
  --line:#dde2e6; --muted:#5e6d7a;
  --code-bg:#0d1219; --code-green:#7dd3c0; --code-yellow:#fbbf24;
  --code-purple:#c084fc; --code-comment:#4b5563; --code-white:#e2e8f0;
  --wrap:1160px; --r:14px;
}

.lp *{box-sizing:border-box;}
.lp{font-family:'Inter',sans-serif;color:var(--ink);background:var(--paper);-webkit-font-smoothing:antialiased;}
.lp h1,.lp h2,.lp h3,.lp h4{font-family:'Space Grotesk',sans-serif;margin:0;letter-spacing:-.01em;}
.lp a{color:inherit;text-decoration:none;}
.lp p{margin:0;}
.lp-wrap{max-width:var(--wrap);margin:0 auto;padding:0 28px;}
.lp-mono{font-family:'IBM Plex Mono',monospace;}

/* REVEAL */
.lp-rv{opacity:0;transform:translateY(18px);transition:opacity .65s cubic-bezier(.16,1,.3,1),transform .65s cubic-bezier(.16,1,.3,1);}
.lp-rv.in{opacity:1;transform:none;}
@media(prefers-reduced-motion:reduce){.lp-rv{opacity:1;transform:none;transition:none;}}

/* NAV */
.lp-nav-wrap{position:sticky;top:0;z-index:100;background:rgba(10,15,20,.92);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-bottom:1px solid rgba(255,255,255,.07);}
.lp-nav{display:flex;align-items:center;justify-content:space-between;height:62px;}
.lp-nav-links{display:flex;gap:30px;}
.lp-nav-links a{font-size:14px;font-weight:500;color:rgba(255,255,255,.5);transition:color .15s;}
.lp-nav-links a:hover{color:#fff;}
.lp-nav-right{display:flex;align-items:center;gap:12px;}
@media(max-width:680px){.lp-nav-links{display:none;}}

/* BUTTONS */
.lp-btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:10px 20px;border-radius:8px;font-size:14px;font-weight:600;border:1.5px solid transparent;cursor:pointer;font-family:'Inter',sans-serif;transition:all .18s;white-space:nowrap;}
.lp-btn-lg{padding:13px 26px;font-size:15px;}
.lp-btn-amber{background:var(--amber);color:var(--ink);border-color:var(--amber);}
.lp-btn-amber:hover{background:#f5b54a;transform:translateY(-1px);box-shadow:0 8px 22px rgba(232,163,61,.38);}
.lp-btn-outline{background:transparent;color:#fff;border-color:rgba(255,255,255,.25);}
.lp-btn-outline:hover{border-color:rgba(255,255,255,.6);transform:translateY(-1px);}
.lp-btn-ghost{background:transparent;color:var(--ink);border-color:var(--line);}
.lp-btn-ghost:hover{border-color:var(--ink);transform:translateY(-1px);}
.lp-btn-dark{background:var(--ink);color:#fff;border-color:var(--ink);}
.lp-btn-dark:hover{transform:translateY(-1px);box-shadow:0 8px 22px rgba(10,15,20,.3);}

/* HERO */
.lp-hero{background:var(--ink);color:#fff;padding:90px 0 72px;}
.lp-hero-grid{display:grid;grid-template-columns:1fr 1fr;gap:56px;align-items:center;}
@media(max-width:840px){.lp-hero-grid{grid-template-columns:1fr;}}
.lp-eyebrow{display:inline-flex;align-items:center;gap:7px;font-size:11.5px;letter-spacing:.07em;color:var(--code-green);font-family:'IBM Plex Mono',monospace;margin-bottom:20px;}
.lp-eyebrow-dot{width:6px;height:6px;border-radius:50%;background:var(--teal);animation:lp-pulse 2s ease-in-out infinite;}
@keyframes lp-pulse{0%,100%{opacity:1;}50%{opacity:.25;}}
@media(prefers-reduced-motion:reduce){.lp-eyebrow-dot{animation:none;}}
.lp-h1{font-size:clamp(32px,4vw,54px);line-height:1.07;font-weight:700;color:#fff;}
.lp-h1 em{font-style:normal;color:var(--amber);}
.lp-hero-sub{margin-top:18px;font-size:17px;line-height:1.7;color:rgba(255,255,255,.5);max-width:460px;}
.lp-hero-ctas{display:flex;gap:12px;margin-top:30px;flex-wrap:wrap;}

/* MOCK PANEL */
.lp-mock{background:#111820;border:1px solid rgba(255,255,255,.1);border-radius:14px;overflow:hidden;box-shadow:0 40px 100px rgba(0,0,0,.55);}
.lp-mock-bar{display:flex;align-items:center;gap:7px;padding:11px 16px;background:#0d1319;border-bottom:1px solid rgba(255,255,255,.07);}
.lp-dot{width:10px;height:10px;border-radius:50%;}
.lp-mock-title{flex:1;text-align:center;font-size:11.5px;color:rgba(255,255,255,.25);font-family:'IBM Plex Mono',monospace;}
.lp-mock-tabs{display:flex;padding:0 14px;border-bottom:1px solid rgba(255,255,255,.07);}
.lp-mock-tab{font-size:12px;padding:9px 12px;color:rgba(255,255,255,.35);font-family:'IBM Plex Mono',monospace;}
.lp-mock-tab.on{color:var(--code-green);border-bottom:2px solid var(--teal);margin-bottom:-1px;}
.lp-mock-body{padding:14px;}
.lp-mock-row{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:7px;margin-bottom:3px;background:rgba(255,255,255,.03);cursor:default;transition:background .12s;}
.lp-mock-row:hover{background:rgba(255,255,255,.06);}
.lp-sev{font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;font-family:'IBM Plex Mono',monospace;flex-shrink:0;letter-spacing:.04em;}
.sc{background:#3b0f0f;color:#f87171;}.sh{background:#3a1e09;color:#fb923c;}
.sm{background:#2e270a;color:#fbbf24;}.sl{background:#0a2218;color:#34d399;}
.lp-mock-fname{flex:1;font-size:12.5px;color:rgba(255,255,255,.82);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.lp-mock-asset{font-size:10.5px;color:rgba(255,255,255,.28);font-family:'IBM Plex Mono',monospace;flex-shrink:0;}
.lp-mock-footer{display:flex;align-items:center;justify-content:space-between;padding:10px 10px 4px;margin-top:4px;border-top:1px solid rgba(255,255,255,.06);}
.lp-mock-live{display:flex;align-items:center;gap:6px;font-size:11.5px;font-family:'IBM Plex Mono',monospace;color:var(--code-green);}
.lp-mock-live-dot{width:6px;height:6px;border-radius:50%;background:var(--teal);animation:lp-pulse 1.5s ease-in-out infinite;}
.lp-mock-counts{display:flex;gap:14px;font-size:11px;color:rgba(255,255,255,.3);font-family:'IBM Plex Mono',monospace;}

/* PIPELINE */
.lp-pipe{background:#111820;padding:60px 0;}
.lp-pipe-head{text-align:center;margin-bottom:48px;}
.lp-pipe-head h2{font-family:'Space Grotesk',sans-serif;font-size:clamp(20px,2.6vw,28px);color:#fff;font-weight:700;letter-spacing:-.01em;}
.lp-pipe-head p{margin-top:10px;font-size:15px;color:rgba(255,255,255,.38);}
.lp-pipe-row{display:flex;align-items:flex-start;justify-content:center;gap:0;flex-wrap:wrap;}
.lp-pipe-stage{display:flex;flex-direction:column;align-items:center;flex:1;min-width:130px;max-width:180px;padding:0 12px;position:relative;}
.lp-pipe-stage::after{content:'›';position:absolute;right:-6px;top:16px;font-size:20px;color:rgba(255,255,255,.15);}
.lp-pipe-stage:last-child::after{display:none;}
.lp-pipe-num{width:38px;height:38px;border-radius:50%;border:1.5px solid rgba(255,255,255,.14);display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:600;color:rgba(255,255,255,.4);font-family:'IBM Plex Mono',monospace;margin-bottom:12px;transition:border-color .25s,color .25s,background .25s;}
.lp-pipe-stage:hover .lp-pipe-num{border-color:var(--teal);color:var(--code-green);background:rgba(62,157,137,.1);}
.lp-pipe-label{font-size:13px;font-weight:700;color:rgba(255,255,255,.72);text-align:center;margin-bottom:7px;font-family:'Space Grotesk',sans-serif;}
.lp-pipe-items{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:4px;text-align:center;}
.lp-pipe-items li{font-size:11.5px;color:rgba(255,255,255,.32);line-height:1.4;}
@media(max-width:700px){.lp-pipe-stage::after{display:none;}.lp-pipe-stage{min-width:110px;}}

/* SECTION */
.lp-sec{padding:84px 0;position:relative;}
.lp-sec-alt{background:#fff;}
.lp-tag{display:inline-block;font-size:11px;letter-spacing:.08em;font-weight:700;color:var(--teal-dark);background:var(--teal-pale);padding:3px 10px;border-radius:4px;margin-bottom:12px;font-family:'IBM Plex Mono',monospace;}
.lp-h2{font-size:clamp(28px,3.4vw,42px);line-height:1.1;font-weight:700;}
.lp-h2 em{font-style:normal;color:var(--teal-dark);}
.lp-sec-sub{margin-top:16px;font-size:16px;line-height:1.7;color:var(--muted);max-width:480px;}
.lp-bullets{list-style:none;padding:0;margin:22px 0 0;display:flex;flex-direction:column;gap:9px;}
.lp-bullets li{display:flex;align-items:flex-start;gap:9px;font-size:14px;color:var(--ink-soft);line-height:1.5;}
.lp-bullets li::before{content:'→';color:var(--teal);font-size:13px;margin-top:1px;flex-shrink:0;font-family:'IBM Plex Mono',monospace;}
.lp-chapter-grid{display:grid;grid-template-columns:1fr 1fr;gap:64px;align-items:center;}
.lp-chapter-grid.flip{direction:rtl;}
.lp-chapter-grid.flip > *{direction:ltr;}
@media(max-width:820px){.lp-chapter-grid,.lp-chapter-grid.flip{grid-template-columns:1fr;direction:ltr;gap:36px;}}

/* RISK MATRIX VISUAL */
.lp-matrix-wrap{background:#fff;border:1px solid var(--line);border-radius:14px;padding:24px;box-shadow:0 8px 32px rgba(10,15,20,.08);}
.lp-matrix-title{font-size:12px;font-weight:700;letter-spacing:.06em;color:var(--muted);font-family:'IBM Plex Mono',monospace;margin-bottom:16px;}
.lp-matrix{display:grid;grid-template-columns:20px repeat(5,1fr);grid-template-rows:repeat(5,1fr) 20px;gap:4px;margin-bottom:12px;aspect-ratio:1/1;max-width:280px;}
.lp-mx-cell{border-radius:5px;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;font-family:'IBM Plex Mono',monospace;}
.mx-low{background:#d1fae5;color:#065f46;}
.mx-med{background:#fef3c7;color:#92400e;}
.mx-high{background:#fee2e2;color:#991b1b;}
.mx-crit{background:#7f1d1d;color:#fca5a5;}
.mx-hl{outline:2.5px solid var(--ink);outline-offset:1px;}
.lp-mx-axis{display:flex;align-items:center;justify-content:center;font-size:9px;color:var(--muted);font-family:'IBM Plex Mono',monospace;writing-mode:initial;}
.lp-mx-y{writing-mode:vertical-rl;transform:rotate(180deg);}
.lp-risk-card{margin-top:16px;border-top:1px solid var(--line);padding-top:14px;display:flex;gap:12px;align-items:center;}
.lp-risk-badge{padding:6px 14px;border-radius:6px;font-size:12px;font-weight:700;background:#fee2e2;color:#991b1b;font-family:'IBM Plex Mono',monospace;}
.lp-risk-meta{font-size:12.5px;color:var(--muted);line-height:1.5;}
.lp-risk-meta strong{color:var(--ink);}

/* SIGMA CODE VISUAL */
.lp-code-wrap{border-radius:14px;overflow:hidden;box-shadow:0 8px 32px rgba(10,15,20,.12);}
.lp-code-bar{background:#1a2230;display:flex;align-items:center;gap:7px;padding:11px 16px;border-bottom:1px solid rgba(255,255,255,.07);}
.lp-code-bar-label{flex:1;text-align:center;font-size:11.5px;color:rgba(255,255,255,.28);font-family:'IBM Plex Mono',monospace;}
.lp-code-body{background:var(--code-bg);padding:20px 22px;font-family:'IBM Plex Mono',monospace;font-size:12.5px;line-height:1.8;overflow-x:auto;}
.ck{color:var(--code-purple);}
.cv{color:var(--code-green);}
.cs{color:#60a5fa;}
.cc{color:var(--code-comment);}
.cy{color:var(--code-yellow);}
.cw{color:var(--code-white);}

/* CLIENT SWITCHER VISUAL */
.lp-clients-wrap{background:#fff;border:1px solid var(--line);border-radius:14px;overflow:hidden;box-shadow:0 8px 32px rgba(10,15,20,.08);}
.lp-clients-head{padding:14px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;}
.lp-clients-head-label{font-size:12px;font-weight:700;letter-spacing:.06em;color:var(--muted);font-family:'IBM Plex Mono',monospace;}
.lp-client-row{display:flex;align-items:center;gap:12px;padding:13px 18px;border-bottom:1px solid var(--line);cursor:default;transition:background .12s;}
.lp-client-row:last-child{border-bottom:none;}
.lp-client-row.active{background:var(--teal-pale);}
.lp-client-row:hover:not(.active){background:var(--paper);}
.lp-client-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;}
.lp-client-info{flex:1;}
.lp-client-name{font-size:13.5px;font-weight:600;color:var(--ink);}
.lp-client-meta{font-size:11.5px;color:var(--muted);margin-top:1px;font-family:'IBM Plex Mono',monospace;}
.lp-client-tag{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:4px;}
.ct-ok{background:#d1fae5;color:#065f46;}.ct-warn{background:#fee2e2;color:#991b1b;}.ct-scan{background:#fef3c7;color:#92400e;}

/* COMPLIANCE VISUAL */
.lp-fw-wrap{background:#fff;border:1px solid var(--line);border-radius:14px;overflow:hidden;box-shadow:0 8px 32px rgba(10,15,20,.08);}
.lp-fw-head{padding:13px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;}
.lp-fw-head-label{font-size:12px;font-weight:700;letter-spacing:.06em;color:var(--muted);font-family:'IBM Plex Mono',monospace;}
.lp-fw-sel{font-size:12px;color:var(--teal-dark);font-weight:600;font-family:'IBM Plex Mono',monospace;background:var(--teal-pale);padding:3px 9px;border-radius:5px;}
.lp-fw-row{display:flex;align-items:center;gap:10px;padding:10px 18px;border-bottom:1px solid var(--line);font-size:13px;}
.lp-fw-row:last-child{border-bottom:none;}
.lp-fw-id{font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--muted);min-width:72px;flex-shrink:0;}
.lp-fw-name{flex:1;color:var(--ink);}
.lp-fw-status{font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;font-family:'IBM Plex Mono',monospace;}
.fs-pass{background:#d1fae5;color:#065f46;}.fs-fail{background:#fee2e2;color:#991b1b;}.fs-part{background:#fef3c7;color:#92400e;}
.lp-fw-foot{padding:13px 18px;background:var(--paper);border-top:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;}
.lp-fw-foot-note{font-size:12px;color:var(--muted);font-family:'IBM Plex Mono',monospace;}
.lp-fw-dl{font-size:12px;font-weight:700;color:var(--teal-dark);background:var(--teal-pale);padding:5px 12px;border-radius:6px;cursor:default;}

/* INTEGRATION */
.lp-integ{padding:60px 0;background:var(--paper);}
.lp-integ-head{text-align:center;margin-bottom:36px;}
.lp-integ-head p{font-size:13px;letter-spacing:.06em;font-weight:700;color:var(--muted);font-family:'IBM Plex Mono',monospace;}
.lp-integ-groups{display:flex;flex-direction:column;gap:18px;}
.lp-integ-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:center;}
.lp-integ-key{font-size:11px;color:var(--muted);font-family:'IBM Plex Mono',monospace;min-width:88px;text-align:right;flex-shrink:0;}
.lp-pill{font-size:12.5px;font-weight:500;padding:5px 13px;border-radius:6px;border:1px solid var(--line);color:var(--ink-soft);background:#fff;}

/* CAPABILITY */
.lp-cap{padding:72px 0;background:#fff;}
.lp-cap-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:40px;}
@media(max-width:820px){.lp-cap-grid{grid-template-columns:1fr 1fr;}}
@media(max-width:520px){.lp-cap-grid{grid-template-columns:1fr;}}
.lp-cap-group{background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:20px;}
.lp-cap-group-tag{font-size:10.5px;letter-spacing:.07em;font-weight:700;color:var(--muted);font-family:'IBM Plex Mono',monospace;margin-bottom:12px;}
.lp-cap-item{display:flex;align-items:center;gap:7px;font-size:13px;color:var(--ink-soft);padding:4px 0;}
.lp-cap-item::before{content:'';width:5px;height:5px;border-radius:50%;background:var(--teal);flex-shrink:0;}

/* CTA */
.lp-cta{background:var(--ink);color:#fff;padding:80px 0;text-align:center;}
.lp-cta h2{font-size:clamp(26px,3.2vw,38px);font-weight:700;color:#fff;}
.lp-cta p{margin-top:12px;font-size:16px;color:rgba(255,255,255,.45);}
.lp-cta-actions{display:flex;gap:12px;justify-content:center;margin-top:28px;flex-wrap:wrap;}

/* FOOTER */
.lp-footer{background:#0d1219;padding:28px 0;border-top:1px solid rgba(255,255,255,.07);}
.lp-footer-inner{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;}
.lp-footer-note{font-size:12.5px;color:rgba(255,255,255,.25);}
.lp-footer-sign{font-size:13px;color:rgba(255,255,255,.45);cursor:pointer;transition:color .15s;}
.lp-footer-sign:hover{color:#fff;}
`;

/* ─── DATA ─────────────────────────────────────────────────────────────────── */
const PIPELINE = [
  { n: "01", label: "Discover", items: ["Asset inventory", "Vulnerability scans", "CVE enrichment", "Posture trends"] },
  { n: "02", label: "Analyse", items: ["Risk assessment", "Attack path graphs", "Threat intelligence", "NL queries"] },
  { n: "03", label: "Respond", items: ["Threat register", "Control deficiencies", "CTEM programs", "Remediation"] },
  { n: "04", label: "Report", items: ["VAPT reports", "Evidence packages", "Compliance heatmaps", "Custom frameworks"] },
  { n: "05", label: "Automate", items: ["60+ AI agents", "Webhook dispatch", "API access", "AI guardrails"] },
  { n: "06", label: "Manage", items: ["Multi-tenant console", "Client posture", "Connector health", "Soft-delete & audit"] },
];

const CAPABILITIES: { tag: string; items: string[] }[] = [
  { tag: "DISCOVER", items: ["Asset discovery & inventory", "Vulnerability scanning", "CVE blast radius", "Posture trend charts", "Technology fingerprinting", "AI-assisted scan wizard"] },
  { tag: "ANALYSE", items: ["Attack path visualisation", "Risk staging gate", "FAIR-lite risk scoring", "Threat intelligence mapping", "Compliance gap analysis", "Ask-your-data NL query"] },
  { tag: "RESPOND", items: ["Threat register (MITRE)", "Control deficiency tracker", "5-phase CTEM workflow", "Remediation action tracker", "Crown jewel prioritisation", "VAPT report generation"] },
  { tag: "REPORT", items: ["PDF & DOCX export", "Compliance evidence ZIP", "Framework heatmaps", "Custom control frameworks", "Scan version history & diff", "Embeddable scorecard"] },
  { tag: "AUTOMATE", items: ["60+ specialist AI agents", "Webhook delivery (HMAC)", "M2M API keys", "AI workflow builder", "RAG knowledge base", "Provider failover"] },
  { tag: "SCANNERS", items: ["OWASP ZAP, Nmap, OpenVAS", "Semgrep, CodeQL, Sonar", "Trivy, Gitleaks, TruffleHog", "Tenable, Qualys, Rapid7", "Burp Enterprise, Snyk", "Invicti, Acunetix"] },
];

/* ─── COMPONENT ─────────────────────────────────────────────────────────────── */
export default function LandingV2() {
  const { instance } = useMsal();
  const isAuthenticated = useIsAuthenticated();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) navigate("/hub", { replace: true });
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = CSS;
    document.head.appendChild(style);
    return () => { document.head.removeChild(style); };
  }, []);

  useEffect(() => {
    const els = document.querySelectorAll<HTMLElement>(".lp-rv");
    const io = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }),
      { threshold: 0.1 }
    );
    els.forEach(el => io.observe(el));
    return () => io.disconnect();
  }, []);

  const signIn = () =>
    instance.loginRedirect({ ...loginRequest, redirectStartPage: `${window.location.origin}/hub` }).catch(console.error);

  return (
    <div className="lp">

      {/* ── NAV ── */}
      <header className="lp-nav-wrap">
        <div className="lp-wrap lp-nav">
          <img src="/owlet-logo.svg" alt="Owlet" style={{ height: 34, width: "auto" }} />
          <nav className="lp-nav-links">
            <a href="#lp-pipeline">How it works</a>
            <a href="#lp-cap">Capabilities</a>
            <a href="#lp-integ">Integrations</a>
          </nav>
          <div className="lp-nav-right">
            <button className="lp-btn lp-btn-outline" onClick={signIn}>Sign in</button>
          </div>
        </div>
      </header>

      {/* ── HERO ── */}
      <section className="lp-hero">
        <div className="lp-wrap">
          <div className="lp-hero-grid">
            <div className="lp-rv">
              <div className="lp-eyebrow lp-mono">
                <span className="lp-eyebrow-dot" />
                SECURITY ENGINEERING PLATFORM
              </div>
              <h1 className="lp-h1">The full lifecycle.<br /><em>Not just a scanner.</em></h1>
              <p className="lp-hero-sub">
                From asset discovery and vulnerability assessment to risk evaluation,
                compliance monitoring, threat modelling, and audit-ready reporting —
                connected end to end, without the integration overhead.
              </p>
              <div className="lp-hero-ctas">
                <button className="lp-btn lp-btn-amber lp-btn-lg" onClick={signIn}>Sign in to explore</button>
                <a href="#lp-pipeline" className="lp-btn lp-btn-outline lp-btn-lg">See how it works</a>
              </div>
            </div>

            {/* mock findings panel */}
            <div className="lp-mock lp-rv" style={{ transitionDelay: ".1s" }}>
              <div className="lp-mock-bar">
                <span className="lp-dot" style={{ background: "#ff5f57" }} />
                <span className="lp-dot" style={{ background: "#febc2e" }} />
                <span className="lp-dot" style={{ background: "#28c840" }} />
                <span className="lp-mock-title lp-mono">Owlet — Findings</span>
              </div>
              <div className="lp-mock-tabs">
                <span className="lp-mock-tab on lp-mono">Findings</span>
                <span className="lp-mock-tab lp-mono">Assets</span>
                <span className="lp-mock-tab lp-mono">Risk</span>
              </div>
              <div className="lp-mock-body">
                {[
                  { sev: "CRIT", cls: "sc", title: "Remote code execution via deserialization", asset: "api-gateway.prod" },
                  { sev: "HIGH", cls: "sh", title: "S3 bucket publicly accessible", asset: "storage-logs-backup" },
                  { sev: "HIGH", cls: "sh", title: "MFA not enforced — Admin role", asset: "Entra ID · Global Admins" },
                  { sev: "MED",  cls: "sm", title: "TLS 1.0 enabled on legacy endpoint", asset: "payments-api-v1" },
                  { sev: "LOW",  cls: "sl", title: "Missing security headers (X-Frame)", asset: "portal.corp.internal" },
                ].map((r, i) => (
                  <div key={i} className="lp-mock-row">
                    <span className={`lp-sev ${r.cls}`}>{r.sev}</span>
                    <span className="lp-mock-fname">{r.title}</span>
                    <span className="lp-mock-asset">{r.asset}</span>
                  </div>
                ))}
                <div className="lp-mock-footer">
                  <span className="lp-mock-live lp-mono">
                    <span className="lp-mock-live-dot" />3 agents running
                  </span>
                  <div className="lp-mock-counts">
                    <span>12 assets</span>
                    <span>31 findings</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── PIPELINE ── */}
      <section className="lp-pipe" id="lp-pipeline">
        <div className="lp-wrap">
          <div className="lp-pipe-head lp-rv">
            <h2>Six stages. One workflow.</h2>
            <p>Most teams stitch together a scanner, a GRC tool, a ticketing system, and a spreadsheet. This replaces all of them.</p>
          </div>
          <div className="lp-pipe-row">
            {PIPELINE.map((s, i) => (
              <div key={i} className="lp-pipe-stage lp-rv" style={{ transitionDelay: `${i * 0.07}s` }}>
                <div className="lp-pipe-num lp-mono">{s.n}</div>
                <div className="lp-pipe-label">{s.label}</div>
                <ul className="lp-pipe-items">
                  {s.items.map((it, j) => <li key={j}>{it}</li>)}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CHAPTER 1: Risk staging gate ── */}
      <section className="lp-sec">
        <div className="lp-wrap">
          <div className="lp-chapter-grid">
            <div className="lp-rv">
              <span className="lp-tag">RISK MANAGEMENT</span>
              <h2 className="lp-h2">Findings don't<br /><em>automatically become risks.</em></h2>
              <p className="lp-sec-sub">
                Most tools dump scanner output straight into a risk register.
                Owlet puts everything through a staging gate first — a structured
                evaluation that walks through probability factors and consequence
                before anything is formally recorded.
              </p>
              <ul className="lp-bullets">
                <li>8-step evaluation: accessibility, discoverability, exploitability, authentication, repeatability, consequence, and treatment</li>
                <li>Live 5×5 risk matrix updates as you score each factor</li>
                <li>AI drafts the risk proposal from scanner findings — you evaluate it</li>
                <li>Staging area keeps proposals separate from the live register until reviewed</li>
                <li>FAIR-lite financial exposure scoring on accepted risks</li>
              </ul>
            </div>

            {/* risk matrix visual */}
            <div className="lp-rv" style={{ transitionDelay: ".1s" }}>
              <div className="lp-matrix-wrap">
                <div className="lp-matrix-title lp-mono">Risk Matrix — Live Scoring</div>
                <div className="lp-matrix" style={{ fontFamily: "IBM Plex Mono, monospace" }}>
                  {/* Y-axis label */}
                  <div className="lp-mx-axis lp-mx-y" style={{ gridColumn: 1, gridRow: "1/6", fontSize: 9, color: "var(--muted)", writingMode: "vertical-rl", transform: "rotate(180deg)", textAlign: "center" }}>LIKELIHOOD</div>
                  {/* rows top→bottom = high likelihood → low */}
                  {[
                    ["mx-med","mx-high","mx-high","mx-crit","mx-crit"],
                    ["mx-low","mx-med","mx-high","mx-high","mx-crit"],
                    ["mx-low","mx-low","mx-med","mx-high","mx-high mx-hl"],
                    ["mx-low","mx-low","mx-low","mx-med","mx-high"],
                    ["mx-low","mx-low","mx-low","mx-low","mx-med"],
                  ].map((row, ri) =>
                    row.map((cls, ci) => (
                      <div key={`${ri}-${ci}`} className={`lp-mx-cell ${cls}`}
                        style={{ gridColumn: ci + 2, gridRow: ri + 1, fontSize: 9 }}>
                        {cls.includes("crit") ? "C" : cls.includes("high") ? "H" : cls.includes("med") ? "M" : "L"}
                      </div>
                    ))
                  )}
                  {/* X-axis */}
                  <div style={{ gridColumn: "2/7", gridRow: 6, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9, color: "var(--muted)", fontFamily: "IBM Plex Mono, monospace", paddingTop: 4 }}>
                    CONSEQUENCE →
                  </div>
                </div>
                <div className="lp-risk-card">
                  <span className="lp-risk-badge lp-mono">HIGH · 12</span>
                  <div className="lp-risk-meta">
                    <strong>MFA Bypass — Admin Role</strong><br />
                    Consequence 4 × Likelihood avg 3.0
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── CHAPTER 2: AI deliverables ── */}
      <section className="lp-sec lp-sec-alt">
        <div className="lp-wrap">
          <div className="lp-chapter-grid flip">
            {/* sigma code visual */}
            <div className="lp-rv">
              <div className="lp-code-wrap">
                <div className="lp-code-bar">
                  <span className="lp-dot" style={{ background: "#ff5f57" }} />
                  <span className="lp-dot" style={{ background: "#febc2e" }} />
                  <span className="lp-dot" style={{ background: "#28c840" }} />
                  <span className="lp-code-bar-label lp-mono">sigma-rule — generated by Threat Detection Agent</span>
                </div>
                <div className="lp-code-body">
                  <span className="cc"># Auto-generated · review before deployment{"\n"}</span>
                  <span className="ck">title</span><span className="cw">: </span><span className="cv">Suspicious PowerShell Download Cradle{"\n"}</span>
                  <span className="ck">status</span><span className="cw">: </span><span className="cy">experimental{"\n"}</span>
                  <span className="ck">logsource</span><span className="cw">:{"\n"}</span>
                  <span className="cw">  </span><span className="ck">product</span><span className="cw">: </span><span className="cv">windows{"\n"}</span>
                  <span className="cw">  </span><span className="ck">service</span><span className="cw">: </span><span className="cv">sysmon{"\n"}</span>
                  <span className="ck">detection</span><span className="cw">:{"\n"}</span>
                  <span className="cw">  </span><span className="ck">selection</span><span className="cw">:{"\n"}</span>
                  <span className="cw">    </span><span className="ck">EventID</span><span className="cw">: </span><span className="cs">1{"\n"}</span>
                  <span className="cw">    </span><span className="ck">CommandLine|contains</span><span className="cw">:{"\n"}</span>
                  <span className="cw">      - </span><span className="cv">&apos;IEX&apos;{"\n"}</span>
                  <span className="cw">      - </span><span className="cv">&apos;DownloadString&apos;{"\n"}</span>
                  <span className="cw">  </span><span className="ck">condition</span><span className="cw">: </span><span className="cv">selection{"\n"}</span>
                  <span className="ck">level</span><span className="cw">: </span><span className="cy">high{"\n"}</span>
                  <span className="ck">tags</span><span className="cw">:{"\n"}</span>
                  <span className="cw">  - </span><span className="cv">attack.execution{"\n"}</span>
                  <span className="cw">  - </span><span className="cv">attack.t1059.001</span>
                </div>
              </div>
              <div style={{ display: "flex", gap: 10, marginTop: 14, flexWrap: "wrap" }}>
                {["VAPT Report", "Sigma Rule", "FAIR Assessment", "Remediation Playbook"].map(d => (
                  <span key={d} className="lp-pill" style={{ fontSize: 12, fontWeight: 600, borderColor: "var(--teal-pale)", color: "var(--teal-dark)", background: "var(--teal-pale)" }}>{d}</span>
                ))}
              </div>
            </div>

            <div className="lp-rv" style={{ transitionDelay: ".1s" }}>
              <span className="lp-tag">AI AGENTS</span>
              <h2 className="lp-h2">Not suggestions.<br /><em>Actual deliverables.</em></h2>
              <p className="lp-sec-sub">
                The agents here produce things you can ship: VAPT reports written from
                scan findings, Sigma detection rule stubs for every identified threat,
                FAIR-based risk assessments, and step-by-step remediation playbooks.
                Run an agent, get a document.
              </p>
              <ul className="lp-bullets">
                <li>VAPT reports generated from findings — executive summary, per-finding remediation, conclusion</li>
                <li>Sigma YAML rule stubs per threat, matched to the component's log source</li>
                <li>Orchestrator agent chains threat intel, compliance, and remediation in one run</li>
                <li>AI code review — function-level, 4-phase: triage → review → self-critique → cross-file taint</li>
                <li>Export as PDF or DOCX — full report or remediation plan only</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* ── CHAPTER 3: Multi-tenant ── */}
      <section className="lp-sec">
        <div className="lp-wrap">
          <div className="lp-chapter-grid">
            <div className="lp-rv">
              <span className="lp-tag">MULTI-TENANT</span>
              <h2 className="lp-h2">One console.<br /><em>Every client.</em></h2>
              <p className="lp-sec-sub">
                Multi-tenancy isn't an add-on. The client selector is global — every
                page, every agent, every report is scoped to the active account.
                Teams managing multiple organisations don't need to switch tabs, tools,
                or contexts.
              </p>
              <ul className="lp-bullets">
                <li>Global client context — no per-page selectors or repeated lookups</li>
                <li>Per-client findings, risks, compliance posture, VAPT history, and scorecard</li>
                <li>Soft-delete with 30-day retention, full restore, and permanent delete cascade</li>
                <li>Embeddable public scorecard per client — no auth required, embed anywhere</li>
                <li>Connector health dashboard — green/yellow/red per client, per scanner</li>
              </ul>
            </div>

            {/* client switcher visual */}
            <div className="lp-rv" style={{ transitionDelay: ".1s" }}>
              <div className="lp-clients-wrap">
                <div className="lp-clients-head">
                  <span className="lp-clients-head-label lp-mono">Active Account</span>
                  <span style={{ fontSize: 12, color: "var(--muted)", fontFamily: "IBM Plex Mono, monospace" }}>3 clients</span>
                </div>
                {[
                  { name: "ACME Corporation", meta: "12 findings · last scan 2h ago", color: "#10b981", tagCls: "ct-ok", tag: "Healthy" },
                  { name: "Northfield Group", meta: "3 critical · scan running", color: "#ef4444", tagCls: "ct-warn", tag: "Critical", active: true },
                  { name: "Meridian Holdings", meta: "Importing Nessus CSV…", color: "#f59e0b", tagCls: "ct-scan", tag: "Scanning" },
                ].map((c, i) => (
                  <div key={i} className={`lp-client-row${c.active ? " active" : ""}`}>
                    <span className="lp-client-dot" style={{ background: c.color }} />
                    <div className="lp-client-info">
                      <div className="lp-client-name">{c.name}</div>
                      <div className="lp-client-meta lp-mono">{c.meta}</div>
                    </div>
                    <span className={`lp-client-tag ${c.tagCls}`}>{c.tag}</span>
                  </div>
                ))}
                <div style={{ padding: "12px 18px", borderTop: "1px solid var(--line)", display: "flex", gap: 10 }}>
                  {["Findings", "Risk", "Posture", "VAPT"].map(t => (
                    <span key={t} style={{ fontSize: 11.5, padding: "4px 10px", borderRadius: 5, background: "var(--paper)", color: "var(--muted)", fontFamily: "IBM Plex Mono, monospace", cursor: "default" }}>{t}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── CHAPTER 4: Compliance to evidence ── */}
      <section className="lp-sec lp-sec-alt">
        <div className="lp-wrap">
          <div className="lp-chapter-grid flip">
            {/* framework visual */}
            <div className="lp-rv">
              <div className="lp-fw-wrap">
                <div className="lp-fw-head">
                  <span className="lp-fw-head-label lp-mono">Compliance Monitor</span>
                  <span className="lp-fw-sel lp-mono">NIST CSF 2.0</span>
                </div>
                {[
                  { id: "ID.AM-1", name: "Asset inventory maintained", st: "fs-pass", label: "Pass" },
                  { id: "ID.AM-2", name: "Software platform inventory", st: "fs-pass", label: "Pass" },
                  { id: "PR.AC-1", name: "Identity and credential management", st: "fs-fail", label: "Gap" },
                  { id: "PR.DS-1", name: "Data-at-rest protection", st: "fs-part", label: "Partial" },
                  { id: "DE.CM-1", name: "Network monitoring active", st: "fs-pass", label: "Pass" },
                  { id: "RS.RP-1", name: "Response plan in place", st: "fs-fail", label: "Gap" },
                ].map((r, i) => (
                  <div key={i} className="lp-fw-row" style={{ background: r.st === "fs-fail" ? "#fff8f8" : "transparent" }}>
                    <span className="lp-fw-id lp-mono">{r.id}</span>
                    <span className="lp-fw-name">{r.name}</span>
                    <span className={`lp-fw-status ${r.st} lp-mono`}>{r.label}</span>
                  </div>
                ))}
                <div className="lp-fw-foot">
                  <span className="lp-fw-foot-note lp-mono">67% compliant · 2 gaps</span>
                  <span className="lp-fw-dl">↓ Evidence ZIP</span>
                </div>
              </div>
            </div>

            <div className="lp-rv" style={{ transitionDelay: ".1s" }}>
              <span className="lp-tag">COMPLIANCE</span>
              <h2 className="lp-h2">Control gap to<br /><em>audit package.</em></h2>
              <p className="lp-sec-sub">
                Map findings directly to framework controls. Build custom frameworks
                from your own control library. When audit time comes, download a single
                ZIP with findings, control assessments, remediation logs, and agent reports — ready to hand over.
              </p>
              <ul className="lp-bullets">
                <li>NIST CSF 2.0, NIST AI RMF, ISO 27001, PCI DSS v4.0, GDPR, CIS v8 out of the box</li>
                <li>Custom framework builder — pick controls from any existing framework or write your own</li>
                <li>Compliance scoped to a specific scan — compare before and after a remediation sprint</li>
                <li>One-click evidence ZIP: findings CSV, control gaps JSON, remediation log, agent reports</li>
                <li>Framework advisor — AI recommends relevant frameworks based on your environment</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* ── INTEGRATIONS ── */}
      <div className="lp-integ" id="lp-integ">
        <div className="lp-wrap">
          <div className="lp-integ-head lp-rv">
            <p className="lp-mono">CONNECTS TO YOUR EXISTING STACK</p>
          </div>
          <div className="lp-integ-groups">
            {[
              { key: "scanners", items: ["Tenable.io", "Qualys VMDR", "Rapid7 InsightVM", "Burp Enterprise", "Snyk", "Invicti", "Acunetix"] },
              { key: "built-in", items: ["OWASP ZAP", "Nmap", "OpenVAS", "Semgrep", "CodeQL", "SonarQube", "Trivy", "Gitleaks", "TruffleHog"] },
              { key: "import", items: ["SARIF", "Nessus CSV", "Burp XML", "OpenVAS XML", "Qualys CSV", "Checkmarx", "Generic CSV / JSON"] },
              { key: "cloud", items: ["Azure (Entra ID · Defender · Resource Graph)", "AWS (Security Hub · Inspector)", "GitHub Actions"] },
              { key: "ai", items: ["Azure OpenAI", "OpenAI", "Google Gemini", "AWS Bedrock", "Anthropic Claude"] },
            ].map((g, i) => (
              <div key={i} className="lp-integ-row lp-rv" style={{ transitionDelay: `${i * 0.06}s` }}>
                <span className="lp-integ-key lp-mono">{g.key}</span>
                {g.items.map((it, j) => <span key={j} className="lp-pill">{it}</span>)}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── CAPABILITIES ── */}
      <section className="lp-cap" id="lp-cap">
        <div className="lp-wrap">
          <div className="lp-rv">
            <span className="lp-tag">WHAT'S IN THE PLATFORM</span>
            <h2 className="lp-h2" style={{ marginTop: 8 }}>Everything, enumerated.</h2>
            <p style={{ marginTop: 12, fontSize: 15, color: "var(--muted)" }}>No feature hidden behind a tier. Here's the full list.</p>
          </div>
          <div className="lp-cap-grid">
            {CAPABILITIES.map((g, i) => (
              <div key={i} className="lp-cap-group lp-rv" style={{ transitionDelay: `${i * 0.06}s` }}>
                <div className="lp-cap-group-tag lp-mono">{g.tag}</div>
                {g.items.map((it, j) => (
                  <div key={j} className="lp-cap-item">{it}</div>
                ))}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ── */}
      <section className="lp-cta">
        <div className="lp-wrap lp-rv">
          <h2>Ready to look inside?</h2>
          <p>Sign in with your organisation account and explore the platform.</p>
          <div className="lp-cta-actions">
            <button className="lp-btn lp-btn-amber lp-btn-lg" onClick={signIn}>Sign in</button>
          </div>
        </div>
      </section>

      {/* ── FOOTER ── */}
      <footer className="lp-footer">
        <div className="lp-wrap lp-footer-inner">
          <span className="lp-footer-note">© {new Date().getFullYear()} Owlet. All rights reserved.</span>
          <span className="lp-footer-sign" onClick={signIn}>Sign in →</span>
        </div>
      </footer>

    </div>
  );
}
