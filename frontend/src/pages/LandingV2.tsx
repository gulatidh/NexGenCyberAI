import { useEffect, useRef } from "react";
import { useMsal, useIsAuthenticated } from "@azure/msal-react";
import { useNavigate } from "react-router-dom";
import { loginRequest } from "../auth/msalConfig";

const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

  :root {
    --ink:#0C1116; --ink-soft:#2A3340; --paper:#EEF1F3; --card:#FFFFFF;
    --amber:#E8A33D; --amber-deep:#C77F1E;
    --teal:#2F6F62; --teal-bright:#3E9D89; --teal-soft:#E4EFEC;
    --violet:#7C6FE0; --coral:#E0716F; --line:#DCE2E5; --muted:#5B6672;
    --radius:18px; --wrap:1200px;
  }
  @property --angle { syntax:'<angle>'; initial-value:0deg; inherits:false; }

  .ol-land *{box-sizing:border-box;}
  .ol-land{-webkit-font-smoothing:antialiased; font-family:'Inter',sans-serif; color:var(--ink); background:var(--paper); position:relative;}
  .ol-land h1,.ol-land h2,.ol-land h3{font-family:'Space Grotesk',sans-serif;margin:0;letter-spacing:-0.01em;}
  .ol-mono{font-family:'IBM Plex Mono',monospace;}
  .ol-wrap{max-width:var(--wrap);margin:0 auto;padding:0 32px;}
  .ol-land a{color:inherit;text-decoration:none;}

  .ol-grain{position:fixed;inset:0;z-index:9999;pointer-events:none;opacity:.035;mix-blend-mode:multiply;
    background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='120' height='120'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");}

  .ol-reveal{opacity:0;transform:translateY(28px);transition:opacity .7s cubic-bezier(.16,1,.3,1),transform .7s cubic-bezier(.16,1,.3,1);}
  .ol-reveal.in{opacity:1;transform:translateY(0);}
  @media(prefers-reduced-motion:reduce){.ol-reveal{opacity:1;transform:none;transition:none;}}

  /* HEADER */
  .ol-header{position:sticky;top:0;z-index:50;background:rgba(238,241,243,0.72);backdrop-filter:blur(16px) saturate(160%);-webkit-backdrop-filter:blur(16px) saturate(160%);border-bottom:1px solid var(--line);}
  .ol-nav{display:flex;align-items:center;justify-content:space-between;height:72px;}
  .ol-nav-links{display:flex;gap:36px;font-size:14.5px;font-weight:500;color:var(--ink-soft);}
  .ol-nav-links a{position:relative;transition:color .15s ease;}
  .ol-nav-links a::after{content:"";position:absolute;left:0;bottom:-6px;width:0;height:1.5px;background:var(--amber-deep);transition:width .25s cubic-bezier(.16,1,.3,1);}
  .ol-nav-links a:hover{color:var(--ink);}
  .ol-nav-links a:hover::after{width:100%;}
  .ol-nav-cta{display:flex;align-items:center;gap:20px;}
  .ol-sign-in{font-size:14.5px;font-weight:500;color:var(--ink-soft);background:none;border:none;cursor:pointer;padding:0;font-family:'Inter',sans-serif;}
  .ol-sign-in:hover{color:var(--ink);}
  @media(max-width:860px){.ol-nav-links{display:none;}}

  /* BUTTONS */
  .ol-btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 22px;border-radius:999px;font-size:14.5px;font-weight:600;border:1px solid transparent;transition:transform .2s cubic-bezier(.16,1,.3,1),box-shadow .2s ease,background .2s ease;white-space:nowrap;position:relative;overflow:hidden;cursor:pointer;font-family:'Inter',sans-serif;text-decoration:none;}
  .ol-btn-lg{padding:14px 26px;font-size:15px;}
  .ol-btn-dark{background:var(--ink);color:#fff;}
  .ol-btn-dark:hover{transform:translateY(-2px);box-shadow:0 10px 24px rgba(12,17,22,0.28);}
  .ol-btn-ghost{border-color:var(--line);color:var(--ink);background:transparent;}
  .ol-btn-ghost:hover{border-color:var(--ink);transform:translateY(-2px);}
  .ol-btn-amber{background:var(--amber);color:var(--ink);}
  .ol-btn-amber:hover{background:#fff;transform:translateY(-2px);box-shadow:0 10px 24px rgba(232,163,61,0.28);}
  .ol-btn-ghost-dark{border-color:#3A4552;color:#fff;background:transparent;}
  .ol-btn-ghost-dark:hover{border-color:#fff;transform:translateY(-2px);}
  .ol-shine{position:absolute;top:0;left:-120%;width:60%;height:100%;background:linear-gradient(120deg,transparent,rgba(255,255,255,0.35),transparent);transform:skewX(-20deg);transition:left .6s ease;}
  .ol-btn:hover .ol-shine{left:130%;}

  /* HERO */
  .ol-hero{position:relative;padding:96px 0 0;overflow:hidden;}
  .ol-mesh{position:absolute;inset:-20% -10% auto -10%;height:900px;z-index:0;filter:blur(60px);opacity:.55;pointer-events:none;}
  .ol-blob{position:absolute;border-radius:50%;animation:ol-float 14s ease-in-out infinite;}
  .ol-blob1{width:480px;height:480px;top:-140px;left:-80px;background:radial-gradient(circle at 30% 30%,#3E9D89,transparent 70%);}
  .ol-blob2{width:420px;height:420px;top:60px;right:-100px;background:radial-gradient(circle at 60% 40%,#E8A33D,transparent 70%);animation-delay:-4s;}
  .ol-blob3{width:360px;height:360px;top:220px;left:40%;background:radial-gradient(circle at 50% 50%,#0C1116,transparent 70%);opacity:.4;animation-delay:-8s;}
  @keyframes ol-float{0%,100%{transform:translate(0,0) scale(1);}33%{transform:translate(20px,-30px) scale(1.05);}66%{transform:translate(-25px,15px) scale(0.97);}}
  @media(prefers-reduced-motion:reduce){.ol-blob{animation:none;}}
  .ol-spotlight{position:absolute;width:600px;height:600px;border-radius:50%;pointer-events:none;background:radial-gradient(circle,rgba(232,163,61,0.12),transparent 65%);transform:translate(-50%,-50%);z-index:0;transition:opacity .3s ease;opacity:0;}

  .ol-hero-grid{position:relative;z-index:1;display:grid;grid-template-columns:1.05fr 0.95fr;gap:48px;align-items:center;}
  @media(max-width:860px){.ol-hero-grid{grid-template-columns:1fr;}}
  .ol-eyebrow{display:inline-flex;align-items:center;gap:8px;font-size:12.5px;letter-spacing:.06em;color:var(--teal);background:var(--teal-soft);padding:6px 12px;border-radius:999px;margin-bottom:22px;border:1px solid rgba(47,111,98,.15);}
  .ol-eyebrow::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--teal-bright);animation:ol-pulse-dot 2s ease-in-out infinite;}
  @keyframes ol-pulse-dot{0%,100%{opacity:1;}50%{opacity:.3;}}
  .ol-h1{font-size:clamp(36px,4.6vw,60px);line-height:1.03;font-weight:700;}
  .ol-grad{background:linear-gradient(100deg,var(--amber-deep),var(--teal-bright) 60%,var(--amber-deep));background-size:200% auto;-webkit-background-clip:text;background-clip:text;color:transparent;animation:ol-grad-shift 6s ease-in-out infinite;}
  @keyframes ol-grad-shift{0%,100%{background-position:0% center;}50%{background-position:100% center;}}
  @media(prefers-reduced-motion:reduce){.ol-grad{animation:none;}}
  .ol-lead{margin-top:22px;font-size:18px;line-height:1.6;color:var(--muted);max-width:520px;}
  .ol-hero-ctas{display:flex;gap:14px;margin-top:34px;flex-wrap:wrap;}

  .ol-radar-panel{background:rgba(255,255,255,0.5);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.6);border-radius:28px;padding:36px;box-shadow:0 20px 60px rgba(12,17,22,.08),inset 0 1px 0 rgba(255,255,255,.8);}
  .ol-radar-wrap{position:relative;aspect-ratio:1/1;max-width:400px;margin:0 auto;}
  .ol-ring{position:absolute;inset:0;border-radius:50%;border:1px solid rgba(12,17,22,.12);}
  .ol-ring.r2{inset:14%;}.ol-ring.r3{inset:28%;}.ol-ring.r4{inset:42%;}
  .ol-sweep{position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,rgba(62,157,137,0.4),transparent 30%);animation:ol-spin 5s linear infinite;mix-blend-mode:multiply;}
  @keyframes ol-spin{to{transform:rotate(360deg);}}
  .ol-center{position:absolute;left:50%;top:50%;width:8px;height:8px;background:var(--ink);border-radius:50%;transform:translate(-50%,-50%);}
  .ol-blip{position:absolute;width:9px;height:9px;border-radius:50%;background:var(--teal-bright);box-shadow:0 0 10px rgba(62,157,137,.6);}
  .ol-blip.crit{background:var(--amber-deep);box-shadow:0 0 0 0 rgba(199,127,30,.6),0 0 12px rgba(199,127,30,.8);animation:ol-blip-pulse 1.8s ease-out infinite;}
  @keyframes ol-blip-pulse{0%{box-shadow:0 0 0 0 rgba(199,127,30,.5),0 0 12px rgba(199,127,30,.8);}70%{box-shadow:0 0 0 16px rgba(199,127,30,0),0 0 12px rgba(199,127,30,.8);}100%{box-shadow:0 0 0 0 rgba(199,127,30,0),0 0 12px rgba(199,127,30,.8);}}
  .ol-radar-caption{display:flex;justify-content:space-between;margin-top:18px;font-size:12px;color:var(--muted);}
  @media(prefers-reduced-motion:reduce){.ol-sweep{animation:none;}.ol-eyebrow::before{animation:none;}.ol-blip.crit{animation:none;}}

  /* TICKER */
  .ol-ticker-outer{position:relative;z-index:1;margin-top:70px;border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:var(--ink);overflow:hidden;white-space:nowrap;}
  .ol-ticker-track{display:inline-flex;padding:14px 0;animation:ol-ticker 32s linear infinite;}
  @media(prefers-reduced-motion:reduce){.ol-ticker-track{animation:none;}}
  @keyframes ol-ticker{from{transform:translateX(0);}to{transform:translateX(-50%);}}
  .ol-tick-item{font-size:13px;color:#C7D0D6;padding:0 32px;border-right:1px solid #2A3340;}
  .ol-tag{color:var(--amber);margin-right:8px;}

  /* STATS */
  .ol-stats{padding:64px 0;}
  .ol-stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:22px;}
  @media(max-width:760px){.ol-stats-grid{grid-template-columns:repeat(2,1fr);}}
  .ol-stat-card{position:relative;padding:26px 24px;border-radius:18px;background:var(--card);border:1px solid var(--line);overflow:hidden;transition:transform .35s cubic-bezier(.16,1,.3,1),box-shadow .35s ease,border-color .35s ease;}
  .ol-stat-card::before{content:"";position:absolute;inset:0;background:radial-gradient(220px circle at var(--mx,50%) var(--my,50%),rgba(62,157,137,.16),transparent 60%);opacity:0;transition:opacity .3s ease;}
  .ol-stat-card:hover::before{opacity:1;}
  .ol-stat-card:hover{transform:translateY(-6px);box-shadow:0 18px 36px rgba(12,17,22,.08);border-color:rgba(62,157,137,.3);}
  .ol-stat-num{font-family:'Space Grotesk',sans-serif;font-size:38px;font-weight:700;position:relative;}
  .ol-stat-label{position:relative;margin-top:6px;font-size:13.5px;color:var(--muted);}

  /* SECTION */
  .ol-section{padding:96px 0;position:relative;}
  .ol-section-head{max-width:640px;margin:0 auto 56px;text-align:center;}
  .ol-h2{font-size:clamp(28px,3.4vw,42px);font-weight:700;}
  .ol-h2-sm{font-size:clamp(26px,3vw,36px);font-weight:700;max-width:520px;}
  .ol-accent{background:linear-gradient(100deg,var(--teal-bright),var(--violet));-webkit-background-clip:text;background-clip:text;color:transparent;}
  .ol-section-head p{margin-top:16px;font-size:17px;color:var(--muted);line-height:1.6;}
  .ol-dotfield{position:absolute;inset:0;z-index:-1;background-image:radial-gradient(circle,rgba(12,17,22,.08) 1px,transparent 1px);background-size:26px 26px;-webkit-mask-image:radial-gradient(ellipse 60% 50% at 50% 30%,black 20%,transparent 75%);mask-image:radial-gradient(ellipse 60% 50% at 50% 30%,black 20%,transparent 75%);}

  /* PRODUCT CARDS */
  .ol-cat-groups{display:grid;grid-template-columns:repeat(4,1fr);gap:20px;perspective:1200px;}
  @media(max-width:980px){.ol-cat-groups{grid-template-columns:repeat(2,1fr);}}
  @media(max-width:560px){.ol-cat-groups{grid-template-columns:1fr;}}
  .ol-cat-group{position:relative;background:var(--card);border-radius:var(--radius);padding:2px;transform-style:preserve-3d;will-change:transform;}
  .ol-glow-border{position:absolute;inset:0;border-radius:var(--radius);padding:1.5px;background:conic-gradient(from var(--angle,0deg),var(--accent1),var(--accent2),var(--accent1));-webkit-mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0);-webkit-mask-composite:xor;mask-composite:exclude;opacity:0;transition:opacity .35s ease;animation:ol-rot-border 3.5s linear infinite;}
  .ol-cat-group:hover .ol-glow-border{opacity:1;}
  @keyframes ol-rot-border{to{--angle:360deg;}}
  @media(prefers-reduced-motion:reduce){.ol-glow-border{animation:none;}}
  .ol-cat-inner{position:relative;background:var(--card);border:1px solid var(--line);border-radius:calc(var(--radius) - 2px);padding:26px 22px;height:100%;transition:border-color .3s ease,box-shadow .3s ease;}
  .ol-cat-group:hover .ol-cat-inner{border-color:transparent;box-shadow:0 24px 48px rgba(12,17,22,.10);}
  .ol-cat-icon{width:38px;height:38px;border-radius:11px;display:flex;align-items:center;justify-content:center;background:var(--icon-bg);margin-bottom:16px;transition:transform .4s cubic-bezier(.34,1.56,.64,1);}
  .ol-cat-group:hover .ol-cat-icon{transform:scale(1.12) rotate(-6deg);}
  .ol-cat-tag{font-size:11px;letter-spacing:.08em;color:var(--teal);margin-bottom:18px;display:block;}
  .ol-product-item{padding:16px 0;border-top:1px solid var(--line);}
  .ol-product-item:first-of-type{border-top:none;padding-top:0;}
  .ol-h3{font-size:16.5px;font-weight:600;margin-bottom:6px;font-family:'Space Grotesk',sans-serif;}
  .ol-product-item p{font-size:13.5px;color:var(--muted);line-height:1.5;margin:0;}
  .ol-cg-detect{--accent1:#3E9D89;--accent2:#7C6FE0;--icon-bg:#E4EFEC;}
  .ol-cg-assess{--accent1:#E8A33D;--accent2:#E0716F;--icon-bg:#FBEBD8;}
  .ol-cg-respond{--accent1:#7C6FE0;--accent2:#3E9D89;--icon-bg:#EEECFB;}
  .ol-cg-govern{--accent1:#E0716F;--accent2:#E8A33D;--icon-bg:#FBE4E3;}

  /* CAROUSEL */
  .ol-carousel-head{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:32px;}
  .ol-carousel-nav{display:flex;gap:10px;}
  .ol-nav-arrow{width:40px;height:40px;border-radius:50%;border:1px solid var(--line);background:var(--card);display:flex;align-items:center;justify-content:center;transition:background .2s ease,border-color .2s ease,transform .2s ease;cursor:pointer;color:var(--ink);}
  .ol-nav-arrow:hover{background:var(--ink);border-color:var(--ink);transform:scale(1.06);color:#fff;}
  .ol-carousel-track{display:flex;gap:20px;overflow-x:auto;scroll-snap-type:x mandatory;padding:6px 6px 14px;scrollbar-width:none;perspective:1200px;}
  .ol-carousel-track::-webkit-scrollbar{display:none;}
  .ol-car-card{flex:0 0 auto;width:300px;scroll-snap-align:start;position:relative;background:rgba(255,255,255,0.65);backdrop-filter:blur(12px);border:1px solid var(--line);border-radius:var(--radius);padding:28px 24px 26px;display:flex;flex-direction:column;gap:14px;transition:transform .3s cubic-bezier(.16,1,.3,1),box-shadow .3s ease,border-color .3s ease;transform-style:preserve-3d;will-change:transform;overflow:hidden;}
  .ol-car-card::after{content:"";position:absolute;inset:0;background:radial-gradient(180px circle at var(--mx,50%) var(--my,50%),rgba(255,255,255,0.55),transparent 60%);opacity:0;transition:opacity .3s ease;pointer-events:none;}
  .ol-car-card:hover::after{opacity:1;}
  .ol-car-card:hover{box-shadow:0 22px 44px rgba(12,17,22,.12);border-color:rgba(62,157,137,.3);}
  .ol-car-icon{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,var(--teal-soft),#fff);transition:transform .4s cubic-bezier(.34,1.56,.64,1);}
  .ol-car-card:hover .ol-car-icon{transform:scale(1.1) rotate(6deg);}
  .ol-car-card h3{font-size:19px;font-weight:600;font-family:'Space Grotesk',sans-serif;margin:0;}
  .ol-car-card p{font-size:14px;color:var(--muted);line-height:1.55;margin:0;}

  /* CTA */
  .ol-cta-banner{position:relative;background:linear-gradient(160deg,#0C1116,#16222A 60%,#10201C);color:#fff;border-radius:28px;padding:72px 48px;text-align:center;overflow:hidden;}
  .ol-grid-pat{position:absolute;inset:0;background-image:linear-gradient(rgba(255,255,255,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.045) 1px,transparent 1px);background-size:36px 36px;-webkit-mask-image:radial-gradient(ellipse 70% 60% at 50% 50%,black,transparent 80%);mask-image:radial-gradient(ellipse 70% 60% at 50% 50%,black,transparent 80%);pointer-events:none;}
  .ol-cta-banner::before{content:"";position:absolute;inset:0;background:radial-gradient(circle at 30% 20%,rgba(62,157,137,.25),transparent 55%),radial-gradient(circle at 80% 80%,rgba(232,163,61,.18),transparent 55%);pointer-events:none;}
  .ol-cta-tagline{position:relative;font-size:15px;letter-spacing:.02em;color:var(--amber);margin-bottom:14px;font-weight:600;font-family:'Space Grotesk',sans-serif;}
  .ol-h2-cta{position:relative;font-size:clamp(28px,3.6vw,42px);font-weight:700;color:#fff;max-width:600px;margin:0 auto;}
  .ol-sub{position:relative;color:#A6B0B8;margin-top:14px;font-size:16px;}

  /* FOOTER */
  .ol-footer{margin-top:96px;padding:64px 0 32px;border-top:1px solid var(--line);}
  .ol-footer-top{display:grid;grid-template-columns:1.4fr repeat(4,1fr);gap:32px;padding-bottom:48px;}
  @media(max-width:860px){.ol-footer-top{grid-template-columns:repeat(2,1fr);}}
  .ol-footer-head{font-size:12.5px;letter-spacing:.06em;color:var(--muted);margin:0 0 16px;font-family:'Space Grotesk',sans-serif;}
  .ol-footer-col ul{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:11px;}
  .ol-footer-col a{font-size:14px;color:var(--ink-soft);transition:color .15s ease;}
  .ol-footer-col a:hover{color:var(--ink);}
  .ol-footer-bottom{display:flex;justify-content:space-between;align-items:center;padding-top:28px;border-top:1px solid var(--line);font-size:13px;color:var(--muted);flex-wrap:wrap;gap:12px;}
  .ol-footer-bottom-links{display:flex;gap:20px;}
`;

const TICKER_ITEMS = [
  ["SCAN",  "214 assets scanned — 3 critical findings"],
  ["CVE",   "New disclosure matched to 2 internet-facing hosts"],
  ["DRIFT", "Compliance drift detected — ISO 27001 A.12.4"],
  ["AGENT", "AI Security Advisor closed 12 findings automatically"],
  ["PATH",  "Attack path identified — public host → domain admin"],
  ["RISK",  "Financial exposure re-scored for this week"],
  ["SCAN",  "214 assets scanned — 3 critical findings"],
  ["CVE",   "New disclosure matched to 2 internet-facing hosts"],
  ["DRIFT", "Compliance drift detected — ISO 27001 A.12.4"],
  ["AGENT", "AI Security Advisor closed 12 findings automatically"],
  ["PATH",  "Attack path identified — public host → domain admin"],
  ["RISK",  "Financial exposure re-scored — down 8% this week"],
];

const STATS = [
  { target: 60, suffix: "+", label: "specialist AI agents" },
  { target: 8,  suffix: "",  label: "purpose-built products" },
  { target: 5,  suffix: "-phase", label: "CTEM workflow" },
  { target: 4,  suffix: "",  label: "frameworks: NIST, ISO 27001, PCI DSS, GDPR" },
];

const CAROUSEL_CARDS = [
  { title: "Deployment",  desc: "Runs in your cloud, on-prem, or fully hosted — same platform, same agents, same console either way.",
    icon: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#2F6F62" strokeWidth="1.8"><rect x="3" y="4" width="18" height="14" rx="2"/><path d="M8 21h8M12 18v3"/></svg> },
  { title: "Onboarding",  desc: "Point Owlet at a tenant and get posture, findings, and risk scoring the same day.",
    icon: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#2F6F62" strokeWidth="1.8"><path d="M13 2 3 14h7l-1 8 10-12h-7l1-8Z"/></svg> },
  { title: "Support",     desc: "Analysts who've run SOCs answer questions directly — not a generic ticket queue.",
    icon: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#2F6F62" strokeWidth="1.8"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/></svg> },
  { title: "Licensing",   desc: "License by product or by platform, and scale as tenants, agents, and assets grow.",
    icon: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#2F6F62" strokeWidth="1.8"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg> },
  { title: "Frameworks",  desc: "Map custom controls alongside NIST, ISO, PCI DSS, and GDPR out of the box.",
    icon: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#2F6F62" strokeWidth="1.8"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></svg> },
];

export default function LandingV2() {
  const { instance } = useMsal();
  const isAuthenticated = useIsAuthenticated();
  const navigate = useNavigate();
  const carRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isAuthenticated) navigate("/hub", { replace: true });
  }, [isAuthenticated, navigate]);

  // Inject CSS
  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = CSS;
    document.head.appendChild(style);
    return () => { document.head.removeChild(style); };
  }, []);

  // Scroll reveal
  useEffect(() => {
    const els = document.querySelectorAll<HTMLElement>(".ol-reveal");
    const io = new IntersectionObserver(entries => {
      entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } });
    }, { threshold: 0.12 });
    els.forEach(el => io.observe(el));
    return () => io.disconnect();
  }, []);

  // Spotlight
  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const hero = document.getElementById("ol-hero");
    const spot = document.getElementById("ol-spotlight");
    if (reduced || !hero || !spot) return;
    const move = (e: MouseEvent) => {
      const r = hero.getBoundingClientRect();
      spot.style.left = (e.clientX - r.left) + "px";
      spot.style.top  = (e.clientY - r.top)  + "px";
      spot.style.opacity = "1";
    };
    const leave = () => { spot.style.opacity = "0"; };
    hero.addEventListener("mousemove", move);
    hero.addEventListener("mouseleave", leave);
    return () => { hero.removeEventListener("mousemove", move); hero.removeEventListener("mouseleave", leave); };
  }, []);

  // Tilt + glow
  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!reduced) {
      document.querySelectorAll<HTMLElement>(".ol-tilt").forEach(card => {
        const move = (e: MouseEvent) => {
          const r = card.getBoundingClientRect();
          const x = (e.clientX - r.left) / r.width  - 0.5;
          const y = (e.clientY - r.top)  / r.height - 0.5;
          card.style.transform = `rotateY(${x * 7}deg) rotateX(${-y * 7}deg) translateY(-4px)`;
        };
        const leave = () => { card.style.transform = ""; };
        card.addEventListener("mousemove", move);
        card.addEventListener("mouseleave", leave);
      });
    }
    document.querySelectorAll<HTMLElement>(".ol-stat-card, .ol-car-card").forEach(card => {
      card.addEventListener("mousemove", (e: MouseEvent) => {
        const r = card.getBoundingClientRect();
        card.style.setProperty("--mx", ((e.clientX - r.left) / r.width  * 100) + "%");
        card.style.setProperty("--my", ((e.clientY - r.top)  / r.height * 100) + "%");
      });
    });
  }, []);

  // Counters
  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const io = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        const el = entry.target as HTMLElement;
        const target = parseInt(el.dataset.target || "0", 10);
        const suffix = el.dataset.suffix || "";
        if (reduced) { el.textContent = target + suffix; io.unobserve(el); return; }
        const start = performance.now();
        const tick = (now: number) => {
          const p = Math.min((now - start) / 1200, 1);
          el.textContent = Math.round((1 - Math.pow(1 - p, 3)) * target) + suffix;
          if (p < 1) requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
        io.unobserve(el);
      });
    }, { threshold: 0.5 });
    document.querySelectorAll(".ol-counter").forEach(c => io.observe(c));
    return () => io.disconnect();
  }, []);

  const signIn = () => instance.loginRedirect({ ...loginRequest, redirectStartPage: `${window.location.origin}/hub` }).catch(console.error);
  const scrollCar = (dir: number) => carRef.current?.scrollBy({ left: 640 * dir, behavior: "smooth" });

  return (
    <div className="ol-land">
      <div className="ol-grain" aria-hidden="true" />

      {/* NAV */}
      <header className="ol-header">
        <div className="ol-wrap ol-nav">
          <img src="/owlet-logo.svg" alt="Owlet" style={{ height: 36, width: "auto" }} />
          <nav className="ol-nav-links">
            <a href="#ol-platform">Platform</a>
            <a href="#ol-products">Products</a>
            <a href="#ol-why">Why Owlet</a>
          </nav>
          <div className="ol-nav-cta">
            <button className="ol-sign-in" onClick={signIn}>Sign in</button>
            <button className="ol-btn ol-btn-dark" onClick={signIn}>
              <span className="ol-shine" />Explore the platform
            </button>
          </div>
        </div>
      </header>

      {/* HERO */}
      <section className="ol-hero" id="ol-hero">
        <div className="ol-mesh" aria-hidden="true">
          <div className="ol-blob ol-blob1" />
          <div className="ol-blob ol-blob2" />
          <div className="ol-blob ol-blob3" />
        </div>
        <div className="ol-spotlight" id="ol-spotlight" aria-hidden="true" />
        <div className="ol-wrap">
          <div className="ol-hero-grid">
            <div className="ol-reveal">
              <span className="ol-eyebrow ol-mono">CONTINUOUS SECURITY MONITORING</span>
              <h1 className="ol-h1">See your exposure. <span className="ol-grad">See it clearly.</span></h1>
              <p className="ol-lead">Owlet brings vulnerability management, threat intelligence, compliance, and risk into one console — with 60+ AI agents doing the work across every tenant you manage.</p>
              <div className="ol-hero-ctas">
                <button className="ol-btn ol-btn-dark ol-btn-lg" onClick={signIn}><span className="ol-shine" />See the platform</button>
                <a href="#ol-why" className="ol-btn ol-btn-ghost ol-btn-lg">How it works</a>
              </div>
            </div>
            <div className="ol-radar-panel ol-reveal">
              <div className="ol-radar-wrap" aria-hidden="true">
                <div className="ol-ring" /><div className="ol-ring r2" /><div className="ol-ring r3" /><div className="ol-ring r4" />
                <div className="ol-sweep" />
                <div className="ol-center" />
                <div className="ol-blip" style={{ left: "22%", top: "38%" }} />
                <div className="ol-blip" style={{ left: "68%", top: "26%" }} />
                <div className="ol-blip crit" style={{ left: "74%", top: "64%" }} />
                <div className="ol-blip" style={{ left: "40%", top: "76%" }} />
                <div className="ol-blip" style={{ left: "58%", top: "50%" }} />
              </div>
              <div className="ol-radar-caption ol-mono"><span>214 assets</span><span>3 critical</span><span>live</span></div>
            </div>
          </div>
        </div>
        <div className="ol-ticker-outer" role="marquee" aria-label="Live platform activity">
          <div className="ol-ticker-track">
            {TICKER_ITEMS.map(([tag, text], i) => (
              <span key={i} className="ol-tick-item ol-mono"><span className="ol-tag">{tag}</span>{text}</span>
            ))}
          </div>
        </div>
      </section>

      {/* STATS */}
      <section className="ol-stats" id="ol-platform">
        <div className="ol-wrap ol-stats-grid">
          {STATS.map((s, i) => (
            <div key={i} className="ol-stat-card ol-reveal">
              <div className="ol-stat-num">
                <span className="ol-counter" data-target={String(s.target)} data-suffix={s.suffix}>0</span>
              </div>
              <div className="ol-stat-label">{s.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* PRODUCTS */}
      <section className="ol-section" id="ol-products">
        <div className="ol-dotfield" aria-hidden="true" />
        <div className="ol-wrap">
          <div className="ol-section-head ol-reveal">
            <h2 className="ol-h2">One platform, <span className="ol-accent">every</span> security function</h2>
            <p>Eight purpose-built products across four categories — choose what you need, or run them all together.</p>
          </div>
          <div className="ol-cat-groups">
            <div className="ol-cat-group ol-cg-detect ol-reveal ol-tilt">
              <div className="ol-glow-border" />
              <div className="ol-cat-inner">
                <div className="ol-cat-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2F6F62" strokeWidth="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg></div>
                <span className="ol-cat-tag ol-mono">DETECT</span>
                <div className="ol-product-item"><h3 className="ol-h3">Threat Intelligence</h3><p>MITRE ATT&amp;CK–mapped threats, attack path graphs, and exposure tracking.</p></div>
                <div className="ol-product-item"><h3 className="ol-h3">Attack Surface Discovery</h3><p>Continuous asset and exposure mapping across cloud, on-prem, and shadow IT.</p></div>
              </div>
            </div>
            <div className="ol-cat-group ol-cg-assess ol-reveal ol-tilt">
              <div className="ol-glow-border" />
              <div className="ol-cat-inner">
                <div className="ol-cat-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#C77F1E" strokeWidth="2"><path d="M12 20V10M18 20V4M6 20v-4"/></svg></div>
                <span className="ol-cat-tag ol-mono">ASSESS</span>
                <div className="ol-product-item"><h3 className="ol-h3">Vulnerability Management</h3><p>Scans, findings, posture trends, and multi-scanner orchestration in one place.</p></div>
                <div className="ol-product-item"><h3 className="ol-h3">Risk Manager</h3><p>FAIR-lite ALE scoring, financial exposure dashboards, and board-ready reports.</p></div>
              </div>
            </div>
            <div className="ol-cat-group ol-cg-respond ol-reveal ol-tilt">
              <div className="ol-glow-border" />
              <div className="ol-cat-inner">
                <div className="ol-cat-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#7C6FE0" strokeWidth="2"><path d="M13 2 3 14h7l-1 8 10-12h-7l1-8Z"/></svg></div>
                <span className="ol-cat-tag ol-mono">RESPOND</span>
                <div className="ol-product-item"><h3 className="ol-h3">AI Security Advisor</h3><p>60+ specialist AI agents — risk scoring, threat intel, IR playbooks, and more.</p></div>
                <div className="ol-product-item"><h3 className="ol-h3">Incident Response</h3><p>Guided runbooks and automated containment steps when something is actually wrong.</p></div>
              </div>
            </div>
            <div className="ol-cat-group ol-cg-govern ol-reveal ol-tilt">
              <div className="ol-glow-border" />
              <div className="ol-cat-inner">
                <div className="ol-cat-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#E0716F" strokeWidth="2"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M8 2v4M16 2v4M3 10h18"/></svg></div>
                <span className="ol-cat-tag ol-mono">GOVERN</span>
                <div className="ol-product-item"><h3 className="ol-h3">Compliance Monitor</h3><p>Framework control gaps across NIST, ISO 27001, PCI DSS, GDPR, and CIS v8.</p></div>
                <div className="ol-product-item"><h3 className="ol-h3">Governance &amp; CTEM</h3><p>5-phase CTEM workflow, remediation tracker, and an embeddable security scorecard.</p></div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* WHY / CAROUSEL */}
      <section className="ol-section" id="ol-why" style={{ paddingTop: 0 }}>
        <div className="ol-wrap">
          <div className="ol-carousel-head ol-reveal">
            <h2 className="ol-h2-sm">How Owlet fits into your stack</h2>
            <div className="ol-carousel-nav">
              <button className="ol-nav-arrow" onClick={() => scrollCar(-1)} aria-label="Previous">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M15 18l-6-6 6-6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" stroke="currentColor"/></svg>
              </button>
              <button className="ol-nav-arrow" onClick={() => scrollCar(1)} aria-label="Next">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M9 18l6-6-6-6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" stroke="currentColor"/></svg>
              </button>
            </div>
          </div>
          <div className="ol-carousel-track ol-reveal" ref={carRef}>
            {CAROUSEL_CARDS.map((c, i) => (
              <div key={i} className="ol-car-card ol-tilt">
                <div className="ol-car-icon">{c.icon}</div>
                <h3>{c.title}</h3>
                <p>{c.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA BANNER */}
      <section className="ol-section" style={{ paddingTop: 0 }}>
        <div className="ol-wrap">
          <div className="ol-cta-banner ol-reveal">
            <div className="ol-grid-pat" aria-hidden="true" />
            <div className="ol-cta-tagline ol-mono">OWLET</div>
            <h2 className="ol-h2-cta">Everything security teams need to know, in one place.</h2>
            <p className="ol-sub">Point Owlet at a tenant and see posture, findings, and risk the same day.</p>
            <div className="ol-hero-ctas" style={{ justifyContent: "center", marginTop: 30 }}>
              <button className="ol-btn ol-btn-amber ol-btn-lg" onClick={signIn}><span className="ol-shine" />See the platform</button>
              <a href="#ol-products" className="ol-btn ol-btn-ghost-dark ol-btn-lg">Learn more</a>
            </div>
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="ol-footer">
        <div className="ol-wrap">
          <div className="ol-footer-top">
            <div className="ol-footer-col">
              <img src="/owlet-logo.svg" alt="Owlet" style={{ height: 32, width: "auto", marginBottom: 14, display: "block" }} />
              <p style={{ fontSize: 13.5, color: "var(--muted)", lineHeight: 1.6, maxWidth: 220, margin: 0 }}>One platform for vulnerability management, threat intelligence, compliance, and risk.</p>
            </div>
            <div className="ol-footer-col">
              <h4 className="ol-footer-head">PRODUCT</h4>
              <ul>
                <li><a href="#ol-products">Vulnerability Management</a></li>
                <li><a href="#ol-products">Threat Intelligence</a></li>
                <li><a href="#ol-products">Compliance Monitor</a></li>
                <li><a href="#ol-products">Risk Manager</a></li>
                <li><a href="#ol-products">AI Security Advisor</a></li>
              </ul>
            </div>
            <div className="ol-footer-col">
              <h4 className="ol-footer-head">PLATFORM</h4>
              <ul>
                <li><a href="#ol-platform">Multi-tenant console</a></li>
                <li><a href="#ol-platform">AI agents</a></li>
                <li><a href="#ol-platform">Integrations</a></li>
                <li><a href="#ol-platform">API reference</a></li>
              </ul>
            </div>
            <div className="ol-footer-col">
              <h4 className="ol-footer-head">COMPANY</h4>
              <ul>
                <li><a href="#ol-why">About</a></li>
                <li><a href="#ol-why">Careers</a></li>
                <li><a href="#ol-why">Blog</a></li>
                <li><a href="#ol-why">Contact</a></li>
              </ul>
            </div>
            <div className="ol-footer-col">
              <h4 className="ol-footer-head">RESOURCES</h4>
              <ul>
                <li><a href="#">Docs</a></li>
                <li><a href="#">Security</a></li>
                <li><a href="#">Trust center</a></li>
                <li><a href="#">Status</a></li>
              </ul>
            </div>
          </div>
          <div className="ol-footer-bottom">
            <span>© {new Date().getFullYear()} Owlet. All rights reserved.</span>
            <div className="ol-footer-bottom-links"><a href="#">Privacy</a><a href="#">Terms</a><a href="#">Trust center</a></div>
          </div>
        </div>
      </footer>
    </div>
  );
}
