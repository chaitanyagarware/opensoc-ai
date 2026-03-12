import { useState, useRef, useCallback } from "react";

// ─────────────────────────────────────────────────────────────────────────────
// IMPORTANT: Replace this URL after deploying your Cloudflare Worker proxy
// See PROXY_SETUP.md for step-by-step instructions
// ─────────────────────────────────────────────────────────────────────────────
const PROXY_URL = "https://opensoc-proxy.chaitanyagarware01.workers.dev";

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#dc2626", bg: "#450a0a", border: "#991b1b", light: "#fca5a5" },
  HIGH:     { color: "#ea580c", bg: "#431407", border: "#9a3412", light: "#fdba74" },
  MEDIUM:   { color: "#d97706", bg: "#451a03", border: "#92400e", light: "#fcd34d" },
  LOW:      { color: "#16a34a", bg: "#052e16", border: "#166534", light: "#86efac" },
  INFO:     { color: "#2563eb", bg: "#172554", border: "#1e40af", light: "#93c5fd" },
};

const SAMPLES = [
  `192.168.1.45 - admin [12/Mar/2025:03:17:42 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28.0"`,
  `91.108.4.20 - - [16/Mar/2025:01:05:33 +0000] "GET /profile?id=1 OR 1=1-- HTTP/1.1" 403 12466 "-" "burpsuite"`,
  `10.0.0.5 - - [12/Mar/2025:14:22:11 +0000] "GET /../../../etc/passwd HTTP/1.1" 404 287 "-" "curl/7.68.0"`,
  `172.16.0.3 - - [12/Mar/2025:22:11:05 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 8421 "-" "Mozilla/5.0"`,
];

const SYSTEM_PROMPT = `You are OpenSOC-AI, an expert security analyst. Analyze the security log entry and return ONLY valid JSON with these exact fields:
{
  "threat_type": "category name e.g. SQL Injection, Brute Force, Path Traversal, XSS, Command Injection, Reconnaissance, Benign",
  "mitre_id": "ATT&CK technique ID e.g. T1190, T1110, T1059",
  "severity": "exactly one of: CRITICAL, HIGH, MEDIUM, LOW, INFO",
  "risk_score": integer 0-100,
  "evidence": "specific suspicious indicators found in the log",
  "recommendation": "one concrete remediation step"
}
Return ONLY the JSON object. No markdown fences, no explanation.`;

async function analyzeLog(logText) {
  const res = await fetch(PROXY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 600,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: `Analyze this security log entry:\n\n${logText}` }],
    }),
  });
  if (!res.ok) {
    const err = await res.text().catch(() => "");
    throw new Error(`Proxy returned ${res.status}${err ? ": " + err.slice(0, 120) : ""}`);
  }
  const data = await res.json();
  const raw = data.content?.map(b => b.text || "").join("") || "";
  const clean = raw.replace(/```json|```/g, "").trim();
  return JSON.parse(clean);
}

// ── STYLES ────────────────────────────────────────────────────────────────────
const css = `
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: #09090b;
    color: #e4e4e7;
    font-family: 'IBM Plex Sans', sans-serif;
    font-size: 16px;
    line-height: 1.6;
    min-height: 100vh;
  }

  .app {
    max-width: 1280px;
    margin: 0 auto;
    padding: 0 24px 60px;
  }

  /* HEADER */
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 24px 0 20px;
    border-bottom: 1px solid #27272a;
    margin-bottom: 40px;
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .logo-icon {
    width: 40px; height: 40px;
    background: linear-gradient(135deg, #f97316, #dc2626);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
  }
  .logo-text { font-family: 'IBM Plex Mono', monospace; font-size: 22px; font-weight: 600; color: #fff; letter-spacing: -0.5px; }
  .logo-sub { font-size: 13px; color: #71717a; margin-top: 1px; }
  .header-badges { display: flex; gap: 10px; align-items: center; }
  .badge {
    padding: 5px 12px; border-radius: 20px; font-size: 13px; font-weight: 500;
    font-family: 'IBM Plex Mono', monospace;
  }
  .badge-green { background: #052e16; color: #4ade80; border: 1px solid #166534; }
  .badge-blue  { background: #172554; color: #60a5fa; border: 1px solid #1e40af; }

  /* LAYOUT */
  .layout { display: grid; grid-template-columns: 1fr 340px; gap: 28px; }
  @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } }

  /* CARD */
  .card {
    background: #18181b;
    border: 1px solid #27272a;
    border-radius: 14px;
    padding: 28px;
  }
  .card + .card { margin-top: 20px; }
  .card-title {
    font-size: 13px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.08em; color: #71717a;
    margin-bottom: 18px;
    display: flex; align-items: center; gap: 8px;
  }
  .card-title::before {
    content: ''; display: block; width: 3px; height: 14px;
    background: #f97316; border-radius: 2px;
  }

  /* TABS */
  .tabs { display: flex; gap: 4px; background: #09090b; border-radius: 10px; padding: 4px; margin-bottom: 24px; border: 1px solid #27272a; }
  .tab {
    flex: 1; padding: 11px; border-radius: 7px; border: none; cursor: pointer;
    font-family: 'IBM Plex Sans', sans-serif; font-size: 15px; font-weight: 500;
    transition: all 0.15s; color: #71717a; background: transparent;
  }
  .tab.active { background: #27272a; color: #fff; }
  .tab:hover:not(.active) { color: #a1a1aa; background: #18181b; }

  /* TEXTAREA */
  .log-label { font-size: 14px; color: #a1a1aa; margin-bottom: 8px; display: block; }
  .log-input {
    width: 100%; min-height: 130px; padding: 16px;
    background: #09090b; border: 1.5px solid #3f3f46; border-radius: 10px;
    color: #e4e4e7; font-family: 'IBM Plex Mono', monospace; font-size: 14px;
    line-height: 1.7; resize: vertical; outline: none;
    transition: border-color 0.15s;
  }
  .log-input:focus { border-color: #f97316; }
  .log-input::placeholder { color: #52525b; }

  /* SAMPLE BUTTONS */
  .samples { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
  .sample-btn {
    padding: 6px 12px; border-radius: 6px; border: 1px solid #3f3f46;
    background: #27272a; color: #a1a1aa; font-size: 13px;
    cursor: pointer; transition: all 0.15s; font-family: 'IBM Plex Sans', sans-serif;
  }
  .sample-btn:hover { border-color: #f97316; color: #f97316; background: #1c1c1e; }

  /* ANALYZE BUTTON */
  .analyze-btn {
    width: 100%; margin-top: 16px; padding: 16px;
    background: linear-gradient(135deg, #ea580c, #dc2626);
    border: none; border-radius: 10px; color: #fff;
    font-family: 'IBM Plex Sans', sans-serif; font-size: 16px; font-weight: 600;
    cursor: pointer; transition: opacity 0.15s, transform 0.1s;
    display: flex; align-items: center; justify-content: center; gap: 10px;
  }
  .analyze-btn:hover:not(:disabled) { opacity: 0.9; transform: translateY(-1px); }
  .analyze-btn:disabled { opacity: 0.5; cursor: not-allowed; }

  /* SPINNER */
  .spinner {
    width: 18px; height: 18px; border: 2px solid rgba(255,255,255,0.3);
    border-top-color: #fff; border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ERROR */
  .error-box {
    margin-top: 16px; padding: 14px 16px;
    background: #450a0a; border: 1px solid #991b1b; border-radius: 10px;
    color: #fca5a5; font-size: 14px;
    display: flex; align-items: flex-start; gap: 10px;
  }

  /* RESULT CARD */
  .result {
    margin-top: 20px; border-radius: 12px; overflow: hidden;
    border: 1.5px solid #3f3f46; animation: fadeIn 0.3s ease;
  }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

  .result-header {
    padding: 18px 22px; display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 12px;
  }
  .result-threat { font-size: 20px; font-weight: 700; color: #fff; }
  .result-mitre {
    font-family: 'IBM Plex Mono', monospace; font-size: 13px;
    padding: 4px 10px; border-radius: 6px; font-weight: 500;
  }

  .result-body { background: #18181b; padding: 22px; display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  @media (max-width: 600px) { .result-body { grid-template-columns: 1fr; } }

  .result-field { display: flex; flex-direction: column; gap: 5px; }
  .field-label { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.07em; color: #71717a; }
  .field-value { font-size: 15px; color: #e4e4e7; line-height: 1.5; }
  .field-value.mono { font-family: 'IBM Plex Mono', monospace; font-size: 14px; }

  .risk-bar-wrap { margin-top: 6px; }
  .risk-bar-track { height: 8px; background: #27272a; border-radius: 999px; overflow: hidden; }
  .risk-bar-fill { height: 100%; border-radius: 999px; transition: width 0.6s ease; }
  .risk-num { font-size: 13px; color: #a1a1aa; margin-top: 5px; font-family: 'IBM Plex Mono', monospace; }

  .severity-badge {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 6px 14px; border-radius: 20px; font-size: 14px; font-weight: 600;
    font-family: 'IBM Plex Mono', monospace; letter-spacing: 0.04em;
  }
  .severity-dot { width: 8px; height: 8px; border-radius: 50%; }

  .result-rec {
    background: #09090b; border-top: 1px solid #27272a;
    padding: 16px 22px; font-size: 14px; color: #a1a1aa;
    display: flex; align-items: flex-start; gap: 10px;
  }
  .rec-icon { font-size: 16px; margin-top: 1px; flex-shrink: 0; }

  /* BATCH */
  .dropzone {
    border: 2px dashed #3f3f46; border-radius: 12px; padding: 48px 24px;
    text-align: center; cursor: pointer; transition: all 0.2s;
    background: #09090b;
  }
  .dropzone:hover, .dropzone.drag { border-color: #f97316; background: #1a0a00; }
  .drop-icon { font-size: 40px; margin-bottom: 12px; }
  .drop-title { font-size: 17px; font-weight: 600; color: #e4e4e7; margin-bottom: 6px; }
  .drop-sub { font-size: 14px; color: #71717a; }

  .progress-wrap { margin-top: 16px; }
  .progress-track { height: 6px; background: #27272a; border-radius: 999px; overflow: hidden; }
  .progress-fill { height: 100%; background: linear-gradient(90deg, #ea580c, #f97316); border-radius: 999px; transition: width 0.3s; }
  .progress-label { font-size: 13px; color: #71717a; margin-top: 8px; font-family: 'IBM Plex Mono', monospace; }

  .batch-controls { display: flex; gap: 10px; margin-top: 16px; }
  .btn-secondary {
    flex: 1; padding: 12px; border-radius: 8px;
    border: 1px solid #3f3f46; background: #27272a;
    color: #e4e4e7; font-size: 14px; font-weight: 500;
    cursor: pointer; font-family: 'IBM Plex Sans', sans-serif;
    transition: all 0.15s;
  }
  .btn-secondary:hover { border-color: #71717a; }
  .btn-danger {
    flex: 1; padding: 12px; border-radius: 8px;
    border: 1px solid #991b1b; background: #450a0a;
    color: #fca5a5; font-size: 14px; font-weight: 500;
    cursor: pointer; font-family: 'IBM Plex Sans', sans-serif;
    transition: all 0.15s;
  }

  /* QUEUE */
  .queue { margin-top: 16px; display: flex; flex-direction: column; gap: 8px; max-height: 440px; overflow-y: auto; }
  .queue::-webkit-scrollbar { width: 4px; }
  .queue::-webkit-scrollbar-track { background: #18181b; }
  .queue::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 2px; }

  .q-row {
    background: #09090b; border: 1px solid #27272a; border-radius: 8px;
    padding: 12px 14px; cursor: pointer; transition: border-color 0.15s;
  }
  .q-row:hover { border-color: #3f3f46; }
  .q-row.expanded { border-color: #52525b; }
  .q-top { display: flex; align-items: center; gap: 10px; }
  .q-status { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .q-status.pending  { background: #52525b; }
  .q-status.scanning { background: #f97316; animation: pulse 1s infinite; }
  .q-status.done-ok  { background: #22c55e; }
  .q-status.done-err { background: #ef4444; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

  .q-text { font-family: 'IBM Plex Mono', monospace; font-size: 13px; color: #a1a1aa; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .q-badge { font-family: 'IBM Plex Mono', monospace; font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px; flex-shrink: 0; }

  .q-detail { margin-top: 10px; padding-top: 10px; border-top: 1px solid #27272a; font-size: 13px; display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .q-field { display: flex; flex-direction: column; gap: 2px; }
  .q-field-label { font-size: 11px; color: #52525b; text-transform: uppercase; letter-spacing: 0.06em; }
  .q-field-value { color: #d4d4d8; font-family: 'IBM Plex Mono', monospace; font-size: 12px; }

  /* SIDEBAR */
  .stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .stat-box { background: #09090b; border: 1px solid #27272a; border-radius: 10px; padding: 16px; }
  .stat-num { font-size: 28px; font-weight: 700; font-family: 'IBM Plex Mono', monospace; line-height: 1; }
  .stat-label { font-size: 12px; color: #71717a; margin-top: 5px; }

  .history-list { display: flex; flex-direction: column; gap: 8px; max-height: 320px; overflow-y: auto; }
  .history-list::-webkit-scrollbar { width: 4px; }
  .history-list::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 2px; }
  .hist-item { background: #09090b; border: 1px solid #27272a; border-radius: 8px; padding: 10px 12px; }
  .hist-threat { font-size: 14px; font-weight: 600; color: #e4e4e7; }
  .hist-log { font-size: 12px; color: #52525b; font-family: 'IBM Plex Mono', monospace; margin-top: 3px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .status-row { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #27272a; font-size: 14px; }
  .status-row:last-child { border-bottom: none; }
  .status-key { color: #71717a; }
  .status-val { font-family: 'IBM Plex Mono', monospace; font-size: 13px; color: #e4e4e7; }
  .dot-green { display: inline-block; width: 7px; height: 7px; background: #22c55e; border-radius: 50%; margin-right: 6px; }

  /* EXPORT */
  .export-btn {
    width: 100%; padding: 11px; border-radius: 8px;
    border: 1px solid #3f3f46; background: transparent;
    color: #a1a1aa; font-size: 14px; cursor: pointer;
    font-family: 'IBM Plex Sans', sans-serif; transition: all 0.15s;
    margin-top: 12px;
  }
  .export-btn:hover { border-color: #71717a; color: #e4e4e7; }
  .export-btn:disabled { opacity: 0.4; cursor: not-allowed; }
`;

// ─────────────────────────────────────────────────────────────────────────────
export default function OpenSOC() {
  const [tab, setTab] = useState("single");
  const [logText, setLogText] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [history, setHistory] = useState([]);

  // Batch
  const [queue, setQueue] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [drag, setDrag] = useState(false);
  const abortRef = useRef(false);
  const fileRef = useRef();

  const sev = result ? (SEVERITY_CONFIG[result.severity] || SEVERITY_CONFIG.INFO) : null;

  // Single analysis
  const handleAnalyze = useCallback(async () => {
    if (!logText.trim()) return;
    setLoading(true); setError(""); setResult(null);
    try {
      const r = await analyzeLog(logText.trim());
      setResult(r);
      setHistory(h => [{ threat: r.threat_type, log: logText.trim(), severity: r.severity }, ...h].slice(0, 10));
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  }, [logText]);

  // File upload
  const handleFile = useCallback((file) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => {
      const lines = e.target.result.split("\n")
        .map(l => l.trim()).filter(l => l && !l.startsWith("#")).slice(0, 50);
      setQueue(lines.map(l => ({ text: l, status: "pending", result: null, error: null, open: false })));
    };
    reader.readAsText(file);
  }, []);

  const handleDrop = useCallback(e => {
    e.preventDefault(); setDrag(false);
    handleFile(e.dataTransfer.files[0]);
  }, [handleFile]);

  const runBatch = useCallback(async () => {
    if (!queue.length) return;
    setScanning(true); abortRef.current = false;
    for (let i = 0; i < queue.length; i++) {
      if (abortRef.current) break;
      setQueue(q => q.map((r, j) => j === i ? { ...r, status: "scanning" } : r));
      try {
        const r = await analyzeLog(queue[i].text);
        setQueue(q => q.map((row, j) => j === i ? { ...row, status: "done-ok", result: r } : row));
        setHistory(h => [{ threat: r.threat_type, log: queue[i].text, severity: r.severity }, ...h].slice(0, 10));
      } catch (e) {
        setQueue(q => q.map((row, j) => j === i ? { ...row, status: "done-err", error: e.message } : row));
      }
      setProgress(Math.round(((i + 1) / queue.length) * 100));
      await new Promise(r => setTimeout(r, 300));
    }
    setScanning(false);
  }, [queue]);

  const exportCSV = useCallback(() => {
    const done = queue.filter(r => r.result);
    if (!done.length) return;
    const header = "Log,Threat Type,MITRE ID,Severity,Risk Score,Evidence,Recommendation";
    const rows = done.map(r => [r.text, r.result.threat_type, r.result.mitre_id, r.result.severity,
      r.result.risk_score, r.result.evidence, r.result.recommendation]
      .map(v => `"${String(v).replace(/"/g, '""')}"`).join(","));
    const blob = new Blob([header + "\n" + rows.join("\n")], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = "opensoc-results.csv"; a.click();
  }, [queue]);

  const statsTotal = history.length;
  const statsCrit  = history.filter(h => h.severity === "CRITICAL" || h.severity === "HIGH").length;

  return (
    <>
      <style>{css}</style>
      <div className="app">

        {/* HEADER */}
        <header className="header">
          <div className="logo">
            <div className="logo-icon">🛡️</div>
            <div>
              <div className="logo-text">OpenSOC<span style={{color:"#f97316"}}>-AI</span></div>
              <div className="logo-sub">AI-Powered Threat Analyzer</div>
            </div>
          </div>
          <div className="header-badges">
            <span className="badge badge-green">● LIVE</span>
            <span className="badge badge-blue">TinyLlama · LoRA</span>
          </div>
        </header>

        <div className="layout">
          {/* ── MAIN PANEL ── */}
          <div>
            <div className="card">
              <div className="tabs">
                <button className={`tab ${tab==="single"?"active":""}`} onClick={()=>setTab("single")}>
                  🔍 Single Log
                </button>
                <button className={`tab ${tab==="batch"?"active":""}`} onClick={()=>setTab("batch")}>
                  📂 Batch File Scan
                </button>
              </div>

              {/* ─ SINGLE TAB ─ */}
              {tab === "single" && (
                <>
                  <label className="log-label">Paste a raw security log entry below</label>
                  <textarea
                    className="log-input"
                    placeholder={`192.168.1.45 - admin [12/Mar/2025:03:17:42] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"`}
                    value={logText}
                    onChange={e => setLogText(e.target.value)}
                    spellCheck={false}
                  />
                  <div className="samples">
                    <span style={{fontSize:13,color:"#52525b",alignSelf:"center"}}>Samples:</span>
                    {["Brute Force","SQL Inject","Path Trav","XSS"].map((label,i) => (
                      <button key={i} className="sample-btn" onClick={() => setLogText(SAMPLES[i])}>
                        {label}
                      </button>
                    ))}
                  </div>
                  <button
                    className="analyze-btn"
                    onClick={handleAnalyze}
                    disabled={loading || !logText.trim()}
                  >
                    {loading ? <><div className="spinner"/><span>Analyzing…</span></> : <>▶ Analyze Threat</>}
                  </button>

                  {error && (
                    <div className="error-box">
                      <span>⚠️</span>
                      <div>
                        <div style={{fontWeight:600,marginBottom:4}}>Analysis Failed</div>
                        <div>{error}</div>
                        {error.includes("fetch") && (
                          <div style={{marginTop:8,fontSize:13,color:"#fca5a5",opacity:0.8}}>
                            → CORS error: deploy the Cloudflare Worker proxy (see PROXY_SETUP.md)
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {result && sev && (
                    <div className="result" style={{borderColor: sev.border}}>
                      <div className="result-header" style={{background: sev.bg}}>
                        <div>
                          <div style={{fontSize:13,color:sev.light,fontWeight:600,marginBottom:4,fontFamily:"'IBM Plex Mono',monospace",textTransform:"uppercase",letterSpacing:"0.06em"}}>Threat Detected</div>
                          <div className="result-threat">{result.threat_type}</div>
                        </div>
                        <div style={{display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}>
                          <div className="result-mitre" style={{background: sev.bg, border:`1px solid ${sev.border}`, color: sev.light}}>
                            {result.mitre_id}
                          </div>
                          <div className="severity-badge" style={{background:sev.bg, border:`1px solid ${sev.border}`, color:sev.color}}>
                            <div className="severity-dot" style={{background:sev.color}}/>
                            {result.severity}
                          </div>
                        </div>
                      </div>

                      <div className="result-body">
                        <div className="result-field" style={{gridColumn:"1/-1"}}>
                          <div className="field-label">Risk Score</div>
                          <div className="risk-bar-wrap">
                            <div className="risk-bar-track">
                              <div className="risk-bar-fill" style={{width:`${result.risk_score}%`, background: sev.color}}/>
                            </div>
                            <div className="risk-num">{result.risk_score} / 100</div>
                          </div>
                        </div>
                        <div className="result-field">
                          <div className="field-label">Evidence</div>
                          <div className="field-value">{result.evidence}</div>
                        </div>
                        <div className="result-field">
                          <div className="field-label">MITRE ATT&CK</div>
                          <div className="field-value mono">{result.mitre_id}</div>
                        </div>
                      </div>

                      <div className="result-rec">
                        <span className="rec-icon">💡</span>
                        <div><strong style={{color:"#e4e4e7"}}>Recommendation:</strong> {result.recommendation}</div>
                      </div>
                    </div>
                  )}
                </>
              )}

              {/* ─ BATCH TAB ─ */}
              {tab === "batch" && (
                <>
                  {queue.length === 0 ? (
                    <div
                      className={`dropzone ${drag?"drag":""}`}
                      onDragOver={e=>{e.preventDefault();setDrag(true)}}
                      onDragLeave={()=>setDrag(false)}
                      onDrop={handleDrop}
                      onClick={()=>fileRef.current?.click()}
                    >
                      <input ref={fileRef} type="file" accept=".log,.txt,.csv" style={{display:"none"}}
                        onChange={e=>handleFile(e.target.files[0])}/>
                      <div className="drop-icon">📁</div>
                      <div className="drop-title">Drop your log file here</div>
                      <div className="drop-sub">Supports .log · .txt · .csv &nbsp;·&nbsp; Up to 50 lines</div>
                    </div>
                  ) : (
                    <>
                      {/* progress */}
                      {scanning && (
                        <div className="progress-wrap">
                          <div className="progress-track">
                            <div className="progress-fill" style={{width:`${progress}%`}}/>
                          </div>
                          <div className="progress-label">{progress}% — scanning {queue.filter(r=>r.status==="done-ok"||r.status==="done-err").length} of {queue.length}</div>
                        </div>
                      )}

                      <div className="batch-controls">
                        {!scanning ? (
                          <button className="analyze-btn" style={{margin:0,flex:2}} onClick={runBatch}>
                            ▶ Start Scan ({queue.length} entries)
                          </button>
                        ) : (
                          <button className="btn-danger" style={{flex:2}} onClick={()=>{abortRef.current=true;setScanning(false);}}>
                            ⏹ Stop Scan
                          </button>
                        )}
                        <button className="btn-secondary" onClick={()=>{setQueue([]);setProgress(0);}}>Clear</button>
                        <button className="export-btn" style={{flex:1,margin:0}} onClick={exportCSV}
                          disabled={!queue.some(r=>r.result)}>
                          ⬇ CSV
                        </button>
                      </div>

                      {/* summary badges */}
                      {queue.some(r=>r.result) && (
                        <div style={{display:"flex",gap:8,marginTop:14,flexWrap:"wrap"}}>
                          {["CRITICAL","HIGH","MEDIUM","LOW"].map(s => {
                            const n = queue.filter(r=>r.result?.severity===s).length;
                            if (!n) return null;
                            const c = SEVERITY_CONFIG[s];
                            return <span key={s} style={{padding:"4px 12px",borderRadius:20,fontSize:13,fontWeight:600,fontFamily:"'IBM Plex Mono',monospace",background:c.bg,border:`1px solid ${c.border}`,color:c.color}}>{s}: {n}</span>;
                          })}
                        </div>
                      )}

                      {/* queue rows */}
                      <div className="queue">
                        {queue.map((row,i) => {
                          const rc = row.result ? SEVERITY_CONFIG[row.result.severity] : null;
                          return (
                            <div key={i} className={`q-row ${row.open?"expanded":""}`}
                              onClick={()=>setQueue(q=>q.map((r,j)=>j===i?{...r,open:!r.open}:r))}>
                              <div className="q-top">
                                <div className={`q-status ${row.status}`}/>
                                <div className="q-text">{row.text}</div>
                                {row.result && rc && (
                                  <div className="q-badge" style={{background:rc.bg,border:`1px solid ${rc.border}`,color:rc.color}}>
                                    {row.result.severity}
                                  </div>
                                )}
                                {row.status==="done-err" && (
                                  <div className="q-badge" style={{background:"#450a0a",border:"1px solid #991b1b",color:"#fca5a5"}}>ERR</div>
                                )}
                              </div>
                              {row.open && row.result && (
                                <div className="q-detail">
                                  <div className="q-field"><div className="q-field-label">Threat</div><div className="q-field-value">{row.result.threat_type}</div></div>
                                  <div className="q-field"><div className="q-field-label">MITRE</div><div className="q-field-value">{row.result.mitre_id}</div></div>
                                  <div className="q-field"><div className="q-field-label">Risk</div><div className="q-field-value">{row.result.risk_score}/100</div></div>
                                  <div className="q-field"><div className="q-field-label">Evidence</div><div className="q-field-value" style={{fontSize:11}}>{row.result.evidence}</div></div>
                                </div>
                              )}
                              {row.open && row.error && (
                                <div style={{marginTop:8,fontSize:12,color:"#fca5a5",paddingTop:8,borderTop:"1px solid #27272a"}}>Error: {row.error}</div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </>
                  )}
                </>
              )}
            </div>
          </div>

          {/* ── SIDEBAR ── */}
          <div>
            {/* Model Performance */}
            <div className="card">
              <div className="card-title">Model Performance</div>
              <div className="stat-grid">
                <div className="stat-box">
                  <div className="stat-num" style={{color:"#22c55e"}}>68%</div>
                  <div className="stat-label">Threat Accuracy</div>
                </div>
                <div className="stat-box">
                  <div className="stat-num" style={{color:"#f97316"}}>58%</div>
                  <div className="stat-label">Severity Acc.</div>
                </div>
                <div className="stat-box">
                  <div className="stat-num" style={{color:"#60a5fa"}}>0.68</div>
                  <div className="stat-label">F1 Score</div>
                </div>
                <div className="stat-box">
                  <div className="stat-num" style={{color:"#a78bfa"}}>450</div>
                  <div className="stat-label">Train Examples</div>
                </div>
              </div>
            </div>

            {/* Session Stats */}
            <div className="card" style={{marginTop:16}}>
              <div className="card-title">This Session</div>
              <div className="stat-grid">
                <div className="stat-box">
                  <div className="stat-num" style={{color:"#e4e4e7"}}>{statsTotal}</div>
                  <div className="stat-label">Analyzed</div>
                </div>
                <div className="stat-box">
                  <div className="stat-num" style={{color:"#ef4444"}}>{statsCrit}</div>
                  <div className="stat-label">High / Critical</div>
                </div>
              </div>
            </div>

            {/* System Status */}
            <div className="card" style={{marginTop:16}}>
              <div className="card-title">System Status</div>
              <div className="status-row"><span className="status-key">Model</span><span className="status-val"><span className="dot-green"/>TinyLlama-1.1B</span></div>
              <div className="status-row"><span className="status-key">Adapter</span><span className="status-val"><span className="dot-green"/>opensoc-v1</span></div>
              <div className="status-row"><span className="status-key">Taxonomy</span><span className="status-val"><span className="dot-green"/>MITRE ATT&CK</span></div>
              <div className="status-row"><span className="status-key">LoRA Params</span><span className="status-val">12.6M (1.13%)</span></div>
            </div>

            {/* Recent History */}
            {history.length > 0 && (
              <div className="card" style={{marginTop:16}}>
                <div className="card-title">Recent Detections</div>
                <div className="history-list">
                  {history.map((h,i) => {
                    const c = SEVERITY_CONFIG[h.severity] || SEVERITY_CONFIG.INFO;
                    return (
                      <div key={i} className="hist-item">
                        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8}}>
                          <div className="hist-threat">{h.threat}</div>
                          <div style={{fontSize:11,fontWeight:600,padding:"2px 7px",borderRadius:4,fontFamily:"'IBM Plex Mono',monospace",background:c.bg,border:`1px solid ${c.border}`,color:c.color,flexShrink:0}}>{h.severity}</div>
                        </div>
                        <div className="hist-log">{h.log}</div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
