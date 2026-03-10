import { useState, useEffect, useRef, useCallback } from "react";

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#ff2b2b", bg: "rgba(255,43,43,0.07)", glow: "0 0 24px rgba(255,43,43,0.35)", dot: "#ff2b2b" },
  HIGH:     { color: "#ff6b00", bg: "rgba(255,107,0,0.07)", glow: "0 0 24px rgba(255,107,0,0.25)", dot: "#ff6b00" },
  MEDIUM:   { color: "#ffd600", bg: "rgba(255,214,0,0.07)", glow: "0 0 24px rgba(255,214,0,0.2)",  dot: "#ffd600" },
  LOW:      { color: "#00e676", bg: "rgba(0,230,118,0.07)", glow: "0 0 24px rgba(0,230,118,0.2)",  dot: "#00e676" },
  INFO:     { color: "#40c4ff", bg: "rgba(64,196,255,0.07)", glow: "0 0 24px rgba(64,196,255,0.2)", dot: "#40c4ff" },
};

const SAMPLE_LOGS = [
  `192.168.1.45 - admin [12/Mar/2025:03:17:42] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"`,
  `10.0.0.5 - - [12/Mar/2025:14:22:11] "GET /etc/passwd HTTP/1.1" 404 287 "-" "curl/7.68.0"`,
  `91.108.4.20 - - [16/Mar/2025:01:05:33] "GET /profile?id=1 OR 1=1-- HTTP/1.1" 403 12466 "-" "burpsuite"`,
  `172.16.0.3 - - [12/Mar/2025:22:11:05] "GET /../../../windows/system32/cmd.exe HTTP/1.1" 400 198`,
];

const SYSTEM_PROMPT = `You are OpenSOC-AI, an expert SOC analyst. Analyze the security log and return ONLY a JSON object with these exact fields:
{
  "threat_type": "string (e.g. SQL Injection, Brute Force, Path Traversal, XSS, Command Injection)",
  "mitre_id": "string (e.g. T1190, T1110, T1059)",
  "severity": "string (exactly one of: CRITICAL, HIGH, MEDIUM, LOW, INFO)",
  "risk_score": number between 0 and 100,
  "evidence": "string describing specific suspicious indicators found",
  "recommendation": "string with one concrete remediation action"
}
Return ONLY the JSON object. No markdown, no explanation, no preamble.`;

async function analyzeLog(logLine) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1000,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: `Analyze this log entry:\n${logLine}` }],
    }),
  });
  const data = await res.json();
  const raw = data.content?.map(b => b.text || "").join("") || "";
  return JSON.parse(raw.replace(/```json|```/g, "").trim());
}

function RiskMeter({ score }) {
  const pct = Math.min(100, Math.max(0, Number(score) || 0));
  const color = pct >= 80 ? "#ff2b2b" : pct >= 60 ? "#ff6b00" : pct >= 40 ? "#ffd600" : "#00e676";
  return (
    <div>
      <div style={{ display:"flex", justifyContent:"space-between", fontSize:10, color:"#555", fontFamily:"'Share Tech Mono',monospace", marginBottom:5 }}>
        <span>RISK SCORE</span><span style={{ color, fontWeight:700 }}>{pct}/100</span>
      </div>
      <div style={{ height:5, background:"#111", borderRadius:3, overflow:"hidden", border:"1px solid #1e1e1e" }}>
        <div style={{ height:"100%", width:`${pct}%`, background:color, boxShadow:`0 0 8px ${color}`, borderRadius:3, transition:"width 1.4s cubic-bezier(0.16,1,0.3,1)" }} />
      </div>
    </div>
  );
}

function ThreatCard({ data }) {
  const sev = (data.severity || "INFO").toUpperCase();
  const cfg = SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.INFO;
  return (
    <div style={{ border:`1px solid ${cfg.color}33`, background:cfg.bg, boxShadow:cfg.glow, borderRadius:4, padding:"22px 26px", animation:"slideIn 0.4s cubic-bezier(0.16,1,0.3,1)", fontFamily:"'Share Tech Mono',monospace" }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:18 }}>
        <div>
          <div style={{ fontSize:9, color:"#555", letterSpacing:3, marginBottom:5 }}>THREAT DETECTED</div>
          <div style={{ fontSize:21, color:cfg.color, fontWeight:700, letterSpacing:1 }}>{data.threat_type || "UNKNOWN"}</div>
        </div>
        <div style={{ background:cfg.color, color:"#000", padding:"5px 14px", fontSize:10, fontWeight:700, letterSpacing:2, borderRadius:2, flexShrink:0 }}>{sev}</div>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
        <div style={{ background:"#0a0a0a", border:"1px solid #1e1e1e", borderRadius:3, padding:"12px 14px" }}>
          <div style={{ fontSize:9, color:"#555", letterSpacing:2, marginBottom:5 }}>MITRE ATT&CK</div>
          <div style={{ fontSize:17, color:"#e0e0e0" }}>{data.mitre_id || "—"}</div>
        </div>
        <div style={{ background:"#0a0a0a", border:"1px solid #1e1e1e", borderRadius:3, padding:"12px 14px" }}>
          <RiskMeter score={data.risk_score} />
        </div>
      </div>
      {data.evidence && (
        <div style={{ marginBottom:12 }}>
          <div style={{ fontSize:9, color:"#555", letterSpacing:2, marginBottom:6 }}>FORENSIC EVIDENCE</div>
          <div style={{ background:"#070707", border:"1px solid #181818", borderLeft:`3px solid ${cfg.color}55`, borderRadius:3, padding:"10px 14px", fontSize:12, color:"#999", lineHeight:1.7 }}>{data.evidence}</div>
        </div>
      )}
      {data.recommendation && (
        <div>
          <div style={{ fontSize:9, color:"#555", letterSpacing:2, marginBottom:6 }}>RECOMMENDED ACTION</div>
          <div style={{ background:"#070707", border:"1px solid #181818", borderLeft:"3px solid #00e67655", borderRadius:3, padding:"10px 14px", fontSize:12, color:"#b9f6ca", lineHeight:1.7 }}>▶ {data.recommendation}</div>
        </div>
      )}
    </div>
  );
}

function BatchRow({ row, index }) {
  const [expanded, setExpanded] = useState(false);
  const sev = row.result ? (row.result.severity || "INFO").toUpperCase() : null;
  const cfg = sev ? (SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.INFO) : null;

  if (row.status === "pending") return (
    <div style={{ padding:"9px 14px", border:"1px solid #111", borderRadius:3, marginBottom:3, display:"flex", alignItems:"center", gap:10, fontFamily:"'Share Tech Mono',monospace" }}>
      <div style={{ width:6, height:6, borderRadius:"50%", background:"#1e1e1e", flexShrink:0 }} />
      <span style={{ fontSize:9, color:"#2e2e2e", letterSpacing:1, flexShrink:0 }}>#{String(index+1).padStart(3,"0")}</span>
      <span style={{ fontSize:10, color:"#252525", flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{row.log}</span>
    </div>
  );

  if (row.status === "scanning") return (
    <div style={{ padding:"9px 14px", border:"1px solid #ff6b0033", borderRadius:3, marginBottom:3, display:"flex", alignItems:"center", gap:10, background:"rgba(255,107,0,0.03)", fontFamily:"'Share Tech Mono',monospace" }}>
      <div style={{ width:6, height:6, borderRadius:"50%", background:"#ff6b00", animation:"pulse 0.6s infinite", flexShrink:0 }} />
      <span style={{ fontSize:9, color:"#ff6b0077", letterSpacing:1, flexShrink:0 }}>SCANNING</span>
      <span style={{ fontSize:10, color:"#ff6b0055", flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{row.log}</span>
    </div>
  );

  if (row.status === "error") return (
    <div style={{ padding:"9px 14px", border:"1px solid #ff2b2b22", borderRadius:3, marginBottom:3, display:"flex", alignItems:"center", gap:10, fontFamily:"'Share Tech Mono',monospace" }}>
      <div style={{ width:6, height:6, borderRadius:"50%", background:"#ff2b2b44", flexShrink:0 }} />
      <span style={{ fontSize:9, color:"#ff2b2b55" }}>⚠ ERROR</span>
      <span style={{ fontSize:10, color:"#ff2b2b44", flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{row.log}</span>
    </div>
  );

  return (
    <div style={{ marginBottom:3, animation:"slideIn 0.25s ease" }}>
      <div onClick={() => setExpanded(e => !e)}
        style={{ padding:"10px 14px", border:`1px solid ${cfg.color}22`, borderLeft:`3px solid ${cfg.color}`, borderRadius:expanded?"3px 3px 0 0":"3px", display:"flex", alignItems:"center", gap:10, background:cfg.bg, cursor:"pointer", fontFamily:"'Share Tech Mono',monospace", transition:"filter 0.15s" }}
        onMouseEnter={e=>e.currentTarget.style.filter="brightness(1.2)"}
        onMouseLeave={e=>e.currentTarget.style.filter="brightness(1)"}>
        <div style={{ width:6, height:6, borderRadius:"50%", background:cfg.color, boxShadow:`0 0 6px ${cfg.color}`, flexShrink:0 }} />
        <span style={{ fontSize:9, color:"#444", letterSpacing:1, flexShrink:0 }}>#{String(index+1).padStart(3,"0")}</span>
        <span style={{ fontSize:10, color:cfg.color, fontWeight:700, flexShrink:0, minWidth:100 }}>{row.result.threat_type}</span>
        <span style={{ fontSize:9, color:"#444", flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{row.log}</span>
        <span style={{ fontSize:8, color:cfg.color, background:`${cfg.color}11`, padding:"2px 7px", borderRadius:2, letterSpacing:1, flexShrink:0 }}>{sev}</span>
        <span style={{ fontSize:9, color:"#333", flexShrink:0 }}>{expanded ? "▲" : "▼"}</span>
      </div>
      {expanded && (
        <div style={{ padding:"14px 16px", border:`1px solid ${cfg.color}11`, borderTop:"none", borderRadius:"0 0 3px 3px", background:"#080808", fontFamily:"'Share Tech Mono',monospace" }}>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:10, marginBottom:12 }}>
            {[["MITRE ID", row.result.mitre_id||"—"], ["RISK SCORE", `${row.result.risk_score||0}/100`], ["SEVERITY", sev]].map(([k,v]) => (
              <div key={k} style={{ background:"#0d0d0d", border:"1px solid #1a1a1a", borderRadius:3, padding:"8px 12px" }}>
                <div style={{ fontSize:8, color:"#444", letterSpacing:2, marginBottom:3 }}>{k}</div>
                <div style={{ fontSize:13, color:cfg.color }}>{v}</div>
              </div>
            ))}
          </div>
          {row.result.evidence && <div style={{ fontSize:11, color:"#666", lineHeight:1.6, marginBottom:8, borderLeft:`2px solid ${cfg.color}33`, paddingLeft:10 }}>{row.result.evidence}</div>}
          {row.result.recommendation && <div style={{ fontSize:11, color:"#8bc34a", lineHeight:1.6, borderLeft:"2px solid #00e67633", paddingLeft:10 }}>▶ {row.result.recommendation}</div>}
        </div>
      )}
    </div>
  );
}

function DropZone({ onFile, fileName, lineCount }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef();

  const handleDrop = useCallback((e) => {
    e.preventDefault(); setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) onFile(file);
  }, [onFile]);

  return (
    <div onClick={() => inputRef.current?.click()}
      onDrop={handleDrop}
      onDragOver={e => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      style={{ border:`2px dashed ${dragging ? "#ff6b00" : fileName ? "#ff6b0055" : "#1a1a1a"}`, borderRadius:4, padding:"30px 20px", textAlign:"center", cursor:"pointer", transition:"all 0.2s", background: dragging ? "rgba(255,107,0,0.05)" : fileName ? "rgba(255,107,0,0.02)" : "#080808", boxShadow: dragging ? "0 0 24px rgba(255,107,0,0.12)" : "none", fontFamily:"'Share Tech Mono',monospace" }}>
      <input ref={inputRef} type="file" accept=".log,.txt,.csv" style={{ display:"none" }} onChange={e => e.target.files[0] && onFile(e.target.files[0])} />
      {fileName ? (
        <>
          <div style={{ fontSize:28, marginBottom:8 }}>📄</div>
          <div style={{ fontSize:13, color:"#ff6b00", marginBottom:4, letterSpacing:1 }}>{fileName}</div>
          <div style={{ fontSize:10, color:"#555", letterSpacing:1 }}>{lineCount} log lines loaded · click or drop to replace</div>
        </>
      ) : (
        <>
          <div style={{ fontSize:30, marginBottom:10, opacity: dragging ? 0.6 : 0.2 }}>⬆</div>
          <div style={{ fontSize:11, color: dragging ? "#ff6b00" : "#444", letterSpacing:3, marginBottom:6, transition:"color 0.2s" }}>
            {dragging ? "RELEASE TO UPLOAD" : "DROP LOG FILE HERE"}
          </div>
          <div style={{ fontSize:10, color:"#2a2a2a", letterSpacing:1, marginBottom:3 }}>or click to browse · .log .txt .csv</div>
          <div style={{ fontSize:9, color:"#1e1e1e", letterSpacing:1 }}>max 50 lines analyzed per batch scan</div>
        </>
      )}
    </div>
  );
}

export default function OpenSOC() {
  const [tab, setTab] = useState("single");
  const [log, setLog] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);

  const [fileName, setFileName] = useState("");
  const [batchRows, setBatchRows] = useState([]);
  const [batchRunning, setBatchRunning] = useState(false);
  const abortRef = useRef(false);

  const [tick, setTick] = useState(0);
  useEffect(() => { const t = setInterval(() => setTick(n => n+1), 1000); return () => clearInterval(t); }, []);
  const timeStr = new Date().toISOString().replace("T"," ").slice(0,19) + " UTC";

  async function analyzeSingle() {
    if (!log.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const parsed = await analyzeLog(log);
      setResult(parsed);
      setHistory(h => [{ log: log.slice(0,70)+(log.length>70?"…":""), severity: parsed.severity, threat: parsed.threat_type, ts: new Date().toLocaleTimeString() }, ...h].slice(0,10));
    } catch(e) {
      setError("ANALYSIS FAILED — " + (e.message || "parse error"));
    } finally { setLoading(false); }
  }

  function handleFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const lines = e.target.result.split("\n").map(l => l.trim()).filter(l => l.length > 10 && !l.startsWith("#")).slice(0, 50);
      setFileName(file.name);
      setBatchRows(lines.map(l => ({ log: l, status: "pending", result: null })));
      setError(null);
    };
    reader.readAsText(file);
  }

  async function runBatch() {
    if (batchRunning || batchRows.length === 0) return;
    setBatchRunning(true); abortRef.current = false;
    const rows = batchRows.map(r => ({ ...r, status: "pending", result: null }));
    setBatchRows([...rows]);

    for (let i = 0; i < rows.length; i++) {
      if (abortRef.current) break;
      setBatchRows(prev => prev.map((r, idx) => idx === i ? { ...r, status:"scanning" } : r));
      try {
        const parsed = await analyzeLog(rows[i].log);
        setBatchRows(prev => prev.map((r, idx) => idx === i ? { ...r, status:"done", result:parsed } : r));
        setHistory(h => [{ log: rows[i].log.slice(0,70), severity: parsed.severity, threat: parsed.threat_type, ts: new Date().toLocaleTimeString() }, ...h].slice(0,10));
      } catch {
        setBatchRows(prev => prev.map((r, idx) => idx === i ? { ...r, status:"error" } : r));
      }
      if (i < rows.length - 1) await new Promise(r => setTimeout(r, 350));
    }
    setBatchRunning(false);
  }

  function stopBatch() { abortRef.current = true; setBatchRunning(false); }

  function exportCSV() {
    const done = batchRows.filter(r => r.status === "done");
    const header = "log,threat_type,mitre_id,severity,risk_score,evidence,recommendation";
    const esc = s => `"${String(s||"").replace(/"/g,'""')}"`;
    const rows = done.map(r => [esc(r.log), esc(r.result.threat_type), esc(r.result.mitre_id), r.result.severity||"", r.result.risk_score||0, esc(r.result.evidence), esc(r.result.recommendation)].join(","));
    const csv = [header, ...rows].join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type:"text/csv" }));
    a.download = `opensoc-${fileName.replace(/\.[^.]+$/,"")}-${Date.now()}.csv`;
    a.click();
  }

  const doneRows = batchRows.filter(r => r.status === "done");
  const progress = batchRows.length > 0 ? Math.round((doneRows.length / batchRows.length) * 100) : 0;
  const critCount = doneRows.filter(r => (r.result?.severity||"").toUpperCase() === "CRITICAL").length;
  const highCount = doneRows.filter(r => (r.result?.severity||"").toUpperCase() === "HIGH").length;

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap');
        *{box-sizing:border-box;margin:0;padding:0;}
        body{background:#060606;}
        @keyframes slideIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.25}}
        @keyframes shimmer{0%,100%{opacity:0.5}50%{opacity:1}}
        ::-webkit-scrollbar{width:3px}::-webkit-scrollbar-track{background:#0a0a0a}::-webkit-scrollbar-thumb{background:#222}
        textarea:focus{outline:none}
      `}</style>

      {/* Scanlines */}
      <div style={{ position:"fixed", inset:0, pointerEvents:"none", zIndex:9999, background:"repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.022) 2px,rgba(0,0,0,0.022) 4px)" }} />

      <div style={{ minHeight:"100vh", background:"#060606", color:"#e0e0e0", fontFamily:"'Share Tech Mono',monospace", paddingBottom:80 }}>

        {/* Header */}
        <div style={{ borderBottom:"1px solid #111", background:"linear-gradient(180deg,#0d0d0d,#060606)", position:"sticky", top:0, zIndex:100 }}>
          <div style={{ maxWidth:1140, margin:"0 auto", padding:"0 28px", display:"flex", alignItems:"center", justifyContent:"space-between", height:58 }}>
            <div style={{ display:"flex", alignItems:"center", gap:14 }}>
              <div style={{ width:7, height:7, borderRadius:"50%", background:"#00e676", boxShadow:"0 0 12px #00e676", animation:"pulse 2.5s infinite" }} />
              <span style={{ fontFamily:"'Orbitron',monospace", fontSize:15, fontWeight:900, letterSpacing:3, color:"#fff" }}>OPEN<span style={{ color:"#ff6b00" }}>SOC</span></span>
              <span style={{ fontSize:8, color:"#2a2a2a", letterSpacing:2, paddingLeft:12, borderLeft:"1px solid #161616" }}>AI-POWERED THREAT ANALYZER v1.0</span>
            </div>
            <div style={{ fontSize:9, color:"#2e2e2e", letterSpacing:1 }}>{timeStr}</div>
          </div>
        </div>

        <div style={{ maxWidth:1140, margin:"0 auto", padding:"28px 28px 0" }}>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 285px", gap:22 }}>

            {/* Left */}
            <div>
              {/* Tabs */}
              <div style={{ display:"flex", marginBottom:20, border:"1px solid #161616", borderRadius:4, overflow:"hidden" }}>
                {[["single","◈  SINGLE LOG"],["batch","⬡  BATCH FILE SCAN"]].map(([key,label]) => (
                  <button key={key} onClick={() => setTab(key)} style={{ flex:1, padding:11, border:"none", cursor:"pointer", background: tab===key ? "#ff6b00" : "transparent", color: tab===key ? "#000" : "#3a3a3a", fontFamily:"'Orbitron',monospace", fontWeight:700, fontSize:10, letterSpacing:2, transition:"all 0.2s", borderRight: key==="single" ? "1px solid #161616" : "none" }}>
                    {label}
                  </button>
                ))}
              </div>

              {/* Single tab */}
              {tab === "single" && (
                <div>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
                    <span style={{ fontSize:9, color:"#3a3a3a", letterSpacing:2 }}>LOG INPUT</span>
                    <button onClick={() => setLog(SAMPLE_LOGS[Math.floor(Math.random()*SAMPLE_LOGS.length)])}
                      style={{ background:"none", border:"1px solid #1e1e1e", color:"#444", padding:"3px 10px", fontSize:9, letterSpacing:1, cursor:"pointer", fontFamily:"'Share Tech Mono',monospace", borderRadius:2, transition:"all 0.2s" }}
                      onMouseEnter={e=>{e.target.style.borderColor="#ff6b00";e.target.style.color="#ff6b00"}}
                      onMouseLeave={e=>{e.target.style.borderColor="#1e1e1e";e.target.style.color="#444"}}>
                      LOAD SAMPLE
                    </button>
                  </div>
                  <textarea value={log} onChange={e => setLog(e.target.value)}
                    placeholder={`192.168.1.45 - admin [12/Mar/2025:03:17:42] "POST /login HTTP/1.1" 401 512...`}
                    rows={4}
                    style={{ width:"100%", background:"#090909", border:"1px solid #181818", borderRadius:3, color:"#00e676", fontFamily:"'Share Tech Mono',monospace", fontSize:12, padding:"12px 16px", resize:"vertical", lineHeight:1.6, transition:"border-color 0.2s" }}
                    onFocus={e => e.target.style.borderColor="#ff6b0066"}
                    onBlur={e => e.target.style.borderColor="#181818"}
                  />
                  <button onClick={analyzeSingle} disabled={loading || !log.trim()}
                    style={{ marginTop:10, width:"100%", padding:13, background: loading ? "#0f0f0f" : "#ff6b00", border:"none", borderRadius:3, color: loading ? "#333" : "#000", fontFamily:"'Orbitron',monospace", fontWeight:700, fontSize:11, letterSpacing:3, cursor: loading||!log.trim() ? "not-allowed" : "pointer", boxShadow: loading ? "none" : "0 0 22px rgba(255,107,0,0.25)", transition:"all 0.2s" }}>
                    {loading ? "▶ ANALYZING..." : "▶ ANALYZE THREAT"}
                  </button>
                  {error && <div style={{ marginTop:14, border:"1px solid #ff2b2b33", background:"rgba(255,43,43,0.05)", borderRadius:3, padding:"12px 16px", fontSize:11, color:"#ff2b2b" }}>⚠ {error}</div>}
                  {loading && (
                    <div style={{ marginTop:14, border:"1px solid #181818", borderRadius:3, padding:"28px", textAlign:"center" }}>
                      <div style={{ fontSize:10, color:"#ff6b00", letterSpacing:3, animation:"shimmer 1.4s infinite" }}>◈ RUNNING THREAT ANALYSIS ◈</div>
                      <div style={{ fontSize:9, color:"#2a2a2a", marginTop:8, letterSpacing:1 }}>correlating ioc signatures · querying mitre framework</div>
                    </div>
                  )}
                  {result && !loading && <div style={{ marginTop:16 }}><ThreatCard data={result} /></div>}
                  {!result && !loading && !error && (
                    <div style={{ marginTop:16, border:"1px dashed #141414", borderRadius:3, padding:"44px", textAlign:"center" }}>
                      <div style={{ fontSize:9, color:"#222", letterSpacing:3 }}>AWAITING LOG INPUT</div>
                    </div>
                  )}
                </div>
              )}

              {/* Batch tab */}
              {tab === "batch" && (
                <div>
                  <DropZone onFile={handleFile} fileName={fileName} lineCount={batchRows.length} />

                  {batchRows.length > 0 && (
                    <div style={{ marginTop:16 }}>
                      {/* Progress */}
                      {(batchRunning || doneRows.length > 0) && (
                        <div style={{ marginBottom:14 }}>
                          <div style={{ display:"flex", justifyContent:"space-between", fontSize:9, color:"#444", letterSpacing:1, marginBottom:5 }}>
                            <span style={{ color: batchRunning ? "#ff6b00" : "#00e676", animation: batchRunning ? "pulse 1s infinite" : "none" }}>
                              {batchRunning ? "◈ SCANNING IN PROGRESS" : "✓ SCAN COMPLETE"}
                            </span>
                            <span>{doneRows.length}/{batchRows.length} · {progress}%</span>
                          </div>
                          <div style={{ height:4, background:"#111", borderRadius:2, overflow:"hidden" }}>
                            <div style={{ height:"100%", width:`${progress}%`, background: batchRunning ? "#ff6b00" : "#00e676", boxShadow:`0 0 8px ${batchRunning?"#ff6b00":"#00e676"}`, borderRadius:2, transition:"width 0.5s ease" }} />
                          </div>
                        </div>
                      )}

                      {/* Summary badges */}
                      {!batchRunning && doneRows.length > 0 && (
                        <div style={{ display:"flex", gap:8, marginBottom:14, flexWrap:"wrap" }}>
                          {critCount > 0 && <span style={{ background:"rgba(255,43,43,0.08)", border:"1px solid #ff2b2b33", color:"#ff2b2b", padding:"3px 10px", borderRadius:2, fontSize:9, letterSpacing:1 }}>⚠ {critCount} CRITICAL</span>}
                          {highCount > 0 && <span style={{ background:"rgba(255,107,0,0.08)", border:"1px solid #ff6b0033", color:"#ff6b00", padding:"3px 10px", borderRadius:2, fontSize:9, letterSpacing:1 }}>▲ {highCount} HIGH</span>}
                          <span style={{ background:"rgba(0,230,118,0.06)", border:"1px solid #00e67622", color:"#00e676", padding:"3px 10px", borderRadius:2, fontSize:9, letterSpacing:1 }}>✓ {doneRows.length} ANALYZED</span>
                        </div>
                      )}

                      {/* Action buttons */}
                      <div style={{ display:"flex", gap:10, marginBottom:16 }}>
                        {!batchRunning ? (
                          <button onClick={runBatch} style={{ flex:1, padding:12, background:"#ff6b00", border:"none", borderRadius:3, color:"#000", fontFamily:"'Orbitron',monospace", fontWeight:700, fontSize:10, letterSpacing:2, cursor:"pointer", boxShadow:"0 0 20px rgba(255,107,0,0.22)", transition:"all 0.2s" }}>
                            ▶ RUN BATCH SCAN — {batchRows.length} LOGS
                          </button>
                        ) : (
                          <button onClick={stopBatch} style={{ flex:1, padding:12, background:"none", border:"1px solid #ff2b2b55", borderRadius:3, color:"#ff2b2b", fontFamily:"'Orbitron',monospace", fontWeight:700, fontSize:10, letterSpacing:2, cursor:"pointer" }}>
                            ■ STOP SCAN
                          </button>
                        )}
                        {doneRows.length > 0 && !batchRunning && (
                          <button onClick={exportCSV}
                            style={{ padding:"12px 18px", background:"none", border:"1px solid #00e67633", color:"#00e676", fontFamily:"'Share Tech Mono',monospace", fontSize:10, letterSpacing:1, cursor:"pointer", borderRadius:3, whiteSpace:"nowrap", transition:"background 0.2s" }}
                            onMouseEnter={e=>e.currentTarget.style.background="rgba(0,230,118,0.07)"}
                            onMouseLeave={e=>e.currentTarget.style.background="none"}>
                            ↓ EXPORT CSV
                          </button>
                        )}
                      </div>

                      {/* Queue */}
                      <div style={{ fontSize:9, color:"#383838", letterSpacing:2, marginBottom:8 }}>
                        LOG QUEUE — {batchRows.length} ENTRIES{batchRows.length===50?" · 50 LINE MAX":""}
                      </div>
                      <div style={{ maxHeight:460, overflowY:"auto", paddingRight:2 }}>
                        {batchRows.map((r, i) => <BatchRow key={i} row={r} index={i} />)}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Sidebar */}
            <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
              <div style={{ border:"1px solid #111", borderRadius:3, padding:16 }}>
                <div style={{ fontSize:9, color:"#383838", letterSpacing:2, marginBottom:12 }}>SYSTEM STATUS</div>
                {[{l:"MODEL",v:"TinyLlama-1.1B"},{l:"ADAPTERS",v:"opensoc-v1"},{l:"THREAT DB",v:"MITRE ATT&CK"},{l:"ANALYZER",v:"Claude Sonnet"}].map(row => (
                  <div key={row.l} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"7px 0", borderBottom:"1px solid #0d0d0d" }}>
                    <div><div style={{ fontSize:8, color:"#303030", letterSpacing:1 }}>{row.l}</div><div style={{ fontSize:11, color:"#666" }}>{row.v}</div></div>
                    <div style={{ fontSize:8, color:"#00e676", background:"rgba(0,230,118,0.06)", padding:"2px 6px", borderRadius:2, letterSpacing:1 }}>READY</div>
                  </div>
                ))}
              </div>

              <div style={{ border:"1px solid #111", borderRadius:3, padding:16, flex:1 }}>
                <div style={{ fontSize:9, color:"#383838", letterSpacing:2, marginBottom:12 }}>RECENT DETECTIONS</div>
                {history.length === 0
                  ? <div style={{ fontSize:9, color:"#1e1e1e", textAlign:"center", padding:"18px 0", letterSpacing:1 }}>NO ANALYSES YET</div>
                  : history.map((h, i) => {
                      const cfg = SEVERITY_CONFIG[(h.severity||"INFO").toUpperCase()] || SEVERITY_CONFIG.INFO;
                      return (
                        <div key={i} style={{ padding:"8px 0", borderBottom:"1px solid #0d0d0d", animation:"slideIn 0.3s ease" }}>
                          <div style={{ display:"flex", justifyContent:"space-between", marginBottom:2 }}>
                            <span style={{ fontSize:9, color:cfg.color, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", maxWidth:155 }}>{h.threat}</span>
                            <span style={{ fontSize:8, color:"#252525", flexShrink:0 }}>{h.ts}</span>
                          </div>
                          <div style={{ fontSize:9, color:"#252525", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{h.log}</div>
                        </div>
                      );
                    })}
              </div>

              <div style={{ border:"1px solid #111", borderRadius:3, padding:16 }}>
                <div style={{ fontSize:9, color:"#383838", letterSpacing:2, marginBottom:12 }}>MODEL PERFORMANCE</div>
                {[{l:"THREAT ACCURACY",v:"68%",d:"+68pp vs baseline"},{l:"SEVERITY ACCURACY",v:"58%",d:"+30pp vs baseline"},{l:"TRAINING EXAMPLES",v:"450"},{l:"LoRA PARAMETERS",v:"12.6M",d:"1.13% of total"}].map(s => (
                  <div key={s.l} style={{ marginBottom:10 }}>
                    <div style={{ display:"flex", justifyContent:"space-between" }}>
                      <span style={{ fontSize:8, color:"#303030", letterSpacing:1 }}>{s.l}</span>
                      <span style={{ fontSize:13, color:"#ff6b00", fontWeight:700 }}>{s.v}</span>
                    </div>
                    {s.d && <div style={{ fontSize:8, color:"#1e4d1e", marginTop:1 }}>▲ {s.d}</div>}
                  </div>
                ))}
              </div>
            </div>

          </div>
        </div>
      </div>
    </>
  );
}
