import { useState, useEffect, useRef } from "react";
import api from "../utils/api";

const SEVERITY_STYLES = {
  Critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
  High:     { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
  Medium:   { bg: "#1a1200", color: "#BA7517", border: "#633806" },
  Low:      { bg: "#0a1400", color: "#639922", border: "#27500A" },
};

const CONFIDENCE_STYLES = {
  Confirmed: { color: "#1D9E75", bg: "#0a1a14", border: "#0F6E56" },
  Probable:  { color: "#BA7517", bg: "#1a1200", border: "#633806" },
  Possible:  { color: "#555",    bg: "#111",    border: "#222" },
};

function generateSessionId() {
  return "idor-" + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

function Input({ label, hint, ...props }) {
  return (
    <div>
      <label style={{ fontSize: "12px", color: "#666", display: "block", marginBottom: "6px" }}>
        {label} {hint && <span style={{ color: "#444" }}>{hint}</span>}
      </label>
      <input style={{ width: "100%", boxSizing: "border-box" }} {...props} />
    </div>
  );
}

export default function IDORScanner() {
  const [targetUrl, setTargetUrl]   = useState("");
  const [loginUrl, setLoginUrl]     = useState("");
  const [authType, setAuthType]     = useState("cookie");
  const [user1, setUser1]           = useState({ username: "", password: "" });
  const [user2, setUser2]           = useState({ username: "", password: "" });
  const [customEndpoints, setCustomEndpoints] = useState("");
  const [consent, setConsent]       = useState(false);
  const [loading, setLoading]       = useState(false);
  const [results, setResults]       = useState(null);
  const [error, setError]           = useState("");
  const [logs, setLogs]             = useState([]);
  const [progress, setProgress]     = useState(0);
  const [liveFindings, setLiveFindings] = useState([]);
  const [showPass1, setShowPass1]   = useState(false);
  const [showPass2, setShowPass2]   = useState(false);

  const logsEndRef = useRef(null);
  const sseRef     = useRef(null);

  useEffect(() => { logsEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [logs]);
  useEffect(() => () => sseRef.current?.close(), []);

  const handleScan = async () => {
    if (!consent)              return setError("You must check the authorization box.");
    if (!targetUrl.trim())     return setError("Target URL is required.");
    if (!user1.username || !user1.password) return setError("Account 1 credentials required.");
    if (!user2.username || !user2.password) return setError("Account 2 credentials required.");
    if (user1.username === user2.username)  return setError("Account 1 and Account 2 must be different users.");

    setLoading(true); setError(""); setResults(null);
    setLogs([]); setProgress(0); setLiveFindings([]);

    const sessionId = generateSessionId();
    const apiBase   = import.meta.env.VITE_API_URL || "";
    const evtSource = new EventSource(`${apiBase}/api/idorscan/progress/${sessionId}`);
    sseRef.current  = evtSource;

    evtSource.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.type === "log") {
        setLogs((prev) => [...prev, { msg: data.msg, ts: data.ts }]);
        if (data.percent) setProgress(data.percent);
      }
      if (data.type === "finding") {
        setLiveFindings((prev) => [data.finding, ...prev].slice(0, 15));
      }
      if (data.type === "complete") { setProgress(100); evtSource.close(); }
      if (data.type === "error")    { setError(data.msg); evtSource.close(); setLoading(false); }
    };
    evtSource.onerror = () => evtSource.close();

    const endpoints = customEndpoints.trim()
      ? customEndpoints.split("\n").map((e) => e.trim()).filter(Boolean)
      : [];

    try {
      const res = await api.post("/api/idorscan/scan", {
        targetUrl: targetUrl.trim(),
        loginUrl:  loginUrl.trim() || undefined,
        account1:  user1,
        account2:  user2,
        authType,
        customEndpoints: endpoints,
        consent,
        sessionId,
      });
      setResults(res.data.data);
    } catch (err) {
      setError(err.response?.data?.error || "Scan failed. Is the server running?");
    } finally {
      evtSource.close();
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "32px", maxWidth: "1100px" }}>
      {/* Header */}
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>IDOR Scanner</h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Two-account tester — logs in as two different users and checks if Account B can access Account A's data.
          Best tool for finding broken access control in fintech apps.
        </p>
      </div>

      {/* Warning */}
      <div style={{ background: "#1a1200", border: "0.5px solid #633806", borderRadius: "10px", padding: "14px 16px", marginBottom: "20px", fontSize: "13px", color: "#BA7517" }}>
        Only use with two test accounts you own on systems you have written permission to test.
      </div>

      {/* Form */}
      <div style={{ background: "#131315", border: "0.5px solid #1e1e22", borderRadius: "12px", padding: "24px", marginBottom: "24px" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

          {/* Target */}
          <Input label="Target URL" placeholder="e.g. https://uat-bugbounty.nonprod.syfe.com"
            value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} />

          {/* Login URL */}
          <Input label="Login URL" hint="(optional — leave blank to auto-detect)"
            placeholder="e.g. https://app.syfe.com/login"
            value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)} />

          {/* Auth type */}
          <div>
            <label style={{ fontSize: "12px", color: "#666", display: "block", marginBottom: "8px" }}>Auth type</label>
            <div style={{ display: "flex", gap: "8px" }}>
              {["cookie", "api"].map((type) => (
                <button key={type} onClick={() => setAuthType(type)} style={{
                  padding: "6px 18px", borderRadius: "8px", fontSize: "12px", border: "0.5px solid",
                  background: authType === type ? "#7F77DD" : "transparent",
                  color:      authType === type ? "white"   : "#666",
                  borderColor: authType === type ? "#534AB7" : "#1e1e22",
                  cursor: "pointer",
                }}>
                  {type === "cookie" ? "Cookie / Session" : "API / JWT Token"}
                </button>
              ))}
            </div>
            <div style={{ fontSize: "11px", color: "#444", marginTop: "6px" }}>
              {authType === "cookie" ? "For traditional web apps with form-based login" : "For React/mobile apps that return a JWT token on login"}
            </div>
          </div>

          {/* Two accounts */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
            {/* Account 1 */}
            <div style={{ background: "#0d0d0f", border: "0.5px solid #1e1e22", borderRadius: "10px", padding: "16px" }}>
              <div style={{ fontSize: "12px", color: "#7F77DD", marginBottom: "12px", fontWeight: "500" }}>
                Account A — Owner
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                <Input label="Username / Email" placeholder="user1@example.com"
                  value={user1.username} onChange={(e) => setUser1({ ...user1, username: e.target.value })} />
                <div>
                  <label style={{ fontSize: "12px", color: "#666", display: "block", marginBottom: "6px" }}>Password</label>
                  <div style={{ position: "relative" }}>
                    <input type={showPass1 ? "text" : "password"} placeholder="Password"
                      value={user1.password} onChange={(e) => setUser1({ ...user1, password: e.target.value })}
                      style={{ width: "100%", boxSizing: "border-box", paddingRight: "50px" }} />
                    <button onClick={() => setShowPass1(!showPass1)} style={{ position: "absolute", right: "10px", top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "#555", fontSize: "11px", cursor: "pointer" }}>
                      {showPass1 ? "Hide" : "Show"}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Account 2 */}
            <div style={{ background: "#0d0d0f", border: "0.5px solid #1e1e22", borderRadius: "10px", padding: "16px" }}>
              <div style={{ fontSize: "12px", color: "#E24B4A", marginBottom: "12px", fontWeight: "500" }}>
                Account B — Attacker
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                <Input label="Username / Email" placeholder="user2@example.com"
                  value={user2.username} onChange={(e) => setUser2({ ...user2, username: e.target.value })} />
                <div>
                  <label style={{ fontSize: "12px", color: "#666", display: "block", marginBottom: "6px" }}>Password</label>
                  <div style={{ position: "relative" }}>
                    <input type={showPass2 ? "text" : "password"} placeholder="Password"
                      value={user2.password} onChange={(e) => setUser2({ ...user2, password: e.target.value })}
                      style={{ width: "100%", boxSizing: "border-box", paddingRight: "50px" }} />
                    <button onClick={() => setShowPass2(!showPass2)} style={{ position: "absolute", right: "10px", top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "#555", fontSize: "11px", cursor: "pointer" }}>
                      {showPass2 ? "Hide" : "Show"}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Custom endpoints */}
          <div>
            <label style={{ fontSize: "12px", color: "#666", display: "block", marginBottom: "6px" }}>
              Custom endpoints to test <span style={{ color: "#444" }}>(optional — one per line)</span>
            </label>
            <textarea placeholder={`https://api.syfe.com/api/v1/portfolio/12345\nhttps://api.syfe.com/api/v1/orders/67890`}
              value={customEndpoints} onChange={(e) => setCustomEndpoints(e.target.value)}
              rows={3} style={{ width: "100%", boxSizing: "border-box", resize: "vertical" }} />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
              Add specific API endpoints with IDs you want to test. Tool will also auto-discover endpoints.
            </div>
          </div>

          {/* Consent */}
          <label style={{ display: "flex", alignItems: "flex-start", gap: "10px", cursor: "pointer",
            padding: "12px", background: "#0d0d0f", borderRadius: "8px",
            border: consent ? "0.5px solid #3C3489" : "0.5px solid #1e1e22" }}>
            <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} style={{ width: "auto", marginTop: "2px" }} />
            <span style={{ fontSize: "13px", color: "#777", lineHeight: "1.5" }}>
              I confirm both accounts are mine and I have <span style={{ color: "#a89ff5" }}>written authorization</span> to test this application for vulnerabilities.
            </span>
          </label>

          {error && <div style={{ fontSize: "13px", color: "#E24B4A", background: "#1a0a0a", border: "0.5px solid #791F1F", borderRadius: "8px", padding: "10px 14px" }}>{error}</div>}

          <button className="btn-primary" onClick={handleScan} disabled={loading} style={{ alignSelf: "flex-start", padding: "10px 28px" }}>
            {loading ? "Scanning..." : "Start IDOR Scan"}
          </button>
        </div>
      </div>

      {/* Live panel */}
      {loading && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: "16px", marginBottom: "24px" }}>
          {/* Log */}
          <div style={{ background: "#0d0d0f", border: "0.5px solid #1e1e22", borderRadius: "12px", overflow: "hidden" }}>
            <div style={{ padding: "14px 18px", borderBottom: "0.5px solid #1e1e22" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                <span style={{ fontSize: "12px", color: "#666" }}>Live scan log</span>
                <span style={{ fontSize: "12px", color: "#7F77DD" }}>{progress}%</span>
              </div>
              <div style={{ height: "4px", background: "#1e1e22", borderRadius: "2px" }}>
                <div style={{ height: "100%", borderRadius: "2px", background: "linear-gradient(90deg,#534AB7,#7F77DD)", width: `${progress}%`, transition: "width 0.4s ease" }} />
              </div>
            </div>
            <div style={{ height: "260px", overflowY: "auto", padding: "12px 18px", fontFamily: "monospace", fontSize: "12px" }}>
              {logs.map((log, i) => (
                <div key={i} style={{ display: "flex", gap: "10px", marginBottom: "4px" }}>
                  <span style={{ color: "#333", flexShrink: 0 }}>{log.ts ? new Date(log.ts).toLocaleTimeString([], { hour12: false }) : ""}</span>
                  <span style={{ color: i === logs.length - 1 ? "#a89ff5" : "#555" }}>{log.msg}</span>
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          </div>

          {/* Live findings */}
          <div style={{ background: "#0d0d0f", border: "0.5px solid #1e1e22", borderRadius: "12px", overflow: "hidden" }}>
            <div style={{ padding: "14px 18px", borderBottom: "0.5px solid #1e1e22", fontSize: "12px", color: "#555" }}>Live findings</div>
            <div style={{ height: "294px", overflowY: "auto", padding: "8px" }}>
              {liveFindings.length === 0
                ? <div style={{ padding: "20px", textAlign: "center", color: "#333", fontSize: "12px" }}>IDOR findings will appear here...</div>
                : liveFindings.map((f, i) => {
                    const s = SEVERITY_STYLES[f.severity] || SEVERITY_STYLES.High;
                    return (
                      <div key={i} style={{ padding: "8px 10px", marginBottom: "4px", background: "#111", borderRadius: "8px", borderLeft: `2px solid ${s.border}` }}>
                        <span style={{ fontSize: "10px", padding: "1px 6px", borderRadius: "8px", background: s.bg, color: s.color }}>{f.severity}</span>
                        <div style={{ fontSize: "12px", color: "#888", marginTop: "3px" }}>{f.type}</div>
                        {f.endpoint && <div style={{ fontSize: "11px", color: "#444", fontFamily: "monospace", marginTop: "2px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.endpoint}</div>}
                      </div>
                    );
                  })
              }
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Session status */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
            {[results.sessionA, results.sessionB].map((session, i) => (
              <div key={i} style={{ background: "#131315", border: `0.5px solid ${session?.authenticated ? "#085041" : "#791F1F"}`, borderRadius: "10px", padding: "14px 18px", display: "flex", alignItems: "center", gap: "10px" }}>
                <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: session?.authenticated ? "#1D9E75" : "#E24B4A", flexShrink: 0 }} />
                <div>
                  <div style={{ fontSize: "13px", color: session?.authenticated ? "#1D9E75" : "#E24B4A", fontWeight: "500" }}>
                    Account {i === 0 ? "A" : "B"} — {session?.authenticated ? "Authenticated" : "Failed"}
                  </div>
                  <div style={{ fontSize: "12px", color: "#555" }}>{session?.username}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Summary cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "10px" }}>
            {[
              { label: "IDOR findings", val: results.summary?.total || 0, color: results.summary?.total > 0 ? "#ff4444" : "#1D9E75" },
              { label: "High severity", val: results.summary?.high || 0, color: "#E24B4A" },
              { label: "Endpoints tested", val: results.summary?.testedEndpoints || 0, color: "#7F77DD" },
              { label: "APIs discovered", val: results.summary?.apiEndpointsFound || 0, color: "#a89ff5" },
            ].map((s) => (
              <div key={s.label} style={{ background: "#131315", border: "0.5px solid #1e1e22", borderRadius: "10px", padding: "14px" }}>
                <div style={{ fontSize: "20px", fontWeight: "500", color: s.color }}>{s.val}</div>
                <div style={{ fontSize: "11px", color: "#555", marginTop: "3px" }}>{s.label}</div>
              </div>
            ))}
          </div>

          {/* API endpoints found */}
          {results.apiEndpoints?.length > 0 && (
            <details style={{ background: "#131315", border: "0.5px solid #1e1e22", borderRadius: "12px", padding: "16px 20px" }}>
              <summary style={{ fontSize: "13px", color: "#666", cursor: "pointer" }}>
                {results.apiEndpoints.length} API endpoints discovered
              </summary>
              <div style={{ marginTop: "12px", display: "flex", flexDirection: "column", gap: "4px" }}>
                {results.apiEndpoints.map((ep, i) => (
                  <div key={i} style={{ fontSize: "12px", color: "#555", fontFamily: "monospace", display: "flex", gap: "12px" }}>
                    <span style={{ color: "#1D9E75" }}>200</span>
                    <span>{ep.url}</span>
                    <span style={{ color: "#444" }}>{ep.dataSize} bytes</span>
                  </div>
                ))}
              </div>
            </details>
          )}

          {/* Findings */}
          <div style={{ background: "#131315", border: "0.5px solid #1e1e22", borderRadius: "12px", overflow: "hidden" }}>
            <div style={{ padding: "14px 20px", borderBottom: "0.5px solid #1e1e22", fontSize: "12px", color: "#666", textTransform: "uppercase", letterSpacing: "0.6px" }}>
              {results.findings.length} IDOR findings
            </div>
            {results.findings.length === 0
              ? (
                <div style={{ padding: "32px", textAlign: "center" }}>
                  <div style={{ color: "#1D9E75", fontSize: "14px", marginBottom: "8px" }}>No IDOR vulnerabilities found</div>
                  <div style={{ color: "#444", fontSize: "12px" }}>Try adding custom API endpoints manually in the form above</div>
                </div>
              )
              : results.findings.map((v, i) => {
                  const s = SEVERITY_STYLES[v.severity] || SEVERITY_STYLES.High;
                  const c = CONFIDENCE_STYLES[v.confidence] || CONFIDENCE_STYLES.Possible;
                  return (
                    <div key={i} style={{ padding: "18px 20px", borderBottom: i < results.findings.length - 1 ? "0.5px solid #0f0f11" : "none" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px", flexWrap: "wrap" }}>
                        <span style={{ fontSize: "11px", padding: "2px 8px", borderRadius: "10px", background: s.bg, color: s.color, border: `0.5px solid ${s.border}` }}>{v.severity}</span>
                        {v.confidence && <span style={{ fontSize: "11px", padding: "2px 8px", borderRadius: "10px", background: c.bg, color: c.color, border: `0.5px solid ${c.border}` }}>{v.confidence}</span>}
                        <span style={{ fontSize: "14px", fontWeight: "500", color: "#ccc" }}>{v.type}</span>
                      </div>
                      <div style={{ fontSize: "13px", color: "#777", marginBottom: "8px", lineHeight: "1.6" }}>{v.detail}</div>
                      {v.evidence && <div style={{ fontSize: "12px", color: "#555", fontFamily: "monospace", background: "#0d0d0f", padding: "8px 12px", borderRadius: "6px", marginBottom: "8px" }}>{v.evidence}</div>}
                      {v.accountA && (
                        <div style={{ fontSize: "12px", color: "#555", marginBottom: "6px" }}>
                          <span style={{ color: "#7F77DD" }}>Account A (owner): </span>{v.accountA}
                          <span style={{ color: "#444" }}> → </span>
                          <span style={{ color: "#E24B4A" }}>Account B (attacker): </span>{v.accountB}
                        </div>
                      )}
                      {v.endpoint && <div style={{ fontSize: "12px", fontFamily: "monospace", color: "#a89ff5", marginBottom: "8px" }}>{v.method} {v.endpoint}</div>}
                      {v.remediation && (
                        <div style={{ fontSize: "12px", color: "#1D9E75", background: "#0a1a14", padding: "8px 12px", borderRadius: "6px", borderLeft: "2px solid #1D9E75" }}>
                          Fix: {v.remediation}
                        </div>
                      )}
                    </div>
                  );
                })
            }
          </div>
        </div>
      )}
    </div>
  );
}
