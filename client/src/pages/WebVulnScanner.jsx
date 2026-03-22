import { useState, useEffect, useRef } from "react";
import api from "../utils/api";

const SEVERITY_STYLES = {
  Critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
  High: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
  Medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
  Low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
  Info: { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" },
};

const CONFIDENCE_STYLES = {
  Confirmed: { color: "#1D9E75", bg: "#0a1a14", border: "#0F6E56" },
  Probable: { color: "#BA7517", bg: "#1a1200", border: "#633806" },
  Possible: { color: "#555", bg: "#111", border: "#222" },
};

const PHASE_LABELS = {
  init: "Initializing",
  headers: "Security Headers",
  files: "Sensitive Files",
  redirect: "Open Redirect",
  cors: "CORS Check",
  clickjack: "Clickjacking",
  crawl: "Page Crawler",
  domxss: "DOM XSS",
  csrf: "CSRF Check",
  auth: "Broken Auth",
  jwt: "JWT Security",
  ssrf: "SSRF Test",
  lfi: "LFI / Traversal",
  xss: "XSS Payloads",
  sqli: "SQL Injection",
  ssti: "SSTI",
  proto: "Prototype Pollution",
  secrets: "Secret Scanner",
  tech: "Tech Fingerprint",
  smuggling: "HTTP Smuggling",
  oob: "OOB Detection",
  stored_xss: "Stored XSS",
  xxe: "XXE Injection",
  finalize: "Finalizing",
  done: "Complete",
};

function generateSessionId() {
  return (
    "gr-" + Math.random().toString(36).slice(2, 10) + Date.now().toString(36)
  );
}

export default function WebVulnScanner() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("all");
  const [logs, setLogs] = useState([]);
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState("");
  const [liveFindings, setLiveFindings] = useState([]);

  const logsEndRef = useRef(null);
  const sseRef = useRef(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);
  useEffect(() => () => sseRef.current?.close(), []);

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a target URL.");

    setLoading(true);
    setError("");
    setResults(null);
    setLogs([]);
    setProgress(0);
    setCurrentPhase("init");
    setLiveFindings([]);

    const sessionId = generateSessionId();
    const apiBase = import.meta.env.VITE_API_URL || "";
    const evtSource = new EventSource(
      `${apiBase}/api/webvuln/scan/progress/${sessionId}`,
    );
    sseRef.current = evtSource;

    evtSource.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.type === "log") {
        setLogs((prev) => [
          ...prev,
          { msg: data.msg, phase: data.phase, ts: data.ts },
        ]);
        if (data.percent) setProgress(data.percent);
        if (data.phase) setCurrentPhase(data.phase);
      }
      if (data.type === "finding") {
        setLiveFindings((prev) => [data.finding, ...prev].slice(0, 20));
      }
      if (data.type === "complete") {
        setProgress(100);
        evtSource.close();
      }
      if (data.type === "error") {
        setError(data.msg);
        evtSource.close();
        setLoading(false);
      }
    };
    evtSource.onerror = () => evtSource.close();

    try {
      const res = await api.post("/api/webvuln/scan", {
        target: target.trim(),
        consent,
        sessionId,
      });
      setResults(res.data.data);
      setActiveTab("all");
    } catch (err) {
      setError(
        err.response?.data?.error || "Scan failed. Is the server running?",
      );
    } finally {
      evtSource.close();
      setLoading(false);
    }
  };

  const confirmed =
    results?.findings?.filter((f) => f.confidence === "Confirmed").length || 0;
  const filtered =
    results?.findings?.filter((f) => {
      if (activeTab === "all") return true;
      if (activeTab === "confirmed") return f.confidence === "Confirmed";
      return f.severity.toLowerCase() === activeTab;
    }) || [];

  return (
    <div style={{ padding: "32px", maxWidth: "1100px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Web Vulnerability Scanner
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Deep automated scan — XSS, SQLi, SSRF, IDOR, secrets, headers, OWASP
          Top 10. Real-time live results with confidence scoring.
        </p>
      </div>

      {/* Input */}
      <div
        style={{
          background: "#131315",
          border: "0.5px solid #1e1e22",
          borderRadius: "12px",
          padding: "24px",
          marginBottom: "24px",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <div>
            <label
              style={{
                fontSize: "12px",
                color: "#666",
                display: "block",
                marginBottom: "6px",
              }}
            >
              Target URL
            </label>
            <input
              type="text"
              placeholder="e.g. https://uat-bugbounty.nonprod.syfe.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              style={{ width: "100%", boxSizing: "border-box" }}
            />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
              Free test: http://testphp.vulnweb.com
            </div>
          </div>

          <label
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: "10px",
              cursor: "pointer",
              padding: "12px",
              background: "#0d0d0f",
              borderRadius: "8px",
              border: consent ? "0.5px solid #3C3489" : "0.5px solid #1e1e22",
            }}
          >
            <input
              type="checkbox"
              checked={consent}
              onChange={(e) => setConsent(e.target.checked)}
              style={{ width: "auto", marginTop: "2px" }}
            />
            <span
              style={{ fontSize: "13px", color: "#777", lineHeight: "1.5" }}
            >
              I confirm I have{" "}
              <span style={{ color: "#a89ff5" }}>written authorization</span> to
              test this target.
            </span>
          </label>

          {error && (
            <div
              style={{
                fontSize: "13px",
                color: "#E24B4A",
                background: "#1a0a0a",
                border: "0.5px solid #791F1F",
                borderRadius: "8px",
                padding: "10px 14px",
              }}
            >
              {error}
            </div>
          )}

          <button
            className="btn-primary"
            onClick={handleScan}
            disabled={loading}
            style={{ alignSelf: "flex-start", padding: "10px 28px" }}
          >
            {loading ? "Scanning..." : "Start Deep Scan"}
          </button>
        </div>
      </div>

      {/* Live scan panel */}
      {loading && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 340px",
            gap: "16px",
            marginBottom: "24px",
          }}
        >
          {/* Live log */}
          <div
            style={{
              background: "#0d0d0f",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                padding: "14px 18px",
                borderBottom: "0.5px solid #1e1e22",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginBottom: "8px",
                }}
              >
                <span style={{ fontSize: "12px", color: "#666" }}>
                  {PHASE_LABELS[currentPhase] || "Scanning..."}
                </span>
                <span style={{ fontSize: "12px", color: "#7F77DD" }}>
                  {progress}%
                </span>
              </div>
              <div
                style={{
                  height: "4px",
                  background: "#1e1e22",
                  borderRadius: "2px",
                }}
              >
                <div
                  style={{
                    height: "100%",
                    borderRadius: "2px",
                    background: "linear-gradient(90deg,#534AB7,#7F77DD)",
                    width: `${progress}%`,
                    transition: "width 0.4s ease",
                  }}
                />
              </div>
            </div>
            <div
              style={{
                height: "280px",
                overflowY: "auto",
                padding: "12px 18px",
                fontFamily: "monospace",
                fontSize: "12px",
              }}
            >
              {logs.map((log, i) => (
                <div
                  key={i}
                  style={{ display: "flex", gap: "10px", marginBottom: "4px" }}
                >
                  <span style={{ color: "#333", flexShrink: 0 }}>
                    {log.ts
                      ? new Date(log.ts).toLocaleTimeString([], {
                          hour12: false,
                        })
                      : ""}
                  </span>
                  <span
                    style={{
                      color: i === logs.length - 1 ? "#a89ff5" : "#555",
                    }}
                  >
                    {log.msg}
                  </span>
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          </div>

          {/* Live findings ticker */}
          <div
            style={{
              background: "#0d0d0f",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                padding: "14px 18px",
                borderBottom: "0.5px solid #1e1e22",
                fontSize: "12px",
                color: "#555",
              }}
            >
              Live findings
            </div>
            <div style={{ height: "312px", overflowY: "auto", padding: "8px" }}>
              {liveFindings.length === 0 ? (
                <div
                  style={{
                    padding: "20px",
                    textAlign: "center",
                    color: "#333",
                    fontSize: "12px",
                  }}
                >
                  Findings will appear here...
                </div>
              ) : (
                liveFindings.map((f, i) => {
                  const s = SEVERITY_STYLES[f.severity] || SEVERITY_STYLES.Low;
                  return (
                    <div
                      key={i}
                      style={{
                        padding: "8px 10px",
                        marginBottom: "4px",
                        background: "#111",
                        borderRadius: "8px",
                        borderLeft: `2px solid ${s.border}`,
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          gap: "6px",
                          marginBottom: "3px",
                        }}
                      >
                        <span
                          style={{
                            fontSize: "10px",
                            padding: "1px 6px",
                            borderRadius: "8px",
                            background: s.bg,
                            color: s.color,
                          }}
                        >
                          {f.severity}
                        </span>
                        {f.confidence === "Confirmed" && (
                          <span
                            style={{
                              fontSize: "10px",
                              padding: "1px 6px",
                              borderRadius: "8px",
                              background: "#0a1a14",
                              color: "#1D9E75",
                            }}
                          >
                            Confirmed
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: "12px", color: "#888" }}>
                        {f.type}
                      </div>
                      {f.endpoint && (
                        <div
                          style={{
                            fontSize: "11px",
                            color: "#444",
                            fontFamily: "monospace",
                            marginTop: "2px",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {f.endpoint}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Summary cards */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(8,1fr)",
              gap: "10px",
            }}
          >
            {[
              {
                label: "Risk score",
                val: `${results.riskScore}/100`,
                color:
                  results.riskScore >= 60
                    ? "#E24B4A"
                    : results.riskScore >= 30
                      ? "#BA7517"
                      : "#1D9E75",
              },
              {
                label: "Critical",
                val: results.summary.critical,
                color: "#ff4444",
              },
              { label: "High", val: results.summary.high, color: "#E24B4A" },
              {
                label: "Medium",
                val: results.summary.medium,
                color: "#BA7517",
              },
              { label: "Low", val: results.summary.low, color: "#639922" },
              { label: "Confirmed", val: confirmed, color: "#1D9E75" },
              { label: "Pages", val: results.pagesScanned, color: "#7F77DD" },
              {
                label: "Secrets",
                val: results.secretsFound?.length || 0,
                color: results.secretsFound?.length > 0 ? "#ff4444" : "#1D9E75",
              },
            ].map((s) => (
              <div
                key={s.label}
                style={{
                  background: "#131315",
                  border: "0.5px solid #1e1e22",
                  borderRadius: "10px",
                  padding: "12px",
                }}
              >
                <div
                  style={{
                    fontSize: "18px",
                    fontWeight: "500",
                    color: s.color,
                  }}
                >
                  {s.val}
                </div>
                <div
                  style={{ fontSize: "11px", color: "#555", marginTop: "2px" }}
                >
                  {s.label}
                </div>
              </div>
            ))}
          </div>

          {/* Filter tabs */}
          <div
            style={{
              display: "flex",
              gap: "4px",
              background: "#131315",
              padding: "4px",
              borderRadius: "10px",
              border: "0.5px solid #1e1e22",
              width: "fit-content",
              flexWrap: "wrap",
            }}
          >
            {[
              { label: `All (${results.summary.total})`, val: "all" },
              { label: `Confirmed (${confirmed})`, val: "confirmed" },
              {
                label: `Critical (${results.summary.critical})`,
                val: "critical",
              },
              { label: `High (${results.summary.high})`, val: "high" },
              { label: `Medium (${results.summary.medium})`, val: "medium" },
              { label: `Low (${results.summary.low})`, val: "low" },
            ].map((tab) => (
              <button
                key={tab.val}
                onClick={() => setActiveTab(tab.val)}
                style={{
                  padding: "6px 14px",
                  borderRadius: "8px",
                  fontSize: "12px",
                  background: activeTab === tab.val ? "#7F77DD" : "transparent",
                  color: activeTab === tab.val ? "white" : "#666",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Findings */}
          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                padding: "14px 20px",
                borderBottom: "0.5px solid #1e1e22",
                fontSize: "12px",
                color: "#666",
                textTransform: "uppercase",
                letterSpacing: "0.6px",
              }}
            >
              {filtered.length} findings
            </div>
            {filtered.length === 0 ? (
              <div
                style={{
                  padding: "32px",
                  textAlign: "center",
                  color: "#1D9E75",
                  fontSize: "14px",
                }}
              >
                No vulnerabilities found in this category.
              </div>
            ) : (
              filtered.map((v, i) => {
                const s = SEVERITY_STYLES[v.severity] || SEVERITY_STYLES.Low;
                const c =
                  CONFIDENCE_STYLES[v.confidence] || CONFIDENCE_STYLES.Possible;
                return (
                  <div
                    key={i}
                    style={{
                      padding: "18px 20px",
                      borderBottom:
                        i < filtered.length - 1
                          ? "0.5px solid #0f0f11"
                          : "none",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                        marginBottom: "8px",
                        flexWrap: "wrap",
                      }}
                    >
                      <span
                        style={{
                          fontSize: "11px",
                          padding: "2px 8px",
                          borderRadius: "10px",
                          background: s.bg,
                          color: s.color,
                          border: `0.5px solid ${s.border}`,
                        }}
                      >
                        {v.severity}
                      </span>
                      {v.confidence && (
                        <span
                          style={{
                            fontSize: "11px",
                            padding: "2px 8px",
                            borderRadius: "10px",
                            background: c.bg,
                            color: c.color,
                            border: `0.5px solid ${c.border}`,
                          }}
                        >
                          {v.confidence}
                        </span>
                      )}
                      <span
                        style={{
                          fontSize: "14px",
                          fontWeight: "500",
                          color: "#ccc",
                        }}
                      >
                        {v.type}
                      </span>
                      {v.owasp && (
                        <span
                          style={{
                            fontSize: "11px",
                            padding: "2px 8px",
                            borderRadius: "10px",
                            background: "#0d0d2e",
                            color: "#7F77DD",
                            border: "0.5px solid #3C3489",
                          }}
                        >
                          {v.owasp}
                        </span>
                      )}
                    </div>
                    <div
                      style={{
                        fontSize: "13px",
                        color: "#777",
                        marginBottom: "8px",
                        lineHeight: "1.6",
                      }}
                    >
                      {v.detail}
                    </div>
                    {v.evidence && (
                      <div
                        style={{
                          fontSize: "12px",
                          color: "#555",
                          fontFamily: "monospace",
                          background: "#0d0d0f",
                          padding: "8px 12px",
                          borderRadius: "6px",
                          marginBottom: "8px",
                        }}
                      >
                        {v.evidence}
                      </div>
                    )}
                    {v.endpoint && (
                      <div
                        style={{
                          fontSize: "12px",
                          color: "#555",
                          marginBottom: "6px",
                        }}
                      >
                        <span style={{ color: "#444" }}>Endpoint: </span>
                        <span
                          style={{ fontFamily: "monospace", color: "#a89ff5" }}
                        >
                          {v.method} {v.endpoint}
                        </span>
                        {v.parameter && (
                          <span style={{ color: "#444" }}>
                            {" "}
                            — Parameter:{" "}
                            <span style={{ color: "#BA7517" }}>
                              {v.parameter}
                            </span>
                          </span>
                        )}
                      </div>
                    )}
                    {v.remediation && (
                      <div
                        style={{
                          fontSize: "12px",
                          color: "#1D9E75",
                          background: "#0a1a14",
                          padding: "8px 12px",
                          borderRadius: "6px",
                          borderLeft: "2px solid #1D9E75",
                          marginTop: "8px",
                        }}
                      >
                        Fix: {v.remediation}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
