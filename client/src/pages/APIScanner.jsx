import { useState } from "react";
import api from "../utils/api";

const SEVERITY_STYLES = {
  Critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
  High: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
  Medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
  Low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
  Info: { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" },
};

export default function APIScanner() {
  const [target, setTarget] = useState("");
  const [authToken, setAuthToken] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [showEndpoints, setShowEndpoints] = useState(false);
  const [activeTab, setActiveTab] = useState("all");

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a target URL.");

    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Discovering API endpoints...",
      "Testing HTTP methods...",
      "Checking authentication...",
      "Testing rate limiting...",
      "Scanning for sensitive data...",
      "Testing for injection...",
      "Checking CORS configuration...",
      "Analyzing findings...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 6000);

    try {
      const res = await api.post("/api/apiscan/scan", {
        target: target.trim(),
        authToken: authToken.trim() || undefined,
        consent,
      });
      setResults(res.data.data);
      setActiveTab("all");
    } catch (err) {
      setError(err.response?.data?.error || "Scan failed.");
    } finally {
      clearInterval(interval);
      setLoading(false);
    }
  };

  const filtered =
    results?.findings?.filter((f) => {
      if (activeTab === "all") return true;
      return f.severity.toLowerCase() === activeTab;
    }) || [];

  return (
    <div style={{ padding: "32px", maxWidth: "1000px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          API Security Scanner
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Test REST APIs for authentication flaws, injection, rate limiting,
          CORS, mass assignment and more.
        </p>
      </div>

      {/* Form */}
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
              placeholder="e.g. https://api.example.com or https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
              Scanner will auto-discover API endpoints under this URL
            </div>
          </div>

          <div>
            <label
              style={{
                fontSize: "12px",
                color: "#666",
                display: "block",
                marginBottom: "6px",
              }}
            >
              Bearer token{" "}
              <span style={{ color: "#444" }}>
                (optional — for testing authenticated endpoints)
              </span>
            </label>
            <input
              type="text"
              placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
              value={authToken}
              onChange={(e) => setAuthToken(e.target.value)}
              style={{ fontFamily: "monospace", fontSize: "12px" }}
            />
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
              perform security testing on this API.
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
            {loading ? "Scanning..." : "Start API Scan"}
          </button>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div
          style={{
            background: "#131315",
            border: "0.5px solid #1e1e22",
            borderRadius: "12px",
            padding: "32px",
            textAlign: "center",
          }}
        >
          <div
            style={{
              width: "32px",
              height: "32px",
              border: "2px solid #1e1e22",
              borderTop: "2px solid #7F77DD",
              borderRadius: "50%",
              animation: "spin 0.8s linear infinite",
              margin: "0 auto 16px",
            }}
          />
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
          <div
            style={{ color: "#a89ff5", fontSize: "14px", marginBottom: "6px" }}
          >
            {loadingMsg}
          </div>
          <div style={{ color: "#444", fontSize: "12px" }}>
            Testing all discovered endpoints — may take 2–4 minutes
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Summary */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(6, 1fr)",
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
                label: "Endpoints",
                val: results.endpointsFound,
                color: "#7F77DD",
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

          {/* Discovered endpoints */}
          {results.endpoints?.length > 0 && (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                overflow: "hidden",
              }}
            >
              <div
                onClick={() => setShowEndpoints(!showEndpoints)}
                style={{
                  padding: "14px 20px",
                  fontSize: "12px",
                  color: "#666",
                  textTransform: "uppercase",
                  letterSpacing: "0.6px",
                  cursor: "pointer",
                  display: "flex",
                  justifyContent: "space-between",
                }}
              >
                <span>{results.endpoints.length} API endpoints discovered</span>
                <span>{showEndpoints ? "▲ Hide" : "▼ Show"}</span>
              </div>
              {showEndpoints &&
                results.endpoints.map((ep, i) => (
                  <div
                    key={i}
                    style={{
                      padding: "10px 20px",
                      borderTop: "0.5px solid #0f0f11",
                      display: "flex",
                      alignItems: "center",
                      gap: "12px",
                      fontSize: "12px",
                    }}
                  >
                    <span
                      style={{
                        padding: "2px 6px",
                        borderRadius: "4px",
                        background: ep.status === 200 ? "#0a1a14" : "#1a1200",
                        color: ep.status === 200 ? "#1D9E75" : "#BA7517",
                        fontFamily: "monospace",
                      }}
                    >
                      {ep.status}
                    </span>
                    <span
                      style={{
                        color: "#ccc",
                        fontFamily: "monospace",
                        flex: 1,
                      }}
                    >
                      {ep.url}
                    </span>
                    {ep.isJSON && (
                      <span style={{ color: "#7F77DD", fontSize: "10px" }}>
                        JSON
                      </span>
                    )}
                  </div>
                ))}
            </div>
          )}

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
            }}
          >
            {[
              { label: `All (${results.summary.total})`, val: "all" },
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
                const s = SEVERITY_STYLES[v.severity] || SEVERITY_STYLES.Info;
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
                        gap: "10px",
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
                    {v.endpoint && (
                      <div
                        style={{
                          fontSize: "12px",
                          color: "#555",
                          fontFamily: "monospace",
                          marginBottom: "6px",
                        }}
                      >
                        {v.method || "GET"} {v.endpoint}
                      </div>
                    )}
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
                    {v.remediation && (
                      <div
                        style={{
                          fontSize: "12px",
                          color: "#1D9E75",
                          background: "#0a1a14",
                          padding: "8px 12px",
                          borderRadius: "6px",
                          borderLeft: "2px solid #1D9E75",
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
