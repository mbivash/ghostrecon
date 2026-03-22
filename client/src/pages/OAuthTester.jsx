import { useState } from "react";
import api from "../utils/api";

const SEVERITY_STYLES = {
  Critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
  High: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
  Medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
  Low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
  Info: { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" },
};

export default function OAuthTester() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [showEndpoints, setShowEndpoints] = useState(false);

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a target URL.");
    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Discovering OAuth endpoints...",
      "Parsing discovery document...",
      "Testing open redirect...",
      "Checking CSRF protection...",
      "Testing token leakage...",
      "Checking JWT security...",
      "Testing PKCE enforcement...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 5000);

    try {
      const res = await api.post("/api/oauth/scan", {
        target: target.trim(),
        consent,
      });
      setResults(res.data.data);
    } catch (err) {
      setError(err.response?.data?.error || "Scan failed.");
    } finally {
      clearInterval(interval);
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          OAuth 2.0 Tester
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Test OAuth 2.0 and OpenID Connect implementations for open redirects,
          CSRF, token leakage, JWT weaknesses and PKCE enforcement.
        </p>
      </div>

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
              placeholder="e.g. https://accounts.example.com or https://api.example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
              Auto-discovers /.well-known/openid-configuration and OAuth
              endpoints
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
            <span style={{ fontSize: "13px", color: "#777" }}>
              I confirm I have{" "}
              <span style={{ color: "#a89ff5" }}>written authorization</span> to
              test this OAuth implementation.
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
            {loading ? "Testing..." : "Test OAuth Security"}
          </button>
        </div>
      </div>

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
            Testing OAuth 2.0 security controls
          </div>
        </div>
      )}

      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(4, 1fr)",
              gap: "10px",
            }}
          >
            {[
              {
                label: "Endpoints found",
                val: results.summary.endpointsFound,
                color: "#7F77DD",
              },
              {
                label: "Critical",
                val: results.summary.critical,
                color: "#ff4444",
              },
              { label: "High", val: results.summary.high, color: "#E24B4A" },
              { label: "Total", val: results.summary.total, color: "#e8e6f0" },
            ].map((s) => (
              <div
                key={s.label}
                style={{
                  background: "#131315",
                  border: "0.5px solid #1e1e22",
                  borderRadius: "10px",
                  padding: "14px",
                }}
              >
                <div
                  style={{
                    fontSize: "22px",
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

          {Object.keys(results.endpoints).length > 0 && (
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
                <span>OAuth endpoints discovered</span>
                <span>{showEndpoints ? "▲ Hide" : "▼ Show"}</span>
              </div>
              {showEndpoints && (
                <div style={{ padding: "0 20px 16px" }}>
                  {Object.entries(results.endpoints)
                    .filter(([k, v]) => v && typeof v === "string")
                    .map(([key, value]) => (
                      <div
                        key={key}
                        style={{
                          display: "flex",
                          gap: "12px",
                          padding: "6px 0",
                          fontSize: "12px",
                          borderBottom: "0.5px solid #0f0f11",
                        }}
                      >
                        <span
                          style={{
                            color: "#7F77DD",
                            minWidth: "180px",
                            flexShrink: 0,
                          }}
                        >
                          {key.replace(/([A-Z])/g, " $1").trim()}
                        </span>
                        <span
                          style={{
                            color: "#777",
                            fontFamily: "monospace",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {value}
                        </span>
                      </div>
                    ))}
                </div>
              )}
            </div>
          )}

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
              {results.findings.length} findings
            </div>
            {results.findings.map((f, i) => {
              const s = SEVERITY_STYLES[f.severity] || SEVERITY_STYLES.Info;
              return (
                <div
                  key={i}
                  style={{
                    padding: "16px 20px",
                    borderBottom:
                      i < results.findings.length - 1
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
                      {f.severity}
                    </span>
                    <span
                      style={{
                        fontSize: "14px",
                        fontWeight: "500",
                        color: "#ccc",
                      }}
                    >
                      {f.type}
                    </span>
                    {f.owasp && (
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
                        {f.owasp}
                      </span>
                    )}
                  </div>
                  {f.endpoint && (
                    <div
                      style={{
                        fontSize: "12px",
                        color: "#555",
                        fontFamily: "monospace",
                        marginBottom: "6px",
                      }}
                    >
                      {f.endpoint}
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
                    {f.detail}
                  </div>
                  {f.evidence && (
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
                      {f.evidence}
                    </div>
                  )}
                  {f.remediation && (
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
                      Fix: {f.remediation}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
