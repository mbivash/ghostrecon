import { useState } from "react";
import api from "../utils/api";

const API = "http://localhost:5000";

const SEVERITY_STYLES = {
  Critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
  High: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
  Medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
  Low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
};

export default function WebVulnScanner() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [loadingMsg, setLoadingMsg] = useState("");

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a target URL.");

    setLoading(true);
    setError("");
    setResults(null);

    // Show loading messages so user knows it's working
    const messages = [
      "Fetching target page...",
      "Checking security headers...",
      "Testing forms for XSS...",
      "Testing for SQL injection...",
      "Checking for open redirects...",
      "Analyzing results...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const msgInterval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 3000);

    try {
      const res = await api.post(`${API}/api/webvuln/scan`, {
        target: target.trim(),
        consent,
      });
      setResults(res.data.data);
    } catch (err) {
      setError(
        err.response?.data?.error || "Scan failed. Is the server running?",
      );
    } finally {
      clearInterval(msgInterval);
      setLoading(false);
    }
  };

  const riskScore = (summary) => {
    if (!summary) return 0;
    return Math.min(
      100,
      summary.critical * 40 +
        summary.high * 20 +
        summary.medium * 10 +
        summary.low * 5,
    );
  };

  const riskLabel = (score) => {
    if (score >= 60) return { label: "Critical Risk", color: "#ff4444" };
    if (score >= 40) return { label: "High Risk", color: "#E24B4A" };
    if (score >= 20) return { label: "Medium Risk", color: "#BA7517" };
    if (score > 0) return { label: "Low Risk", color: "#639922" };
    return { label: "Clean", color: "#1D9E75" };
  };

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      {/* Header */}
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Web Vulnerability Scanner
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Scan websites for XSS, SQL injection, missing headers and more.
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
              placeholder="e.g. http://testphp.vulnweb.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "6px" }}>
              Free test target: http://testphp.vulnweb.com (intentionally
              vulnerable site)
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
              test this website for vulnerabilities.
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
            {loading ? "Scanning..." : "Start Scan"}
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
            This may take 20–60 seconds
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
              gridTemplateColumns: "repeat(5, 1fr)",
              gap: "10px",
            }}
          >
            {[
              {
                label: "Risk score",
                val: riskScore(results.summary),
                suffix: "/100",
                color: riskLabel(riskScore(results.summary)).color,
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
                  padding: "14px",
                }}
              >
                <div
                  style={{
                    fontSize: "20px",
                    fontWeight: "500",
                    color: s.color,
                  }}
                >
                  {s.val}
                  {s.suffix || ""}
                </div>
                <div
                  style={{ fontSize: "11px", color: "#555", marginTop: "3px" }}
                >
                  {s.label}
                </div>
              </div>
            ))}
          </div>

          {/* Target info */}
          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              padding: "16px 20px",
            }}
          >
            <div
              style={{
                fontSize: "11px",
                color: "#444",
                textTransform: "uppercase",
                letterSpacing: "0.6px",
                marginBottom: "10px",
              }}
            >
              Target info
            </div>
            <div style={{ display: "flex", gap: "32px", flexWrap: "wrap" }}>
              {[
                { label: "URL", val: results.target },
                { label: "Status", val: results.info.statusCode },
                { label: "Server", val: results.info.server },
                { label: "Forms found", val: results.info.formsFound },
              ].map((item) => (
                <div key={item.label}>
                  <div style={{ fontSize: "11px", color: "#555" }}>
                    {item.label}
                  </div>
                  <div
                    style={{
                      fontSize: "13px",
                      color: "#ccc",
                      marginTop: "2px",
                      fontFamily: "monospace",
                    }}
                  >
                    {item.val}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Vulnerabilities list */}
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
              {results.vulnerabilities.length} vulnerabilities found
            </div>

            {results.vulnerabilities.length === 0 ? (
              <div
                style={{
                  padding: "32px",
                  textAlign: "center",
                  color: "#1D9E75",
                  fontSize: "14px",
                }}
              >
                No vulnerabilities detected. Site appears secure.
              </div>
            ) : (
              results.vulnerabilities.map((v, i) => {
                const style =
                  SEVERITY_STYLES[v.severity] || SEVERITY_STYLES.Low;
                return (
                  <div
                    key={i}
                    style={{
                      padding: "16px 20px",
                      borderBottom:
                        i < results.vulnerabilities.length - 1
                          ? "0.5px solid #0f0f11"
                          : "none",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "10px",
                        marginBottom: "6px",
                      }}
                    >
                      <span
                        style={{
                          fontSize: "11px",
                          padding: "2px 8px",
                          borderRadius: "10px",
                          background: style.bg,
                          color: style.color,
                          border: `0.5px solid ${style.border}`,
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
                    </div>
                    <div
                      style={{
                        fontSize: "13px",
                        color: "#666",
                        marginBottom: "6px",
                      }}
                    >
                      {v.detail}
                    </div>
                    <div
                      style={{
                        fontSize: "12px",
                        color: "#555",
                        fontFamily: "monospace",
                        background: "#0d0d0f",
                        padding: "6px 10px",
                        borderRadius: "6px",
                        display: "inline-block",
                      }}
                    >
                      {v.evidence}
                    </div>
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
