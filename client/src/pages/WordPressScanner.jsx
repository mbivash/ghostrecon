import { useState } from "react";
import api from "../utils/api";

const SEVERITY_STYLES = {
  Critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
  High: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
  Medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
  Low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
};

export default function WordPressScanner() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("all");
  const [showPlugins, setShowPlugins] = useState(false);

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a WordPress site URL.");

    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Detecting WordPress installation...",
      "Checking WordPress version...",
      "Testing XML-RPC and REST API...",
      "Enumerating users...",
      "Scanning for vulnerable plugins...",
      "Checking login security...",
      "Testing for exposed files...",
      "Analyzing findings...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 5000);

    try {
      const res = await api.post("/api/wordpress/scan", {
        target: target.trim(),
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
      return f.severity?.toLowerCase() === activeTab;
    }) || [];

  return (
    <div style={{ padding: "32px", maxWidth: "1000px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          WordPress Scanner
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Deep WordPress security audit — version, plugins, users, XML-RPC, REST
          API, login security and 15+ checks.
        </p>
      </div>

      {/* Info banner */}
      <div
        style={{
          background: "#0d0d2e",
          border: "0.5px solid #3C3489",
          borderRadius: "10px",
          padding: "12px 16px",
          marginBottom: "20px",
          fontSize: "13px",
          color: "#a89ff5",
        }}
      >
        40% of all websites run WordPress. This scanner checks for the most
        common WordPress vulnerabilities that lead to real breaches.
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
              WordPress site URL
            </label>
            <input
              type="text"
              placeholder="e.g. https://yourwordpresssite.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
              The scanner will auto-detect if the site runs WordPress
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
              perform security testing on this WordPress site.
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
            {loading ? "Scanning..." : "Start WordPress Scan"}
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
            Running 15+ WordPress specific checks
          </div>
        </div>
      )}

      {/* Not WordPress */}
      {results && !results.isWordPress && (
        <div
          style={{
            background: "#131315",
            border: "0.5px solid #1e1e22",
            borderRadius: "12px",
            padding: "32px",
            textAlign: "center",
          }}
        >
          <div style={{ fontSize: "32px", marginBottom: "16px" }}>🔍</div>
          <div
            style={{
              fontSize: "16px",
              fontWeight: "500",
              color: "#e8e6f0",
              marginBottom: "8px",
            }}
          >
            Not a WordPress site
          </div>
          <div style={{ fontSize: "13px", color: "#555" }}>
            This site does not appear to be running WordPress. Use the Web
            Vulnerability Scanner for general security testing.
          </div>
        </div>
      )}

      {/* Results */}
      {results && results.isWordPress && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* WordPress info card */}
          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              padding: "20px",
              display: "flex",
              alignItems: "center",
              gap: "20px",
            }}
          >
            <div style={{ fontSize: "40px" }}>🔵</div>
            <div style={{ flex: 1 }}>
              <div
                style={{
                  fontSize: "16px",
                  fontWeight: "500",
                  color: "#e8e6f0",
                  marginBottom: "4px",
                }}
              >
                WordPress detected — {results.target}
              </div>
              {results.wpVersion && (
                <div style={{ fontSize: "13px", color: "#777" }}>
                  Version: {results.wpVersion}
                </div>
              )}
              <div
                style={{ fontSize: "12px", color: "#555", marginTop: "4px" }}
              >
                {results.plugins?.length || 0} plugins detected ·{" "}
                {results.vulnerablePlugins?.length || 0} vulnerable
              </div>
            </div>
            <div style={{ textAlign: "center" }}>
              <div
                style={{
                  fontSize: "28px",
                  fontWeight: "500",
                  color:
                    results.riskScore >= 70
                      ? "#E24B4A"
                      : results.riskScore >= 40
                        ? "#BA7517"
                        : "#1D9E75",
                }}
              >
                {results.riskScore}
              </div>
              <div style={{ fontSize: "10px", color: "#444" }}>RISK SCORE</div>
            </div>
          </div>

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
              { label: "Total", val: results.summary.total, color: "#7F77DD" },
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
                    fontSize: "20px",
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

          {/* Vulnerable plugins */}
          {results.vulnerablePlugins?.length > 0 && (
            <div
              style={{
                background: "#1a0a0a",
                border: "0.5px solid #791F1F",
                borderRadius: "12px",
                padding: "20px",
              }}
            >
              <div
                style={{
                  fontSize: "13px",
                  fontWeight: "500",
                  color: "#E24B4A",
                  marginBottom: "12px",
                }}
              >
                ⚠️ {results.vulnerablePlugins.length} vulnerable plugin(s)
                detected
              </div>
              {results.vulnerablePlugins.map((p, i) => (
                <div
                  key={i}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    padding: "8px 0",
                    borderBottom:
                      i < results.vulnerablePlugins.length - 1
                        ? "0.5px solid #791F1F33"
                        : "none",
                  }}
                >
                  <span
                    style={{
                      fontSize: "11px",
                      padding: "2px 8px",
                      borderRadius: "10px",
                      background: "#1a0505",
                      color: "#ff4444",
                      border: "0.5px solid #600",
                    }}
                  >
                    {p.severity}
                  </span>
                  <span
                    style={{
                      fontSize: "13px",
                      color: "#ccc",
                      fontWeight: "500",
                    }}
                  >
                    {p.name}
                  </span>
                  <span style={{ fontSize: "11px", color: "#555" }}>
                    {p.cve}
                  </span>
                  <span style={{ fontSize: "12px", color: "#777", flex: 1 }}>
                    {p.vulnDesc}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* All plugins */}
          {results.plugins?.length > 0 && (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                overflow: "hidden",
              }}
            >
              <div
                onClick={() => setShowPlugins(!showPlugins)}
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
                <span>{results.plugins.length} plugins detected</span>
                <span>{showPlugins ? "▲ Hide" : "▼ Show"}</span>
              </div>
              {showPlugins && (
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(3, 1fr)",
                    gap: "1px",
                    background: "#0f0f11",
                  }}
                >
                  {results.plugins.map((p, i) => (
                    <div
                      key={i}
                      style={{
                        padding: "10px 14px",
                        background: "#131315",
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <div
                        style={{
                          width: "6px",
                          height: "6px",
                          borderRadius: "50%",
                          background: p.vulnerable ? "#E24B4A" : "#1D9E75",
                          flexShrink: 0,
                        }}
                      />
                      <span
                        style={{
                          fontSize: "12px",
                          color: p.vulnerable ? "#E24B4A" : "#ccc",
                        }}
                      >
                        {p.name}
                      </span>
                    </div>
                  ))}
                </div>
              )}
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
                No findings in this category.
              </div>
            ) : (
              filtered.map((v, i) => {
                const s = SEVERITY_STYLES[v.severity] || SEVERITY_STYLES.Low;
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
