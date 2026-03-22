import { useState } from "react";
import api from "../utils/api";

const SEVERITY_STYLES = {
  Critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
  High: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
  Medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
  Low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
  Info: { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" },
};

export default function GraphQLScanner() {
  const [target, setTarget] = useState("");
  const [graphqlUrl, setGraphqlUrl] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [showSchema, setShowSchema] = useState(false);

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a target URL.");
    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Finding GraphQL endpoint...",
      "Testing introspection...",
      "Checking query depth limits...",
      "Testing batch attacks...",
      "Checking field suggestions...",
      "Testing injection...",
      "Analyzing results...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 5000);

    try {
      const res = await api.post("/api/graphql-scan/scan", {
        target: target.trim(),
        graphqlUrl: graphqlUrl.trim() || undefined,
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
          GraphQL Scanner
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Deep GraphQL security testing — introspection, batching attacks, depth
          limits, injection, field suggestions.
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
              placeholder="e.g. https://api.example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
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
              GraphQL endpoint{" "}
              <span style={{ color: "#444" }}>(optional — auto-detected)</span>
            </label>
            <input
              type="text"
              placeholder="e.g. https://api.example.com/graphql"
              value={graphqlUrl}
              onChange={(e) => setGraphqlUrl(e.target.value)}
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
            <span style={{ fontSize: "13px", color: "#777" }}>
              I confirm I have{" "}
              <span style={{ color: "#a89ff5" }}>written authorization</span> to
              test this GraphQL API.
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
            {loading ? "Scanning..." : "Start GraphQL Scan"}
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
            Running 7 GraphQL security checks
          </div>
        </div>
      )}

      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div
            style={{
              background: "#131315",
              border: `0.5px solid ${results.endpointFound ? "#085041" : "#791F1F"}`,
              borderRadius: "12px",
              padding: "16px 20px",
            }}
          >
            <div
              style={{
                fontSize: "14px",
                fontWeight: "500",
                color: results.endpointFound ? "#1D9E75" : "#E24B4A",
              }}
            >
              {results.endpointFound
                ? `GraphQL endpoint found: ${results.graphqlEndpoint}`
                : "No GraphQL endpoint found"}
            </div>
          </div>

          {results.endpointFound && (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(4, 1fr)",
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
                {
                  label: "Total",
                  val: results.summary.total,
                  color: "#e8e6f0",
                },
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
                    style={{
                      fontSize: "11px",
                      color: "#555",
                      marginTop: "2px",
                    }}
                  >
                    {s.label}
                  </div>
                </div>
              ))}
            </div>
          )}

          {results.schema && (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                overflow: "hidden",
              }}
            >
              <div
                onClick={() => setShowSchema(!showSchema)}
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
                <span>
                  Schema — {results.schema.queries?.length || 0} queries,{" "}
                  {results.schema.mutations?.length || 0} mutations
                </span>
                <span>{showSchema ? "▲ Hide" : "▼ Show"}</span>
              </div>
              {showSchema && (
                <div style={{ padding: "16px 20px" }}>
                  {results.schema.queries?.length > 0 && (
                    <div style={{ marginBottom: "12px" }}>
                      <div
                        style={{
                          fontSize: "11px",
                          color: "#7F77DD",
                          marginBottom: "6px",
                        }}
                      >
                        QUERIES
                      </div>
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: "6px",
                        }}
                      >
                        {results.schema.queries.map((q, i) => (
                          <span
                            key={i}
                            style={{
                              fontSize: "11px",
                              padding: "2px 8px",
                              borderRadius: "6px",
                              background: "#0d0d0f",
                              color: "#a89ff5",
                              fontFamily: "monospace",
                            }}
                          >
                            {q}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {results.schema.mutations?.length > 0 && (
                    <div>
                      <div
                        style={{
                          fontSize: "11px",
                          color: "#E24B4A",
                          marginBottom: "6px",
                        }}
                      >
                        MUTATIONS
                      </div>
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: "6px",
                        }}
                      >
                        {results.schema.mutations.map((m, i) => (
                          <span
                            key={i}
                            style={{
                              fontSize: "11px",
                              padding: "2px 8px",
                              borderRadius: "6px",
                              background: "#0d0d0f",
                              color: "#E24B4A",
                              fontFamily: "monospace",
                            }}
                          >
                            {m}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
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
