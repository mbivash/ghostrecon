import { useState } from "react";
import api from "../utils/api";

const SEVERITY_STYLES = {
  Critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
  High: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
  Medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
  Low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
  Info: { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" },
};

export default function DNSCheck() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [showRecords, setShowRecords] = useState(false);
  const [showSubdomains, setShowSubdomains] = useState(false);
  const [activeTab, setActiveTab] = useState("all");

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a domain.");
    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Resolving nameservers...",
      "Testing zone transfer (AXFR)...",
      "Checking DNSSEC...",
      "Enumerating subdomains...",
      "Checking for open resolvers...",
      "Analyzing DNS records...",
      "Checking CAA and wildcard records...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 5000);

    try {
      const res = await api.post("/api/dnscheck/scan", {
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
      return f.severity.toLowerCase() === activeTab;
    }) || [];

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          DNS Security Check
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Zone transfer, DNSSEC, open resolvers, CAA records, wildcard DNS,
          subdomain enumeration and more.
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
              Target domain
            </label>
            <input
              type="text"
              placeholder="e.g. google.com or yourdomain.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
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
              <span style={{ color: "#a89ff5" }}>authorization</span> to perform
              DNS security testing on this domain.
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
            {loading ? "Scanning..." : "Start DNS Check"}
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
            Running 9 DNS security checks
          </div>
        </div>
      )}

      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Summary */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(5, 1fr)",
              gap: "10px",
            }}
          >
            {[
              {
                label: "Nameservers",
                val: results.summary.nameservers,
                color: "#7F77DD",
              },
              {
                label: "Subdomains found",
                val: results.summary.subdomainsFound,
                color: "#a89ff5",
              },
              {
                label: "Critical",
                val: results.summary.critical,
                color: results.summary.critical > 0 ? "#ff4444" : "#1D9E75",
              },
              {
                label: "High",
                val: results.summary.high,
                color: results.summary.high > 0 ? "#E24B4A" : "#1D9E75",
              },
              {
                label: "Total findings",
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

          {/* Nameservers */}
          {results.nameservers.length > 0 && (
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
                Nameservers
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                {results.nameservers.map((ns, i) => (
                  <span
                    key={i}
                    style={{
                      fontSize: "12px",
                      color: "#a89ff5",
                      fontFamily: "monospace",
                      padding: "4px 10px",
                      background: "#0d0d2e",
                      borderRadius: "6px",
                      border: "0.5px solid #3C3489",
                    }}
                  >
                    {ns}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* DNS Records */}
          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              overflow: "hidden",
            }}
          >
            <div
              onClick={() => setShowRecords(!showRecords)}
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
              <span>DNS Records</span>
              <span>{showRecords ? "▲ Hide" : "▼ Show"}</span>
            </div>
            {showRecords && (
              <div style={{ padding: "0 20px 16px" }}>
                {Object.entries(results.records).map(([type, values]) => {
                  if (!values || values.length === 0) return null;
                  return (
                    <div key={type} style={{ marginBottom: "12px" }}>
                      <div
                        style={{
                          fontSize: "11px",
                          color: "#7F77DD",
                          fontFamily: "monospace",
                          marginBottom: "4px",
                        }}
                      >
                        {type}
                      </div>
                      {(Array.isArray(values) ? values : [values])
                        .slice(0, 3)
                        .map((v, i) => (
                          <div
                            key={i}
                            style={{
                              fontSize: "12px",
                              color: "#777",
                              fontFamily: "monospace",
                              padding: "4px 8px",
                              background: "#0d0d0f",
                              borderRadius: "4px",
                              marginBottom: "2px",
                            }}
                          >
                            {typeof v === "object"
                              ? JSON.stringify(v).substring(0, 120)
                              : v.toString().substring(0, 120)}
                          </div>
                        ))}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Subdomains */}
          {results.subdomains.length > 0 && (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                overflow: "hidden",
              }}
            >
              <div
                onClick={() => setShowSubdomains(!showSubdomains)}
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
                <span>{results.subdomains.length} active subdomains found</span>
                <span>{showSubdomains ? "▲ Hide" : "▼ Show"}</span>
              </div>
              {showSubdomains &&
                results.subdomains.map((s, i) => (
                  <div
                    key={i}
                    style={{
                      padding: "10px 20px",
                      borderTop: "0.5px solid #0f0f11",
                      display: "flex",
                      justifyContent: "space-between",
                      fontSize: "13px",
                    }}
                  >
                    <span style={{ color: "#ccc", fontFamily: "monospace" }}>
                      {s.subdomain}
                    </span>
                    <span style={{ color: "#555", fontFamily: "monospace" }}>
                      {s.ip || s.cname}
                    </span>
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
                No findings in this category.
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
