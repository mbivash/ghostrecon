import { useState } from "react";
import api from "../utils/api";

export default function NetworkScanner() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [scanType, setScanType] = useState("common");
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [showAllPorts, setShowAllPorts] = useState(false);
  const [activeTab, setActiveTab] = useState("all");

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a target.");
    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Resolving hostname...",
      "Scanning ports...",
      "Grabbing service banners...",
      "Detecting service versions...",
      "Analyzing security risks...",
      "Generating findings...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 8000);

    try {
      const res = await api.post("/api/network/scan", {
        target: target.trim(),
        consent,
        scanType,
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

  const riskColor = (risk) => {
    if (risk === "Critical") return "#ff4444";
    if (risk === "High") return "#E24B4A";
    if (risk === "Medium") return "#BA7517";
    if (risk === "Low") return "#1D9E75";
    return "#555";
  };

  const sevStyle = (sev) => {
    if (sev === "Critical")
      return { bg: "#1a0505", color: "#ff4444", border: "#600" };
    if (sev === "High")
      return { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" };
    if (sev === "Medium")
      return { bg: "#1a1200", color: "#BA7517", border: "#633806" };
    if (sev === "Low")
      return { bg: "#0a1400", color: "#639922", border: "#27500A" };
    return { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" };
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
          Network Scanner
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Real TCP port scanning with service detection, banner grabbing and
          version fingerprinting. Finds exposed databases, remote access, and
          dangerous services.
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
              Target
            </label>
            <input
              type="text"
              placeholder="e.g. 192.168.1.1 or example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
              IP address or hostname — real TCP port scanner
            </div>
          </div>

          <div>
            <label
              style={{
                fontSize: "12px",
                color: "#666",
                display: "block",
                marginBottom: "8px",
              }}
            >
              Scan type
            </label>
            <div style={{ display: "flex", gap: "8px" }}>
              {[
                {
                  val: "quick",
                  label: "Quick",
                  desc: "20 critical ports — fast",
                },
                { val: "common", label: "Common", desc: "80 important ports" },
                { val: "full", label: "Full", desc: "80+ ports — thorough" },
              ].map((type) => (
                <button
                  key={type.val}
                  onClick={() => setScanType(type.val)}
                  style={{
                    flex: 1,
                    padding: "10px",
                    borderRadius: "8px",
                    cursor: "pointer",
                    background: scanType === type.val ? "#13121f" : "#0d0d0f",
                    border:
                      scanType === type.val
                        ? "0.5px solid #7F77DD"
                        : "0.5px solid #1e1e22",
                    textAlign: "left",
                  }}
                >
                  <div
                    style={{
                      fontSize: "13px",
                      fontWeight: "500",
                      color: scanType === type.val ? "#a89ff5" : "#ccc",
                    }}
                  >
                    {type.label}
                  </div>
                  <div
                    style={{
                      fontSize: "11px",
                      color: "#555",
                      marginTop: "2px",
                    }}
                  >
                    {type.desc}
                  </div>
                </button>
              ))}
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
              perform port scanning on this target.
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
            {loading ? "Scanning..." : "Start Port Scan"}
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
            Real TCP scan — may take 1–3 minutes
          </div>
        </div>
      )}

      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Target info */}
          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              padding: "16px 20px",
              display: "flex",
              alignItems: "center",
              gap: "20px",
            }}
          >
            <div style={{ flex: 1 }}>
              <div
                style={{
                  fontSize: "16px",
                  fontWeight: "500",
                  color: "#e8e6f0",
                }}
              >
                {results.target}
              </div>
              <div
                style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}
              >
                IP: {results.ip}
              </div>
            </div>
            <div style={{ textAlign: "center" }}>
              <div
                style={{
                  fontSize: "28px",
                  fontWeight: "500",
                  color:
                    results.summary.critical > 0
                      ? "#ff4444"
                      : results.summary.high > 0
                        ? "#E24B4A"
                        : "#1D9E75",
                }}
              >
                {results.summary.openPorts}
              </div>
              <div style={{ fontSize: "11px", color: "#444" }}>open ports</div>
            </div>
          </div>

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
                label: "Ports scanned",
                val: results.summary.portsScanned,
                color: "#7F77DD",
              },
              {
                label: "Open ports",
                val: results.summary.openPorts,
                color: "#e8e6f0",
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

          {/* Open ports table */}
          {results.openPorts.length > 0 && (
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
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <span
                  style={{
                    fontSize: "12px",
                    color: "#666",
                    textTransform: "uppercase",
                    letterSpacing: "0.6px",
                  }}
                >
                  {results.openPorts.length} open ports
                </span>
              </div>
              {(showAllPorts
                ? results.openPorts
                : results.openPorts.slice(0, 15)
              ).map((port, i) => (
                <div
                  key={i}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "12px",
                    padding: "12px 20px",
                    borderBottom: "0.5px solid #0f0f11",
                  }}
                >
                  <span
                    style={{
                      fontSize: "14px",
                      fontWeight: "500",
                      color: "#a89ff5",
                      fontFamily: "monospace",
                      width: "50px",
                      flexShrink: 0,
                    }}
                  >
                    {port.port}
                  </span>
                  <span
                    style={{
                      fontSize: "13px",
                      color: "#ccc",
                      width: "120px",
                      flexShrink: 0,
                    }}
                  >
                    {port.service}
                  </span>
                  <span
                    style={{
                      fontSize: "11px",
                      color: riskColor(port.risk),
                      padding: "2px 8px",
                      borderRadius: "10px",
                      background: "#0d0d0f",
                      border: `0.5px solid ${riskColor(port.risk)}33`,
                      flexShrink: 0,
                    }}
                  >
                    {port.risk}
                  </span>
                  <span style={{ fontSize: "12px", color: "#555", flex: 1 }}>
                    {port.description}
                  </span>
                  {port.version && (
                    <span
                      style={{
                        fontSize: "11px",
                        color: "#7F77DD",
                        fontFamily: "monospace",
                        flexShrink: 0,
                      }}
                    >
                      {port.version}
                    </span>
                  )}
                  {port.banner && !port.version && (
                    <span
                      style={{
                        fontSize: "11px",
                        color: "#444",
                        fontFamily: "monospace",
                        flexShrink: 0,
                        maxWidth: "200px",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {port.banner.substring(0, 50)}
                    </span>
                  )}
                </div>
              ))}
              {results.openPorts.length > 15 && (
                <div
                  onClick={() => setShowAllPorts(!showAllPorts)}
                  style={{
                    padding: "12px 20px",
                    textAlign: "center",
                    fontSize: "13px",
                    color: "#7F77DD",
                    cursor: "pointer",
                    borderTop: "0.5px solid #0f0f11",
                  }}
                >
                  {showAllPorts
                    ? "▲ Show less"
                    : `▼ Show all ${results.openPorts.length} ports`}
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
              {filtered.length} security findings
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
                const s = sevStyle(v.severity);
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
