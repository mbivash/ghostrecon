import { useState } from "react";
import api from "../utils/api";

export default function SubdomainTakeover() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [showActive, setShowActive] = useState(false);

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a target domain.");

    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Enumerating subdomains...",
      "Checking DNS records...",
      "Testing for dangling CNAMEs...",
      "Checking service fingerprints...",
      "Analyzing results...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 5000);

    try {
      const res = await api.post("/api/takeover/scan", {
        target: target.trim(),
        consent,
      });
      setResults(res.data.data);
    } catch (err) {
      setError(
        err.response?.data?.error || "Scan failed. Is the server running?",
      );
    } finally {
      clearInterval(interval);
      setLoading(false);
    }
  };

  const sevStyle = (sev) => {
    if (sev === "Critical")
      return { bg: "#1a0505", color: "#ff4444", border: "#600" };
    if (sev === "High")
      return { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" };
    if (sev === "Medium")
      return { bg: "#1a1200", color: "#BA7517", border: "#633806" };
    return { bg: "#0a1400", color: "#639922", border: "#27500A" };
  };

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Subdomain Takeover
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Detect dangling DNS records that could allow an attacker to claim your
          subdomains.
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
              placeholder="e.g. example.com or startup.io"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
              Checks 40 common subdomains for takeover vulnerabilities
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
              test this domain for subdomain takeover vulnerabilities.
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
            This may take 30–60 seconds
          </div>
        </div>
      )}

      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Summary */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(4, 1fr)",
              gap: "10px",
            }}
          >
            {[
              {
                label: "Subdomains checked",
                val: results.totalChecked,
                color: "#e8e6f0",
              },
              {
                label: "Active subdomains",
                val: results.activeSubdomains,
                color: "#7F77DD",
              },
              {
                label: "Vulnerable",
                val: results.vulnerableSubdomains,
                color: results.vulnerableSubdomains > 0 ? "#E24B4A" : "#1D9E75",
              },
              {
                label: "Status",
                val: results.vulnerableSubdomains > 0 ? "At risk" : "Clean",
                color: results.vulnerableSubdomains > 0 ? "#E24B4A" : "#1D9E75",
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
                    fontSize: "20px",
                    fontWeight: "500",
                    color: s.color,
                  }}
                >
                  {s.val}
                </div>
                <div
                  style={{ fontSize: "11px", color: "#555", marginTop: "3px" }}
                >
                  {s.label}
                </div>
              </div>
            ))}
          </div>

          {/* Vulnerable findings */}
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
              {results.findings.length} vulnerable subdomains found
            </div>

            {results.findings.length === 0 ? (
              <div
                style={{
                  padding: "32px",
                  textAlign: "center",
                  color: "#1D9E75",
                  fontSize: "14px",
                }}
              >
                No subdomain takeover vulnerabilities found.
              </div>
            ) : (
              results.findings.map((f, i) => {
                const s = sevStyle(f.severity);
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
                          fontFamily: "monospace",
                        }}
                      >
                        {f.subdomain}
                      </span>
                    </div>
                    <div
                      style={{
                        fontSize: "13px",
                        color: "#666",
                        marginBottom: "6px",
                      }}
                    >
                      Points to unclaimed{" "}
                      <span style={{ color: "#a89ff5" }}>{f.service}</span> —
                      attacker can register this and take control
                    </div>
                    {f.cname && (
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
                        CNAME: {f.cname}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>

          {/* Active subdomains */}
          {results.active.length > 0 && (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                overflow: "hidden",
              }}
            >
              <div
                onClick={() => setShowActive(!showActive)}
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
                <span>{results.active.length} active subdomains found</span>
                <span>{showActive ? "▲ Hide" : "▼ Show"}</span>
              </div>

              {showActive &&
                results.active.map((a, i) => (
                  <div
                    key={i}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "10px 20px",
                      borderTop: "0.5px solid #0f0f11",
                      fontSize: "13px",
                    }}
                  >
                    <span style={{ color: "#ccc", fontFamily: "monospace" }}>
                      {a.subdomain}
                    </span>
                    <div
                      style={{
                        display: "flex",
                        gap: "12px",
                        alignItems: "center",
                      }}
                    >
                      {a.ip && (
                        <span
                          style={{
                            color: "#555",
                            fontSize: "12px",
                            fontFamily: "monospace",
                          }}
                        >
                          {a.ip}
                        </span>
                      )}
                      <span
                        style={{
                          fontSize: "10px",
                          padding: "2px 8px",
                          borderRadius: "10px",
                          background: "#0a1a14",
                          color: "#1D9E75",
                          border: "0.5px solid #085041",
                        }}
                      >
                        Active
                      </span>
                    </div>
                  </div>
                ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
