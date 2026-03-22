import { useState } from "react";
import api from "../utils/api";

export default function SubdomainTakeover() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [showAlive, setShowAlive] = useState(false);
  const [showDead, setShowDead] = useState(false);

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a target domain.");

    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Querying crt.sh certificate transparency logs...",
      "Processing SSL certificate history...",
      "Running subdomain brute force...",
      "Resolving discovered subdomains...",
      "Checking for takeover vulnerabilities...",
      "Identifying sensitive subdomains...",
      "Analyzing attack surface...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 6000);

    try {
      const res = await api.post("/api/takeover/scan", {
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

  return (
    <div style={{ padding: "32px", maxWidth: "1000px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Subdomain Enumeration & Takeover
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Advanced subdomain discovery using Certificate Transparency logs
          (crt.sh) combined with brute force. Finds every subdomain ever issued
          an SSL certificate.
        </p>
      </div>

      {/* crt.sh info */}
      <div
        style={{
          background: "#0d0d2e",
          border: "0.5px solid #3C3489",
          borderRadius: "10px",
          padding: "14px 16px",
          marginBottom: "20px",
        }}
      >
        <div
          style={{
            fontSize: "12px",
            fontWeight: "500",
            color: "#a89ff5",
            marginBottom: "6px",
          }}
        >
          Powered by Certificate Transparency
        </div>
        <div style={{ fontSize: "12px", color: "#7F77DD", lineHeight: "1.6" }}>
          Every SSL certificate ever issued for a domain is logged publicly.
          crt.sh searches these logs to find subdomains that brute force would
          never find — including old, forgotten and internal subdomains.
        </div>
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
              Queries crt.sh + brute forces 50 common names — checks up to 200
              subdomains
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
              enumerate subdomains of this domain.
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
            {loading ? "Scanning..." : "Start Enumeration"}
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
            May take 1–3 minutes for large domains
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Source stats */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(2, 1fr)",
              gap: "12px",
            }}
          >
            <div
              style={{
                background: "#0d0d2e",
                border: "0.5px solid #3C3489",
                borderRadius: "12px",
                padding: "16px 20px",
              }}
            >
              <div
                style={{
                  fontSize: "11px",
                  color: "#7F77DD",
                  textTransform: "uppercase",
                  letterSpacing: "0.6px",
                  marginBottom: "8px",
                }}
              >
                Certificate Transparency (crt.sh)
              </div>
              <div
                style={{
                  fontSize: "28px",
                  fontWeight: "500",
                  color: "#a89ff5",
                }}
              >
                {results.sources.crtsh}
              </div>
              <div
                style={{ fontSize: "12px", color: "#555", marginTop: "4px" }}
              >
                subdomains from SSL certificate history
              </div>
            </div>
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
                  color: "#666",
                  textTransform: "uppercase",
                  letterSpacing: "0.6px",
                  marginBottom: "8px",
                }}
              >
                Brute Force
              </div>
              <div
                style={{
                  fontSize: "28px",
                  fontWeight: "500",
                  color: "#e8e6f0",
                }}
              >
                {results.sources.bruteforce}
              </div>
              <div
                style={{ fontSize: "12px", color: "#555", marginTop: "4px" }}
              >
                common subdomain names tested
              </div>
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
                label: "Total checked",
                val: results.summary.totalChecked,
                color: "#e8e6f0",
              },
              {
                label: "Alive",
                val: results.summary.aliveSubdomains,
                color: "#7F77DD",
              },
              {
                label: "Vulnerable",
                val: results.summary.vulnerableSubdomains,
                color:
                  results.summary.vulnerableSubdomains > 0
                    ? "#E24B4A"
                    : "#1D9E75",
              },
              {
                label: "Interesting",
                val: results.summary.interestingSubdomains,
                color:
                  results.summary.interestingSubdomains > 0
                    ? "#BA7517"
                    : "#555",
              },
              {
                label: "Dead",
                val: results.summary.deadSubdomains,
                color: "#333",
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

          {/* Vulnerable subdomains alert */}
          {results.vulnerableSubdomains.length > 0 && (
            <div
              style={{
                background: "#1a0505",
                border: "0.5px solid #600",
                borderRadius: "12px",
                padding: "16px 20px",
              }}
            >
              <div
                style={{
                  fontSize: "14px",
                  fontWeight: "500",
                  color: "#ff4444",
                  marginBottom: "10px",
                }}
              >
                ⚠️ {results.vulnerableSubdomains.length} subdomain(s) vulnerable
                to takeover
              </div>
              {results.vulnerableSubdomains.map((s, i) => (
                <div
                  key={i}
                  style={{
                    fontSize: "13px",
                    color: "#E24B4A",
                    fontFamily: "monospace",
                    padding: "4px 0",
                  }}
                >
                  {s.subdomain} → {s.service}
                </div>
              ))}
            </div>
          )}

          {/* Interesting subdomains */}
          {results.interestingSubdomains.length > 0 && (
            <div
              style={{
                background: "#1a1200",
                border: "0.5px solid #633806",
                borderRadius: "12px",
                padding: "16px 20px",
              }}
            >
              <div
                style={{
                  fontSize: "13px",
                  fontWeight: "500",
                  color: "#BA7517",
                  marginBottom: "10px",
                }}
              >
                🔍 {results.interestingSubdomains.length} sensitive subdomain(s)
                found
              </div>
              {results.interestingSubdomains.map((s, i) => (
                <div
                  key={i}
                  style={{
                    fontSize: "13px",
                    color: "#BA7517",
                    fontFamily: "monospace",
                    padding: "3px 0",
                  }}
                >
                  {s.subdomain} — {s.ip || s.cname}
                </div>
              ))}
            </div>
          )}

          {/* Findings */}
          {results.findings.length > 0 && (
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
                    {f.subdomain && (
                      <div
                        style={{
                          fontSize: "12px",
                          color: "#a89ff5",
                          fontFamily: "monospace",
                          marginBottom: "6px",
                        }}
                      >
                        {f.subdomain}
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
          )}

          {/* All alive subdomains */}
          {results.aliveSubdomains.length > 0 && (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                overflow: "hidden",
              }}
            >
              <div
                onClick={() => setShowAlive(!showAlive)}
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
                <span>{results.aliveSubdomains.length} alive subdomains</span>
                <span>{showAlive ? "▲ Hide" : "▼ Show"}</span>
              </div>
              {showAlive &&
                results.aliveSubdomains.map((s, i) => (
                  <div
                    key={i}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                      padding: "10px 20px",
                      borderTop: "0.5px solid #0f0f11",
                      fontSize: "12px",
                    }}
                  >
                    <div
                      style={{
                        width: "6px",
                        height: "6px",
                        borderRadius: "50%",
                        background: s.vulnerable
                          ? "#E24B4A"
                          : s.interesting
                            ? "#BA7517"
                            : "#1D9E75",
                        flexShrink: 0,
                      }}
                    />
                    <span
                      style={{
                        color: "#ccc",
                        fontFamily: "monospace",
                        flex: 1,
                      }}
                    >
                      {s.subdomain}
                    </span>
                    <span
                      style={{
                        color: "#555",
                        fontFamily: "monospace",
                        fontSize: "11px",
                      }}
                    >
                      {s.ip || s.cname || ""}
                    </span>
                    {s.vulnerable && (
                      <span
                        style={{
                          fontSize: "10px",
                          padding: "2px 6px",
                          borderRadius: "6px",
                          background: "#1a0505",
                          color: "#ff4444",
                          border: "0.5px solid #600",
                        }}
                      >
                        VULNERABLE
                      </span>
                    )}
                    {s.interesting && !s.vulnerable && (
                      <span
                        style={{
                          fontSize: "10px",
                          padding: "2px 6px",
                          borderRadius: "6px",
                          background: "#1a1200",
                          color: "#BA7517",
                          border: "0.5px solid #633806",
                        }}
                      >
                        SENSITIVE
                      </span>
                    )}
                  </div>
                ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
