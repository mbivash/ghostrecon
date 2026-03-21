import { useState } from "react";
import api from "../utils/api";

export default function SSLChecker() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a target domain.");

    setLoading(true);
    setError("");
    setResults(null);

    try {
      const res = await api.post("/api/ssl/scan", {
        target: target.trim(),
        consent,
      });
      setResults(res.data.data);
    } catch (err) {
      setError(
        err.response?.data?.error || "Scan failed. Is the server running?",
      );
    } finally {
      setLoading(false);
    }
  };

  const sevStyle = (sev) => {
    const styles = {
      Critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
      High: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
      Medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
      Low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
      Info: { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" },
    };
    return styles[sev] || styles.Info;
  };

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      {/* Header */}
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          SSL/TLS Checker
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Check SSL certificate validity, expiry, protocol version and security
          grade.
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
              Target domain
            </label>
            <input
              type="text"
              placeholder="e.g. google.com or github.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
              Enter domain only — no https:// needed
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
              <span style={{ color: "#a89ff5" }}>authorization</span> to check
              this domain's SSL certificate.
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
            {loading ? "Checking..." : "Check SSL"}
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
          <div style={{ color: "#a89ff5", fontSize: "14px" }}>
            Checking SSL certificate...
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Grade card */}
          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              padding: "24px",
              display: "flex",
              alignItems: "center",
              gap: "24px",
            }}
          >
            {/* Big grade */}
            <div
              style={{
                width: "80px",
                height: "80px",
                flexShrink: 0,
                border: `2px solid ${results.gradeColor || "#1D9E75"}`,
                borderRadius: "12px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                background: "#0d0d0f",
              }}
            >
              <span
                style={{
                  fontSize: "36px",
                  fontWeight: "500",
                  color: results.gradeColor || "#1D9E75",
                }}
              >
                {results.grade || "A"}
              </span>
            </div>

            {/* Summary */}
            <div style={{ flex: 1 }}>
              <div
                style={{
                  fontSize: "16px",
                  fontWeight: "500",
                  color: "#e8e6f0",
                  marginBottom: "4px",
                }}
              >
                {results.hostname}
              </div>
              <div
                style={{
                  fontSize: "13px",
                  color: results.valid ? "#1D9E75" : "#E24B4A",
                  marginBottom: "8px",
                }}
              >
                {results.valid
                  ? "Certificate is valid and trusted"
                  : "Certificate has issues"}
              </div>
              {results.daysRemaining !== undefined && (
                <div style={{ fontSize: "12px", color: "#555" }}>
                  {results.daysRemaining > 0
                    ? `Expires in ${results.daysRemaining} days — ${results.validTo}`
                    : `Expired on ${results.validTo}`}
                </div>
              )}
            </div>

            {/* Days bar */}
            {results.daysRemaining !== undefined && results.daysTotal && (
              <div style={{ width: "120px", flexShrink: 0 }}>
                <div
                  style={{
                    fontSize: "11px",
                    color: "#555",
                    marginBottom: "6px",
                    textAlign: "right",
                  }}
                >
                  {results.daysRemaining} days left
                </div>
                <div
                  style={{
                    height: "6px",
                    background: "#1e1e22",
                    borderRadius: "3px",
                  }}
                >
                  <div
                    style={{
                      height: "100%",
                      borderRadius: "3px",
                      width: `${Math.min(100, Math.max(0, (results.daysRemaining / results.daysTotal) * 100))}%`,
                      background:
                        results.daysRemaining > 30
                          ? "#1D9E75"
                          : results.daysRemaining > 0
                            ? "#BA7517"
                            : "#E24B4A",
                    }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Certificate details */}
          {results.subject && (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                padding: "20px",
              }}
            >
              <div
                style={{
                  fontSize: "11px",
                  color: "#444",
                  textTransform: "uppercase",
                  letterSpacing: "0.6px",
                  marginBottom: "14px",
                }}
              >
                Certificate details
              </div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: "12px",
                }}
              >
                {[
                  { label: "Common name", val: results.subject?.cn },
                  { label: "Organization", val: results.subject?.org },
                  { label: "Issued by", val: results.issuer?.org },
                  { label: "Valid from", val: results.validFrom },
                  { label: "Valid to", val: results.validTo },
                  { label: "Protocol", val: results.protocol },
                  { label: "Cipher", val: results.cipher },
                  {
                    label: "Serial number",
                    val: results.serialNumber?.substring(0, 20) + "...",
                  },
                ].map((item) => (
                  <div
                    key={item.label}
                    style={{
                      padding: "10px 14px",
                      background: "#0d0d0f",
                      borderRadius: "8px",
                    }}
                  >
                    <div
                      style={{
                        fontSize: "11px",
                        color: "#555",
                        marginBottom: "3px",
                      }}
                    >
                      {item.label}
                    </div>
                    <div
                      style={{
                        fontSize: "13px",
                        color: "#ccc",
                        fontFamily: "monospace",
                      }}
                    >
                      {item.val || "N/A"}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* SAN */}
          {results.san && results.san !== "None" && (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                padding: "20px",
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
                Subject alternative names
              </div>
              <div
                style={{
                  fontSize: "13px",
                  color: "#777",
                  fontFamily: "monospace",
                  lineHeight: "1.8",
                }}
              >
                {results.san}
              </div>
            </div>
          )}

          {/* Issues */}
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
              {results.issues?.length || 0} findings
            </div>
            {results.issues?.map((issue, i) => {
              const s = sevStyle(issue.severity);
              return (
                <div
                  key={i}
                  style={{
                    padding: "16px 20px",
                    borderBottom:
                      i < results.issues.length - 1
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
                        background: s.bg,
                        color: s.color,
                        border: `0.5px solid ${s.border}`,
                      }}
                    >
                      {issue.severity}
                    </span>
                    <span
                      style={{
                        fontSize: "14px",
                        fontWeight: "500",
                        color: "#ccc",
                      }}
                    >
                      {issue.issue}
                    </span>
                  </div>
                  <div style={{ fontSize: "13px", color: "#666" }}>
                    {issue.detail}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
