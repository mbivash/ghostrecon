import { useState } from "react";
import api from "../utils/api";

export default function S3Scanner() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a domain.");
    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Generating bucket name patterns...",
      "Checking S3 buckets...",
      "Testing read access...",
      "Testing write access...",
      "Checking subdomain buckets...",
      "Analyzing results...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 8000);

    try {
      const res = await api.post("/api/s3scan/scan", {
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
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          S3 Bucket Scanner
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Find misconfigured AWS S3 buckets — public read, public write,
          directory listing and more.
        </p>
      </div>

      <div
        style={{
          background: "#1a1200",
          border: "0.5px solid #633806",
          borderRadius: "10px",
          padding: "12px 16px",
          marginBottom: "20px",
          fontSize: "13px",
          color: "#BA7517",
        }}
      >
        S3 misconfigurations have exposed billions of records. Capital One lost
        100M customer records. Facebook exposed 500M user records. This scanner
        finds these issues before attackers do.
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
              placeholder="e.g. startup.com or yourcompany.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
              Checks 35+ common S3 bucket naming patterns for this domain
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
              scan for S3 buckets associated with this domain.
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
            {loading ? "Scanning..." : "Scan S3 Buckets"}
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
            Checking 35+ bucket names — may take 1-2 minutes
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
                label: "Buckets checked",
                val: results.summary.bucketsChecked,
                color: "#7F77DD",
              },
              {
                label: "Buckets found",
                val: results.summary.bucketsFound,
                color: "#BA7517",
              },
              {
                label: "Vulnerable",
                val: results.summary.vulnerableBuckets,
                color:
                  results.summary.vulnerableBuckets > 0 ? "#E24B4A" : "#1D9E75",
              },
              {
                label: "Critical findings",
                val: results.summary.critical,
                color: results.summary.critical > 0 ? "#ff4444" : "#1D9E75",
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
                    fontSize: "24px",
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

          {/* Vulnerable buckets alert */}
          {results.vulnerableBuckets.length > 0 && (
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
                  marginBottom: "8px",
                }}
              >
                ⚠️ {results.vulnerableBuckets.length} vulnerable bucket(s) found
              </div>
              {results.vulnerableBuckets.map((b, i) => (
                <div
                  key={i}
                  style={{
                    fontSize: "13px",
                    color: "#E24B4A",
                    fontFamily: "monospace",
                  }}
                >
                  {b}.s3.amazonaws.com
                </div>
              ))}
            </div>
          )}

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
              {results.findings.length} findings
            </div>

            {results.findings.map((v, i) => {
              const s = sevStyle(v.severity);
              return (
                <div
                  key={i}
                  style={{
                    padding: "18px 20px",
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
                  {v.url && (
                    <div
                      style={{
                        fontSize: "12px",
                        color: "#555",
                        fontFamily: "monospace",
                        marginBottom: "6px",
                      }}
                    >
                      {v.url}
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
            })}
          </div>
        </div>
      )}
    </div>
  );
}
