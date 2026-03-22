import { useState } from "react";
import api from "../utils/api";

export default function S3Scanner() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [showPossible, setShowPossible] = useState(false);

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a domain.");
    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Crawling site for S3 URLs...",
      "Scanning JavaScript files...",
      "Testing confirmed S3 buckets...",
      "Testing possible bucket names...",
      "Analyzing results...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 6000);

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

  const confirmedFindings =
    results?.findings?.filter((f) => f.confirmed === true) || [];
  const possibleFindings =
    results?.findings?.filter((f) => f.confirmed === false) || [];
  const infoFindings =
    results?.findings?.filter((f) => f.severity === "Info") || [];

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          S3 Bucket Scanner
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Crawls the target site and finds real S3 bucket URLs in page source
          and JavaScript files — then tests only confirmed buckets for
          misconfigurations.
        </p>
      </div>

      {/* How it works */}
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
            marginBottom: "8px",
          }}
        >
          How this scanner works
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          {[
            "1. Crawls your site and all JavaScript files for S3 bucket URLs",
            "2. Tests confirmed buckets — found directly in your source code",
            "3. Tests possible buckets — common naming patterns (clearly labeled)",
            "4. Only confirmed findings should be actioned immediately",
          ].map((step, i) => (
            <div key={i} style={{ fontSize: "12px", color: "#7F77DD" }}>
              {step}
            </div>
          ))}
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
              Target URL
            </label>
            <input
              type="text"
              placeholder="e.g. https://yourcompany.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
              Enter the full website URL — scanner will crawl source code for
              real S3 references
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
              perform S3 security testing on this domain.
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
            Crawling site and testing buckets
          </div>
        </div>
      )}

      {/* Results */}
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
                label: "JS files scanned",
                val: results.summary.jsFilesScanned,
                color: "#7F77DD",
              },
              {
                label: "Confirmed buckets",
                val: results.summary.confirmedBuckets,
                color:
                  results.summary.confirmedBuckets > 0 ? "#BA7517" : "#1D9E75",
              },
              {
                label: "Critical findings",
                val: results.summary.critical,
                color: results.summary.critical > 0 ? "#ff4444" : "#1D9E75",
              },
              {
                label: "High findings",
                val: results.summary.high,
                color: results.summary.high > 0 ? "#E24B4A" : "#1D9E75",
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

          {/* Confirmed buckets list */}
          {results.confirmedBuckets.length > 0 && (
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
                  fontSize: "12px",
                  color: "#666",
                  textTransform: "uppercase",
                  letterSpacing: "0.6px",
                  marginBottom: "10px",
                }}
              >
                {results.confirmedBuckets.length} S3 bucket(s) found in site
                source code
              </div>
              {results.confirmedBuckets.map((b, i) => (
                <div
                  key={i}
                  style={{
                    fontSize: "13px",
                    color: "#a89ff5",
                    fontFamily: "monospace",
                    padding: "4px 0",
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                  }}
                >
                  <span
                    style={{
                      fontSize: "10px",
                      padding: "2px 6px",
                      borderRadius: "6px",
                      background: "#0a1a14",
                      color: "#1D9E75",
                      border: "0.5px solid #085041",
                    }}
                  >
                    CONFIRMED
                  </span>
                  {b}.s3.amazonaws.com
                </div>
              ))}
            </div>
          )}

          {/* Confirmed findings */}
          {confirmedFindings.length > 0 && (
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
                  color: "#e8e6f0",
                  textTransform: "uppercase",
                  letterSpacing: "0.6px",
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                }}
              >
                <span
                  style={{
                    width: "8px",
                    height: "8px",
                    borderRadius: "50%",
                    background: "#E24B4A",
                    display: "inline-block",
                  }}
                />
                {confirmedFindings.length} confirmed findings — action required
              </div>
              {confirmedFindings.map((v, i) => {
                const s = sevStyle(v.severity);
                return (
                  <div
                    key={i}
                    style={{
                      padding: "16px 20px",
                      borderBottom:
                        i < confirmedFindings.length - 1
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
                    </div>
                    {v.endpoint && (
                      <div
                        style={{
                          fontSize: "12px",
                          color: "#555",
                          fontFamily: "monospace",
                          marginBottom: "6px",
                        }}
                      >
                        {v.endpoint}
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
          )}

          {/* Possible findings */}
          {possibleFindings.length > 0 && (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                overflow: "hidden",
              }}
            >
              <div
                onClick={() => setShowPossible(!showPossible)}
                style={{
                  padding: "14px 20px",
                  borderBottom: showPossible ? "0.5px solid #1e1e22" : "none",
                  fontSize: "12px",
                  color: "#666",
                  textTransform: "uppercase",
                  letterSpacing: "0.6px",
                  cursor: "pointer",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <div
                  style={{ display: "flex", alignItems: "center", gap: "8px" }}
                >
                  <span
                    style={{
                      width: "8px",
                      height: "8px",
                      borderRadius: "50%",
                      background: "#BA7517",
                      display: "inline-block",
                    }}
                  />
                  {possibleFindings.length} possible findings — verify ownership
                  before acting
                </div>
                <span>{showPossible ? "▲ Hide" : "▼ Show"}</span>
              </div>
              {showPossible &&
                possibleFindings.map((v, i) => {
                  const s = sevStyle(v.severity);
                  return (
                    <div
                      key={i}
                      style={{
                        padding: "16px 20px",
                        borderBottom:
                          i < possibleFindings.length - 1
                            ? "0.5px solid #0f0f11"
                            : "none",
                        background: "rgba(186,117,23,0.03)",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "11px",
                          color: "#BA7517",
                          marginBottom: "8px",
                        }}
                      >
                        ⚠️ Ownership not confirmed — verify this bucket belongs
                        to your organization
                      </div>
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
                      </div>
                      {v.endpoint && (
                        <div
                          style={{
                            fontSize: "12px",
                            color: "#555",
                            fontFamily: "monospace",
                            marginBottom: "6px",
                          }}
                        >
                          {v.endpoint}
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
          )}

          {/* Info findings */}
          {infoFindings.length > 0 &&
            confirmedFindings.length === 0 &&
            possibleFindings.length === 0 && (
              <div
                style={{
                  background: "#131315",
                  border: "0.5px solid #1e1e22",
                  borderRadius: "12px",
                  padding: "24px",
                  textAlign: "center",
                }}
              >
                <div style={{ fontSize: "32px", marginBottom: "12px" }}>✅</div>
                <div
                  style={{
                    fontSize: "15px",
                    fontWeight: "500",
                    color: "#1D9E75",
                    marginBottom: "8px",
                  }}
                >
                  No S3 misconfigurations found
                </div>
                <div
                  style={{ fontSize: "13px", color: "#555", lineHeight: "1.6" }}
                >
                  {infoFindings[0]?.detail}
                </div>
              </div>
            )}
        </div>
      )}
    </div>
  );
}
