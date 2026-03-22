import { useState } from "react";
import api from "../utils/api";

export default function SecretScanner() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [deepScan, setDeepScan] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a target URL.");
    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Fetching main page...",
      "Scanning JavaScript files...",
      "Checking inline scripts...",
      deepScan ? "Deep scanning config files..." : "Analyzing patterns...",
      "Matching secret patterns...",
      "Generating findings...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 5000);

    try {
      const res = await api.post("/api/secretscan/scan", {
        target: target.trim(),
        consent,
        deepScan,
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
    return { bg: "#0a1400", color: "#639922", border: "#27500A" };
  };

  const SECRET_TYPES = [
    "AWS Access Key",
    "Google API Key",
    "GitHub Token",
    "Stripe API Key",
    "Razorpay Key",
    "Slack Token",
    "JWT Token",
    "Private Key",
    "Database URL",
    "Firebase API Key",
    "Twilio Auth Token",
    "SendGrid API Key",
  ];

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Secret Scanner
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Find exposed API keys, tokens, credentials and secrets in page source
          and JavaScript files.
        </p>
      </div>

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
          Detects 30+ secret types
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
          {SECRET_TYPES.map((type) => (
            <span
              key={type}
              style={{
                fontSize: "11px",
                padding: "2px 8px",
                borderRadius: "10px",
                background: "#131315",
                color: "#7F77DD",
                border: "0.5px solid #3C3489",
              }}
            >
              {type}
            </span>
          ))}
        </div>
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
              placeholder="e.g. https://yourapp.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
          </div>

          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              cursor: "pointer",
              padding: "10px",
              background: "#0d0d0f",
              borderRadius: "8px",
              border: deepScan ? "0.5px solid #3C3489" : "0.5px solid #1e1e22",
            }}
          >
            <input
              type="checkbox"
              checked={deepScan}
              onChange={(e) => setDeepScan(e.target.checked)}
              style={{ width: "auto" }}
            />
            <div>
              <div
                style={{
                  fontSize: "13px",
                  color: deepScan ? "#a89ff5" : "#ccc",
                }}
              >
                Deep scan
              </div>
              <div style={{ fontSize: "11px", color: "#555" }}>
                Also check config.js, env.js, constants.js and other common
                config files
              </div>
            </div>
          </label>

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
              scan this site for exposed secrets.
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
            {loading ? "Scanning..." : "Scan for Secrets"}
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
            Scanning {deepScan ? "20+" : "10+"} JS files for 30+ secret patterns
          </div>
        </div>
      )}

      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(4, 1fr)",
              gap: "10px",
            }}
          >
            {[
              {
                label: "URLs scanned",
                val: results.summary.urlsScanned,
                color: "#7F77DD",
              },
              {
                label: "JS files",
                val: results.summary.jsFilesScanned,
                color: "#a89ff5",
              },
              {
                label: "Secrets found",
                val: results.summary.secretsFound,
                color: results.summary.secretsFound > 0 ? "#ff4444" : "#1D9E75",
              },
              {
                label: "Critical",
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
                    fontSize: "22px",
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

          {results.summary.secretsFound === 0 ? (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                padding: "48px",
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
                No secrets found
              </div>
              <div style={{ fontSize: "13px", color: "#555" }}>
                Scanned {results.summary.urlsScanned} URLs and{" "}
                {results.summary.jsFilesScanned} JS files. No exposed
                credentials detected.
              </div>
            </div>
          ) : (
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
                  color: "#E24B4A",
                  textTransform: "uppercase",
                  letterSpacing: "0.6px",
                }}
              >
                ⚠️ {results.summary.secretsFound} secret(s) found — rotate
                immediately
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
                    </div>
                    {f.url && (
                      <div
                        style={{
                          fontSize: "12px",
                          color: "#555",
                          fontFamily: "monospace",
                          marginBottom: "6px",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {f.url}
                      </div>
                    )}
                    <div
                      style={{
                        fontSize: "13px",
                        color: "#777",
                        marginBottom: "8px",
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

          {results.urlsScanned?.length > 0 && (
            <details
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                padding: "14px 20px",
              }}
            >
              <summary
                style={{ fontSize: "12px", color: "#666", cursor: "pointer" }}
              >
                {results.urlsScanned.length} URLs scanned
              </summary>
              <div
                style={{
                  marginTop: "10px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "4px",
                }}
              >
                {results.urlsScanned.map((url, i) => (
                  <div
                    key={i}
                    style={{
                      fontSize: "11px",
                      color: "#555",
                      fontFamily: "monospace",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {url}
                  </div>
                ))}
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  );
}
