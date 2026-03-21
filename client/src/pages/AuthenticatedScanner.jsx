import { useState } from "react";
import api from "../utils/api";

const SEVERITY_STYLES = {
  Critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
  High: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
  Medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
  Low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
  Info: { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" },
};

export default function AuthenticatedScanner() {
  const [target, setTarget] = useState("");
  const [loginUrl, setLoginUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a target URL.");
    if (!username.trim()) return setError("Please enter a username.");
    if (!password.trim()) return setError("Please enter a password.");

    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Finding login form...",
      "Attempting authentication...",
      "Login successful — crawling pages...",
      "Scanning authenticated pages...",
      "Testing for XSS and SQLi...",
      "Testing for IDOR vulnerabilities...",
      "Analyzing results...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 8000);

    try {
      const res = await api.post("/api/authscan/scan", {
        target: target.trim(),
        loginUrl: loginUrl.trim() || undefined,
        username: username.trim(),
        password,
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

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Authenticated Scanner
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Log in and scan protected pages for XSS, SQLi, IDOR and more. Finds
          vulnerabilities invisible to unauthenticated scanners.
        </p>
      </div>

      {/* Warning */}
      <div
        style={{
          background: "#1a1200",
          border: "0.5px solid #633806",
          borderRadius: "10px",
          padding: "14px 16px",
          marginBottom: "20px",
          fontSize: "13px",
          color: "#BA7517",
        }}
      >
        Only use this on systems you own or have explicit written permission to
        test. Credentials are used only for scanning and never stored.
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
              placeholder="e.g. http://testphp.vulnweb.com"
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
              Login page URL{" "}
              <span style={{ color: "#444" }}>
                (optional — leave blank to auto-detect)
              </span>
            </label>
            <input
              type="text"
              placeholder="e.g. http://testphp.vulnweb.com/login.php"
              value={loginUrl}
              onChange={(e) => setLoginUrl(e.target.value)}
            />
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "12px",
            }}
          >
            <div>
              <label
                style={{
                  fontSize: "12px",
                  color: "#666",
                  display: "block",
                  marginBottom: "6px",
                }}
              >
                Username / Email
              </label>
              <input
                type="text"
                placeholder="e.g. admin"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
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
                Password
              </label>
              <div style={{ position: "relative" }}>
                <input
                  type={showPassword ? "text" : "password"}
                  placeholder="Password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={{ paddingRight: "60px" }}
                />
                <button
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    position: "absolute",
                    right: "10px",
                    top: "50%",
                    transform: "translateY(-50%)",
                    background: "none",
                    border: "none",
                    color: "#555",
                    fontSize: "12px",
                    cursor: "pointer",
                  }}
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
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
              perform authenticated security testing on this application.
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
            {loading ? "Scanning..." : "Start Authenticated Scan"}
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
            This may take 2–5 minutes
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Login status */}
          <div
            style={{
              background: "#131315",
              border: `0.5px solid ${results.loginSuccessful ? "#085041" : "#791F1F"}`,
              borderRadius: "12px",
              padding: "16px 20px",
              display: "flex",
              alignItems: "center",
              gap: "12px",
            }}
          >
            <div
              style={{
                width: "10px",
                height: "10px",
                borderRadius: "50%",
                background: results.loginSuccessful ? "#1D9E75" : "#E24B4A",
                flexShrink: 0,
              }}
            />
            <div>
              <div
                style={{
                  fontSize: "14px",
                  fontWeight: "500",
                  color: results.loginSuccessful ? "#1D9E75" : "#E24B4A",
                }}
              >
                {results.loginSuccessful
                  ? "Authentication successful"
                  : "Authentication failed"}
              </div>
              <div
                style={{ fontSize: "12px", color: "#555", marginTop: "2px" }}
              >
                {results.pagesScanned} authenticated pages scanned ·{" "}
                {results.findings.length} findings
              </div>
            </div>
          </div>

          {/* Stats */}
          {results.loginSuccessful && (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(4, 1fr)",
                gap: "10px",
              }}
            >
              {[
                {
                  label: "Pages scanned",
                  val: results.pagesScanned,
                  color: "#7F77DD",
                },
                {
                  label: "Critical",
                  val: results.findings.filter((f) => f.severity === "Critical")
                    .length,
                  color: "#ff4444",
                },
                {
                  label: "High",
                  val: results.findings.filter((f) => f.severity === "High")
                    .length,
                  color: "#E24B4A",
                },
                {
                  label: "Total findings",
                  val: results.findings.length,
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
                      fontSize: "20px",
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
                      marginTop: "3px",
                    }}
                  >
                    {s.label}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Authenticated URLs */}
          {results.authenticatedUrls?.length > 0 && (
            <details
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                padding: "16px 20px",
              }}
            >
              <summary
                style={{ fontSize: "13px", color: "#666", cursor: "pointer" }}
              >
                {results.authenticatedUrls.length} authenticated pages crawled
              </summary>
              <div
                style={{
                  marginTop: "12px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "4px",
                }}
              >
                {results.authenticatedUrls.map((url, i) => (
                  <div
                    key={i}
                    style={{
                      fontSize: "12px",
                      color: "#555",
                      fontFamily: "monospace",
                    }}
                  >
                    {url}
                  </div>
                ))}
              </div>
            </details>
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
                {results.findings.length} findings from authenticated scan
              </div>
              {results.findings.map((v, i) => {
                const s = SEVERITY_STYLES[v.severity] || SEVERITY_STYLES.Info;
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
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
