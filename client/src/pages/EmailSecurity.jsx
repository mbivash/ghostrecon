import { useState } from "react";
import api from "../utils/api";

export default function EmailSecurity() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a domain.");
    setLoading(true);
    setError("");
    setResults(null);
    try {
      const res = await api.post("/api/emailsecurity/scan", {
        target: target.trim(),
        consent,
      });
      setResults(res.data.data);
    } catch (err) {
      setError(err.response?.data?.error || "Scan failed.");
    } finally {
      setLoading(false);
    }
  };

  const scoreColor = (score) => {
    if (score >= 80) return "#1D9E75";
    if (score >= 50) return "#BA7517";
    return "#E24B4A";
  };

  const statusBadge = (exists, label) => (
    <span
      style={{
        fontSize: "11px",
        padding: "2px 8px",
        borderRadius: "10px",
        background: exists ? "#0a1a14" : "#1a0a0a",
        color: exists ? "#1D9E75" : "#E24B4A",
        border: `0.5px solid ${exists ? "#085041" : "#791F1F"}`,
      }}
    >
      {exists ? `${label} configured` : `${label} missing`}
    </span>
  );

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
          Email Security
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Check SPF, DKIM, DMARC and MX records. Find out if your domain can be
          spoofed.
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
              Domain to check
            </label>
            <input
              type="text"
              placeholder="e.g. google.com or yourbusiness.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
              Enter domain only — no http:// needed
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
              this domain's email security.
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
            {loading ? "Checking..." : "Check Email Security"}
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
            Checking DNS records...
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Score + spoofing alert */}
          <div
            style={{
              background: "#131315",
              border: `0.5px solid ${results.spoofable ? "#791F1F" : "#085041"}`,
              borderRadius: "12px",
              padding: "24px",
              display: "flex",
              alignItems: "center",
              gap: "24px",
            }}
          >
            <div
              style={{
                width: "80px",
                height: "80px",
                flexShrink: 0,
                border: `2px solid ${scoreColor(results.score)}`,
                borderRadius: "12px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                background: "#0d0d0f",
              }}
            >
              <span
                style={{
                  fontSize: "28px",
                  fontWeight: "500",
                  color: scoreColor(results.score),
                }}
              >
                {results.score}
              </span>
            </div>
            <div style={{ flex: 1 }}>
              <div
                style={{
                  fontSize: "16px",
                  fontWeight: "500",
                  color: "#e8e6f0",
                  marginBottom: "6px",
                }}
              >
                {results.domain}
              </div>
              <div
                style={{
                  fontSize: "13px",
                  marginBottom: "10px",
                  color: results.spoofable ? "#E24B4A" : "#1D9E75",
                }}
              >
                {results.spoofReason}
              </div>
              <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                {statusBadge(results.spf.exists, "SPF")}
                {statusBadge(results.dkim.exists, "DKIM")}
                {statusBadge(results.dmarc.exists, "DMARC")}
                {statusBadge(results.mx.exists, "MX")}
              </div>
            </div>
          </div>

          {/* SPF */}
          <Section
            title="SPF Record"
            badge={results.spf.exists ? results.spf.strength : "missing"}
            badgeColor={
              results.spf.strength === "strong"
                ? "#1D9E75"
                : results.spf.strength === "weak"
                  ? "#BA7517"
                  : "#E24B4A"
            }
          >
            {results.spf.record && (
              <div
                style={{
                  fontSize: "12px",
                  color: "#777",
                  fontFamily: "monospace",
                  background: "#0d0d0f",
                  padding: "8px 12px",
                  borderRadius: "6px",
                  marginBottom: "10px",
                }}
              >
                {results.spf.record}
              </div>
            )}
            {results.spf.issues.map((issue, i) => (
              <Issue key={i} text={issue} type="issue" />
            ))}
            {results.spf.recommendations.map((rec, i) => (
              <Issue key={i} text={rec} type="fix" />
            ))}
            {results.spf.issues.length === 0 && (
              <Issue text="SPF is properly configured" type="good" />
            )}
          </Section>

          {/* DKIM */}
          <Section
            title="DKIM Record"
            badge={
              results.dkim.exists
                ? `${results.dkim.selectors.length} selector(s) found`
                : "missing"
            }
            badgeColor={results.dkim.exists ? "#1D9E75" : "#E24B4A"}
          >
            {results.dkim.selectors.map((s, i) => (
              <div
                key={i}
                style={{
                  fontSize: "12px",
                  color: "#777",
                  fontFamily: "monospace",
                  background: "#0d0d0f",
                  padding: "8px 12px",
                  borderRadius: "6px",
                  marginBottom: "6px",
                }}
              >
                Selector: {s.selector} — {s.valid ? "✓ Valid" : "✗ Invalid"}
              </div>
            ))}
            {results.dkim.issues.map((issue, i) => (
              <Issue key={i} text={issue} type="issue" />
            ))}
            {results.dkim.recommendations.map((rec, i) => (
              <Issue key={i} text={rec} type="fix" />
            ))}
            {results.dkim.issues.length === 0 && (
              <Issue text="DKIM is properly configured" type="good" />
            )}
          </Section>

          {/* DMARC */}
          <Section
            title="DMARC Record"
            badge={
              results.dmarc.exists ? `p=${results.dmarc.policy}` : "missing"
            }
            badgeColor={
              results.dmarc.policy === "reject"
                ? "#1D9E75"
                : results.dmarc.policy === "quarantine"
                  ? "#BA7517"
                  : "#E24B4A"
            }
          >
            {results.dmarc.record && (
              <div
                style={{
                  fontSize: "12px",
                  color: "#777",
                  fontFamily: "monospace",
                  background: "#0d0d0f",
                  padding: "8px 12px",
                  borderRadius: "6px",
                  marginBottom: "10px",
                }}
              >
                {results.dmarc.record}
              </div>
            )}
            {results.dmarc.issues.map((issue, i) => (
              <Issue key={i} text={issue} type="issue" />
            ))}
            {results.dmarc.recommendations.map((rec, i) => (
              <Issue key={i} text={rec} type="fix" />
            ))}
            {results.dmarc.issues.length === 0 && (
              <Issue text="DMARC is properly configured" type="good" />
            )}
          </Section>

          {/* MX */}
          <Section
            title="MX Records"
            badge={results.mx.exists ? results.mx.provider : "missing"}
            badgeColor={results.mx.exists ? "#7F77DD" : "#E24B4A"}
          >
            {results.mx.records.map((r, i) => (
              <div
                key={i}
                style={{
                  fontSize: "12px",
                  color: "#777",
                  fontFamily: "monospace",
                  background: "#0d0d0f",
                  padding: "8px 12px",
                  borderRadius: "6px",
                  marginBottom: "6px",
                }}
              >
                Priority {r.priority}: {r.exchange}
              </div>
            ))}
            {results.mx.issues.map((issue, i) => (
              <Issue key={i} text={issue} type="issue" />
            ))}
            {results.mx.recommendations.map((rec, i) => (
              <Issue key={i} text={rec} type="fix" />
            ))}
          </Section>

          {/* All issues summary */}
          {results.allIssues.length > 0 && (
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
                {results.allIssues.length} issues found
              </div>
              {results.allIssues.map((item, i) => {
                const s = sevStyle(item.severity);
                return (
                  <div
                    key={i}
                    style={{
                      padding: "14px 20px",
                      borderBottom:
                        i < results.allIssues.length - 1
                          ? "0.5px solid #0f0f11"
                          : "none",
                      display: "flex",
                      alignItems: "flex-start",
                      gap: "10px",
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
                        flexShrink: 0,
                        marginTop: "2px",
                      }}
                    >
                      {item.severity}
                    </span>
                    <div>
                      <span
                        style={{
                          fontSize: "12px",
                          color: "#555",
                          marginRight: "8px",
                        }}
                      >
                        [{item.source}]
                      </span>
                      <span style={{ fontSize: "13px", color: "#ccc" }}>
                        {item.issue}
                      </span>
                    </div>
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

function Section({ title, badge, badgeColor, children }) {
  return (
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
          display: "flex",
          alignItems: "center",
          gap: "10px",
          marginBottom: "14px",
        }}
      >
        <span style={{ fontSize: "14px", fontWeight: "500", color: "#e8e6f0" }}>
          {title}
        </span>
        <span
          style={{
            fontSize: "11px",
            padding: "2px 8px",
            borderRadius: "10px",
            background: "#0d0d0f",
            color: badgeColor,
            border: `0.5px solid ${badgeColor}`,
          }}
        >
          {badge}
        </span>
      </div>
      {children}
    </div>
  );
}

function Issue({ text, type }) {
  const styles = {
    issue: { color: "#E24B4A", icon: "✗" },
    fix: { color: "#7F77DD", icon: "→" },
    good: { color: "#1D9E75", icon: "✓" },
  };
  const s = styles[type];
  return (
    <div
      style={{
        display: "flex",
        gap: "8px",
        fontSize: "13px",
        color: s.color,
        marginBottom: "6px",
      }}
    >
      <span style={{ flexShrink: 0 }}>{s.icon}</span>
      <span>{text}</span>
    </div>
  );
}
