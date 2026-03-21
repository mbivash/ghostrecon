import { useState } from "react";
import api from "../utils/api";

export default function OsintEngine() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("dns");

  const handleScan = async () => {
    if (!consent) return setError("You must check the authorization box.");
    if (!target.trim()) return setError("Please enter a target domain.");

    setLoading(true);
    setError("");
    setResults(null);

    const messages = [
      "Resolving DNS records...",
      "Running Whois lookup...",
      "Scanning for subdomains...",
      "Geolocating IP address...",
      "Detecting tech stack...",
      "Compiling results...",
    ];
    let i = 0;
    setLoadingMsg(messages[0]);
    const interval = setInterval(() => {
      i++;
      if (i < messages.length) setLoadingMsg(messages[i]);
    }, 4000);

    try {
      const res = await api.post(`/api/osint/scan`, {
        target: target.trim(),
        consent,
      });
      setResults(res.data.data);
      setActiveTab("dns");
    } catch (err) {
      setError(
        err.response?.data?.error || "Scan failed. Is the server running?",
      );
    } finally {
      clearInterval(interval);
      setLoading(false);
    }
  };

  const tabs = ["dns", "whois", "subdomains", "geo", "tech"];

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      {/* Header */}
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          OSINT Engine
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Passive intelligence gathering — DNS, Whois, subdomains, geolocation
          and tech stack.
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
            <div
              style={{ fontSize: "12px", color: "#666", marginBottom: "6px" }}
            >
              Target domain
            </div>
            <input
              type="text"
              placeholder="e.g. google.com or github.com"
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
              I confirm this is{" "}
              <span style={{ color: "#a89ff5" }}>passive reconnaissance</span>{" "}
              and I am authorized to gather this information.
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
            {loading ? "Scanning..." : "Start OSINT Scan"}
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
            This may take 20–40 seconds
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div>
          {/* Summary bar */}
          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              padding: "16px 20px",
              marginBottom: "16px",
              display: "flex",
              gap: "32px",
              flexWrap: "wrap",
            }}
          >
            {[
              { label: "Domain", val: results.target },
              { label: "IP address", val: results.ipList?.[0] || "N/A" },
              {
                label: "Subdomains found",
                val: results.subdomains?.length || 0,
              },
              { label: "Technologies", val: results.techStack?.length || 0 },
              {
                label: "DNS record types",
                val: Object.keys(results.dns || {}).filter(
                  (k) => results.dns[k]?.length > 0,
                ).length,
              },
            ].map((item) => (
              <div key={item.label}>
                <div style={{ fontSize: "11px", color: "#555" }}>
                  {item.label}
                </div>
                <div
                  style={{
                    fontSize: "13px",
                    fontWeight: "500",
                    color: "#e8e6f0",
                    marginTop: "2px",
                    fontFamily: "monospace",
                  }}
                >
                  {item.val}
                </div>
              </div>
            ))}
          </div>

          {/* Tabs */}
          <div
            style={{
              display: "flex",
              gap: "4px",
              marginBottom: "16px",
              background: "#131315",
              padding: "4px",
              borderRadius: "10px",
              border: "0.5px solid #1e1e22",
              width: "fit-content",
            }}
          >
            {tabs.map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  padding: "7px 16px",
                  borderRadius: "8px",
                  fontSize: "13px",
                  background: activeTab === tab ? "#7F77DD" : "transparent",
                  color: activeTab === tab ? "white" : "#666",
                  border: "none",
                  cursor: "pointer",
                  textTransform: "capitalize",
                }}
              >
                {tab === "geo"
                  ? "Geolocation"
                  : tab === "tech"
                    ? "Tech stack"
                    : tab.toUpperCase()}
              </button>
            ))}
          </div>

          {/* DNS Tab */}
          {activeTab === "dns" && (
            <ResultCard>
              {Object.entries(results.dns || {}).map(
                ([type, records]) =>
                  records &&
                  records.length > 0 && (
                    <div key={type} style={{ marginBottom: "16px" }}>
                      <div
                        style={{
                          fontSize: "11px",
                          color: "#7F77DD",
                          textTransform: "uppercase",
                          letterSpacing: "0.8px",
                          marginBottom: "6px",
                        }}
                      >
                        {type} Records
                      </div>
                      {records.map((r, i) => (
                        <div
                          key={i}
                          style={{
                            fontSize: "13px",
                            color: "#ccc",
                            fontFamily: "monospace",
                            padding: "5px 10px",
                            background: "#0d0d0f",
                            borderRadius: "6px",
                            marginBottom: "4px",
                          }}
                        >
                          {typeof r === "object"
                            ? JSON.stringify(r)
                            : String(r)}
                        </div>
                      ))}
                    </div>
                  ),
              )}
            </ResultCard>
          )}

          {/* Whois Tab */}
          {activeTab === "whois" && (
            <ResultCard>
              {Object.keys(results.whois || {}).length > 0 ? (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "10px",
                  }}
                >
                  {Object.entries(results.whois).map(([key, val]) => (
                    <div
                      key={key}
                      style={{
                        display: "flex",
                        gap: "16px",
                        padding: "8px 0",
                        borderBottom: "0.5px solid #0f0f11",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "12px",
                          color: "#555",
                          width: "120px",
                          flexShrink: 0,
                          textTransform: "capitalize",
                        }}
                      >
                        {key}
                      </div>
                      <div
                        style={{
                          fontSize: "13px",
                          color: "#ccc",
                          fontFamily: "monospace",
                        }}
                      >
                        {val}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ fontSize: "13px", color: "#555" }}>
                  Whois data not available for this domain.
                </div>
              )}
            </ResultCard>
          )}

          {/* Subdomains Tab */}
          {activeTab === "subdomains" && (
            <ResultCard>
              <div
                style={{
                  fontSize: "12px",
                  color: "#555",
                  marginBottom: "12px",
                }}
              >
                {results.subdomains?.length || 0} subdomains found
              </div>
              {results.subdomains?.length === 0 ? (
                <div style={{ fontSize: "13px", color: "#555" }}>
                  No subdomains found.
                </div>
              ) : (
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: "6px",
                  }}
                >
                  {results.subdomains.map((sub, i) => (
                    <div
                      key={i}
                      style={{
                        fontSize: "13px",
                        color: "#a89ff5",
                        fontFamily: "monospace",
                        padding: "6px 10px",
                        background: "#0d0d0f",
                        borderRadius: "6px",
                      }}
                    >
                      {sub}
                    </div>
                  ))}
                </div>
              )}
            </ResultCard>
          )}

          {/* Geolocation Tab */}
          {activeTab === "geo" && (
            <ResultCard>
              {results.geoIP?.status === "success" ? (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "10px",
                  }}
                >
                  {[
                    { label: "IP address", val: results.geoIP.query },
                    { label: "Country", val: results.geoIP.country },
                    { label: "Region", val: results.geoIP.regionName },
                    { label: "City", val: results.geoIP.city },
                    { label: "ISP", val: results.geoIP.isp },
                    { label: "Organization", val: results.geoIP.org },
                    { label: "AS number", val: results.geoIP.as },
                  ].map((item) => (
                    <div
                      key={item.label}
                      style={{
                        display: "flex",
                        gap: "16px",
                        padding: "8px 0",
                        borderBottom: "0.5px solid #0f0f11",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "12px",
                          color: "#555",
                          width: "120px",
                          flexShrink: 0,
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
              ) : (
                <div style={{ fontSize: "13px", color: "#555" }}>
                  Geolocation data not available.
                </div>
              )}
            </ResultCard>
          )}

          {/* Tech Stack Tab */}
          {activeTab === "tech" && (
            <ResultCard>
              <div
                style={{
                  fontSize: "12px",
                  color: "#555",
                  marginBottom: "12px",
                }}
              >
                {results.techStack?.length || 0} technologies detected
              </div>
              {results.techStack?.length === 0 ? (
                <div style={{ fontSize: "13px", color: "#555" }}>
                  No technologies detected.
                </div>
              ) : (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "8px",
                  }}
                >
                  {results.techStack.map((tech, i) => (
                    <div
                      key={i}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        padding: "10px 14px",
                        background: "#0d0d0f",
                        borderRadius: "8px",
                      }}
                    >
                      <div style={{ fontSize: "14px", color: "#ccc" }}>
                        {tech.name}
                      </div>
                      <div
                        style={{
                          fontSize: "11px",
                          padding: "2px 8px",
                          borderRadius: "10px",
                          background: "#0d0d2e",
                          color: "#7F77DD",
                          border: "0.5px solid #3C3489",
                        }}
                      >
                        {tech.category}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </ResultCard>
          )}
        </div>
      )}
    </div>
  );
}

function ResultCard({ children }) {
  return (
    <div
      style={{
        background: "#131315",
        border: "0.5px solid #1e1e22",
        borderRadius: "12px",
        padding: "20px",
      }}
    >
      {children}
    </div>
  );
}
