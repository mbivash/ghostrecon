import { useState } from "react";
import api from "../utils/api";

export default function NetworkScanner() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!consent)
      return setError("You must check the authorization box before scanning.");
    if (!target.trim()) return setError("Please enter a target IP or domain.");

    setLoading(true);
    setError("");
    setResults(null);

    try {
      const res = await api.post("/api/network/scan", {
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

  const severityColor = (service) => {
    const dangerous = [
      "ftp",
      "telnet",
      "smtp",
      "http",
      "rdp",
      "vnc",
      "ssh",
      "smb",
    ];
    if (dangerous.includes(service.toLowerCase())) return "#E24B4A";
    return "#1D9E75";
  };

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Network Scanner
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Scan open ports and detect services using Shodan InternetDB.
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
              Target IP or domain
            </label>
            <input
              type="text"
              placeholder="e.g. scanme.nmap.org or 45.33.32.156"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
              Works on any public IP or domain. Test with: scanme.nmap.org
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
              scan this target. Unauthorized scanning is illegal.
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
          <div style={{ color: "#666", fontSize: "14px" }}>
            Scanning {target}...
          </div>
          <div style={{ color: "#444", fontSize: "12px", marginTop: "6px" }}>
            Querying Shodan InternetDB...
          </div>
        </div>
      )}

      {results && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Result header */}
          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              padding: "16px 20px",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div>
              <div
                style={{
                  fontSize: "14px",
                  fontWeight: "500",
                  color: "#e8e6f0",
                }}
              >
                {results.host}
              </div>
              <div
                style={{ fontSize: "12px", color: "#555", marginTop: "2px" }}
              >
                {results.ports.length} open ports · {results.vulns?.length || 0}{" "}
                known CVEs · via {results.source}
              </div>
            </div>
            <div
              style={{
                fontSize: "11px",
                padding: "4px 10px",
                borderRadius: "20px",
                background:
                  results.vulns?.length > 0
                    ? "#1a0505"
                    : results.ports.length > 0
                      ? "#1a0a0a"
                      : "#0a1a14",
                color:
                  results.vulns?.length > 0
                    ? "#ff4444"
                    : results.ports.length > 0
                      ? "#E24B4A"
                      : "#1D9E75",
                border: `0.5px solid ${results.vulns?.length > 0 ? "#600" : results.ports.length > 0 ? "#791F1F" : "#085041"}`,
              }}
            >
              {results.vulns?.length > 0
                ? "Vulnerable"
                : results.ports.length > 0
                  ? "Exposed"
                  : "Clean"}
            </div>
          </div>

          {/* Tags */}
          {results.tags?.length > 0 && (
            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
              {results.tags.map((tag, i) => (
                <span
                  key={i}
                  style={{
                    fontSize: "11px",
                    padding: "3px 10px",
                    borderRadius: "12px",
                    background: "#0d0d2e",
                    color: "#7F77DD",
                    border: "0.5px solid #3C3489",
                  }}
                >
                  {tag}
                </span>
              ))}
            </div>
          )}

          {/* Ports table */}
          {results.ports.length > 0 && (
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
                  padding: "12px 20px",
                  borderBottom: "0.5px solid #1e1e22",
                  fontSize: "11px",
                  color: "#444",
                  textTransform: "uppercase",
                  letterSpacing: "0.6px",
                }}
              >
                Open ports
              </div>
              <table
                style={{
                  width: "100%",
                  borderCollapse: "collapse",
                  fontSize: "13px",
                }}
              >
                <thead>
                  <tr style={{ borderBottom: "0.5px solid #1e1e22" }}>
                    {["Port", "Protocol", "State", "Service", "Risk"].map(
                      (h) => (
                        <th
                          key={h}
                          style={{
                            padding: "10px 20px",
                            textAlign: "left",
                            fontSize: "11px",
                            color: "#444",
                            fontWeight: "500",
                            letterSpacing: "0.5px",
                            textTransform: "uppercase",
                          }}
                        >
                          {h}
                        </th>
                      ),
                    )}
                  </tr>
                </thead>
                <tbody>
                  {results.ports.map((p, i) => (
                    <tr
                      key={i}
                      style={{
                        borderBottom: "0.5px solid #0f0f11",
                        background: i % 2 === 0 ? "transparent" : "#0f0f11",
                      }}
                    >
                      <td
                        style={{
                          padding: "12px 20px",
                          fontFamily: "monospace",
                          color: "#a89ff5",
                        }}
                      >
                        {p.port}
                      </td>
                      <td style={{ padding: "12px 20px", color: "#777" }}>
                        {p.protocol}
                      </td>
                      <td style={{ padding: "12px 20px" }}>
                        <span
                          style={{
                            fontSize: "11px",
                            padding: "2px 8px",
                            borderRadius: "10px",
                            background: "#0a1a14",
                            color: "#1D9E75",
                            border: "0.5px solid #085041",
                          }}
                        >
                          open
                        </span>
                      </td>
                      <td style={{ padding: "12px 20px", color: "#ccc" }}>
                        {p.service}
                      </td>
                      <td style={{ padding: "12px 20px" }}>
                        <span
                          style={{
                            fontSize: "11px",
                            padding: "2px 8px",
                            borderRadius: "10px",
                            color: severityColor(p.service),
                            background:
                              severityColor(p.service) === "#E24B4A"
                                ? "#1a0a0a"
                                : "#0a1a14",
                            border: `0.5px solid ${severityColor(p.service) === "#E24B4A" ? "#791F1F" : "#085041"}`,
                          }}
                        >
                          {severityColor(p.service) === "#E24B4A"
                            ? "Review"
                            : "Low risk"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* CVEs */}
          {results.vulns?.length > 0 && (
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
                  padding: "12px 20px",
                  borderBottom: "0.5px solid #1e1e22",
                  fontSize: "11px",
                  color: "#444",
                  textTransform: "uppercase",
                  letterSpacing: "0.6px",
                }}
              >
                Known vulnerabilities (CVEs)
              </div>
              {results.vulns.map((vuln, i) => (
                <div
                  key={i}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "12px 20px",
                    borderBottom:
                      i < results.vulns.length - 1
                        ? "0.5px solid #0f0f11"
                        : "none",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                    }}
                  >
                    <span
                      style={{
                        fontSize: "11px",
                        padding: "2px 8px",
                        borderRadius: "10px",
                        background: "#1a0a0a",
                        color: "#E24B4A",
                        border: "0.5px solid #791F1F",
                      }}
                    >
                      {vuln.severity}
                    </span>
                    <span
                      style={{
                        fontSize: "13px",
                        color: "#ccc",
                        fontFamily: "monospace",
                      }}
                    >
                      {vuln.id}
                    </span>
                  </div>
                  <a
                    href={vuln.url}
                    target="_blank"
                    rel="noreferrer"
                    style={{
                      fontSize: "11px",
                      color: "#7F77DD",
                      textDecoration: "none",
                    }}
                  >
                    View CVE →
                  </a>
                </div>
              ))}
            </div>
          )}

          {results.ports.length === 0 && results.vulns?.length === 0 && (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                padding: "32px",
                textAlign: "center",
                color: "#1D9E75",
                fontSize: "14px",
              }}
            >
              No open ports or vulnerabilities found on this target.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
