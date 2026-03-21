import { useState } from "react";
import api from "../utils/api";

export default function NetworkScanner() {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("quick");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!consent) {
      setError("You must check the authorization box before scanning.");
      return;
    }
    if (!target.trim()) {
      setError("Please enter a target IP or domain.");
      return;
    }

    setLoading(true);
    setError("");
    setResults(null);

    try {
      const res = await api.post(`/api/network/scan`, {
        target: target.trim(),
        scanType,
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
    const dangerous = ["ftp", "telnet", "smtp", "http", "rdp", "vnc", "ssh"];
    if (dangerous.includes(service.toLowerCase())) return "#E24B4A";
    return "#1D9E75";
  };

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      {/* Header */}
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Network Scanner
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Scan open ports and detect running services on a target.
        </p>
      </div>

      {/* Scan Form */}
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
          {/* Target input */}
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
              placeholder="e.g. 192.168.1.1 or example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
          </div>

          {/* Scan type */}
          <div>
            <label
              style={{
                fontSize: "12px",
                color: "#666",
                display: "block",
                marginBottom: "6px",
              }}
            >
              Scan type
            </label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
            >
              <option value="quick">Quick scan — top 100 ports (fast)</option>
              <option value="ping">Ping sweep — check if host is alive</option>
              <option value="full">
                Full scan — all ports + OS detection (slow)
              </option>
            </select>
          </div>

          {/* Consent checkbox */}
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

          {/* Error */}
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

          {/* Scan button */}
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

      {/* Loading state */}
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
            This may take 10–60 seconds
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div
          style={{
            background: "#131315",
            border: "0.5px solid #1e1e22",
            borderRadius: "12px",
            overflow: "hidden",
          }}
        >
          {/* Result header */}
          <div
            style={{
              padding: "16px 20px",
              borderBottom: "0.5px solid #1e1e22",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
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
                Scanned in {results.duration} · {results.ports.length} open
                ports found
              </div>
            </div>
            <div
              style={{
                fontSize: "11px",
                padding: "4px 10px",
                borderRadius: "20px",
                background: results.ports.length > 0 ? "#1a0a0a" : "#0a1a14",
                color: results.ports.length > 0 ? "#E24B4A" : "#1D9E75",
                border: `0.5px solid ${results.ports.length > 0 ? "#791F1F" : "#085041"}`,
              }}
            >
              {results.ports.length > 0
                ? `${results.ports.length} ports open`
                : "No open ports"}
            </div>
          </div>

          {/* Ports table */}
          {results.ports.length > 0 ? (
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                fontSize: "13px",
              }}
            >
              <thead>
                <tr style={{ borderBottom: "0.5px solid #1e1e22" }}>
                  {["Port", "Protocol", "State", "Service", "Risk"].map((h) => (
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
                  ))}
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
                        {p.state}
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
          ) : (
            <div
              style={{
                padding: "32px",
                textAlign: "center",
                color: "#555",
                fontSize: "14px",
              }}
            >
              No open ports found on this target.
            </div>
          )}

          {/* Raw output toggle */}
          <details
            style={{
              borderTop: "0.5px solid #1e1e22",
              padding: "12px 20px",
            }}
          >
            <summary
              style={{
                fontSize: "12px",
                color: "#555",
                cursor: "pointer",
                userSelect: "none",
              }}
            >
              View raw Nmap output
            </summary>
            <pre
              style={{
                marginTop: "12px",
                fontSize: "11px",
                color: "#666",
                fontFamily: "monospace",
                lineHeight: "1.6",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
              }}
            >
              {results.raw}
            </pre>
          </details>
        </div>
      )}
    </div>
  );
}
