import { useState, useEffect } from "react";
import api from "../utils/api";

const API = "http://localhost:5000";

export default function ReportGenerator() {
  const [scans, setScans] = useState([]);
  const [selected, setSelected] = useState([]);
  const [clientName, setClientName] = useState("");
  const [reportTitle, setReportTitle] = useState("");
  const [analystName, setAnalystName] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingScans, setLoadingScans] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    setLoadingScans(true);
    try {
      const res = await api.get(`${API}/api/history`);
      setScans(res.data.scans);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingScans(false);
    }
  };

  const toggleScan = (id) => {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id],
    );
  };

  const selectAll = () => {
    if (selected.length === scans.length) {
      setSelected([]);
    } else {
      setSelected(scans.map((s) => s.id));
    }
  };

  const generateReport = async () => {
    if (!clientName.trim()) return setError("Please enter a client name.");
    if (!analystName.trim()) return setError("Please enter your name.");
    if (selected.length === 0)
      return setError("Please select at least one scan.");

    setLoading(true);
    setError("");
    setSuccess(false);

    try {
      // Fetch full details for each selected scan
      const scanDetails = await Promise.all(
        selected.map((id) =>
          axios.get(`${API}/api/history/${id}`).then((r) => r.data.scan.result),
        ),
      );

      const response = await axios.post(
        `${API}/api/reports/generate`,
        {
          clientName,
          reportTitle: reportTitle || "Security Assessment Report",
          analystName,
          scans: scanDetails,
        },
        { responseType: "blob" },
      );

      // Auto download
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute(
        "download",
        `ghostrecon-${clientName.replace(/\s+/g, "-")}-${Date.now()}.pdf`,
      );
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      setSuccess(true);
    } catch (err) {
      setError("Failed to generate report. Is the server running?");
    } finally {
      setLoading(false);
    }
  };

  const SEVERITY_STYLE = {
    critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
    high: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
    medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
    low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
    info: { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" },
  };

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      {/* Header */}
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Report Generator
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Select your scans, fill in client details and generate a professional
          PDF.
        </p>
      </div>

      <div
        style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}
      >
        {/* Left — Scan selector */}
        <div>
          <div
            style={{
              fontSize: "11px",
              color: "#444",
              textTransform: "uppercase",
              letterSpacing: "0.8px",
              marginBottom: "10px",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span>Select scans to include</span>
            <button
              onClick={selectAll}
              style={{
                background: "none",
                border: "none",
                color: "#7F77DD",
                fontSize: "11px",
                cursor: "pointer",
                padding: 0,
              }}
            >
              {selected.length === scans.length ? "Deselect all" : "Select all"}
            </button>
          </div>

          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              overflow: "hidden",
              maxHeight: "420px",
              overflowY: "auto",
            }}
          >
            {loadingScans ? (
              <div
                style={{
                  padding: "24px",
                  textAlign: "center",
                  color: "#555",
                  fontSize: "13px",
                }}
              >
                Loading scans...
              </div>
            ) : scans.length === 0 ? (
              <div style={{ padding: "32px", textAlign: "center" }}>
                <div
                  style={{
                    fontSize: "13px",
                    color: "#555",
                    marginBottom: "6px",
                  }}
                >
                  No scans in history
                </div>
                <div style={{ fontSize: "12px", color: "#444" }}>
                  Run some scans first then come back here
                </div>
              </div>
            ) : (
              scans.map((scan, i) => {
                const sev =
                  SEVERITY_STYLE[scan.severity] || SEVERITY_STYLE.info;
                const isSelected = selected.includes(scan.id);
                return (
                  <div
                    key={scan.id}
                    onClick={() => toggleScan(scan.id)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "12px",
                      padding: "12px 16px",
                      borderBottom:
                        i < scans.length - 1 ? "0.5px solid #0f0f11" : "none",
                      cursor: "pointer",
                      background: isSelected ? "#13121f" : "transparent",
                      borderLeft: isSelected
                        ? "2px solid #7F77DD"
                        : "2px solid transparent",
                      transition: "all 0.1s",
                    }}
                    onMouseEnter={(e) => {
                      if (!isSelected)
                        e.currentTarget.style.background = "#0f0f11";
                    }}
                    onMouseLeave={(e) => {
                      if (!isSelected)
                        e.currentTarget.style.background = "transparent";
                    }}
                  >
                    {/* Checkbox */}
                    <div
                      style={{
                        width: "16px",
                        height: "16px",
                        borderRadius: "4px",
                        flexShrink: 0,
                        background: isSelected ? "#7F77DD" : "transparent",
                        border: isSelected
                          ? "1px solid #7F77DD"
                          : "1px solid #333",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      {isSelected && (
                        <svg
                          width="10"
                          height="10"
                          viewBox="0 0 10 10"
                          fill="none"
                        >
                          <path
                            d="M2 5L4 7L8 3"
                            stroke="white"
                            strokeWidth="1.5"
                            strokeLinecap="round"
                          />
                        </svg>
                      )}
                    </div>

                    {/* Scan info */}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div
                        style={{
                          fontSize: "13px",
                          color: "#ccc",
                          fontFamily: "monospace",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {scan.target}
                      </div>
                      <div
                        style={{
                          fontSize: "11px",
                          color: "#444",
                          marginTop: "2px",
                        }}
                      >
                        {scan.type} ·{" "}
                        {new Date(scan.scanned_at).toLocaleDateString()}
                      </div>
                    </div>

                    {/* Severity */}
                    <span
                      style={{
                        fontSize: "10px",
                        padding: "2px 7px",
                        borderRadius: "10px",
                        background: sev.bg,
                        color: sev.color,
                        border: `0.5px solid ${sev.border}`,
                        flexShrink: 0,
                      }}
                    >
                      {scan.findings_count} findings
                    </span>
                  </div>
                );
              })
            )}
          </div>

          {selected.length > 0 && (
            <div
              style={{ fontSize: "12px", color: "#7F77DD", marginTop: "8px" }}
            >
              {selected.length} scan{selected.length > 1 ? "s" : ""} selected
            </div>
          )}
        </div>

        {/* Right — Report details */}
        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          <div
            style={{
              fontSize: "11px",
              color: "#444",
              textTransform: "uppercase",
              letterSpacing: "0.8px",
              marginBottom: "2px",
            }}
          >
            Report details
          </div>

          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              padding: "20px",
              display: "flex",
              flexDirection: "column",
              gap: "14px",
            }}
          >
            <div>
              <div
                style={{ fontSize: "12px", color: "#666", marginBottom: "6px" }}
              >
                Client name
              </div>
              <input
                placeholder="e.g. Acme Corp"
                value={clientName}
                onChange={(e) => setClientName(e.target.value)}
              />
            </div>

            <div>
              <div
                style={{ fontSize: "12px", color: "#666", marginBottom: "6px" }}
              >
                Report title
              </div>
              <input
                placeholder="e.g. Web Application Security Assessment"
                value={reportTitle}
                onChange={(e) => setReportTitle(e.target.value)}
              />
            </div>

            <div>
              <div
                style={{ fontSize: "12px", color: "#666", marginBottom: "6px" }}
              >
                Your name (analyst)
              </div>
              <input
                placeholder="e.g. Your Name"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
              />
            </div>

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

            {success && (
              <div
                style={{
                  fontSize: "13px",
                  color: "#1D9E75",
                  background: "#0a1a14",
                  border: "0.5px solid #085041",
                  borderRadius: "8px",
                  padding: "10px 14px",
                }}
              >
                PDF downloaded successfully!
              </div>
            )}

            <button
              className="btn-primary"
              onClick={generateReport}
              disabled={loading || selected.length === 0}
              style={{ padding: "12px", width: "100%" }}
            >
              {loading
                ? "Generating PDF..."
                : `Generate PDF — ${selected.length} scan${selected.length !== 1 ? "s" : ""}`}
            </button>

            {/* What's included */}
            <div
              style={{ borderTop: "0.5px solid #1e1e22", paddingTop: "14px" }}
            >
              <div
                style={{
                  fontSize: "11px",
                  color: "#444",
                  marginBottom: "10px",
                }}
              >
                Report includes
              </div>
              {[
                "Cover page with client details",
                "Executive summary",
                "All selected scan results",
                "Vulnerability details with evidence",
                "Prioritized recommendations",
              ].map((item, i) => (
                <div
                  key={i}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    fontSize: "12px",
                    color: "#555",
                    marginBottom: "6px",
                  }}
                >
                  <div
                    style={{
                      width: "4px",
                      height: "4px",
                      borderRadius: "50%",
                      background: "#7F77DD",
                      flexShrink: 0,
                    }}
                  />
                  {item}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
