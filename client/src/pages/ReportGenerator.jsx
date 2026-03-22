import { useState, useEffect } from "react";
import api from "../utils/api";

export default function ReportGenerator() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(null);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await api.get("/api/reports/scans");
      setScans(res.data.scans);
    } catch (err) {
      setError("Failed to load scans.");
    } finally {
      setLoading(false);
    }
  };

  const generateReport = async (scanId, target) => {
    setGenerating(scanId);
    setError("");
    try {
      const res = await api.post(
        "/api/reports/generate",
        { scanId },
        { responseType: "blob" },
      );
      const blob = new Blob([res.data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `GhostRecon-Report-${target.replace(/[^a-z0-9]/gi, "-")}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError("Failed to generate report.");
    } finally {
      setGenerating(null);
    }
  };

  const sevStyle = (sev) => {
    const styles = {
      critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
      high: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
      medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
      low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
      info: { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" },
    };
    return styles[(sev || "").toLowerCase()] || styles.info;
  };

  const scanTypes = ["all", ...new Set(scans.map((s) => s.type))];
  const filtered =
    filter === "all" ? scans : scans.filter((s) => s.type === filter);

  return (
    <div style={{ padding: "32px", maxWidth: "1000px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Report Generator
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Generate professional PDF security reports with OWASP mapping, risk
          scores and remediation steps.
        </p>
      </div>

      {/* Filter tabs */}
      <div
        style={{
          display: "flex",
          gap: "4px",
          marginBottom: "20px",
          flexWrap: "wrap",
        }}
      >
        {scanTypes.map((type) => (
          <button
            key={type}
            onClick={() => setFilter(type)}
            style={{
              padding: "6px 14px",
              borderRadius: "8px",
              fontSize: "12px",
              background: filter === type ? "#7F77DD" : "#131315",
              color: filter === type ? "white" : "#666",
              border: filter === type ? "none" : "0.5px solid #1e1e22",
              cursor: "pointer",
            }}
          >
            {type === "all" ? "All scans" : type}
          </button>
        ))}
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
            marginBottom: "16px",
          }}
        >
          {error}
        </div>
      )}

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
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span
            style={{
              fontSize: "12px",
              color: "#666",
              textTransform: "uppercase",
              letterSpacing: "0.6px",
            }}
          >
            {filtered.length} scans available
          </span>
          <button
            onClick={fetchScans}
            style={{
              background: "none",
              border: "0.5px solid #1e1e22",
              color: "#555",
              borderRadius: "6px",
              padding: "4px 10px",
              fontSize: "12px",
              cursor: "pointer",
            }}
          >
            Refresh
          </button>
        </div>

        {loading ? (
          <div style={{ padding: "48px", textAlign: "center", color: "#555" }}>
            Loading scans...
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: "48px", textAlign: "center" }}>
            <div
              style={{ fontSize: "14px", color: "#555", marginBottom: "8px" }}
            >
              No scans yet
            </div>
            <div style={{ fontSize: "12px", color: "#444" }}>
              Run a scan first to generate a report
            </div>
          </div>
        ) : (
          filtered.map((scan, i) => {
            const s = sevStyle(scan.severity);
            const isGenerating = generating === scan._id;
            return (
              <div
                key={scan._id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "14px",
                  padding: "16px 20px",
                  borderBottom:
                    i < filtered.length - 1 ? "0.5px solid #0f0f11" : "none",
                }}
              >
                {/* Severity dot */}
                <div
                  style={{
                    width: "8px",
                    height: "8px",
                    borderRadius: "50%",
                    background: s.color,
                    flexShrink: 0,
                  }}
                />

                {/* Info */}
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
                      marginTop: "3px",
                      display: "flex",
                      gap: "12px",
                    }}
                  >
                    <span>{scan.type}</span>
                    <span>
                      {new Date(scan.scanned_at).toLocaleDateString()}
                    </span>
                    <span>{scan.findings_count || 0} findings</span>
                  </div>
                </div>

                {/* Severity badge */}
                <span
                  style={{
                    fontSize: "11px",
                    padding: "2px 8px",
                    borderRadius: "10px",
                    background: s.bg,
                    color: s.color,
                    border: `0.5px solid ${s.border}`,
                    flexShrink: 0,
                  }}
                >
                  {scan.severity || "info"}
                </span>

                {/* Risk score */}
                {scan.result?.riskScore !== undefined && (
                  <div style={{ flexShrink: 0, textAlign: "center" }}>
                    <div
                      style={{
                        fontSize: "16px",
                        fontWeight: "500",
                        color:
                          scan.result.riskScore >= 70
                            ? "#E24B4A"
                            : scan.result.riskScore >= 40
                              ? "#BA7517"
                              : "#1D9E75",
                      }}
                    >
                      {scan.result.riskScore}
                    </div>
                    <div style={{ fontSize: "9px", color: "#444" }}>RISK</div>
                  </div>
                )}

                {/* Generate button */}
                <button
                  onClick={() => generateReport(scan._id, scan.target)}
                  disabled={isGenerating}
                  style={{
                    background: isGenerating ? "#13121f" : "#7F77DD",
                    border: "none",
                    color: "white",
                    borderRadius: "8px",
                    padding: "8px 16px",
                    fontSize: "12px",
                    cursor: isGenerating ? "not-allowed" : "pointer",
                    flexShrink: 0,
                    fontWeight: "500",
                  }}
                >
                  {isGenerating ? "Generating..." : "Download PDF"}
                </button>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
