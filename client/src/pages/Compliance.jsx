import { useState, useEffect } from "react";
import api from "../utils/api";

export default function Compliance() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [report, setReport] = useState(null);
  const [selectedScan, setSelectedScan] = useState(null);
  const [error, setError] = useState("");
  const [activeFramework, setActiveFramework] = useState("owasp");

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await api.get("/api/compliance/scans");
      setScans(res.data.scans);
    } catch (err) {
      setError("Failed to load scans.");
    } finally {
      setLoading(false);
    }
  };

  const generateReport = async (scanId) => {
    setGenerating(true);
    setError("");
    setReport(null);
    try {
      const res = await api.post("/api/compliance/report", { scanId });
      setReport(res.data.data);
      setSelectedScan(res.data.scan);
    } catch (err) {
      setError(err.response?.data?.error || "Failed to generate report.");
    } finally {
      setGenerating(false);
    }
  };

  const scoreColor = (score) => {
    if (score >= 80) return "#1D9E75";
    if (score >= 50) return "#BA7517";
    return "#E24B4A";
  };

  const StatusBadge = ({ status }) => (
    <span
      style={{
        fontSize: "10px",
        padding: "2px 8px",
        borderRadius: "10px",
        background: status === "pass" ? "#0a1a14" : "#1a0a0a",
        color: status === "pass" ? "#1D9E75" : "#E24B4A",
        border: `0.5px solid ${status === "pass" ? "#085041" : "#791F1F"}`,
      }}
    >
      {status === "pass" ? "PASS" : "FAIL"}
    </span>
  );

  const frameworks = [
    { id: "owasp", label: "OWASP Top 10" },
    { id: "pci", label: "PCI-DSS" },
    { id: "iso", label: "ISO 27001" },
  ];

  const getItems = () => {
    if (!report) return [];
    if (activeFramework === "owasp") return report.owasp.items;
    if (activeFramework === "pci") return report.pci.requirements;
    if (activeFramework === "iso") return report.iso.controls;
    return [];
  };

  const getScore = () => {
    if (!report) return 0;
    if (activeFramework === "owasp") return report.owasp.score;
    if (activeFramework === "pci") return report.pci.score;
    if (activeFramework === "iso") return report.iso.score;
    return 0;
  };

  const getStats = () => {
    if (!report) return { passed: 0, failed: 0, total: 0 };
    if (activeFramework === "owasp")
      return {
        passed: report.owasp.passed,
        failed: report.owasp.failed,
        total: report.owasp.total,
      };
    if (activeFramework === "pci")
      return {
        passed: report.pci.passed,
        failed: report.pci.failed,
        total: report.pci.total,
      };
    if (activeFramework === "iso")
      return {
        passed: report.iso.passed,
        failed: report.iso.failed,
        total: report.iso.total,
      };
    return { passed: 0, failed: 0, total: 0 };
  };

  return (
    <div style={{ padding: "32px", maxWidth: "1000px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Compliance Mapping
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Map scan findings to PCI-DSS, ISO 27001 and OWASP Top 10 compliance
          frameworks.
        </p>
      </div>

      {!report ? (
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
            Select a scan to generate compliance report
          </div>

          {loading ? (
            <div
              style={{ padding: "48px", textAlign: "center", color: "#555" }}
            >
              Loading scans...
            </div>
          ) : scans.length === 0 ? (
            <div
              style={{ padding: "48px", textAlign: "center", color: "#555" }}
            >
              No scans found. Run a web vulnerability scan first.
            </div>
          ) : (
            scans
              .filter(
                (s) =>
                  s.type === "Web Vuln Scan" ||
                  s.type === "Authenticated Scan" ||
                  s.type === "API Security Scan",
              )
              .map((scan, i) => (
                <div
                  key={scan._id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "14px",
                    padding: "16px 20px",
                    borderBottom:
                      i < scans.length - 1 ? "0.5px solid #0f0f11" : "none",
                  }}
                >
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
                      }}
                    >
                      {scan.type} ·{" "}
                      {new Date(scan.scanned_at).toLocaleDateString()} ·{" "}
                      {scan.findings_count || 0} findings
                    </div>
                  </div>
                  <button
                    onClick={() => generateReport(scan._id)}
                    disabled={generating}
                    style={{
                      background: "#7F77DD",
                      border: "none",
                      color: "white",
                      borderRadius: "8px",
                      padding: "8px 16px",
                      fontSize: "12px",
                      cursor: "pointer",
                      flexShrink: 0,
                    }}
                  >
                    {generating ? "Generating..." : "Generate Report"}
                  </button>
                </div>
              ))
          )}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Back button */}
          <button
            onClick={() => setReport(null)}
            style={{
              background: "none",
              border: "0.5px solid #1e1e22",
              color: "#666",
              borderRadius: "8px",
              padding: "8px 16px",
              fontSize: "12px",
              cursor: "pointer",
              alignSelf: "flex-start",
            }}
          >
            ← Back to scans
          </button>

          {/* Target info */}
          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              padding: "16px 20px",
            }}
          >
            <div
              style={{ fontSize: "11px", color: "#444", marginBottom: "4px" }}
            >
              Compliance report for
            </div>
            <div
              style={{
                fontSize: "15px",
                fontWeight: "500",
                color: "#e8e6f0",
                fontFamily: "monospace",
              }}
            >
              {selectedScan?.target}
            </div>
            <div style={{ fontSize: "12px", color: "#555", marginTop: "4px" }}>
              {selectedScan?.type} ·{" "}
              {new Date(selectedScan?.scannedAt).toLocaleDateString()}
            </div>
          </div>

          {/* Score cards */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(3, 1fr)",
              gap: "12px",
            }}
          >
            {[
              {
                label: "OWASP Top 10",
                score: report.owasp.score,
                passed: report.owasp.passed,
                total: report.owasp.total,
              },
              {
                label: "PCI-DSS",
                score: report.pci.score,
                passed: report.pci.passed,
                total: report.pci.total,
              },
              {
                label: "ISO 27001",
                score: report.iso.score,
                passed: report.iso.passed,
                total: report.iso.total,
              },
            ].map((fw) => (
              <div
                key={fw.label}
                style={{
                  background: "#131315",
                  border: "0.5px solid #1e1e22",
                  borderRadius: "12px",
                  padding: "20px",
                  textAlign: "center",
                }}
              >
                <div
                  style={{
                    fontSize: "36px",
                    fontWeight: "500",
                    color: scoreColor(fw.score),
                  }}
                >
                  {fw.score}%
                </div>
                <div
                  style={{
                    fontSize: "13px",
                    fontWeight: "500",
                    color: "#e8e6f0",
                    marginTop: "4px",
                  }}
                >
                  {fw.label}
                </div>
                <div
                  style={{ fontSize: "11px", color: "#555", marginTop: "6px" }}
                >
                  {fw.passed} passed · {fw.total - fw.passed} failed
                </div>
                <div
                  style={{
                    height: "4px",
                    background: "#1e1e22",
                    borderRadius: "2px",
                    marginTop: "12px",
                  }}
                >
                  <div
                    style={{
                      height: "100%",
                      borderRadius: "2px",
                      width: `${fw.score}%`,
                      background: scoreColor(fw.score),
                    }}
                  />
                </div>
              </div>
            ))}
          </div>

          {/* Framework tabs */}
          <div
            style={{
              display: "flex",
              gap: "4px",
              background: "#131315",
              padding: "4px",
              borderRadius: "10px",
              border: "0.5px solid #1e1e22",
              width: "fit-content",
            }}
          >
            {frameworks.map((fw) => (
              <button
                key={fw.id}
                onClick={() => setActiveFramework(fw.id)}
                style={{
                  padding: "8px 20px",
                  borderRadius: "8px",
                  fontSize: "13px",
                  background:
                    activeFramework === fw.id ? "#7F77DD" : "transparent",
                  color: activeFramework === fw.id ? "white" : "#666",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                {fw.label}
              </button>
            ))}
          </div>

          {/* Stats bar */}
          <div style={{ display: "flex", gap: "12px" }}>
            {[
              {
                label: "Total controls",
                val: getStats().total,
                color: "#e8e6f0",
              },
              { label: "Passed", val: getStats().passed, color: "#1D9E75" },
              { label: "Failed", val: getStats().failed, color: "#E24B4A" },
              {
                label: "Compliance score",
                val: `${getScore()}%`,
                color: scoreColor(getScore()),
              },
            ].map((s) => (
              <div
                key={s.label}
                style={{
                  background: "#131315",
                  border: "0.5px solid #1e1e22",
                  borderRadius: "10px",
                  padding: "12px 16px",
                  flex: 1,
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
                  style={{ fontSize: "11px", color: "#555", marginTop: "2px" }}
                >
                  {s.label}
                </div>
              </div>
            ))}
          </div>

          {/* Controls list */}
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
              {activeFramework === "owasp"
                ? "OWASP Top 10 2021"
                : activeFramework === "pci"
                  ? "PCI-DSS v3.2.1 Requirements"
                  : "ISO 27001:2013 Controls"}
            </div>

            {getItems().map((item, i) => (
              <div
                key={item.id}
                style={{
                  padding: "16px 20px",
                  borderBottom:
                    i < getItems().length - 1 ? "0.5px solid #0f0f11" : "none",
                  background:
                    item.status === "fail"
                      ? "rgba(226, 75, 74, 0.03)"
                      : "transparent",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: "12px",
                    marginBottom: item.violations?.length > 0 ? "10px" : "0",
                  }}
                >
                  <span
                    style={{
                      fontSize: "11px",
                      color: "#7F77DD",
                      fontFamily: "monospace",
                      flexShrink: 0,
                      marginTop: "2px",
                      minWidth: "70px",
                    }}
                  >
                    {item.id}
                  </span>
                  <div style={{ flex: 1 }}>
                    <div
                      style={{
                        fontSize: "13px",
                        fontWeight: "500",
                        color: "#ccc",
                        marginBottom: "3px",
                      }}
                    >
                      {item.name}
                    </div>
                    <div style={{ fontSize: "12px", color: "#555" }}>
                      {item.description}
                    </div>
                  </div>
                  <StatusBadge status={item.status} />
                </div>

                {item.violations?.length > 0 && (
                  <div
                    style={{
                      marginLeft: "82px",
                      display: "flex",
                      flexDirection: "column",
                      gap: "4px",
                    }}
                  >
                    {item.violations.slice(0, 3).map((v, j) => (
                      <div
                        key={j}
                        style={{
                          fontSize: "11px",
                          color: "#E24B4A",
                          display: "flex",
                          alignItems: "center",
                          gap: "6px",
                        }}
                      >
                        <span>↳</span>
                        <span>
                          {v.type} ({v.severity})
                        </span>
                      </div>
                    ))}
                    {item.violations.length > 3 && (
                      <div
                        style={{
                          fontSize: "11px",
                          color: "#555",
                          marginLeft: "14px",
                        }}
                      >
                        +{item.violations.length - 3} more violations
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {error && (
        <div
          style={{
            fontSize: "13px",
            color: "#E24B4A",
            background: "#1a0a0a",
            border: "0.5px solid #791F1F",
            borderRadius: "8px",
            padding: "10px 14px",
            marginTop: "16px",
          }}
        >
          {error}
        </div>
      )}
    </div>
  );
}
