import { useState, useEffect } from "react";
import api from "../utils/api";

const API = "http://localhost:5000";

const SEVERITY_STYLE = {
  critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
  high: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
  medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
  low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
  info: { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" },
};

export default function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await api.get(`${API}/api/history`);
      setScans(res.data.scans);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const fetchDetail = async (id) => {
    setDetailLoading(true);
    setSelected(id);
    try {
      const res = await axios.get(`${API}/api/history/${id}`);
      setDetail(res.data.scan);
    } catch (err) {
      console.error(err);
    } finally {
      setDetailLoading(false);
    }
  };

  const deleteScan = async (id, e) => {
    e.stopPropagation();
    try {
      await axios.delete(`${API}/api/history/${id}`);
      setScans(scans.filter((s) => s.id !== id));
      if (selected === id) {
        setSelected(null);
        setDetail(null);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const filtered =
    filter === "all"
      ? scans
      : scans.filter((s) => s.type.toLowerCase().includes(filter));

  return (
    <div style={{ padding: "32px", maxWidth: "1100px" }}>
      {/* Header */}
      <div
        style={{
          marginBottom: "28px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
            Scan History
          </h1>
          <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
            All your previous scans — {scans.length} total
          </p>
        </div>
        <button
          onClick={fetchScans}
          style={{
            background: "transparent",
            border: "0.5px solid #1e1e22",
            color: "#666",
            borderRadius: "8px",
            padding: "8px 16px",
            fontSize: "13px",
            cursor: "pointer",
          }}
        >
          Refresh
        </button>
      </div>

      {/* Filter tabs */}
      <div
        style={{
          display: "flex",
          gap: "4px",
          marginBottom: "20px",
          background: "#131315",
          padding: "4px",
          borderRadius: "10px",
          border: "0.5px solid #1e1e22",
          width: "fit-content",
        }}
      >
        {[
          { label: "All scans", val: "all" },
          { label: "Network", val: "network" },
          { label: "Web vuln", val: "web" },
        ].map((f) => (
          <button
            key={f.val}
            onClick={() => setFilter(f.val)}
            style={{
              padding: "7px 16px",
              borderRadius: "8px",
              fontSize: "13px",
              background: filter === f.val ? "#7F77DD" : "transparent",
              color: filter === f.val ? "white" : "#666",
              border: "none",
              cursor: "pointer",
              transition: "all 0.15s",
            }}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div style={{ display: "flex", gap: "16px" }}>
        {/* Scans list */}
        <div style={{ flex: 1 }}>
          {loading ? (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                padding: "32px",
                textAlign: "center",
                color: "#555",
                fontSize: "14px",
              }}
            >
              Loading scans...
            </div>
          ) : filtered.length === 0 ? (
            <div
              style={{
                background: "#131315",
                border: "0.5px solid #1e1e22",
                borderRadius: "12px",
                padding: "48px",
                textAlign: "center",
              }}
            >
              <div
                style={{ fontSize: "14px", color: "#555", marginBottom: "8px" }}
              >
                No scans yet
              </div>
              <div style={{ fontSize: "12px", color: "#444" }}>
                Run a network or web vuln scan and it will appear here
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
              {/* Table header */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 140px 80px 80px 40px",
                  padding: "10px 16px",
                  borderBottom: "0.5px solid #1e1e22",
                  fontSize: "11px",
                  color: "#444",
                  textTransform: "uppercase",
                  letterSpacing: "0.5px",
                }}
              >
                <div>Target</div>
                <div>Type</div>
                <div>Findings</div>
                <div>Severity</div>
                <div></div>
              </div>

              {filtered.map((scan, i) => {
                const sev =
                  SEVERITY_STYLE[scan.severity] || SEVERITY_STYLE.info;
                const isSelected = selected === scan.id;
                return (
                  <div
                    key={scan.id}
                    onClick={() => fetchDetail(scan.id)}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 140px 80px 80px 40px",
                      padding: "12px 16px",
                      borderBottom:
                        i < filtered.length - 1
                          ? "0.5px solid #0f0f11"
                          : "none",
                      cursor: "pointer",
                      background: isSelected ? "#13121f" : "transparent",
                      borderLeft: isSelected
                        ? "2px solid #7F77DD"
                        : "2px solid transparent",
                      transition: "background 0.1s",
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
                    {/* Target */}
                    <div>
                      <div
                        style={{
                          fontSize: "13px",
                          color: "#ccc",
                          fontFamily: "monospace",
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
                        {new Date(scan.scanned_at).toLocaleString()}
                      </div>
                    </div>

                    {/* Type */}
                    <div
                      style={{
                        fontSize: "12px",
                        color: "#666",
                        alignSelf: "center",
                      }}
                    >
                      {scan.type}
                    </div>

                    {/* Findings */}
                    <div
                      style={{
                        fontSize: "13px",
                        color: "#ccc",
                        alignSelf: "center",
                      }}
                    >
                      {scan.findings_count}
                    </div>

                    {/* Severity badge */}
                    <div style={{ alignSelf: "center" }}>
                      <span
                        style={{
                          fontSize: "10px",
                          padding: "2px 8px",
                          borderRadius: "10px",
                          background: sev.bg,
                          color: sev.color,
                          border: `0.5px solid ${sev.border}`,
                        }}
                      >
                        {scan.severity}
                      </span>
                    </div>

                    {/* Delete button */}
                    <div style={{ alignSelf: "center", textAlign: "right" }}>
                      <button
                        onClick={(e) => deleteScan(scan.id, e)}
                        style={{
                          background: "none",
                          border: "none",
                          color: "#444",
                          cursor: "pointer",
                          fontSize: "16px",
                          padding: "2px 6px",
                          borderRadius: "4px",
                          lineHeight: 1,
                        }}
                        title="Delete scan"
                      >
                        ×
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Detail panel */}
        {selected && (
          <div
            style={{
              width: "320px",
              flexShrink: 0,
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              padding: "16px",
              maxHeight: "600px",
              overflowY: "auto",
            }}
          >
            {detailLoading ? (
              <div
                style={{
                  textAlign: "center",
                  color: "#555",
                  padding: "32px",
                  fontSize: "14px",
                }}
              >
                Loading...
              </div>
            ) : detail ? (
              <div>
                <div
                  style={{
                    fontSize: "13px",
                    fontWeight: "500",
                    color: "#e8e6f0",
                    marginBottom: "4px",
                  }}
                >
                  {detail.type}
                </div>
                <div
                  style={{
                    fontSize: "12px",
                    color: "#555",
                    fontFamily: "monospace",
                    marginBottom: "16px",
                  }}
                >
                  {detail.target}
                </div>

                {/* Network scan detail */}
                {detail.result.ports && (
                  <div>
                    <div
                      style={{
                        fontSize: "11px",
                        color: "#444",
                        textTransform: "uppercase",
                        letterSpacing: "0.6px",
                        marginBottom: "8px",
                      }}
                    >
                      Open ports
                    </div>
                    {detail.result.ports.length === 0 ? (
                      <div style={{ fontSize: "13px", color: "#555" }}>
                        No open ports found
                      </div>
                    ) : (
                      detail.result.ports.map((p, i) => (
                        <div
                          key={i}
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            padding: "6px 0",
                            borderBottom: "0.5px solid #0f0f11",
                            fontSize: "12px",
                          }}
                        >
                          <span
                            style={{
                              color: "#a89ff5",
                              fontFamily: "monospace",
                            }}
                          >
                            {p.port}/{p.protocol}
                          </span>
                          <span style={{ color: "#666" }}>{p.service}</span>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {/* Web vuln detail */}
                {detail.result.vulnerabilities && (
                  <div>
                    <div
                      style={{
                        fontSize: "11px",
                        color: "#444",
                        textTransform: "uppercase",
                        letterSpacing: "0.6px",
                        marginBottom: "8px",
                      }}
                    >
                      Vulnerabilities
                    </div>
                    {detail.result.vulnerabilities.length === 0 ? (
                      <div style={{ fontSize: "13px", color: "#1D9E75" }}>
                        No vulnerabilities found
                      </div>
                    ) : (
                      detail.result.vulnerabilities.map((v, i) => {
                        const sev =
                          SEVERITY_STYLE[v.severity?.toLowerCase()] ||
                          SEVERITY_STYLE.info;
                        return (
                          <div
                            key={i}
                            style={{
                              padding: "8px 0",
                              borderBottom: "0.5px solid #0f0f11",
                            }}
                          >
                            <div
                              style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "6px",
                                marginBottom: "3px",
                              }}
                            >
                              <span
                                style={{
                                  fontSize: "10px",
                                  padding: "1px 6px",
                                  borderRadius: "8px",
                                  background: sev.bg,
                                  color: sev.color,
                                  border: `0.5px solid ${sev.border}`,
                                }}
                              >
                                {v.severity}
                              </span>
                            </div>
                            <div style={{ fontSize: "12px", color: "#ccc" }}>
                              {v.type}
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                )}

                <button
                  onClick={() => {
                    setSelected(null);
                    setDetail(null);
                  }}
                  style={{
                    marginTop: "16px",
                    width: "100%",
                    background: "transparent",
                    border: "0.5px solid #1e1e22",
                    color: "#555",
                    borderRadius: "8px",
                    padding: "8px",
                    fontSize: "13px",
                    cursor: "pointer",
                  }}
                >
                  Close
                </button>
              </div>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
}
