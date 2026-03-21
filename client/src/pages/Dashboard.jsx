import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import api from "../utils/api";

const API = "http://localhost:5000";

const modules = [
  {
    name: "Network scanner",
    desc: "Scan ports and open services",
    path: "/network",
    color: "#7F77DD",
    border: "#3C3489",
  },
  {
    name: "Web vuln scanner",
    desc: "Find XSS, SQLi, CSRF issues",
    path: "/webvuln",
    color: "#E24B4A",
    border: "#791F1F",
  },
  {
    name: "OSINT engine",
    desc: "Whois, DNS, subdomains",
    path: "/osint",
    color: "#1D9E75",
    border: "#085041",
  },
  {
    name: "Password tools",
    desc: "Hash crack and analysis",
    path: "/password",
    color: "#BA7517",
    border: "#633806",
  },
  {
    name: "Report generator",
    desc: "Export professional PDFs",
    path: "/reports",
    color: "#639922",
    border: "#27500A",
  },
  {
    name: "Scan history",
    desc: "All your previous scans",
    path: "/history",
    color: "#D4537E",
    border: "#72243E",
  },
];

const SEVERITY_STYLE = {
  critical: { bg: "#1a0505", color: "#ff4444", border: "#600" },
  high: { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" },
  medium: { bg: "#1a1200", color: "#BA7517", border: "#633806" },
  low: { bg: "#0a1400", color: "#639922", border: "#27500A" },
  info: { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" },
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API}/api/dashboard/stats`);
      setStats(res.data.stats);
    } catch (err) {
      console.error("Failed to load stats:", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "32px", maxWidth: "1100px" }}>
      {/* Header */}
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Dashboard
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Welcome back. All systems operational.
        </p>
      </div>

      {/* Real Stats */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: "12px",
          marginBottom: "28px",
        }}
      >
        {[
          {
            label: "Total scans",
            val: loading ? "..." : (stats?.totalScans ?? 0),
            note: "All time",
            noteColor: "#555",
          },
          {
            label: "Findings",
            val: loading ? "..." : (stats?.totalVulns ?? 0),
            note: "Across all scans",
            noteColor: "#555",
          },
          {
            label: "High severity",
            val: loading ? "..." : (stats?.highSeverity ?? 0),
            note: stats?.highSeverity > 0 ? "Needs attention" : "All clear",
            noteColor: stats?.highSeverity > 0 ? "#E24B4A" : "#1D9E75",
          },
          {
            label: "Unique targets",
            val: loading ? "..." : (stats?.activeTargets ?? 0),
            note: "Scanned targets",
            noteColor: "#555",
          },
        ].map((s) => (
          <div
            key={s.label}
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "10px",
              padding: "16px",
            }}
          >
            <div
              style={{ fontSize: "24px", fontWeight: "500", color: "#e8e6f0" }}
            >
              {s.val}
            </div>
            <div style={{ fontSize: "12px", color: "#555", marginTop: "2px" }}>
              {s.label}
            </div>
            <div
              style={{ fontSize: "11px", color: s.noteColor, marginTop: "6px" }}
            >
              {s.note}
            </div>
          </div>
        ))}
      </div>

      {/* Two column layout */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "16px",
          marginBottom: "16px",
        }}
      >
        {/* Modules */}
        <div>
          <div
            style={{
              fontSize: "11px",
              color: "#444",
              letterSpacing: "0.8px",
              textTransform: "uppercase",
              marginBottom: "12px",
            }}
          >
            Modules
          </div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "10px",
            }}
          >
            {modules.map((m) => (
              <Link key={m.path} to={m.path} style={{ textDecoration: "none" }}>
                <div
                  style={{
                    background: "#131315",
                    border: "0.5px solid #1e1e22",
                    borderRadius: "12px",
                    padding: "16px",
                    cursor: "pointer",
                    transition: "border-color 0.15s",
                  }}
                  onMouseEnter={(e) =>
                    (e.currentTarget.style.borderColor = m.border)
                  }
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.borderColor = "#1e1e22")
                  }
                >
                  <div
                    style={{
                      width: "8px",
                      height: "8px",
                      borderRadius: "50%",
                      background: m.color,
                      marginBottom: "10px",
                    }}
                  />
                  <div
                    style={{
                      fontSize: "13px",
                      fontWeight: "500",
                      color: "#ccc",
                      marginBottom: "3px",
                    }}
                  >
                    {m.name}
                  </div>
                  <div style={{ fontSize: "11px", color: "#555" }}>
                    {m.desc}
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </div>

        {/* Recent scans */}
        <div>
          <div
            style={{
              fontSize: "11px",
              color: "#444",
              letterSpacing: "0.8px",
              textTransform: "uppercase",
              marginBottom: "12px",
            }}
          >
            Recent scans
          </div>
          <div
            style={{
              background: "#131315",
              border: "0.5px solid #1e1e22",
              borderRadius: "12px",
              overflow: "hidden",
            }}
          >
            {loading ? (
              <div
                style={{
                  padding: "24px",
                  textAlign: "center",
                  color: "#555",
                  fontSize: "13px",
                }}
              >
                Loading...
              </div>
            ) : !stats?.recentScans?.length ? (
              <div style={{ padding: "24px", textAlign: "center" }}>
                <div
                  style={{
                    fontSize: "13px",
                    color: "#555",
                    marginBottom: "6px",
                  }}
                >
                  No scans yet
                </div>
                <div style={{ fontSize: "12px", color: "#444" }}>
                  Run your first scan to see it here
                </div>
              </div>
            ) : (
              stats.recentScans.map((scan, i) => {
                const sev =
                  SEVERITY_STYLE[scan.severity] || SEVERITY_STYLE.info;
                return (
                  <Link
                    key={scan.id}
                    to="/history"
                    style={{ textDecoration: "none" }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "10px",
                        padding: "12px 16px",
                        borderBottom:
                          i < stats.recentScans.length - 1
                            ? "0.5px solid #0f0f11"
                            : "none",
                        transition: "background 0.1s",
                      }}
                      onMouseEnter={(e) =>
                        (e.currentTarget.style.background = "#0f0f11")
                      }
                      onMouseLeave={(e) =>
                        (e.currentTarget.style.background = "transparent")
                      }
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
                            marginTop: "2px",
                          }}
                        >
                          {scan.type} ·{" "}
                          {new Date(scan.scanned_at).toLocaleDateString()}
                        </div>
                      </div>
                      <span
                        style={{
                          fontSize: "10px",
                          padding: "2px 8px",
                          borderRadius: "10px",
                          background: sev.bg,
                          color: sev.color,
                          border: `0.5px solid ${sev.border}`,
                          flexShrink: 0,
                        }}
                      >
                        {scan.severity}
                      </span>
                    </div>
                  </Link>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
