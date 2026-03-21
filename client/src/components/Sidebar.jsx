import { Link, useLocation } from "react-router-dom";

const nav = [
  {
    section: "Main",
    items: [{ label: "Dashboard", path: "/" }],
  },
  {
    section: "Recon",
    items: [
      { label: "Network scanner", path: "/network" },
      { label: "Web vuln scanner", path: "/webvuln" },
      { label: "OSINT engine", path: "/osint" },
      { label: "SSL/TLS checker", path: "/ssl" },
      { label: "CVE database", path: "/cve" },
      { label: "Subdomain takeover", path: "/takeover" },
      { label: "Email security", path: "/emailsecurity" },
    ],
  },
  {
    section: "Attack",
    items: [{ label: "Password tools", path: "/password" }],
  },
  {
    section: "Output",
    items: [
      { label: "Scheduled scans", path: "/schedules" },
      { label: "Report generator", path: "/reports" },
      { label: "Scan history", path: "/history" },
    ],
  },
  {
    section: "Account",
    items: [{ label: "Settings", path: "/settings" }],
  },
];

export default function Sidebar() {
  const location = useLocation();

  return (
    <div
      style={{
        width: "210px",
        background: "#0a0a0c",
        borderRight: "0.5px solid #1a1a1e",
        display: "flex",
        flexDirection: "column",
        minHeight: "100vh",
        flexShrink: 0,
      }}
    >
      <div
        style={{
          padding: "20px 18px",
          borderBottom: "0.5px solid #1a1a1e",
          display: "flex",
          alignItems: "center",
          gap: "10px",
        }}
      >
        <div
          style={{
            width: "28px",
            height: "28px",
            background: "#13121f",
            border: "0.5px solid #3C3489",
            borderRadius: "7px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <circle cx="8" cy="8" r="5" stroke="#7F77DD" strokeWidth="1" />
            <circle cx="8" cy="8" r="2" fill="#7F77DD" />
            <line
              x1="8"
              y1="1"
              x2="8"
              y2="3"
              stroke="#7F77DD"
              strokeWidth="1.2"
            />
            <line
              x1="8"
              y1="13"
              x2="8"
              y2="15"
              stroke="#7F77DD"
              strokeWidth="1.2"
            />
            <line
              x1="1"
              y1="8"
              x2="3"
              y2="8"
              stroke="#7F77DD"
              strokeWidth="1.2"
            />
            <line
              x1="13"
              y1="8"
              x2="15"
              y2="8"
              stroke="#7F77DD"
              strokeWidth="1.2"
            />
          </svg>
        </div>
        <span style={{ fontSize: "15px", fontWeight: "500", color: "#e8e6f0" }}>
          Ghost<span style={{ color: "#7F77DD" }}>Recon</span>
        </span>
      </div>

      <div style={{ flex: 1, padding: "8px 0" }}>
        {nav.map((group) => (
          <div key={group.section}>
            <div
              style={{
                padding: "12px 14px 4px",
                fontSize: "10px",
                color: "#444",
                letterSpacing: "0.8px",
                textTransform: "uppercase",
              }}
            >
              {group.section}
            </div>
            {group.items.map((item) => {
              const active = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  style={{ textDecoration: "none" }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                      padding: "9px 14px",
                      fontSize: "13px",
                      color: active ? "#a89ff5" : "#777",
                      background: active ? "#13121f" : "transparent",
                      borderLeft: active
                        ? "2px solid #7F77DD"
                        : "2px solid transparent",
                      transition: "all 0.1s",
                    }}
                  >
                    <div
                      style={{
                        width: "6px",
                        height: "6px",
                        borderRadius: "50%",
                        background: active ? "#7F77DD" : "#333",
                        flexShrink: 0,
                      }}
                    />
                    {item.label}
                  </div>
                </Link>
              );
            })}
          </div>
        ))}
      </div>

      <div
        style={{
          padding: "14px",
          borderTop: "0.5px solid #1a1a1e",
          display: "flex",
          alignItems: "center",
          gap: "8px",
        }}
      >
        <div
          style={{
            width: "26px",
            height: "26px",
            borderRadius: "50%",
            background: "#13121f",
            border: "0.5px solid #3C3489",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: "11px",
            color: "#a89ff5",
            fontWeight: "500",
          }}
        >
          GR
        </div>
        <span style={{ fontSize: "12px", color: "#555" }}>
          {JSON.parse(localStorage.getItem("gr_user") || "{}").email ||
            "ghost@recon.io"}
        </span>
      </div>
    </div>
  );
}
