import { useState } from "react";
import api from "../utils/api";

export default function CVESearch() {
  const [keyword, setKeyword] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  const handleSearch = async () => {
    if (!keyword.trim()) return setError("Please enter a keyword.");
    setLoading(true);
    setError("");
    setResults(null);
    try {
      const res = await api.get(
        `/api/cve/search?keyword=${encodeURIComponent(keyword.trim())}`,
      );
      setResults(res.data);
    } catch (err) {
      setError(err.response?.data?.error || "Search failed.");
    } finally {
      setLoading(false);
    }
  };

  const sevStyle = (sev) => {
    const s = (sev || "").toUpperCase();
    if (s === "CRITICAL")
      return { bg: "#1a0505", color: "#ff4444", border: "#600" };
    if (s === "HIGH")
      return { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" };
    if (s === "MEDIUM")
      return { bg: "#1a1200", color: "#BA7517", border: "#633806" };
    return { bg: "#0a1400", color: "#639922", border: "#27500A" };
  };

  const scoreColor = (score) => {
    if (score >= 9) return "#ff4444";
    if (score >= 7) return "#E24B4A";
    if (score >= 4) return "#BA7517";
    return "#639922";
  };

  const suggestions = [
    "OpenSSH",
    "Apache",
    "nginx",
    "MySQL",
    "WordPress",
    "PHP",
    "SSL",
    "OpenSSL",
  ];

  const CveCard = ({ cve }) => {
    const s = sevStyle(cve.severity);
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
            justifyContent: "space-between",
            marginBottom: "12px",
            flexWrap: "wrap",
            gap: "10px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span
              style={{
                fontSize: "14px",
                fontWeight: "500",
                color: "#a89ff5",
                fontFamily: "monospace",
              }}
            >
              {cve.id}
            </span>
            <span
              style={{
                fontSize: "11px",
                padding: "2px 8px",
                borderRadius: "10px",
                background: s.bg,
                color: s.color,
                border: `0.5px solid ${s.border}`,
              }}
            >
              {cve.severity}
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                padding: "4px 12px",
                background: "#0d0d0f",
                borderRadius: "8px",
                border: "0.5px solid #1e1e22",
              }}
            >
              <span style={{ fontSize: "11px", color: "#555" }}>CVSS</span>
              <span
                style={{
                  fontSize: "16px",
                  fontWeight: "500",
                  color: scoreColor(cve.score),
                }}
              >
                {cve.score}
              </span>
            </div>

            <span style={{ fontSize: "12px", color: "#444" }}>
              {cve.published}
            </span>

            <button
              onClick={() => window.open(cve.url, "_blank")}
              style={{
                fontSize: "12px",
                color: "#7F77DD",
                padding: "4px 10px",
                border: "0.5px solid #3C3489",
                borderRadius: "6px",
                background: "#0d0d2e",
                cursor: "pointer",
              }}
            >
              View on NVD
            </button>
          </div>
        </div>

        <div style={{ fontSize: "13px", color: "#888", lineHeight: "1.6" }}>
          {cve.description}
        </div>
      </div>
    );
  };

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          CVE Database
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Search real CVEs from the National Vulnerability Database.
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
        <div style={{ display: "flex", gap: "10px", marginBottom: "14px" }}>
          <input
            type="text"
            placeholder="e.g. OpenSSH, Apache, WordPress, MySQL..."
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            style={{ flex: 1 }}
          />
          <button
            className="btn-primary"
            onClick={handleSearch}
            disabled={loading}
            style={{ padding: "10px 24px", flexShrink: 0 }}
          >
            {loading ? "Searching..." : "Search CVEs"}
          </button>
        </div>

        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
          <span
            style={{ fontSize: "12px", color: "#555", alignSelf: "center" }}
          >
            Quick search:
          </span>
          {suggestions.map((s) => (
            <button
              key={s}
              onClick={() => setKeyword(s)}
              style={{
                fontSize: "11px",
                padding: "4px 10px",
                borderRadius: "20px",
                background: "#0d0d2e",
                color: "#7F77DD",
                border: "0.5px solid #3C3489",
                cursor: "pointer",
              }}
            >
              {s}
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
              marginTop: "12px",
            }}
          >
            {error}
          </div>
        )}
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
          <div style={{ color: "#a89ff5", fontSize: "14px" }}>
            Searching NVD database...
          </div>
          <div style={{ color: "#444", fontSize: "12px", marginTop: "6px" }}>
            Querying nvd.nist.gov
          </div>
        </div>
      )}

      {results && (
        <div>
          <div
            style={{ fontSize: "13px", color: "#555", marginBottom: "16px" }}
          >
            Found {results.cves.length} CVEs for {keyword}
          </div>

          {results.cves.length === 0 ? (
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
              No CVEs found. Try a different search term.
            </div>
          ) : (
            <div
              style={{ display: "flex", flexDirection: "column", gap: "12px" }}
            >
              {results.cves.map((cve, i) => (
                <CveCard key={i} cve={cve} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
