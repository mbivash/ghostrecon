import { useState, useEffect } from "react";
import api from "../utils/api";

export default function ScheduledScans() {
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [target, setTarget] = useState("");
  const [type, setType] = useState("Web Vuln Scan");
  const [frequency, setFrequency] = useState("weekly");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    fetchSchedules();
  }, []);

  const fetchSchedules = async () => {
    setLoading(true);
    try {
      const res = await api.get("/api/schedules");
      setSchedules(res.data.schedules);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const createSchedule = async () => {
    if (!target.trim()) return setError("Please enter a target.");
    setCreating(true);
    setError("");
    setSuccess("");
    try {
      await api.post("/api/schedules", { target, type, frequency });
      setSuccess(`Scheduled ${type} on ${target} — runs ${frequency}`);
      setTarget("");
      fetchSchedules();
    } catch (err) {
      setError(err.response?.data?.error || "Failed to create schedule.");
    } finally {
      setCreating(false);
    }
  };

  const deleteSchedule = async (id) => {
    try {
      await api.delete(`/api/schedules/${id}`);
      setSchedules(schedules.filter((s) => s._id !== id));
    } catch (err) {
      console.error(err);
    }
  };

  const runNow = async (id) => {
    try {
      await api.post(`/api/schedules/${id}/run`);
      setSuccess("Scan started — check history in a few seconds.");
    } catch (err) {
      console.error(err);
    }
  };

  const freqColor = (f) => {
    if (f === "daily")
      return { bg: "#1a0a0a", color: "#E24B4A", border: "#791F1F" };
    if (f === "weekly")
      return { bg: "#0d0d2e", color: "#7F77DD", border: "#3C3489" };
    if (f === "monthly")
      return { bg: "#0a1400", color: "#639922", border: "#27500A" };
    return { bg: "#1a1200", color: "#BA7517", border: "#633806" };
  };

  return (
    <div style={{ padding: "32px", maxWidth: "900px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Scheduled Scans
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Set up automatic scans that run on a schedule. Results saved to
          history automatically.
        </p>
      </div>

      {/* Create new schedule */}
      <div
        style={{
          background: "#131315",
          border: "0.5px solid #1e1e22",
          borderRadius: "12px",
          padding: "24px",
          marginBottom: "24px",
        }}
      >
        <div
          style={{
            fontSize: "11px",
            color: "#444",
            textTransform: "uppercase",
            letterSpacing: "0.8px",
            marginBottom: "16px",
          }}
        >
          New scheduled scan
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          <div>
            <label
              style={{
                fontSize: "12px",
                color: "#666",
                display: "block",
                marginBottom: "6px",
              }}
            >
              Target
            </label>
            <input
              placeholder="e.g. example.com or http://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "12px",
            }}
          >
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
              <select value={type} onChange={(e) => setType(e.target.value)}>
                <option value="Web Vuln Scan">Web vulnerability scan</option>
                <option value="SSL Scan">SSL/TLS check</option>
              </select>
            </div>

            <div>
              <label
                style={{
                  fontSize: "12px",
                  color: "#666",
                  display: "block",
                  marginBottom: "6px",
                }}
              >
                Frequency
              </label>
              <select
                value={frequency}
                onChange={(e) => setFrequency(e.target.value)}
              >
                <option value="hourly">Every hour</option>
                <option value="daily">Every day</option>
                <option value="weekly">Every week</option>
                <option value="monthly">Every month</option>
              </select>
            </div>
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
              {success}
            </div>
          )}

          <button
            className="btn-primary"
            onClick={createSchedule}
            disabled={creating}
            style={{ alignSelf: "flex-start", padding: "10px 24px" }}
          >
            {creating ? "Creating..." : "Create Schedule"}
          </button>
        </div>
      </div>

      {/* Schedules list */}
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
            Active schedules — {schedules.length}
          </span>
          <button
            onClick={fetchSchedules}
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
          <div
            style={{
              padding: "32px",
              textAlign: "center",
              color: "#555",
              fontSize: "14px",
            }}
          >
            Loading...
          </div>
        ) : schedules.length === 0 ? (
          <div style={{ padding: "48px", textAlign: "center" }}>
            <div
              style={{ fontSize: "14px", color: "#555", marginBottom: "6px" }}
            >
              No scheduled scans yet
            </div>
            <div style={{ fontSize: "12px", color: "#444" }}>
              Create one above to start automatic scanning
            </div>
          </div>
        ) : (
          schedules.map((s, i) => {
            const fc = freqColor(s.frequency);
            return (
              <div
                key={s._id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "12px",
                  padding: "14px 20px",
                  borderBottom:
                    i < schedules.length - 1 ? "0.5px solid #0f0f11" : "none",
                }}
              >
                {/* Target + type */}
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
                    {s.target}
                  </div>
                  <div
                    style={{
                      fontSize: "11px",
                      color: "#444",
                      marginTop: "2px",
                    }}
                  >
                    {s.type} · Last run:{" "}
                    {s.lastRun ? new Date(s.lastRun).toLocaleString() : "Never"}
                  </div>
                </div>

                {/* Frequency badge */}
                <span
                  style={{
                    fontSize: "11px",
                    padding: "2px 8px",
                    borderRadius: "10px",
                    background: fc.bg,
                    color: fc.color,
                    border: `0.5px solid ${fc.border}`,
                    flexShrink: 0,
                  }}
                >
                  {s.frequency}
                </span>

                {/* Last findings */}
                <span
                  style={{ fontSize: "12px", color: "#555", flexShrink: 0 }}
                >
                  {s.lastFindings} findings
                </span>

                {/* Actions */}
                <div style={{ display: "flex", gap: "8px", flexShrink: 0 }}>
                  <button
                    onClick={() => runNow(s._id)}
                    style={{
                      background: "#0d0d2e",
                      border: "0.5px solid #3C3489",
                      color: "#7F77DD",
                      borderRadius: "6px",
                      padding: "4px 10px",
                      fontSize: "12px",
                      cursor: "pointer",
                    }}
                  >
                    Run now
                  </button>
                  <button
                    onClick={() => deleteSchedule(s._id)}
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
                    Delete
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
