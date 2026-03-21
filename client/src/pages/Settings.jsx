import { useState } from "react";
import api from "../utils/api";

export default function Settings() {
  const [testEmail, setTestEmail] = useState("");
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState("");
  const [testError, setTestError] = useState("");

  const user = JSON.parse(localStorage.getItem("gr_user") || "{}");

  const sendTest = async () => {
    if (!testEmail.trim())
      return setTestError("Please enter an email address.");
    setTesting(true);
    setTestResult("");
    setTestError("");
    try {
      await api.post("/api/email/test", { email: testEmail });
      setTestResult(`Test email sent to ${testEmail} — check your inbox.`);
    } catch (err) {
      setTestError(err.response?.data?.error || "Failed to send test email.");
    } finally {
      setTesting(false);
    }
  };

  const logout = () => {
    localStorage.removeItem("gr_token");
    localStorage.removeItem("gr_user");
    window.location.href = "/login";
  };

  return (
    <div style={{ padding: "32px", maxWidth: "700px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Settings
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Manage your account and notification preferences.
        </p>
      </div>

      {/* Account info */}
      <div
        style={{
          background: "#131315",
          border: "0.5px solid #1e1e22",
          borderRadius: "12px",
          padding: "20px",
          marginBottom: "16px",
        }}
      >
        <div
          style={{
            fontSize: "11px",
            color: "#444",
            textTransform: "uppercase",
            letterSpacing: "0.8px",
            marginBottom: "14px",
          }}
        >
          Account
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "14px",
            marginBottom: "16px",
          }}
        >
          <div
            style={{
              width: "44px",
              height: "44px",
              borderRadius: "50%",
              background: "#13121f",
              border: "0.5px solid #3C3489",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: "16px",
              color: "#a89ff5",
              fontWeight: "500",
            }}
          >
            {(user.name || "G").charAt(0).toUpperCase()}
          </div>
          <div>
            <div
              style={{ fontSize: "14px", fontWeight: "500", color: "#e8e6f0" }}
            >
              {user.name || "Ghost User"}
            </div>
            <div style={{ fontSize: "13px", color: "#555" }}>{user.email}</div>
          </div>
        </div>
        <button
          onClick={logout}
          style={{
            background: "#1a0a0a",
            border: "0.5px solid #791F1F",
            color: "#E24B4A",
            borderRadius: "8px",
            padding: "8px 16px",
            fontSize: "13px",
            cursor: "pointer",
          }}
        >
          Sign out
        </button>
      </div>

      {/* Email alerts */}
      <div
        style={{
          background: "#131315",
          border: "0.5px solid #1e1e22",
          borderRadius: "12px",
          padding: "20px",
          marginBottom: "16px",
        }}
      >
        <div
          style={{
            fontSize: "11px",
            color: "#444",
            textTransform: "uppercase",
            letterSpacing: "0.8px",
            marginBottom: "14px",
          }}
        >
          Email alerts
        </div>
        <p
          style={{
            fontSize: "13px",
            color: "#555",
            marginBottom: "14px",
            lineHeight: "1.6",
          }}
        >
          Test your email configuration. Make sure you have added EMAIL_USER and
          EMAIL_PASS to your server .env file.
        </p>
        <div style={{ display: "flex", gap: "10px", marginBottom: "10px" }}>
          <input
            type="email"
            placeholder="Enter email to test"
            value={testEmail}
            onChange={(e) => setTestEmail(e.target.value)}
            style={{ flex: 1 }}
          />
          <button
            className="btn-primary"
            onClick={sendTest}
            disabled={testing}
            style={{ padding: "10px 20px", flexShrink: 0 }}
          >
            {testing ? "Sending..." : "Send test"}
          </button>
        </div>
        {testResult && (
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
            {testResult}
          </div>
        )}
        {testError && (
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
            {testError}
          </div>
        )}
      </div>

      {/* Platform info */}
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
            fontSize: "11px",
            color: "#444",
            textTransform: "uppercase",
            letterSpacing: "0.8px",
            marginBottom: "14px",
          }}
        >
          Platform
        </div>
        {[
          { label: "Version", val: "GhostRecon 2.0" },
          { label: "Frontend", val: "ghostrecon-gold.vercel.app" },
          { label: "Backend", val: "ghostrecon-api-dju7.onrender.com" },
          { label: "Database", val: "NeDB (embedded)" },
        ].map((item) => (
          <div
            key={item.label}
            style={{
              display: "flex",
              justifyContent: "space-between",
              padding: "8px 0",
              borderBottom: "0.5px solid #0f0f11",
              fontSize: "13px",
            }}
          >
            <span style={{ color: "#555" }}>{item.label}</span>
            <span style={{ color: "#ccc", fontFamily: "monospace" }}>
              {item.val}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
