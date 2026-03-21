import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../utils/api";

export default function Login() {
  const [mode, setMode] = useState("login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async () => {
    if (!email || !password) return setError("Please fill in all fields.");
    setLoading(true);
    setError("");
    try {
      const res = await aapi.post("http://localhost:5000/api/auth/login", {
        email,
        password,
      });
      localStorage.setItem("gr_token", res.data.token);
      localStorage.setItem("gr_user", JSON.stringify(res.data.user));
      navigate("/");
    } catch (err) {
      setError(err.response?.data?.error || "Login failed.");
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async () => {
    if (!name || !email || !password)
      return setError("Please fill in all fields.");
    setLoading(true);
    setError("");
    try {
      await api.post("http://localhost:5000/api/auth/register", {
        name,
        email,
        password,
      });
      setSuccess("Account created! You can now log in.");
      setMode("login");
      setName("");
    } catch (err) {
      setError(err.response?.data?.error || "Registration failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "var(--gr-bg)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <div
        style={{
          background: "#131315",
          border: "0.5px solid #1e1e22",
          borderRadius: "14px",
          padding: "40px",
          width: "100%",
          maxWidth: "380px",
        }}
      >
        {/* Logo */}
        <div style={{ textAlign: "center", marginBottom: "32px" }}>
          <div
            style={{
              width: "48px",
              height: "48px",
              background: "#13121f",
              border: "0.5px solid #3C3489",
              borderRadius: "12px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              margin: "0 auto 14px",
            }}
          >
            <svg width="24" height="24" viewBox="0 0 16 16" fill="none">
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
          <div
            style={{ fontSize: "20px", fontWeight: "500", color: "#e8e6f0" }}
          >
            Ghost<span style={{ color: "#7F77DD" }}>Recon</span>
          </div>
          <div style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
            {mode === "login"
              ? "Sign in to your account"
              : "Create a new account"}
          </div>
        </div>

        {/* Mode toggle */}
        <div
          style={{
            display: "flex",
            background: "#0d0d0f",
            borderRadius: "8px",
            padding: "3px",
            marginBottom: "20px",
            border: "0.5px solid #1e1e22",
          }}
        >
          {["login", "register"].map((m) => (
            <button
              key={m}
              onClick={() => {
                setMode(m);
                setError("");
                setSuccess("");
              }}
              style={{
                flex: 1,
                padding: "8px",
                borderRadius: "6px",
                fontSize: "13px",
                background: mode === m ? "#7F77DD" : "transparent",
                color: mode === m ? "white" : "#555",
                border: "none",
                cursor: "pointer",
                textTransform: "capitalize",
              }}
            >
              {m}
            </button>
          ))}
        </div>

        {/* Form */}
        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          {mode === "register" && (
            <input
              placeholder="Full name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          )}

          <input
            type="email"
            placeholder="Email address"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />

          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) =>
              e.key === "Enter" &&
              (mode === "login" ? handleLogin() : handleRegister())
            }
          />

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
            onClick={mode === "login" ? handleLogin : handleRegister}
            disabled={loading}
            style={{ padding: "12px", marginTop: "4px" }}
          >
            {loading
              ? "Please wait..."
              : mode === "login"
                ? "Sign in"
                : "Create account"}
          </button>
        </div>

        {/* Default credentials hint */}
        {mode === "login" && (
          <div
            style={{
              textAlign: "center",
              marginTop: "20px",
              fontSize: "12px",
              color: "#333",
            }}
          >
            Default: ghost@recon.io / ghostrecon123
          </div>
        )}
      </div>
    </div>
  );
}
