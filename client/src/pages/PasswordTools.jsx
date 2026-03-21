import { useState } from "react";
import api from "../utils/api";

const TABS = [
  "Hash Identifier",
  "Hash Cracker",
  "Strength Analyzer",
  "Password Generator",
];

export default function PasswordTools() {
  const [activeTab, setActiveTab] = useState(0);

  return (
    <div style={{ padding: "32px", maxWidth: "800px" }}>
      <div style={{ marginBottom: "28px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: "500", color: "#e8e6f0" }}>
          Password Tools
        </h1>
        <p style={{ fontSize: "13px", color: "#555", marginTop: "4px" }}>
          Hash analysis, cracking, strength testing and password generation.
        </p>
      </div>

      <div
        style={{
          display: "flex",
          gap: "4px",
          marginBottom: "24px",
          background: "#131315",
          padding: "4px",
          borderRadius: "10px",
          border: "0.5px solid #1e1e22",
          width: "fit-content",
        }}
      >
        {TABS.map((tab, i) => (
          <button
            key={tab}
            onClick={() => setActiveTab(i)}
            style={{
              padding: "8px 16px",
              borderRadius: "8px",
              fontSize: "13px",
              background: activeTab === i ? "#7F77DD" : "transparent",
              color: activeTab === i ? "white" : "#666",
              border: "none",
              cursor: "pointer",
              transition: "all 0.15s",
            }}
          >
            {tab}
          </button>
        ))}
      </div>

      {activeTab === 0 && <HashIdentifier />}
      {activeTab === 1 && <HashCracker />}
      {activeTab === 2 && <StrengthAnalyzer />}
      {activeTab === 3 && <PasswordGenerator />}
    </div>
  );
}

function HashIdentifier() {
  const [hash, setHash] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const identify = async () => {
    if (!hash.trim()) return;
    setLoading(true);
    try {
      const res = await api.post("/api/password/identify", { hash });
      setResult(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      <Card>
        <Label>Paste a hash to identify</Label>
        <input
          placeholder="e.g. 5f4dcc3b5aa765d61d8327deb882cf99"
          value={hash}
          onChange={(e) => setHash(e.target.value)}
          style={{ fontFamily: "monospace" }}
        />
        <div style={{ fontSize: "11px", color: "#444", marginTop: "4px" }}>
          Test MD5 hash of "password": 5f4dcc3b5aa765d61d8327deb882cf99
        </div>
        <ActionButton
          onClick={identify}
          loading={loading}
          label="Identify Hash"
        />
      </Card>

      {result && (
        <Card>
          <div
            style={{
              fontSize: "12px",
              color: "#555",
              marginBottom: "12px",
              fontFamily: "monospace",
            }}
          >
            {result.hash}
          </div>
          {result.types.map((t, i) => (
            <div
              key={i}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "10px 14px",
                background: "#0d0d0f",
                borderRadius: "8px",
                marginBottom: "8px",
              }}
            >
              <div>
                <span
                  style={{
                    fontSize: "14px",
                    fontWeight: "500",
                    color: "#e8e6f0",
                  }}
                >
                  {t.name}
                </span>
                <span
                  style={{
                    marginLeft: "10px",
                    fontSize: "11px",
                    padding: "2px 7px",
                    borderRadius: "10px",
                    background: "#131315",
                    color: "#777",
                  }}
                >
                  {t.confidence} confidence
                </span>
              </div>
              <span
                style={{
                  fontSize: "11px",
                  padding: "2px 8px",
                  borderRadius: "10px",
                  background: t.crackable ? "#1a0a0a" : "#0a1a14",
                  color: t.crackable ? "#E24B4A" : "#1D9E75",
                  border: `0.5px solid ${t.crackable ? "#791F1F" : "#085041"}`,
                }}
              >
                {t.crackable ? "Crackable" : "Hard to crack"}
              </span>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
}

function HashCracker() {
  const [hash, setHash] = useState("");
  const [hashType, setHashType] = useState("auto");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const crack = async () => {
    if (!hash.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await api.post("/api/password/crack", { hash, hashType });
      setResult(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      <Card>
        <Label>Hash to crack</Label>
        <input
          placeholder="Paste MD5, SHA1 or SHA256 hash"
          value={hash}
          onChange={(e) => setHash(e.target.value)}
          style={{ fontFamily: "monospace", marginBottom: "12px" }}
        />
        <Label>Hash type</Label>
        <select value={hashType} onChange={(e) => setHashType(e.target.value)}>
          <option value="auto">Auto detect</option>
          <option value="md5">MD5</option>
          <option value="sha1">SHA-1</option>
          <option value="sha256">SHA-256</option>
        </select>
        <div style={{ fontSize: "11px", color: "#444", marginTop: "8px" }}>
          Test: crack MD5 of "admin" → 21232f297a57a5a743894a0e4a801fc3
        </div>
        <ActionButton onClick={crack} loading={loading} label="Crack Hash" />
      </Card>

      {result && (
        <Card>
          {result.cracked ? (
            <div>
              <div
                style={{
                  fontSize: "13px",
                  color: "#1D9E75",
                  marginBottom: "12px",
                }}
              >
                Hash cracked successfully
              </div>
              <div
                style={{
                  background: "#0a1a14",
                  border: "0.5px solid #085041",
                  borderRadius: "8px",
                  padding: "16px",
                  textAlign: "center",
                }}
              >
                <div
                  style={{
                    fontSize: "11px",
                    color: "#555",
                    marginBottom: "6px",
                  }}
                >
                  Plaintext password
                </div>
                <div
                  style={{
                    fontSize: "24px",
                    fontWeight: "500",
                    color: "#1D9E75",
                    fontFamily: "monospace",
                  }}
                >
                  {result.password}
                </div>
                <div
                  style={{ fontSize: "12px", color: "#555", marginTop: "8px" }}
                >
                  Algorithm: {result.algorithm} · Found after {result.attempts}{" "}
                  attempts
                </div>
              </div>
            </div>
          ) : (
            <div style={{ textAlign: "center", padding: "16px" }}>
              <div
                style={{
                  fontSize: "14px",
                  color: "#BA7517",
                  marginBottom: "8px",
                }}
              >
                Not found in wordlist
              </div>
              <div style={{ fontSize: "12px", color: "#555" }}>
                Tried {result.attempts} combinations. Password may be strong or
                use special characters.
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

function StrengthAnalyzer() {
  const [password, setPassword] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [show, setShow] = useState(false);

  const analyze = async () => {
    if (!password.trim()) return;
    setLoading(true);
    try {
      const res = await api.post("/api/password/strength", { password });
      setResult(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      <Card>
        <Label>Enter a password to analyze</Label>
        <div style={{ position: "relative" }}>
          <input
            type={show ? "text" : "password"}
            placeholder="Type any password..."
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && analyze()}
            style={{ paddingRight: "60px" }}
          />
          <button
            onClick={() => setShow(!show)}
            style={{
              position: "absolute",
              right: "10px",
              top: "50%",
              transform: "translateY(-50%)",
              background: "none",
              border: "none",
              color: "#555",
              fontSize: "12px",
              cursor: "pointer",
              padding: "4px",
            }}
          >
            {show ? "Hide" : "Show"}
          </button>
        </div>
        <ActionButton
          onClick={analyze}
          loading={loading}
          label="Analyze Strength"
        />
      </Card>

      {result && (
        <Card>
          <div style={{ marginBottom: "20px" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                marginBottom: "8px",
              }}
            >
              <span
                style={{
                  fontSize: "14px",
                  fontWeight: "500",
                  color: result.color,
                }}
              >
                {result.strength}
              </span>
              <span
                style={{
                  fontSize: "14px",
                  fontWeight: "500",
                  color: result.color,
                }}
              >
                {result.score}/100
              </span>
            </div>
            <div
              style={{
                height: "6px",
                background: "#1e1e22",
                borderRadius: "3px",
              }}
            >
              <div
                style={{
                  height: "100%",
                  borderRadius: "3px",
                  width: `${result.score}%`,
                  background: result.color,
                  transition: "width 0.5s ease",
                }}
              />
            </div>
            <div style={{ fontSize: "12px", color: "#555", marginTop: "8px" }}>
              Estimated crack time:{" "}
              <span style={{ color: result.color }}>{result.crackTime}</span>
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            {Object.entries(result.checks).map(([check, passed]) => (
              <div
                key={check}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  fontSize: "13px",
                  color: passed ? "#1D9E75" : "#555",
                }}
              >
                <span style={{ fontSize: "14px" }}>{passed ? "✓" : "✗"}</span>
                {check}
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

function PasswordGenerator() {
  const [length, setLength] = useState(16);
  const [options, setOptions] = useState({
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
  });
  const [password, setPassword] = useState("");
  const [copied, setCopied] = useState(false);

  const generate = async () => {
    try {
      const res = await api.post("/api/password/generate", {
        length,
        ...options,
      });
      setPassword(res.data.password);
      setCopied(false);
    } catch (e) {
      console.error(e);
    }
  };

  const copy = () => {
    navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      <Card>
        <div style={{ marginBottom: "16px" }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              marginBottom: "8px",
            }}
          >
            <Label>Password length</Label>
            <span
              style={{ fontSize: "14px", fontWeight: "500", color: "#7F77DD" }}
            >
              {length}
            </span>
          </div>
          <input
            type="range"
            min="8"
            max="64"
            step="1"
            value={length}
            onChange={(e) => setLength(parseInt(e.target.value))}
            style={{ width: "100%" }}
          />
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "8px",
            marginBottom: "16px",
          }}
        >
          {Object.entries(options).map(([key, val]) => (
            <label
              key={key}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                cursor: "pointer",
                padding: "10px 12px",
                background: val ? "#13121f" : "#0d0d0f",
                borderRadius: "8px",
                border: val ? "0.5px solid #3C3489" : "0.5px solid #1e1e22",
                fontSize: "13px",
                color: val ? "#a89ff5" : "#555",
              }}
            >
              <input
                type="checkbox"
                checked={val}
                onChange={(e) =>
                  setOptions({ ...options, [key]: e.target.checked })
                }
                style={{ width: "auto" }}
              />
              {key.charAt(0).toUpperCase() + key.slice(1)}
            </label>
          ))}
        </div>

        <ActionButton onClick={generate} label="Generate Password" />
      </Card>

      {password && (
        <Card>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div
              style={{
                flex: 1,
                fontFamily: "monospace",
                fontSize: "16px",
                color: "#a89ff5",
                letterSpacing: "1px",
                background: "#0d0d0f",
                padding: "12px 16px",
                borderRadius: "8px",
                wordBreak: "break-all",
              }}
            >
              {password}
            </div>
            <button
              onClick={copy}
              className="btn-primary"
              style={{ padding: "12px 16px", flexShrink: 0 }}
            >
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
          <div style={{ fontSize: "12px", color: "#555", marginTop: "10px" }}>
            Length: {password.length} characters
          </div>
        </Card>
      )}
    </div>
  );
}

function Card({ children }) {
  return (
    <div
      style={{
        background: "#131315",
        border: "0.5px solid #1e1e22",
        borderRadius: "12px",
        padding: "20px",
        display: "flex",
        flexDirection: "column",
        gap: "12px",
      }}
    >
      {children}
    </div>
  );
}

function Label({ children }) {
  return (
    <div style={{ fontSize: "12px", color: "#666", marginBottom: "2px" }}>
      {children}
    </div>
  );
}

function ActionButton({ onClick, loading, label }) {
  return (
    <button
      className="btn-primary"
      onClick={onClick}
      disabled={loading}
      style={{
        alignSelf: "flex-start",
        padding: "10px 24px",
        marginTop: "4px",
      }}
    >
      {loading ? "Working..." : label}
    </button>
  );
}
