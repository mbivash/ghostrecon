const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

// ── Rate Limiters ─────────────────────────────────────

// General API limit — 100 requests per 15 minutes
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: "Too many requests. Please wait 15 minutes and try again.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Scan limit — 10 scans per 15 minutes (prevents abuse)
const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many scans. You can run 10 scans per 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Auth limit — 10 login attempts per hour
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: "Too many login attempts. Please wait 1 hour." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply general limiter to all routes
app.use("/api/", generalLimiter);

// Auth routes — stricter limit
app.use("/api/auth", authLimiter, require("./routes/auth"));

// Protected routes with scan limiter on scan endpoints
const auth = require("./middleware/auth");
app.use("/api/network", auth, scanLimiter, require("./routes/network"));
app.use("/api/webvuln", auth, scanLimiter, require("./routes/webvuln"));
app.use("/api/password", auth, require("./routes/password"));
app.use("/api/reports", auth, require("./routes/reports"));
app.use("/api/history", auth, require("./routes/history"));
app.use("/api/osint", auth, scanLimiter, require("./routes/osint"));
app.use("/api/dashboard", auth, require("./routes/dashboard"));
app.use("/api/ssl", auth, scanLimiter, require("./routes/ssl"));
app.use("/api/cve", auth, require("./routes/cve"));
app.use("/api/takeover", auth, scanLimiter, require("./routes/takeover"));
app.use("/api/schedules", auth, require("./routes/schedules"));
app.use("/api/email", auth, require("./routes/email"));
app.use("/api/emailsecurity", auth, require("./routes/emailsecurity"));
app.use("/api/authscan", auth, require("./routes/authscan"));

app.get("/api/health", (req, res) => {
  res.json({ status: "GhostRecon server running" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`GhostRecon server running on port ${PORT}`);
});
