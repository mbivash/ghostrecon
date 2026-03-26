const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const { getAllowedOrigins, requireEnv } = require("./config");

const JWT_SECRET = requireEnv("JWT_SECRET");
const app = express();
const allowedOrigins = getAllowedOrigins();

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true); // server-to-server
      if (allowedOrigins.length === 0) return callback(null, true); // dev fallback
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("CORS policy blocked this origin."));
    },
    credentials: true,
  }),
);

app.use(express.json({ limit: "1mb" }));

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  message: { error: "Too many requests. Please wait and try again." },
  standardHeaders: true,
  legacyHeaders: false,
});

const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many scans. You can run 10 scans per 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: "Too many login attempts. Please wait 1 hour." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use("/api/", generalLimiter);
app.use("/api/auth", authLimiter, require("./routes/auth"));

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
app.use("/api/apiscan", auth, require("./routes/apiscan"));
app.use("/api/compliance", auth, require("./routes/compliance"));
app.use("/api/wordpress", auth, require("./routes/wordpress"));
app.use("/api/s3scan", auth, require("./routes/s3scanner"));
app.use("/api/dnscheck", auth, require("./routes/dnscheck"));
app.use("/api/secretscan", auth, require("./routes/secretscan"));
app.use("/api/graphql-scan", auth, require("./routes/graphql"));
app.use("/api/oauth", auth, require("./routes/oauth"));
app.use("/api/idorscan", auth, scanLimiter, require("./routes/idorscan"));

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "GhostRecon API",
    jwtConfigured: Boolean(JWT_SECRET),
    timestamp: new Date().toISOString(),
  });
});

app.use((err, req, res, next) => {
  if (err.message === "CORS policy blocked this origin.") {
    return res.status(403).json({ error: err.message });
  }
  return next(err);
});

app.use((err, req, res, next) => {
  console.error("[UnhandledError]", err);
  return res.status(500).json({ error: "Internal server error." });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`GhostRecon server running on port ${PORT}`);
  console.log(
    `Allowed CORS origins: ${allowedOrigins.length > 0 ? allowedOrigins.join(", ") : "* (not restricted)"}`,
  );
});
