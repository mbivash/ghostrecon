const express = require("express");
const cors = require("cors");
require("dotenv").config();

const app = express();

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:4173",
      process.env.FRONTEND_URL,
    ].filter(Boolean),
    credentials: true,
  }),
);

app.use(express.json());

app.use("/api/auth", require("./routes/auth"));

const auth = require("./middleware/auth");
app.use("/api/network", auth, require("./routes/network"));
app.use("/api/webvuln", auth, require("./routes/webvuln"));
app.use("/api/password", auth, require("./routes/password"));
app.use("/api/reports", auth, require("./routes/reports"));
app.use("/api/history", auth, require("./routes/history"));
app.use("/api/osint", auth, require("./routes/osint"));
app.use("/api/dashboard", auth, require("./routes/dashboard"));

app.get("/api/health", (req, res) => {
  res.json({ status: "GhostRecon server running" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`GhostRecon server running on port ${PORT}`);
});
