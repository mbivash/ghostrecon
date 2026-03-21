const express = require("express");
const router = express.Router();
const { authenticatedScan, deepScan } = require("../modules/vulnScanner");
const { scansDb } = require("../database");

router.post("/scan", async (req, res) => {
  const { target, username, password, loginUrl, consent } = req.body;

  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target)
    return res.status(400).json({ error: "Target URL is required." });
  if (!username || !password)
    return res
      .status(400)
      .json({ error: "Username and password are required." });

  let url = target.trim();
  if (!url.startsWith("http")) url = "http://" + url;

  console.log("Starting authenticated scan on:", url);

  try {
    const authResults = await authenticatedScan(url, {
      username,
      password,
      loginUrl,
    });

    const severity = authResults.findings.some((f) => f.severity === "Critical")
      ? "critical"
      : authResults.findings.some((f) => f.severity === "High")
        ? "high"
        : authResults.findings.length > 0
          ? "medium"
          : "info";

    scansDb
      .insert({
        type: "Authenticated Scan",
        userId: req.user?.id,
        target: url,
        result: authResults,
        findings_count: authResults.findings.length,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .catch((e) => console.error(e));

    res.json({ success: true, data: authResults });
  } catch (err) {
    console.error("Auth scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
