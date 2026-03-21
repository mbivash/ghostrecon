const express = require("express");
const router = express.Router();
const { deepScan } = require("../modules/vulnScanner");
const { scansDb } = require("../database");

router.post("/scan", async (req, res) => {
  const { target, consent } = req.body;

  if (!consent) {
    return res.status(403).json({ error: "Authorization required." });
  }

  if (!target) {
    return res.status(400).json({ error: "Target URL is required." });
  }

  let url = target.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "http://" + url;
  }

  console.log("Starting deep scan on:", url);

  try {
    const results = await deepScan(url);

    const severity =
      results.summary.critical > 0
        ? "critical"
        : results.summary.high > 0
          ? "high"
          : results.summary.medium > 0
            ? "medium"
            : results.summary.low > 0
              ? "low"
              : "info";

    scansDb
      .insert({
        type: "Web Vuln Scan",
        userId: req.user?.id,
        target: url,
        result: results,
        findings_count: results.summary.total,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .catch((e) => console.error(e));

    res.json({ success: true, data: results });
  } catch (err) {
    console.error("Scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
