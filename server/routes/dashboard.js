const express = require("express");
const router = express.Router();
const { scansDb } = require("../database");

router.get("/stats", async (req, res) => {
  try {
    const allScans = await scansDb.find({}).sort({ scanned_at: -1 });
    const totalScans = allScans.length;
    const totalVulns = allScans.reduce(
      (sum, s) => sum + (s.findings_count || 0),
      0,
    );
    const highSeverity = allScans.filter(
      (s) => s.severity === "high" || s.severity === "critical",
    ).length;
    const targets = [...new Set(allScans.map((s) => s.target))];
    const recentScans = allScans.slice(0, 5);
    res.json({
      success: true,
      stats: {
        totalScans,
        totalVulns,
        highSeverity,
        activeTargets: targets.length,
        recentScans,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
