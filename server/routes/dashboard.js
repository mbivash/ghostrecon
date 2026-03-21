const express = require("express");
const router = express.Router();
const db = require("../database");

router.get("/stats", (req, res) => {
  try {
    const totalScans = db.prepare("SELECT COUNT(*) as count FROM scans").get();
    const totalVulns = db
      .prepare("SELECT SUM(findings_count) as count FROM scans")
      .get();
    const highSeverity = db
      .prepare(
        "SELECT COUNT(*) as count FROM scans WHERE severity IN ('high', 'critical')",
      )
      .get();
    const recentScans = db
      .prepare(
        `
      SELECT id, type, target, findings_count, severity, scanned_at
      FROM scans ORDER BY scanned_at DESC LIMIT 5
    `,
      )
      .all();
    const activeTargets = db
      .prepare("SELECT COUNT(DISTINCT target) as count FROM scans")
      .get();

    res.json({
      success: true,
      stats: {
        totalScans: totalScans.count || 0,
        totalVulns: totalVulns.count || 0,
        highSeverity: highSeverity.count || 0,
        activeTargets: activeTargets.count || 0,
        recentScans,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
