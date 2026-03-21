const express = require("express");
const router = express.Router();
const db = require("../database");

// Get all scans
router.get("/", (req, res) => {
  try {
    const scans = db
      .prepare(
        `
      SELECT id, type, target, findings_count, severity, scanned_at
      FROM scans
      ORDER BY scanned_at DESC
      LIMIT 100
    `,
      )
      .all();
    res.json({ success: true, scans });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get one scan by id
router.get("/:id", (req, res) => {
  try {
    const scan = db
      .prepare(
        `
      SELECT * FROM scans WHERE id = ?
    `,
      )
      .get(req.params.id);

    if (!scan) return res.status(404).json({ error: "Scan not found." });

    scan.result = JSON.parse(scan.result);
    res.json({ success: true, scan });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a scan
router.delete("/:id", (req, res) => {
  try {
    db.prepare("DELETE FROM scans WHERE id = ?").run(req.params.id);
    res.json({ success: true, message: "Scan deleted." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
