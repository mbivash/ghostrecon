const express = require("express");
const router = express.Router();
const { scansDb } = require("../database");

router.get("/", async (req, res) => {
  try {
    const scans = await scansDb.find({}).sort({ scanned_at: -1 }).limit(100);
    res.json({ success: true, scans });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/:id", async (req, res) => {
  try {
    const scan = await scansDb.findOne({ _id: req.params.id });
    if (!scan) return res.status(404).json({ error: "Scan not found." });
    res.json({ success: true, scan });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete("/:id", async (req, res) => {
  try {
    await scansDb.remove({ _id: req.params.id });
    res.json({ success: true, message: "Scan deleted." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
