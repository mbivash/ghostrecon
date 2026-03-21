const express = require("express");
const router = express.Router();
const { exec } = require("child_process");
const db = require("../database");

router.post("/scan", (req, res) => {
  const { target, scanType, consent } = req.body;

  if (!consent) {
    return res.status(403).json({
      error: "You must confirm you have permission to scan this target.",
    });
  }

  if (!target) {
    return res.status(400).json({ error: "Target is required." });
  }

  const flags = {
    quick: "-T4 -F --open",
    ping: "-sn",
    full: "-T4 -A --open",
  };

  const flag = flags[scanType] || flags.quick;
  const nmapPath = `"C:\\Program Files (x86)\\Nmap\\nmap.exe"`;
  const command = `${nmapPath} ${flag} ${target}`;

  console.log("Running:", command);

  exec(
    command,
    { timeout: 120000, maxBuffer: 1024 * 1024 * 10 },
    (error, stdout, stderr) => {
      console.log("=== RAW OUTPUT START ===");
      console.log(stdout);
      console.log("=== RAW OUTPUT END ===");

      if (!stdout || stdout.trim() === "") {
        return res.status(500).json({ error: "Nmap returned no output." });
      }

      const ports = [];
      const lines = stdout.split("\n");

      lines.forEach((line) => {
        const trimmed = line.trim();
        const match = trimmed.match(/^(\d+)\/(tcp|udp)\s+(\S+)\s*(.*)$/);
        if (match) {
          ports.push({
            port: match[1],
            protocol: match[2],
            state: match[3],
            service: match[4] ? match[4].trim() : "unknown",
          });
        }
      });

      const hostMatch = stdout.match(/Nmap scan report for (.+)/);
      const host = hostMatch ? hostMatch[1].trim() : target;

      const timeMatch = stdout.match(/scanned in ([\d.]+) seconds/);
      const duration = timeMatch ? timeMatch[1] + "s" : "done";

      const resultData = {
        target,
        host,
        ports,
        duration,
        raw: stdout,
        scannedAt: new Date().toISOString(),
      };

      // Save to database
      try {
        db.prepare(
          `
        INSERT INTO scans (type, target, result, findings_count, severity)
        VALUES (?, ?, ?, ?, ?)
      `,
        ).run(
          "Network Scan",
          target,
          JSON.stringify(resultData),
          ports.length,
          ports.length > 0 ? "medium" : "info",
        );
        console.log("Scan saved to database");
      } catch (dbErr) {
        console.error("DB save error:", dbErr);
      }

      res.json({ success: true, data: resultData });
    },
  );
});

module.exports = router;
