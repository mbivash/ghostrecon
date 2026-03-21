const express = require("express");
const router = express.Router();
const cron = require("node-cron");
const { scansDb } = require("../database");
const Datastore = require("nedb-promises");
const path = require("path");

const schedulesDb = new Datastore({
  filename: path.join(__dirname, "../schedules.db"),
  autoload: true,
});

const activeCrons = {};

async function runScheduledScan(schedule) {
  console.log(
    `Running scheduled scan for ${schedule.target} (${schedule.type})`,
  );

  try {
    let result = null;
    let findingsCount = 0;
    let severity = "info";

    if (schedule.type === "Web Vuln Scan") {
      const axios = require("axios");
      const cheerio = require("cheerio");

      let url = schedule.target;
      if (!url.startsWith("http")) url = "http://" + url;

      try {
        const response = await axios.get(url, {
          timeout: 30000,
          validateStatus: () => true,
          headers: { "User-Agent": "GhostRecon Security Scanner" },
        });

        const headers = response.headers;
        const vulnerabilities = [];

        const SECURITY_HEADERS = [
          {
            name: "x-frame-options",
            severity: "Medium",
            desc: "Missing X-Frame-Options",
          },
          {
            name: "content-security-policy",
            severity: "High",
            desc: "Missing Content-Security-Policy",
          },
          {
            name: "strict-transport-security",
            severity: "High",
            desc: "Missing HSTS",
          },
          {
            name: "x-content-type-options",
            severity: "Low",
            desc: "Missing X-Content-Type-Options",
          },
        ];

        SECURITY_HEADERS.forEach((h) => {
          if (!headers[h.name]) {
            vulnerabilities.push({
              type: "Missing Security Header",
              severity: h.severity,
              detail: h.desc,
              evidence: `Header "${h.name}" not present`,
            });
          }
        });

        findingsCount = vulnerabilities.length;
        severity = vulnerabilities.some((v) => v.severity === "High")
          ? "high"
          : vulnerabilities.some((v) => v.severity === "Medium")
            ? "medium"
            : vulnerabilities.length > 0
              ? "low"
              : "info";

        result = {
          target: url,
          vulnerabilities,
          scannedAt: new Date().toISOString(),
        };
      } catch (e) {
        result = {
          target: url,
          error: e.message,
          scannedAt: new Date().toISOString(),
        };
      }
    }

    if (schedule.type === "SSL Scan") {
      const tls = require("tls");
      const hostname = schedule.target
        .replace(/^https?:\/\//, "")
        .replace(/\/.*$/, "");

      await new Promise((resolve) => {
        const socket = tls.connect(
          {
            host: hostname,
            port: 443,
            servername: hostname,
            rejectUnauthorized: false,
            timeout: 10000,
          },
          () => {
            const cert = socket.getPeerCertificate();
            if (cert && cert.valid_to) {
              const daysRemaining = Math.floor(
                (new Date(cert.valid_to) - new Date()) / (1000 * 60 * 60 * 24),
              );
              findingsCount = daysRemaining < 30 ? 1 : 0;
              severity =
                daysRemaining < 0
                  ? "critical"
                  : daysRemaining < 30
                    ? "high"
                    : "info";
              result = {
                hostname,
                daysRemaining,
                validTo: new Date(cert.valid_to).toLocaleDateString(),
                scannedAt: new Date().toISOString(),
              };
            }
            socket.destroy();
            resolve();
          },
        );
        socket.on("error", () => {
          socket.destroy();
          resolve();
        });
        socket.on("timeout", () => {
          socket.destroy();
          resolve();
        });
      });
    }

    if (result) {
      await scansDb.insert({
        type: schedule.type,
        target: schedule.target,
        result,
        findings_count: findingsCount,
        severity,
        scanned_at: new Date().toISOString(),
        scheduled: true,
        scheduleId: schedule._id,
      });

      await schedulesDb.update(
        { _id: schedule._id },
        {
          $set: {
            lastRun: new Date().toISOString(),
            lastFindings: findingsCount,
          },
        },
      );

      console.log(
        `Scheduled scan complete for ${schedule.target} — ${findingsCount} findings`,
      );
    }
  } catch (err) {
    console.error("Scheduled scan error:", err);
  }
}

function getCronExpression(frequency) {
  switch (frequency) {
    case "hourly":
      return "0 * * * *";
    case "daily":
      return "0 9 * * *";
    case "weekly":
      return "0 9 * * 1";
    case "monthly":
      return "0 9 1 * *";
    default:
      return "0 9 * * 1";
  }
}

async function loadAndStartSchedules() {
  try {
    const schedules = await schedulesDb.find({ active: true });
    schedules.forEach((schedule) => {
      startCronJob(schedule);
    });
    console.log(`Loaded ${schedules.length} scheduled scans`);
  } catch (err) {
    console.error("Error loading schedules:", err);
  }
}

function startCronJob(schedule) {
  if (activeCrons[schedule._id]) {
    activeCrons[schedule._id].stop();
  }
  const expression = getCronExpression(schedule.frequency);
  const task = cron.schedule(expression, () => runScheduledScan(schedule));
  activeCrons[schedule._id] = task;
  console.log(`Started cron for ${schedule.target} — ${schedule.frequency}`);
}

loadAndStartSchedules();

router.get("/", async (req, res) => {
  try {
    const schedules = await schedulesDb.find({}).sort({ created_at: -1 });
    res.json({ success: true, schedules });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/", async (req, res) => {
  const { target, type, frequency } = req.body;

  if (!target || !type || !frequency) {
    return res
      .status(400)
      .json({ error: "Target, type and frequency are required." });
  }

  try {
    const schedule = await schedulesDb.insert({
      target: target.trim(),
      type,
      frequency,
      active: true,
      lastRun: null,
      lastFindings: 0,
      created_at: new Date().toISOString(),
    });

    startCronJob(schedule);
    res.json({ success: true, schedule });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete("/:id", async (req, res) => {
  try {
    if (activeCrons[req.params.id]) {
      activeCrons[req.params.id].stop();
      delete activeCrons[req.params.id];
    }
    await schedulesDb.remove({ _id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/:id/run", async (req, res) => {
  try {
    const schedule = await schedulesDb.findOne({ _id: req.params.id });
    if (!schedule)
      return res.status(404).json({ error: "Schedule not found." });
    runScheduledScan(schedule);
    res.json({ success: true, message: "Scan started." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
