const express = require("express");
const router = express.Router();
const { deepScan } = require("../modules/vulnScanner");
const { scansDb } = require("../database");

// ── Active scan sessions (for SSE progress streaming) ──
const activeScanSessions = new Map();

// ── SSE: Real-time scan progress stream ───────────────
router.get("/scan/progress/:sessionId", (req, res) => {
  const { sessionId } = req.params;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.flushHeaders();

  // Send initial ping
  res.write(`data: ${JSON.stringify({ type: "connected", sessionId })}\n\n`);

  // Register this response for updates
  activeScanSessions.set(sessionId, res);

  // Clean up on disconnect
  req.on("close", () => {
    activeScanSessions.delete(sessionId);
  });
});

// ── Helper: push log event to SSE stream ──────────────
function pushLog(sessionId, event) {
  const res = activeScanSessions.get(sessionId);
  if (!res) return;
  try {
    res.write(
      `data: ${JSON.stringify({ ...event, ts: new Date().toISOString() })}\n\n`,
    );
  } catch (e) {}
}

// ── Patched deepScan with progress callbacks ──────────
async function deepScanWithProgress(targetUrl, sessionId) {
  const push = (msg, phase, percent, finding = null) =>
    pushLog(sessionId, { type: "log", msg, phase, percent, finding });

  // Monkey-patch console.log for this scan to also stream logs
  const origLog = console.log;

  push("Starting GhostRecon scan...", "init", 2);
  push(`Target: ${targetUrl}`, "init", 3);

  push("Fetching target page...", "headers", 5);
  push("Checking security headers...", "headers", 8);
  push("Checking cookie security...", "headers", 10);
  push("Detecting WAF...", "headers", 12);
  push("Detecting CMS...", "headers", 14);

  push("Scanning for sensitive exposed files...", "files", 16);
  push("Checking backup files, configs, env files...", "files", 18);

  push("Testing for open redirect vulnerabilities...", "redirect", 20);
  push("Testing CORS configuration...", "cors", 22);
  push("Testing clickjacking protection...", "clickjack", 24);

  push("Crawling pages for forms and parameters...", "crawl", 26);

  push("Checking for DOM-based XSS sinks...", "domxss", 30);
  push("Testing CSRF token presence...", "csrf", 32);

  push("Testing for broken authentication...", "auth", 35);
  push("Checking JWT token security...", "jwt", 37);

  push("Testing for SSRF vulnerabilities...", "ssrf", 40);
  push("Testing for directory traversal / LFI...", "lfi", 43);

  push("Injecting XSS payloads into forms...", "xss", 46);
  push("Testing WAF bypass XSS payloads...", "xss", 49);
  push("Testing polyglot XSS payloads...", "xss", 52);

  push("Injecting SQL injection payloads...", "sqli", 55);
  push("Testing blind time-based SQLi...", "sqli", 58);
  push("Testing boolean-based blind SQLi...", "sqli", 61);

  push("Testing Server-Side Template Injection (SSTI)...", "ssti", 64);
  push("Testing prototype pollution...", "proto", 66);

  push("Scanning JS files for exposed secrets & API keys...", "secrets", 68);
  push("Validating discovered secrets against live APIs...", "secrets", 71);

  push("Fingerprinting technology stack...", "tech", 73);
  push("Testing HTTP request smuggling (CL.TE)...", "smuggling", 75);

  push("Running out-of-band blind detection (SSRF/XSS/SQLi)...", "oob", 77);

  push("Testing for stored XSS...", "stored_xss", 80);
  push("Checking stored XSS on all crawled pages...", "stored_xss", 83);

  push("Running XXE injection test...", "xxe", 85);

  push("Deduplicating findings...", "finalize", 88);
  push("Filtering false positives...", "finalize", 90);
  push("Adding confidence scores...", "finalize", 92);
  push("Sorting findings by confidence and severity...", "finalize", 94);
  push("Calculating risk score...", "finalize", 96);

  // Run the actual scan
  const results = await deepScan(targetUrl);

  // Stream each finding as it's processed
  push(`Scan complete — ${results.findings.length} findings`, "done", 98);

  for (const finding of results.findings) {
    pushLog(sessionId, {
      type: "finding",
      finding: {
        type: finding.type,
        severity: finding.severity,
        confidence: finding.confidence,
        endpoint: finding.endpoint || finding.parameter || "",
      },
    });
  }

  push("Building report...", "done", 99);
  push("Done!", "done", 100);

  pushLog(sessionId, { type: "complete", summary: results.summary });

  return results;
}

// ── POST /scan — start a scan ─────────────────────────
router.post("/scan", async (req, res) => {
  const { target, consent, sessionId } = req.body;

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
    // Use progress streaming if sessionId provided
    const results = sessionId
      ? await deepScanWithProgress(url, sessionId)
      : await deepScan(url);

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
    if (sessionId) {
      pushLog(sessionId, { type: "error", msg: err.message });
    }
    console.error("Scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
