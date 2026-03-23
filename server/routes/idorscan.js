const express = require("express");
const router  = express.Router();
const { runIDORScan } = require("../modules/idorTester");
const { scansDb }     = require("../database");

// Active sessions for SSE streaming
const activeSessions = new Map();

// SSE progress stream
router.get("/progress/:sessionId", (req, res) => {
  const { sessionId } = req.params;
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.flushHeaders();
  res.write(`data: ${JSON.stringify({ type: "connected" })}\n\n`);
  activeSessions.set(sessionId, res);
  req.on("close", () => activeSessions.delete(sessionId));
});

function push(sessionId, event) {
  const res = activeSessions.get(sessionId);
  if (!res) return;
  try { res.write(`data: ${JSON.stringify({ ...event, ts: new Date().toISOString() })}\n\n`); } catch (e) {}
}

// POST /scan — run IDOR scan
router.post("/scan", async (req, res) => {
  const { targetUrl, loginUrl, account1, account2, authType, customEndpoints, consent, sessionId } = req.body;

  if (!consent)    return res.status(403).json({ error: "Authorization required." });
  if (!targetUrl)  return res.status(400).json({ error: "Target URL is required." });
  if (!account1?.username || !account1?.password) return res.status(400).json({ error: "Account 1 credentials required." });
  if (!account2?.username || !account2?.password) return res.status(400).json({ error: "Account 2 credentials required." });

  if (sessionId) {
    push(sessionId, { type: "log", msg: "Starting two-account IDOR scan...", percent: 5 });
    push(sessionId, { type: "log", msg: `Target: ${targetUrl}`, percent: 8 });
    push(sessionId, { type: "log", msg: `Logging in as Account A: ${account1.username}`, percent: 15 });
  }

  try {
    const results = await runIDORScan({
      targetUrl,
      loginUrl,
      account1,
      account2,
      authType: authType || "cookie",
      customEndpoints: customEndpoints || [],
    });

    if (sessionId) {
      push(sessionId, { type: "log", msg: `Account A authenticated`, percent: 30 });
      push(sessionId, { type: "log", msg: `Account B authenticated`, percent: 40 });
      push(sessionId, { type: "log", msg: `Discovered ${results.apiEndpoints.length} API endpoints`, percent: 55 });
      push(sessionId, { type: "log", msg: `Testing ${results.testedEndpoints.length} endpoints for IDOR...`, percent: 65 });
      push(sessionId, { type: "log", msg: `Scan complete — ${results.findings.length} findings`, percent: 100 });
      for (const f of results.findings) {
        push(sessionId, { type: "finding", finding: { type: f.type, severity: f.severity, endpoint: f.endpoint } });
      }
      push(sessionId, { type: "complete", summary: results.summary });
    }

    scansDb.insert({
      type: "IDOR Scan",
      userId: req.user?.id,
      target: targetUrl,
      result: results,
      findings_count: results.findings.length,
      severity: results.findings.length > 0 ? "high" : "info",
      scanned_at: new Date().toISOString(),
    }).catch((e) => console.error(e));

    res.json({ success: true, data: results });
  } catch (err) {
    if (sessionId) push(sessionId, { type: "error", msg: err.message });
    console.error("IDOR scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
