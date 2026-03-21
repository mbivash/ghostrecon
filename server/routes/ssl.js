const express = require("express");
const router = express.Router();
const https = require("https");
const tls = require("tls");
const { scansDb } = require("../database");

function checkSSL(hostname) {
  return new Promise((resolve, reject) => {
    const options = {
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 10000,
    };

    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate(true);
      const authorized = socket.authorized;
      const authError = socket.authorizationError;

      if (!cert || !cert.subject) {
        socket.destroy();
        return reject(new Error("No certificate found"));
      }

      // Parse dates
      const validFrom = new Date(cert.valid_from);
      const validTo = new Date(cert.valid_to);
      const now = new Date();
      const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
      const daysTotal = Math.floor(
        (validTo - validFrom) / (1000 * 60 * 60 * 24),
      );
      const isExpired = daysRemaining < 0;
      const isExpiringSoon = daysRemaining >= 0 && daysRemaining <= 30;

      // Get protocol and cipher
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();

      // Calculate grade
      let grade = "A";
      let gradeColor = "#1D9E75";
      let issues = [];

      if (isExpired) {
        grade = "F";
        gradeColor = "#E24B4A";
        issues.push({
          severity: "Critical",
          issue: "Certificate is expired",
          detail: `Expired on ${validTo.toLocaleDateString()}`,
        });
      } else if (isExpiringSoon) {
        grade = "B";
        gradeColor = "#BA7517";
        issues.push({
          severity: "High",
          issue: "Certificate expiring soon",
          detail: `Expires in ${daysRemaining} days`,
        });
      }

      if (protocol === "TLSv1" || protocol === "TLSv1.1") {
        grade = grade === "A" ? "C" : grade;
        gradeColor = "#BA7517";
        issues.push({
          severity: "High",
          issue: `Outdated protocol: ${protocol}`,
          detail:
            "TLS 1.0 and 1.1 are deprecated and insecure. Upgrade to TLS 1.2 or 1.3",
        });
      }

      if (!authorized) {
        grade = grade === "A" ? "C" : grade;
        gradeColor = "#BA7517";
        issues.push({
          severity: "Medium",
          issue: "Certificate not fully trusted",
          detail: authError || "Authorization error",
        });
      }

      if (cipher && cipher.name && cipher.name.includes("RC4")) {
        grade = "F";
        gradeColor = "#E24B4A";
        issues.push({
          severity: "Critical",
          issue: "Weak cipher: RC4",
          detail: "RC4 cipher is broken and must be disabled immediately",
        });
      }

      if (daysRemaining > 30 && authorized && issues.length === 0) {
        issues.push({
          severity: "Info",
          issue: "Certificate is healthy",
          detail: `Valid for ${daysRemaining} more days`,
        });
      }

      const result = {
        hostname,
        valid: !isExpired && authorized,
        grade,
        gradeColor,
        subject: {
          cn: cert.subject?.CN || hostname,
          org: cert.subject?.O || "Unknown",
          country: cert.subject?.C || "Unknown",
        },
        issuer: {
          cn: cert.issuer?.CN || "Unknown",
          org: cert.issuer?.O || "Unknown",
        },
        validFrom: validFrom.toLocaleDateString(),
        validTo: validTo.toLocaleDateString(),
        daysRemaining,
        daysTotal,
        isExpired,
        isExpiringSoon,
        protocol,
        cipher: cipher?.name || "Unknown",
        serialNumber: cert.serialNumber || "Unknown",
        fingerprint: cert.fingerprint || "Unknown",
        san: cert.subjectaltname || "None",
        issues,
        scannedAt: new Date().toISOString(),
      };

      socket.destroy();
      resolve(result);
    });

    socket.on("error", (err) => {
      socket.destroy();
      reject(err);
    });

    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("Connection timed out"));
    });
  });
}

router.post("/scan", async (req, res) => {
  const { target, consent } = req.body;

  if (!consent) {
    return res.status(403).json({ error: "Authorization required." });
  }

  if (!target) {
    return res.status(400).json({ error: "Target domain is required." });
  }

  // Clean target
  let hostname = target
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .trim();

  console.log("Checking SSL for:", hostname);

  try {
    const result = await checkSSL(hostname);

    // Save to database
    const severity =
      result.grade === "F"
        ? "critical"
        : result.grade === "C"
          ? "high"
          : result.grade === "B"
            ? "medium"
            : "low";

    scansDb
      .insert({
        type: "SSL Scan",
        target: hostname,
        result,
        findings_count: result.issues.filter((i) => i.severity !== "Info")
          .length,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .then(() => console.log("SSL scan saved"))
      .catch((e) => console.error(e));

    res.json({ success: true, data: result });
  } catch (err) {
    console.error("SSL check error:", err.message);

    // If connection refused it means no HTTPS at all
    if (
      err.message.includes("ECONNREFUSED") ||
      err.message.includes("ENOTFOUND")
    ) {
      return res.json({
        success: true,
        data: {
          hostname,
          valid: false,
          grade: "F",
          gradeColor: "#E24B4A",
          issues: [
            {
              severity: "Critical",
              issue: "No HTTPS found",
              detail:
                "This domain does not have SSL/TLS configured. All data is sent unencrypted.",
            },
          ],
          scannedAt: new Date().toISOString(),
        },
      });
    }

    res.status(500).json({ error: "SSL check failed: " + err.message });
  }
});

module.exports = router;
