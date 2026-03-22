const express = require("express");
const router = express.Router();
const axios = require("axios");
const cheerio = require("cheerio");
const { scansDb } = require("../database");
const { SECRET_PATTERNS } = require("../modules/payloads");

const axiosInstance = axios.create({
  timeout: 15000,
  validateStatus: () => true,
  headers: {
    "User-Agent": "Mozilla/5.0 (compatible; GhostRecon Secret Scanner)",
    Accept: "text/html,application/javascript,*/*",
  },
});

async function scanUrlForSecrets(url) {
  const results = { url, secrets: [], error: null };
  try {
    const res = await axiosInstance.get(url);
    const content =
      typeof res.data === "string" ? res.data : JSON.stringify(res.data);
    for (const { name, pattern, severity } of SECRET_PATTERNS) {
      const matches = [...content.matchAll(pattern)];
      if (matches.length > 0) {
        const match = matches[0][0];
        const masked =
          match.length > 12
            ? match.substring(0, 6) + "****" + match.substring(match.length - 4)
            : match.substring(0, 3) + "****";
        results.secrets.push({
          name,
          masked,
          severity,
          count: matches.length,
          url,
        });
      }
    }
  } catch (e) {
    results.error = e.message;
  }
  return results;
}

router.post("/scan", async (req, res) => {
  const { target, consent, deepScan: deep } = req.body;
  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target)
    return res.status(400).json({ error: "Target URL is required." });

  let targetUrl = target.trim();
  if (!targetUrl.startsWith("http")) targetUrl = "http://" + targetUrl;
  const baseUrl = new URL(targetUrl).origin;

  console.log("Secret scan for:", targetUrl);

  try {
    const results = {
      target: targetUrl,
      urlsScanned: [],
      allSecrets: [],
      findings: [],
      scannedAt: new Date().toISOString(),
    };

    // Fetch main page
    let html = "";
    try {
      const mainRes = await axiosInstance.get(targetUrl);
      html = typeof mainRes.data === "string" ? mainRes.data : "";
    } catch (e) {
      return res
        .status(500)
        .json({ error: "Could not reach target: " + e.message });
    }

    // Scan main page
    const mainScan = await scanUrlForSecrets(targetUrl);
    results.urlsScanned.push(targetUrl);
    results.allSecrets.push(...mainScan.secrets);

    // Find and scan JS files
    const $ = cheerio.load(html);
    const jsUrls = [];
    $("script[src]").each((i, el) => {
      const src = $(el).attr("src");
      if (!src) return;
      try {
        const absolute = new URL(src, baseUrl).href;
        jsUrls.push(absolute);
      } catch (e) {}
    });

    // Also find inline scripts
    const inlineScripts = [];
    $("script:not([src])").each((i, el) => {
      const content = $(el).html();
      if (content && content.length > 50) inlineScripts.push(content);
    });

    // Scan inline scripts
    for (const script of inlineScripts) {
      for (const { name, pattern, severity } of SECRET_PATTERNS) {
        const matches = [...script.matchAll(pattern)];
        if (matches.length > 0) {
          const match = matches[0][0];
          const masked =
            match.length > 12
              ? match.substring(0, 6) +
                "****" +
                match.substring(match.length - 4)
              : match.substring(0, 3) + "****";
          results.allSecrets.push({
            name,
            masked,
            severity,
            count: matches.length,
            url: `${targetUrl} (inline script)`,
          });
        }
      }
    }

    // Scan JS files
    const maxJs = deep ? 20 : 10;
    for (const jsUrl of jsUrls.slice(0, maxJs)) {
      const jsScan = await scanUrlForSecrets(jsUrl);
      results.urlsScanned.push(jsUrl);
      results.allSecrets.push(...jsScan.secrets);
    }

    // If deep scan — also check common config files
    if (deep) {
      const configFiles = [
        `${baseUrl}/config.js`,
        `${baseUrl}/app.js`,
        `${baseUrl}/main.js`,
        `${baseUrl}/bundle.js`,
        `${baseUrl}/vendor.js`,
        `${baseUrl}/env.js`,
        `${baseUrl}/.env`,
        `${baseUrl}/config.json`,
        `${baseUrl}/settings.js`,
        `${baseUrl}/constants.js`,
        `${baseUrl}/api.js`,
        `${baseUrl}/secrets.js`,
      ];
      for (const configUrl of configFiles) {
        try {
          const configRes = await axiosInstance.get(configUrl);
          if (configRes.status === 200) {
            const configScan = await scanUrlForSecrets(configUrl);
            results.urlsScanned.push(configUrl);
            results.allSecrets.push(...configScan.secrets);
          }
        } catch (e) {}
      }
    }

    // Remove duplicate secrets
    const seen = new Set();
    results.allSecrets = results.allSecrets.filter((s) => {
      const key = `${s.name}-${s.url}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Generate findings
    results.allSecrets.forEach((secret) => {
      results.findings.push({
        type: `Secret Exposed: ${secret.name}`,
        severity: secret.severity,
        owasp: "A02:2021 - Cryptographic Failures",
        url: secret.url,
        detail: `${secret.name} found in ${secret.url}. This credential may allow attackers to access your cloud services, payment systems, or APIs.`,
        evidence: `Pattern matched: ${secret.masked} (${secret.count} occurrence${secret.count > 1 ? "s" : ""})`,
        remediation: `Immediately rotate/revoke this ${secret.name}. Remove from frontend code. Use environment variables server-side only. Remove from git history.`,
      });
    });

    results.summary = {
      urlsScanned: results.urlsScanned.length,
      jsFilesScanned: jsUrls.length,
      secretsFound: results.allSecrets.length,
      critical: results.findings.filter((f) => f.severity === "Critical")
        .length,
      high: results.findings.filter((f) => f.severity === "High").length,
      medium: results.findings.filter((f) => f.severity === "Medium").length,
      low: results.findings.filter((f) => f.severity === "Low").length,
      total: results.findings.length,
    };

    const severity =
      results.summary.critical > 0
        ? "critical"
        : results.summary.high > 0
          ? "high"
          : results.summary.medium > 0
            ? "medium"
            : "info";

    scansDb
      .insert({
        type: "Secret Scan",
        userId: req.user?.id,
        target: targetUrl,
        result: results,
        findings_count: results.summary.secretsFound,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .catch((e) => console.error(e));

    res.json({ success: true, data: results });
  } catch (err) {
    console.error("Secret scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
