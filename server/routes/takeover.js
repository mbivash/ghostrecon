const express = require("express");
const router = express.Router();
const dns = require("dns").promises;
const https = require("https");
const http = require("http");
const { scansDb } = require("../database");

// Known fingerprints for subdomain takeover
const FINGERPRINTS = [
  {
    service: "GitHub Pages",
    cname: ["github.io"],
    fingerprint: "There isn't a GitHub Pages site here",
    severity: "High",
  },
  {
    service: "Heroku",
    cname: ["herokudns.com", "herokuapp.com"],
    fingerprint: "No such app",
    severity: "High",
  },
  {
    service: "AWS S3",
    cname: ["s3.amazonaws.com", "s3-website"],
    fingerprint: "NoSuchBucket",
    severity: "Critical",
  },
  {
    service: "Netlify",
    cname: ["netlify.com", "netlify.app"],
    fingerprint: "Not Found - Request ID",
    severity: "High",
  },
  {
    service: "Vercel",
    cname: ["vercel.app", "now.sh"],
    fingerprint: "The deployment could not be found",
    severity: "High",
  },
  {
    service: "Shopify",
    cname: ["myshopify.com"],
    fingerprint: "Sorry, this shop is currently unavailable",
    severity: "Medium",
  },
  {
    service: "Fastly",
    cname: ["fastly.net"],
    fingerprint: "Fastly error: unknown domain",
    severity: "Medium",
  },
  {
    service: "Ghost",
    cname: ["ghost.io"],
    fingerprint: "The thing you were looking for is no longer here",
    severity: "Medium",
  },
  {
    service: "Tumblr",
    cname: ["tumblr.com"],
    fingerprint: "Whatever you were looking for doesn't live here",
    severity: "Medium",
  },
  {
    service: "WordPress",
    cname: ["wordpress.com"],
    fingerprint: "Do you want to register",
    severity: "Medium",
  },
  {
    service: "Zendesk",
    cname: ["zendesk.com"],
    fingerprint: "Help Center Closed",
    severity: "Medium",
  },
  {
    service: "Surge.sh",
    cname: ["surge.sh"],
    fingerprint: "project not found",
    severity: "High",
  },
];

// Common subdomains to check
const COMMON_SUBS = [
  "www",
  "mail",
  "ftp",
  "admin",
  "blog",
  "dev",
  "test",
  "api",
  "app",
  "portal",
  "vpn",
  "remote",
  "staging",
  "beta",
  "old",
  "shop",
  "store",
  "cdn",
  "media",
  "static",
  "assets",
  "dashboard",
  "help",
  "support",
  "docs",
  "status",
  "auth",
  "login",
  "secure",
  "payments",
  "checkout",
  "forum",
  "community",
  "wiki",
  "git",
  "jenkins",
  "jira",
  "confluence",
  "careers",
  "jobs",
  "news",
];

function fetchPage(url) {
  return new Promise((resolve) => {
    const proto = url.startsWith("https") ? https : http;
    const req = proto.get(
      url,
      {
        timeout: 8000,
        headers: { "User-Agent": "GhostRecon Security Scanner" },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => {
          if (data.length < 10000) data += chunk;
        });
        res.on("end", () =>
          resolve({ status: res.statusCode, body: data, headers: res.headers }),
        );
      },
    );
    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
  });
}

async function checkSubdomain(subdomain, domain) {
  const full = `${subdomain}.${domain}`;
  const result = {
    subdomain: full,
    exists: false,
    cname: null,
    ip: null,
    vulnerable: false,
    service: null,
    severity: null,
    fingerprint: null,
    status: "not found",
  };

  try {
    // Check if subdomain resolves
    try {
      const addresses = await dns.resolve4(full);
      result.exists = true;
      result.ip = addresses[0];
      result.status = "active";
    } catch (e) {
      // Try CNAME
      try {
        const cnames = await dns.resolveCname(full);
        result.exists = true;
        result.cname = cnames[0];
        result.status = "cname";
      } catch (e2) {
        return result;
      }
    }

    // Check CNAME for known services
    const cnameToCheck = result.cname || "";
    for (const fp of FINGERPRINTS) {
      const matchesCname = fp.cname.some((c) => cnameToCheck.includes(c));
      if (matchesCname) {
        // Fetch the page and check for fingerprint
        const page = await fetchPage(`http://${full}`);
        if (
          page &&
          page.body.toLowerCase().includes(fp.fingerprint.toLowerCase())
        ) {
          result.vulnerable = true;
          result.service = fp.service;
          result.severity = fp.severity;
          result.fingerprint = fp.fingerprint;
          result.status = "vulnerable";
        }
        break;
      }
    }

    return result;
  } catch (e) {
    return result;
  }
}

router.post("/scan", async (req, res) => {
  const { target, consent } = req.body;

  if (!consent) {
    return res.status(403).json({ error: "Authorization required." });
  }

  if (!target) {
    return res.status(400).json({ error: "Target domain is required." });
  }

  let domain = target
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .trim();

  console.log(`Scanning subdomains of ${domain} for takeover...`);

  try {
    const findings = [];
    const active = [];
    const notFound = [];

    // Check subdomains in batches to be fast
    const batchSize = 10;
    for (let i = 0; i < COMMON_SUBS.length; i += batchSize) {
      const batch = COMMON_SUBS.slice(i, i + batchSize);
      const results = await Promise.all(
        batch.map((sub) => checkSubdomain(sub, domain)),
      );

      results.forEach((r) => {
        if (r.vulnerable) findings.push(r);
        else if (r.exists) active.push(r);
        else notFound.push(r.subdomain);
      });
    }

    const summary = {
      domain,
      totalChecked: COMMON_SUBS.length,
      activeSubdomains: active.length + findings.length,
      vulnerableSubdomains: findings.length,
      findings,
      active,
      scannedAt: new Date().toISOString(),
    };

    // Save to database
    const severity = findings.some((f) => f.severity === "Critical")
      ? "critical"
      : findings.some((f) => f.severity === "High")
        ? "high"
        : findings.length > 0
          ? "medium"
          : "info";

    scansDb
      .insert({
        type: "Subdomain Takeover Scan",
        target: domain,
        result: summary,
        findings_count: findings.length,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .catch((e) => console.error(e));

    res.json({ success: true, data: summary });
  } catch (err) {
    console.error("Takeover scan error:", err);
    res.status(500).json({ error: "Scan failed: " + err.message });
  }
});

module.exports = router;
