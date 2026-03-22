const express = require("express");
const router = express.Router();
const dns = require("dns").promises;
const https = require("https");
const http = require("http");
const { scansDb } = require("../database");

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
  {
    service: "Azure",
    cname: ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
    fingerprint: "was not found",
    severity: "High",
  },
  {
    service: "Cargo",
    cname: ["cargocollective.com"],
    fingerprint: "404 Not Found",
    severity: "Medium",
  },
  {
    service: "Feedpress",
    cname: ["feedpress.me"],
    fingerprint: "The feed has not been found",
    severity: "Low",
  },
];

const INTERESTING_SUBDOMAINS = [
  "admin",
  "administrator",
  "api",
  "app",
  "auth",
  "beta",
  "blog",
  "cms",
  "cpanel",
  "dashboard",
  "db",
  "dev",
  "devops",
  "docker",
  "git",
  "grafana",
  "internal",
  "intranet",
  "jenkins",
  "jira",
  "kibana",
  "k8s",
  "kubernetes",
  "ldap",
  "login",
  "manage",
  "management",
  "monitor",
  "mx",
  "mysql",
  "old",
  "panel",
  "phpmyadmin",
  "portal",
  "prod",
  "prometheus",
  "remote",
  "secure",
  "server",
  "sftp",
  "smtp",
  "splunk",
  "sql",
  "ssh",
  "stage",
  "staging",
  "test",
  "testing",
  "vault",
  "vpn",
  "webmail",
  "wiki",
  "www2",
  "zabbix",
];

// ── Query crt.sh ──────────────────────────────────────────────
async function queryCrtSh(domain) {
  return new Promise((resolve) => {
    const url = `https://crt.sh/?q=%.${domain}&output=json`;
    const req = https.get(
      url,
      {
        timeout: 15000,
        headers: {
          "User-Agent": "GhostRecon Security Scanner",
          Accept: "application/json",
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            const certs = JSON.parse(data);
            const subdomains = new Set();

            certs.forEach((cert) => {
              const names = cert.name_value || "";
              names.split("\n").forEach((name) => {
                name = name.trim().toLowerCase();
                if (name.endsWith(`.${domain}`) || name === domain) {
                  // Remove wildcard prefix
                  if (name.startsWith("*.")) {
                    name = name.substring(2);
                  }
                  if (name.length > 0 && !name.includes(" ")) {
                    subdomains.add(name);
                  }
                }
              });
            });

            resolve([...subdomains]);
          } catch (e) {
            resolve([]);
          }
        });
      },
    );
    req.on("error", () => resolve([]));
    req.on("timeout", () => {
      req.destroy();
      resolve([]);
    });
  });
}

// ── Fetch Page for Takeover Check ────────────────────────────
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
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      },
    );
    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
  });
}

// ── Resolve Subdomain ─────────────────────────────────────────
async function resolveSubdomain(subdomain) {
  const result = {
    subdomain,
    alive: false,
    ip: null,
    cname: null,
    vulnerable: false,
    service: null,
    severity: null,
    interesting: false,
    interestingReason: null,
  };

  try {
    const ips = await dns.resolve4(subdomain);
    result.alive = true;
    result.ip = ips[0];
  } catch (e) {
    try {
      const cnames = await dns.resolveCname(subdomain);
      result.alive = true;
      result.cname = cnames[0];
    } catch (e2) {
      return result;
    }
  }

  // Check if interesting subdomain
  const sub = subdomain.split(".")[0].toLowerCase();
  if (INTERESTING_SUBDOMAINS.includes(sub)) {
    result.interesting = true;
    result.interestingReason = `Sensitive subdomain "${sub}" — may expose internal services`;
  }

  // Check for takeover if has CNAME
  if (result.cname) {
    for (const fp of FINGERPRINTS) {
      if (fp.cname.some((c) => result.cname.includes(c))) {
        try {
          const page = await fetchPage(`http://${subdomain}`);
          if (
            page &&
            page.body.toLowerCase().includes(fp.fingerprint.toLowerCase())
          ) {
            result.vulnerable = true;
            result.service = fp.service;
            result.severity = fp.severity;
          }
        } catch (e) {}
        break;
      }
    }
  }

  return result;
}

router.post("/scan", async (req, res) => {
  const { target, consent } = req.body;

  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target)
    return res.status(400).json({ error: "Target domain is required." });

  let domain = target
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .trim();

  console.log(`Advanced subdomain enumeration for ${domain}...`);

  try {
    const results = {
      domain,
      totalFound: 0,
      aliveSubdomains: [],
      deadSubdomains: [],
      vulnerableSubdomains: [],
      interestingSubdomains: [],
      findings: [],
      sources: {
        crtsh: 0,
        bruteforce: 0,
      },
      scannedAt: new Date().toISOString(),
    };

    // Step 1 — Query crt.sh
    console.log("Querying crt.sh...");
    const crtSubdomains = await queryCrtSh(domain);
    results.sources.crtsh = crtSubdomains.length;
    console.log(`crt.sh found ${crtSubdomains.length} subdomains`);

    // Step 2 — Common subdomain brute force
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
      "mx",
      "smtp",
      "pop",
      "imap",
      "webmail",
      "cpanel",
      "whm",
      "ns1",
      "ns2",
      "ns3",
      "autodiscover",
      "autoconfig",
    ];

    const bruteSubdomains = COMMON_SUBS.map((s) => `${s}.${domain}`);

    // Combine all subdomains — crt.sh + brute force, remove duplicates
    const allSubdomains = [...new Set([...crtSubdomains, ...bruteSubdomains])];
    results.totalFound = allSubdomains.length;
    results.sources.bruteforce = bruteSubdomains.length;

    console.log(`Total unique subdomains to check: ${allSubdomains.length}`);

    // Step 3 — Resolve all subdomains in batches
    const batchSize = 15;
    for (let i = 0; i < Math.min(allSubdomains.length, 200); i += batchSize) {
      const batch = allSubdomains.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map((s) => resolveSubdomain(s)),
      );

      batchResults.forEach((r) => {
        if (r.alive) {
          results.aliveSubdomains.push(r);
          if (r.vulnerable) results.vulnerableSubdomains.push(r);
          if (r.interesting) results.interestingSubdomains.push(r);
        } else {
          results.deadSubdomains.push(r.subdomain);
        }
      });
    }

    // Step 4 — Generate findings

    // Vulnerable subdomains
    results.vulnerableSubdomains.forEach((sub) => {
      const sevColor =
        sub.severity === "Critical"
          ? "Critical"
          : sub.severity === "High"
            ? "High"
            : "Medium";
      results.findings.push({
        type: `Subdomain Takeover — ${sub.service}`,
        severity: sevColor,
        owasp: "A01:2021 - Broken Access Control",
        subdomain: sub.subdomain,
        detail: `${sub.subdomain} points to an unclaimed ${sub.service} service. An attacker can register this service and take control of the subdomain, serving malicious content to your users.`,
        evidence: `CNAME: ${sub.cname} → unclaimed ${sub.service}`,
        remediation: `Immediately remove or update the DNS record for ${sub.subdomain}. If you need this subdomain, reclaim the ${sub.service} resource.`,
      });
    });

    // Interesting subdomains
    results.interestingSubdomains.forEach((sub) => {
      results.findings.push({
        type: "Sensitive Subdomain Exposed",
        severity: "Medium",
        owasp: "A05:2021 - Security Misconfiguration",
        subdomain: sub.subdomain,
        detail: `${sub.interestingReason}. IP: ${sub.ip || sub.cname}. These subdomains often expose admin panels, internal tools, development environments or sensitive infrastructure.`,
        evidence: `${sub.subdomain} resolves to ${sub.ip || sub.cname}`,
        remediation: `Review what is running on ${sub.subdomain}. Ensure it requires authentication. Consider restricting access by IP or VPN.`,
      });
    });

    // Large attack surface
    if (results.aliveSubdomains.length > 20) {
      results.findings.push({
        type: "Large Attack Surface",
        severity: "Low",
        owasp: "A05:2021 - Security Misconfiguration",
        detail: `${results.aliveSubdomains.length} active subdomains found. A large number of subdomains increases the attack surface. Forgotten or unmaintained subdomains are common entry points.`,
        evidence: `${results.aliveSubdomains.length} alive subdomains out of ${allSubdomains.length} checked`,
        remediation:
          "Audit all subdomains regularly. Remove unused subdomains. Implement subdomain monitoring.",
      });
    }

    // crt.sh specific findings
    if (results.sources.crtsh > 50) {
      results.findings.push({
        type: "High Subdomain Count via Certificate Transparency",
        severity: "Info",
        owasp: "A05:2021 - Security Misconfiguration",
        detail: `${results.sources.crtsh} subdomains found in certificate transparency logs. These logs are public and give attackers a complete map of your infrastructure.`,
        evidence: `crt.sh returned ${results.sources.crtsh} unique subdomains`,
        remediation:
          "Review all subdomains. Use wildcard certificates where possible to reduce subdomain enumeration via CT logs.",
      });
    }

    results.summary = {
      totalChecked: allSubdomains.length,
      aliveSubdomains: results.aliveSubdomains.length,
      deadSubdomains: results.deadSubdomains.length,
      vulnerableSubdomains: results.vulnerableSubdomains.length,
      interestingSubdomains: results.interestingSubdomains.length,
      crtshSubdomains: results.sources.crtsh,
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
        type: "Subdomain Takeover Scan",
        userId: req.user?.id,
        target: domain,
        result: results,
        findings_count: results.findings.length,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .catch((e) => console.error(e));

    res.json({ success: true, data: results });
  } catch (err) {
    console.error("Subdomain scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
