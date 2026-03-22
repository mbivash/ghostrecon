const express = require("express");
const router = express.Router();
const dns = require("dns").promises;
const https = require("https");
const http = require("http");
const cheerio = require("cheerio");

// ── Whois lookup ─────────────────────────────────────
async function getWhois(domain) {
  return new Promise((resolve) => {
    const net = require("net");
    const client = net.createConnection(43, "whois.iana.org");
    let data = "";
    client.setTimeout(8000);
    client.on("connect", () => client.write(domain + "\r\n"));
    client.on("data", (chunk) => (data += chunk.toString()));
    client.on("end", () => resolve(data));
    client.on("error", () => resolve("Whois lookup failed"));
    client.on("timeout", () => {
      client.destroy();
      resolve("Whois timeout");
    });
  });
}

// ── DNS Records ──────────────────────────────────────
async function getDNSRecords(domain) {
  const records = {};
  const lookups = [
    { type: "A", fn: () => dns.resolve4(domain) },
    { type: "AAAA", fn: () => dns.resolve6(domain) },
    { type: "MX", fn: () => dns.resolveMx(domain) },
    { type: "TXT", fn: () => dns.resolveTxt(domain) },
    { type: "NS", fn: () => dns.resolveNs(domain) },
    { type: "CNAME", fn: () => dns.resolveCname(domain) },
  ];
  for (const lookup of lookups) {
    try {
      records[lookup.type] = await lookup.fn();
    } catch (e) {
      records[lookup.type] = [];
    }
  }
  return records;
}

// ── Subdomain finder ─────────────────────────────────
async function findSubdomains(domain) {
  const commonSubs = [
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
    "smtp",
    "pop",
    "imap",
    "webmail",
    "ns1",
    "ns2",
    "mx",
    "shop",
    "store",
    "cdn",
    "media",
    "static",
    "assets",
    "dashboard",
    "staging",
    "beta",
    "old",
    "new",
    "secure",
    "login",
    "auth",
    "docs",
  ];
  const found = [];
  await Promise.all(
    commonSubs.map(async (sub) => {
      try {
        const fullDomain = `${sub}.${domain}`;
        await dns.resolve4(fullDomain);
        found.push(fullDomain);
      } catch (e) {}
    }),
  );
  return found.sort();
}

// ── IP Geolocation ───────────────────────────────────
async function getGeoIP(ip) {
  return new Promise((resolve) => {
    const url = `http://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,org,as,query`;
    http
      .get(url, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            resolve({});
          }
        });
      })
      .on("error", () => resolve({}));
  });
}

// ── Technology detector ──────────────────────────────
async function detectTech(domain) {
  return new Promise((resolve) => {
    const options = {
      hostname: domain,
      path: "/",
      method: "GET",
      timeout: 10000,
      headers: { "User-Agent": "Mozilla/5.0 (compatible; GhostRecon)" },
    };
    const tech = [];
    const req = https.request(options, (res) => {
      const headers = res.headers;
      if (headers["x-powered-by"])
        tech.push({ name: headers["x-powered-by"], category: "Framework" });
      if (headers["server"])
        tech.push({ name: headers["server"], category: "Web Server" });
      if (headers["x-aspnet-version"])
        tech.push({
          name: "ASP.NET " + headers["x-aspnet-version"],
          category: "Framework",
        });
      if (headers["x-drupal-cache"])
        tech.push({ name: "Drupal", category: "CMS" });
      if (headers["x-wordpress-logged-in"])
        tech.push({ name: "WordPress", category: "CMS" });
      let body = "";
      res.on("data", (chunk) => {
        if (body.length < 50000) body += chunk.toString();
      });
      res.on("end", () => {
        if (body.includes("wp-content"))
          tech.push({ name: "WordPress", category: "CMS" });
        if (body.includes("Joomla"))
          tech.push({ name: "Joomla", category: "CMS" });
        if (body.includes("Drupal"))
          tech.push({ name: "Drupal", category: "CMS" });
        if (body.includes("React"))
          tech.push({ name: "React", category: "JavaScript" });
        if (body.includes("Vue"))
          tech.push({ name: "Vue.js", category: "JavaScript" });
        if (body.includes("Angular"))
          tech.push({ name: "Angular", category: "JavaScript" });
        if (body.includes("jQuery"))
          tech.push({ name: "jQuery", category: "JavaScript" });
        if (body.includes("Bootstrap"))
          tech.push({ name: "Bootstrap", category: "CSS Framework" });
        if (body.includes("Shopify"))
          tech.push({ name: "Shopify", category: "E-commerce" });
        if (body.includes("cloudflare"))
          tech.push({ name: "Cloudflare", category: "CDN" });
        if (body.includes("google-analytics") || body.includes("gtag"))
          tech.push({ name: "Google Analytics", category: "Analytics" });
        const unique = tech.filter(
          (t, i, arr) => arr.findIndex((x) => x.name === t.name) === i,
        );
        resolve(unique);
      });
    });
    req.on("error", () => resolve(tech));
    req.on("timeout", () => {
      req.destroy();
      resolve(tech);
    });
    req.end();
  });
}

// ── Email Harvester ───────────────────────────────────
async function harvestEmails(targetUrl, html, domain) {
  const emails = new Set();
  const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

  // Extract from HTML
  const htmlEmails = html.match(emailPattern) || [];
  htmlEmails.forEach((e) => {
    if (e.endsWith(`.${domain}`) || e.includes(`@${domain}`)) {
      emails.add(e.toLowerCase());
    }
  });

  // Check mailto links
  const $ = cheerio.load(html);
  $('a[href^="mailto:"]').each((i, el) => {
    const href = $(el).attr("href");
    if (href) {
      const email = href
        .replace("mailto:", "")
        .split("?")[0]
        .trim()
        .toLowerCase();
      if (email.includes("@")) emails.add(email);
    }
  });

  // Check meta tags
  $('meta[name="author"]').each((i, el) => {
    const content = $(el).attr("content") || "";
    const metaEmails = content.match(emailPattern) || [];
    metaEmails.forEach((e) => emails.add(e.toLowerCase()));
  });

  // Check schema.org markup
  $('[itemprop="email"]').each((i, el) => {
    const email = $(el).text().trim().toLowerCase();
    if (email.includes("@")) emails.add(email);
  });

  return [...emails].slice(0, 50);
}

// ── Main OSINT route ─────────────────────────────────
router.post("/scan", async (req, res) => {
  const { target, consent } = req.body;

  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target)
    return res.status(400).json({ error: "Target domain is required." });

  let domain = target
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/\/.*$/, "");

  console.log("OSINT scan on:", domain);

  try {
    const [dnsRecords, subdomains, techStack] = await Promise.all([
      getDNSRecords(domain),
      findSubdomains(domain),
      detectTech(domain),
    ]);

    let geoIP = {};
    const ipList = dnsRecords.A || [];
    if (ipList.length > 0) {
      geoIP = await getGeoIP(ipList[0]);
    }

    const whoisRaw = await getWhois(domain);
    const whoisParsed = {};
    const whoisLines = whoisRaw.split("\n");
    whoisLines.forEach((line) => {
      const match = line.match(/^([^:]+):\s*(.+)$/);
      if (match) {
        const key = match[1].trim().toLowerCase();
        const val = match[2].trim();
        if (key.includes("registrar") && !whoisParsed.registrar)
          whoisParsed.registrar = val;
        if (key.includes("creation") && !whoisParsed.created)
          whoisParsed.created = val;
        if (key.includes("expir") && !whoisParsed.expires)
          whoisParsed.expires = val;
        if (key.includes("updated") && !whoisParsed.updated)
          whoisParsed.updated = val;
        if (
          key.includes("registrant") &&
          key.includes("org") &&
          !whoisParsed.org
        )
          whoisParsed.org = val;
        if (key.includes("name server") && !whoisParsed.nameserver)
          whoisParsed.nameserver = val;
      }
    });

    // Fetch HTML for email harvesting
    let html = "";
    try {
      const axios = require("axios");
      const pageRes = await axios.get(`http://${domain}`, {
        timeout: 10000,
        validateStatus: () => true,
      });
      html = typeof pageRes.data === "string" ? pageRes.data : "";
    } catch (e) {}

    // Harvest emails
    const emails = await harvestEmails(`http://${domain}`, html, domain);

    const result = {
      target: domain,
      dns: dnsRecords,
      whois: whoisParsed,
      whoisRaw,
      subdomains,
      geoIP,
      techStack,
      ipList,
      emails,
      findings: [],
      scannedAt: new Date().toISOString(),
    };

    // Add email finding if emails found
    if (emails.length > 0) {
      result.findings.push({
        type: "Email Addresses Harvested",
        severity: "Info",
        detail: `Found ${emails.length} email address(es) associated with ${domain}: ${emails.join(", ")}`,
        evidence: "Emails found in page source, mailto links, and meta tags",
        remediation:
          "Use contact forms instead of displaying email addresses. Use email obfuscation if emails must be shown.",
      });
    }

    try {
      const { scansDb } = require("../database");
      scansDb
        .insert({
          type: "OSINT Scan",
          target: domain,
          result,
          findings_count: subdomains.length + techStack.length + emails.length,
          severity: "info",
          scanned_at: new Date().toISOString(),
        })
        .catch((e) => console.error(e));
    } catch (dbErr) {
      console.error("DB save error:", dbErr);
    }

    res.json({ success: true, data: result });
  } catch (err) {
    console.error("OSINT error:", err);
    res.status(500).json({ error: "OSINT scan failed: " + err.message });
  }
});

module.exports = router;
