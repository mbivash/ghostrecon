const express = require("express");
const router = express.Router();
const axios = require("axios");
const cheerio = require("cheerio");
const { scansDb } = require("../database");

const axiosInstance = axios.create({
  timeout: 15000,
  validateStatus: () => true,
  headers: {
    "User-Agent": "Mozilla/5.0 (compatible; GhostRecon S3 Scanner)",
    Accept: "text/html,application/json,*/*",
  },
});

const S3_PATTERNS = [
  /https?:\/\/([a-z0-9][a-z0-9\-]{2,62})\.s3\.amazonaws\.com/gi,
  /https?:\/\/s3\.amazonaws\.com\/([a-z0-9][a-z0-9\-]{2,62})/gi,
  /https?:\/\/([a-z0-9][a-z0-9\-]{2,62})\.s3\.[a-z0-9\-]+\.amazonaws\.com/gi,
  /https?:\/\/([a-z0-9][a-z0-9\-]{2,62})\.s3-website[a-z0-9\-\.]+\.amazonaws\.com/gi,
];

async function crawlForS3URLs(targetUrl, baseUrl) {
  const foundBuckets = new Set();

  // Fetch main page
  let html = "";
  try {
    const res = await axiosInstance.get(targetUrl);
    html = typeof res.data === "string" ? res.data : "";
  } catch (e) {
    throw new Error("Could not reach target: " + e.message);
  }

  // Extract S3 URLs from main page
  for (const pattern of S3_PATTERNS) {
    const matches = [...html.matchAll(pattern)];
    matches.forEach((m) => {
      if (m[1]) foundBuckets.add(m[1]);
    });
  }

  // Find and fetch JS files
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

  // Fetch JS files and extract S3 URLs
  for (const jsUrl of jsUrls.slice(0, 8)) {
    try {
      const res = await axiosInstance.get(jsUrl);
      const content = typeof res.data === "string" ? res.data : "";
      for (const pattern of S3_PATTERNS) {
        const matches = [...content.matchAll(pattern)];
        matches.forEach((m) => {
          if (m[1]) foundBuckets.add(m[1]);
        });
      }
    } catch (e) {}
  }

  // Also check page source comments and data attributes
  const inlinePatterns = [
    /["']([a-z0-9][a-z0-9\-]{2,62})\.s3\.amazonaws\.com["']/gi,
    /bucket['":\s]+['"]([a-z0-9][a-z0-9\-]{2,62})['"]/gi,
    /s3_bucket['":\s]+['"]([a-z0-9][a-z0-9\-]{2,62})['"]/gi,
    /AWS_BUCKET['":\s]+['"]([a-z0-9][a-z0-9\-]{2,62})['"]/gi,
  ];

  for (const pattern of inlinePatterns) {
    const matches = [...html.matchAll(pattern)];
    matches.forEach((m) => {
      if (m[1] && m[1].length > 3) foundBuckets.add(m[1]);
    });
  }

  return { foundBuckets: [...foundBuckets], html, jsCount: jsUrls.length };
}

function generatePossibleBuckets(domain) {
  const company = domain
    .split(".")[0]
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
  const names = new Set([
    `${company}`,
    `${company}-assets`,
    `${company}-static`,
    `${company}-media`,
    `${company}-uploads`,
    `${company}-files`,
    `${company}-images`,
    `${company}-cdn`,
    `${company}-backup`,
    `${company}-backups`,
    `${company}-data`,
    `${company}-dev`,
    `${company}-staging`,
    `${company}-prod`,
    `${company}-public`,
    `${company}-storage`,
  ]);
  return [...names];
}

async function testBucket(bucketName, isConfirmed) {
  const findings = [];
  const bucketUrl = `https://${bucketName}.s3.amazonaws.com/`;
  const label = isConfirmed ? "(Confirmed)" : "(Possible — verify ownership)";

  try {
    const res = await axiosInstance.get(bucketUrl);

    if (!res) return findings;

    if (res.status === 200) {
      const body =
        typeof res.data === "string" ? res.data : JSON.stringify(res.data);
      const isListing =
        body.includes("<ListBucketResult") || body.includes("<Contents>");

      if (isListing) {
        const fileMatches = body.match(/<Key>([^<]+)<\/Key>/g) || [];
        const files = fileMatches
          .slice(0, 5)
          .map((m) => m.replace(/<\/?Key>/g, ""));

        findings.push({
          type: `S3 Bucket Publicly Listable ${label}`,
          severity: isConfirmed ? "Critical" : "Medium",
          owasp: "A01:2021 - Broken Access Control",
          endpoint: bucketUrl,
          confirmed: isConfirmed,
          detail: isConfirmed
            ? `S3 bucket "${bucketName}" was found in the site source code and is publicly listable. Anyone can see and download all files. ${files.length > 0 ? `Files found: ${files.join(", ")}` : ""}`
            : `S3 bucket "${bucketName}" matches naming patterns for this domain and is publicly listable. Verify if this bucket belongs to your organization. ${files.length > 0 ? `Files found: ${files.join(", ")}` : ""}`,
          evidence: `GET ${bucketUrl} returned HTTP 200 with file listing${isConfirmed ? " — URL found in site source" : " — pattern-based detection"}`,
          remediation:
            "Enable S3 Block Public Access immediately. Set bucket ACL to private. Audit all files for sensitive data exposure.",
        });

        // Test write access
        try {
          const writeRes = await axiosInstance.request({
            method: "PUT",
            url: `${bucketUrl}ghostrecon-test-${Date.now()}.txt`,
            data: "GhostRecon security test",
            timeout: 8000,
            validateStatus: () => true,
          });
          if (writeRes && writeRes.status === 200) {
            findings.push({
              type: `S3 Bucket Publicly Writable ${label}`,
              severity: "Critical",
              owasp: "A01:2021 - Broken Access Control",
              endpoint: bucketUrl,
              confirmed: isConfirmed,
              detail: `S3 bucket "${bucketName}" allows public write access. Attackers can upload malware, ransomware or phishing pages.`,
              evidence: `PUT ${bucketUrl} returned HTTP 200`,
              remediation:
                "Remove public write permissions immediately. Use IAM roles for write access only.",
            });
          }
        } catch (e) {}
      } else {
        findings.push({
          type: `S3 Bucket Public Access ${label}`,
          severity: isConfirmed ? "High" : "Low",
          owasp: "A01:2021 - Broken Access Control",
          endpoint: bucketUrl,
          confirmed: isConfirmed,
          detail: `S3 bucket "${bucketName}" returned HTTP 200. ${isConfirmed ? "Confirmed to belong to this site." : "Ownership unconfirmed."} Public access may be misconfigured.`,
          evidence: `GET ${bucketUrl} returned HTTP 200`,
          remediation:
            "Review bucket permissions. Enable S3 Block Public Access.",
        });
      }
    } else if (res.status === 403) {
      if (isConfirmed) {
        findings.push({
          type: "S3 Bucket Confirmed — Properly Secured",
          severity: "Info",
          owasp: "A01:2021 - Broken Access Control",
          endpoint: bucketUrl,
          confirmed: true,
          detail: `S3 bucket "${bucketName}" was found in site source and is properly restricted (403). This is correct configuration.`,
          evidence: `GET ${bucketUrl} returned HTTP 403 — bucket exists but is private`,
          remediation:
            "No action needed. Bucket is correctly configured as private.",
        });
      }
    }
  } catch (e) {}

  return findings;
}

router.post("/scan", async (req, res) => {
  const { target, consent } = req.body;

  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target)
    return res.status(400).json({ error: "Target domain is required." });

  let targetUrl = target.trim();
  if (!targetUrl.startsWith("http")) targetUrl = "http://" + targetUrl;
  const domain = new URL(targetUrl).hostname;

  console.log("S3 scan for:", domain);

  try {
    const results = {
      domain,
      targetUrl,
      confirmedBuckets: [],
      possibleBuckets: [],
      findings: [],
      jsFilesScanned: 0,
      scannedAt: new Date().toISOString(),
    };

    // Step 1 — Crawl site for real S3 URLs
    console.log("Crawling site for S3 URLs...");
    let crawlResult;
    try {
      crawlResult = await crawlForS3URLs(targetUrl, `https://${domain}`);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }

    results.confirmedBuckets = crawlResult.foundBuckets;
    results.jsFilesScanned = crawlResult.jsCount;
    console.log(
      `Found ${crawlResult.foundBuckets.length} confirmed S3 buckets in source`,
    );

    // Step 2 — Test confirmed buckets
    for (const bucketName of results.confirmedBuckets) {
      console.log(`Testing confirmed bucket: ${bucketName}`);
      const bucketFindings = await testBucket(bucketName, true);
      results.findings.push(...bucketFindings);
    }

    // Step 3 — Generate and test possible buckets
    const possibleNames = generatePossibleBuckets(domain);
    results.possibleBuckets = possibleNames.filter(
      (n) => !results.confirmedBuckets.includes(n),
    );

    console.log(
      `Testing ${Math.min(results.possibleBuckets.length, 10)} possible buckets...`,
    );
    for (const bucketName of results.possibleBuckets.slice(0, 10)) {
      const bucketFindings = await testBucket(bucketName, false);
      results.findings.push(...bucketFindings);
    }

    // Step 4 — If nothing found at all
    if (results.confirmedBuckets.length === 0) {
      results.findings.push({
        type: "No S3 Buckets Found in Site Source",
        severity: "Info",
        detail: `No S3 bucket URLs were found in the page source or ${results.jsFilesScanned} JavaScript file(s) of ${targetUrl}. Either this site does not use AWS S3, or bucket URLs are loaded dynamically after page load.`,
        evidence: `Scanned main page + ${results.jsFilesScanned} JS files`,
        remediation:
          "No action needed. If you use S3, verify buckets have Block Public Access enabled in the AWS console.",
      });
    }

    // Remove duplicates
    const seen = new Set();
    results.findings = results.findings.filter((f) => {
      const key = `${f.type}-${f.endpoint}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    results.summary = {
      confirmedBuckets: results.confirmedBuckets.length,
      possibleBuckets: results.possibleBuckets.length,
      jsFilesScanned: results.jsFilesScanned,
      critical: results.findings.filter((f) => f.severity === "Critical")
        .length,
      high: results.findings.filter((f) => f.severity === "High").length,
      medium: results.findings.filter((f) => f.severity === "Medium").length,
      low: results.findings.filter((f) => f.severity === "Low").length,
      info: results.findings.filter((f) => f.severity === "Info").length,
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
        type: "S3 Bucket Scan",
        userId: req.user?.id,
        target: domain,
        result: results,
        findings_count: results.summary.critical + results.summary.high,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .catch((e) => console.error(e));

    res.json({ success: true, data: results });
  } catch (err) {
    console.error("S3 scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
