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
  let html = "";
  try {
    const res = await axiosInstance.get(targetUrl);
    html = typeof res.data === "string" ? res.data : "";
  } catch (e) {
    throw new Error("Could not reach target: " + e.message);
  }

  for (const pattern of S3_PATTERNS) {
    const matches = [...html.matchAll(pattern)];
    matches.forEach((m) => {
      if (m[1]) foundBuckets.add(m[1]);
    });
  }

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

// ── AWS S3 ────────────────────────────────────────────────────
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
          provider: "AWS S3",
          detail: isConfirmed
            ? `S3 bucket "${bucketName}" found in site source and is publicly listable. Anyone can see and download all files. ${files.length > 0 ? `Files: ${files.join(", ")}` : ""}`
            : `S3 bucket "${bucketName}" matches naming patterns. Publicly listable. Verify ownership. ${files.length > 0 ? `Files: ${files.join(", ")}` : ""}`,
          evidence: `GET ${bucketUrl} returned HTTP 200 with file listing`,
          remediation:
            "Enable S3 Block Public Access. Set bucket ACL to private. Audit all files.",
        });

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
              provider: "AWS S3",
              detail: `S3 bucket "${bucketName}" allows public write access. Attackers can upload malware or phishing pages.`,
              evidence: `PUT ${bucketUrl} returned HTTP 200`,
              remediation:
                "Remove public write permissions immediately. Use IAM roles only.",
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
          provider: "AWS S3",
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
          provider: "AWS S3",
          detail: `S3 bucket "${bucketName}" found in site source and is properly restricted (403).`,
          evidence: `GET ${bucketUrl} returned HTTP 403 — private`,
          remediation: "No action needed. Bucket is correctly configured.",
        });
      }
    }
  } catch (e) {}

  return findings;
}

// ── Azure Blob Storage ────────────────────────────────────────
async function checkAzureBlob(accountName) {
  const findings = [];
  const containerNames = [
    "public",
    "assets",
    "media",
    "uploads",
    "files",
    "images",
    "static",
    "backup",
    "data",
    "cdn",
  ];

  for (const container of containerNames) {
    try {
      const url = `https://${accountName}.blob.core.windows.net/${container}?restype=container&comp=list`;
      const res = await axiosInstance.get(url);
      const body =
        typeof res.data === "string" ? res.data : JSON.stringify(res.data);

      if (res.status === 200 && body.includes("EnumerationResults")) {
        findings.push({
          type: "Azure Blob Container Publicly Listable",
          severity: "Critical",
          owasp: "A01:2021 - Broken Access Control",
          endpoint: url,
          confirmed: false,
          provider: "Azure Blob Storage",
          detail: `Azure Blob Storage container "${container}" in account "${accountName}" is publicly listable. Anyone can see and download all files.`,
          evidence: `GET ${url} returned container listing`,
          remediation:
            "Set container access level to Private. Enable Azure Storage firewall.",
        });
      } else if (res.status === 200) {
        findings.push({
          type: "Azure Blob Container Publicly Accessible",
          severity: "High",
          owasp: "A01:2021 - Broken Access Control",
          endpoint: `https://${accountName}.blob.core.windows.net/${container}`,
          confirmed: false,
          provider: "Azure Blob Storage",
          detail: `Azure Blob container "${container}" in account "${accountName}" returned HTTP 200. Public access may be enabled.`,
          evidence: `GET ${url} returned HTTP 200`,
          remediation: "Review Azure Blob container permissions.",
        });
      }
    } catch (e) {}
  }
  return findings;
}

// ── Google Cloud Storage ──────────────────────────────────────
async function checkGCSBucket(bucketName) {
  const findings = [];
  const gcsUrls = [
    `https://storage.googleapis.com/${bucketName}/`,
    `https://${bucketName}.storage.googleapis.com/`,
  ];

  for (const url of gcsUrls) {
    try {
      const res = await axiosInstance.get(url);
      const body =
        typeof res.data === "string" ? res.data : JSON.stringify(res.data);

      if (res.status === 200) {
        const isListing =
          body.includes("ListBucketResult") ||
          body.includes('"items"') ||
          body.includes("storage#objects");

        if (isListing) {
          findings.push({
            type: "GCS Bucket Publicly Listable",
            severity: "Critical",
            owasp: "A01:2021 - Broken Access Control",
            endpoint: url,
            confirmed: false,
            provider: "Google Cloud Storage",
            detail: `Google Cloud Storage bucket "${bucketName}" is publicly listable. Anyone can see and download all files.`,
            evidence: `GET ${url} returned bucket listing`,
            remediation:
              "Remove allUsers from bucket IAM. Enable uniform bucket-level access.",
          });
        } else {
          findings.push({
            type: "GCS Bucket Publicly Accessible",
            severity: "High",
            owasp: "A01:2021 - Broken Access Control",
            endpoint: url,
            confirmed: false,
            provider: "Google Cloud Storage",
            detail: `GCS bucket "${bucketName}" returned HTTP 200. Public access may be enabled.`,
            evidence: `GET ${url} returned HTTP 200`,
            remediation: "Review GCS bucket IAM permissions.",
          });
        }
        break;
      }
    } catch (e) {}
  }
  return findings;
}

// ── DigitalOcean Spaces ───────────────────────────────────────
async function checkDOSpaces(spaceName) {
  const findings = [];
  const regions = ["nyc3", "ams3", "sgp1", "fra1", "sfo3", "blr1"];

  for (const region of regions.slice(0, 3)) {
    try {
      const url = `https://${spaceName}.${region}.digitaloceanspaces.com/`;
      const res = await axiosInstance.get(url);
      const body =
        typeof res.data === "string" ? res.data : JSON.stringify(res.data);

      if (
        res.status === 200 &&
        (body.includes("ListBucketResult") || body.includes("<Contents>"))
      ) {
        findings.push({
          type: "DigitalOcean Space Publicly Listable",
          severity: "Critical",
          owasp: "A01:2021 - Broken Access Control",
          endpoint: url,
          confirmed: false,
          provider: "DigitalOcean Spaces",
          detail: `DigitalOcean Space "${spaceName}" in ${region} is publicly listable.`,
          evidence: `GET ${url} returned Space listing`,
          remediation: "Set Space to private in DigitalOcean control panel.",
        });
        return findings;
      }
    } catch (e) {}
  }
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

  console.log("Cloud storage scan for:", domain);

  try {
    const results = {
      domain,
      targetUrl,
      confirmedBuckets: [],
      possibleBuckets: [],
      findings: [],
      jsFilesScanned: 0,
      cloudProviders: [
        "AWS S3",
        "Azure Blob Storage",
        "Google Cloud Storage",
        "DigitalOcean Spaces",
      ],
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

    // Step 3 — Generate possible bucket names
    const possibleNames = generatePossibleBuckets(domain);
    results.possibleBuckets = possibleNames.filter(
      (n) => !results.confirmedBuckets.includes(n),
    );

    // Step 4 — Test possible AWS S3 buckets
    console.log(
      `Testing ${Math.min(results.possibleBuckets.length, 10)} possible S3 buckets...`,
    );
    for (const bucketName of results.possibleBuckets.slice(0, 10)) {
      const bucketFindings = await testBucket(bucketName, false);
      results.findings.push(...bucketFindings);
    }

    // Step 5 — Check Azure Blob Storage
    console.log("Checking Azure Blob Storage...");
    for (const name of possibleNames.slice(0, 5)) {
      const azureFindings = await checkAzureBlob(name);
      results.findings.push(
        ...azureFindings.filter((f) => f.severity !== "Info"),
      );
    }

    // Step 6 — Check Google Cloud Storage
    console.log("Checking GCS buckets...");
    for (const name of possibleNames.slice(0, 5)) {
      const gcsFindings = await checkGCSBucket(name);
      results.findings.push(...gcsFindings);
    }

    // Step 7 — Check DigitalOcean Spaces
    console.log("Checking DigitalOcean Spaces...");
    for (const name of possibleNames.slice(0, 3)) {
      const doFindings = await checkDOSpaces(name);
      results.findings.push(...doFindings);
    }

    // Step 8 — Info finding if nothing confirmed
    if (results.confirmedBuckets.length === 0) {
      results.findings.push({
        type: "No Cloud Storage Buckets Found in Site Source",
        severity: "Info",
        detail: `No cloud storage URLs found in page source or ${results.jsFilesScanned} JS file(s) of ${targetUrl}. Checked AWS S3, Azure Blob, GCS and DigitalOcean Spaces naming patterns.`,
        evidence: `Scanned main page + ${results.jsFilesScanned} JS files across 4 cloud providers`,
        remediation:
          "No action needed. If you use cloud storage, verify buckets are properly secured.",
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
      cloudProviders: 4,
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
        type: "Cloud Storage Scan",
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
    console.error("Cloud storage scan error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
