const express = require("express");
const router = express.Router();
const https = require("https");
const http = require("http");
const { scansDb } = require("../database");

const axiosLike = (url, method = "GET") => {
  return new Promise((resolve) => {
    const proto = url.startsWith("https") ? https : http;
    const req = proto.request(
      url,
      {
        method,
        timeout: 10000,
        headers: { "User-Agent": "GhostRecon S3 Scanner" },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
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
    req.end();
  });
};

function generateBucketNames(domain) {
  const base = domain
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/\./g, "-")
    .toLowerCase();
  const company = base.split("-")[0];

  const names = new Set([
    base,
    company,
    `${company}-assets`,
    `${company}-static`,
    `${company}-media`,
    `${company}-uploads`,
    `${company}-files`,
    `${company}-backup`,
    `${company}-backups`,
    `${company}-data`,
    `${company}-dev`,
    `${company}-staging`,
    `${company}-prod`,
    `${company}-production`,
    `${company}-public`,
    `${company}-private`,
    `${company}-images`,
    `${company}-img`,
    `${company}-videos`,
    `${company}-docs`,
    `${company}-documents`,
    `${company}-logs`,
    `${company}-database`,
    `${company}-db`,
    `${company}-api`,
    `${company}-web`,
    `${company}-website`,
    `${company}-cdn`,
    `${company}-storage`,
    `${company}-bucket`,
    `${base}-assets`,
    `${base}-backup`,
    `${base}-media`,
    `${base}-static`,
    `${base}-uploads`,
  ]);

  return [...names].slice(0, 35);
}

async function checkS3Bucket(bucketName) {
  const result = {
    name: bucketName,
    exists: false,
    publicRead: false,
    publicWrite: false,
    publicList: false,
    websiteEnabled: false,
    findings: [],
  };

  const regions = ["s3", "s3.ap-south-1", "s3.us-east-1", "s3.eu-west-1"];

  for (const region of regions) {
    const bucketUrl =
      region === "s3"
        ? `https://${bucketName}.s3.amazonaws.com/`
        : `https://${bucketName}.${region}.amazonaws.com/`;

    try {
      const res = await axiosLike(bucketUrl, "GET");
      if (!res) continue;

      if (res.status === 404 && res.body.includes("NoSuchBucket")) continue;
      if (res.status === 403 || res.status === 200 || res.status === 400) {
        result.exists = true;

        if (res.status === 200) {
          const body = res.body;

          if (
            body.includes("<ListBucketResult") ||
            body.includes("<Contents>")
          ) {
            result.publicList = true;
            result.publicRead = true;

            const fileMatches = body.match(/<Key>([^<]+)<\/Key>/g) || [];
            const files = fileMatches
              .slice(0, 5)
              .map((m) => m.replace(/<\/?Key>/g, ""));

            result.findings.push({
              type: "S3 Bucket Publicly Listable",
              severity: "Critical",
              owasp: "A01:2021 - Broken Access Control",
              bucket: bucketName,
              url: bucketUrl,
              detail: `S3 bucket "${bucketName}" is publicly accessible and allows directory listing. Anyone can see all files stored in this bucket. ${files.length > 0 ? `Files found: ${files.join(", ")}` : ""}`,
              evidence: `GET ${bucketUrl} returned HTTP 200 with bucket listing`,
              remediation:
                "Immediately set bucket ACL to private. Remove any public access grants. Enable S3 Block Public Access settings. Review all files in the bucket for sensitive data.",
            });
          }
        }

        if (res.status === 403) {
          result.findings.push({
            type: "S3 Bucket Exists — Access Restricted",
            severity: "Low",
            owasp: "A05:2021 - Security Misconfiguration",
            bucket: bucketName,
            url: bucketUrl,
            detail: `S3 bucket "${bucketName}" exists but access is restricted. While not immediately exploitable, bucket existence confirms AWS infrastructure.`,
            evidence: `GET ${bucketUrl} returned HTTP 403 Forbidden`,
            remediation:
              "Verify bucket permissions are correctly configured. Ensure no unintended public access exists.",
          });
        }

        // Test write access
        const writeRes = await axiosLike(
          `${bucketUrl}ghostrecon-test-${Date.now()}.txt`,
          "PUT",
        );
        if (writeRes && writeRes.status === 200) {
          result.publicWrite = true;
          result.findings.push({
            type: "S3 Bucket Publicly Writable",
            severity: "Critical",
            owasp: "A01:2021 - Broken Access Control",
            bucket: bucketName,
            url: bucketUrl,
            detail: `S3 bucket "${bucketName}" allows public write access. Attackers can upload malicious files, deface your website, or use your bucket for phishing attacks.`,
            evidence: `PUT ${bucketUrl}test.txt returned HTTP 200`,
            remediation:
              "Immediately remove public write permissions. Set bucket policy to deny all public access. Review AWS IAM permissions.",
          });
        }

        // Check website hosting
        const websiteUrl = `http://${bucketName}.s3-website.ap-south-1.amazonaws.com/`;
        const websiteRes = await axiosLike(websiteUrl, "GET");
        if (
          websiteRes &&
          websiteRes.status === 200 &&
          !websiteRes.body.includes("NoSuchBucket")
        ) {
          result.websiteEnabled = true;
          result.findings.push({
            type: "S3 Static Website Hosting Enabled",
            severity: "Medium",
            owasp: "A05:2021 - Security Misconfiguration",
            bucket: bucketName,
            url: websiteUrl,
            detail: `S3 bucket "${bucketName}" has static website hosting enabled. All files in the bucket may be publicly accessible via the website endpoint.`,
            evidence: `GET ${websiteUrl} returned HTTP 200`,
            remediation:
              "Disable static website hosting if not needed. If needed, ensure only intended files are public.",
          });
        }

        break;
      }
    } catch (e) {}
  }

  return result;
}

async function checkSubdomainBuckets(domain) {
  const findings = [];
  const subdomains = [
    "assets",
    "static",
    "media",
    "uploads",
    "files",
    "cdn",
    "images",
    "backup",
  ];

  for (const sub of subdomains) {
    try {
      const testUrl = `http://${sub}.${domain}/`;
      const res = await axiosLike(testUrl, "GET");

      if (
        res &&
        res.status === 200 &&
        (res.headers["server"] || "").toLowerCase().includes("amazons3")
      ) {
        findings.push({
          type: "S3 Bucket Behind Subdomain",
          severity: "Medium",
          owasp: "A05:2021 - Security Misconfiguration",
          url: testUrl,
          detail: `Subdomain ${sub}.${domain} appears to be serving content from an S3 bucket. Verify the bucket is not publicly misconfigured.`,
          evidence: `${testUrl} served by AmazonS3`,
          remediation:
            "Verify the S3 bucket behind this subdomain is properly secured with private ACL and Block Public Access enabled.",
        });
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

  let domain = target
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .trim();

  console.log("S3 scan for:", domain);

  try {
    const results = {
      domain,
      bucketsChecked: 0,
      bucketsFound: [],
      vulnerableBuckets: [],
      findings: [],
      scannedAt: new Date().toISOString(),
    };

    const bucketNames = generateBucketNames(domain);
    results.bucketsChecked = bucketNames.length;

    console.log(`Checking ${bucketNames.length} bucket names...`);

    // Check buckets in batches
    const batchSize = 5;
    for (let i = 0; i < bucketNames.length; i += batchSize) {
      const batch = bucketNames.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map((name) => checkS3Bucket(name)),
      );

      batchResults.forEach((bucket) => {
        if (bucket.exists) {
          results.bucketsFound.push(bucket.name);
          if (bucket.publicList || bucket.publicWrite || bucket.publicRead) {
            results.vulnerableBuckets.push(bucket.name);
          }
          results.findings.push(...bucket.findings);
        }
      });
    }

    // Check subdomain-based buckets
    const subdomainFindings = await checkSubdomainBuckets(domain);
    results.findings.push(...subdomainFindings);

    if (results.bucketsFound.length === 0) {
      results.findings.push({
        type: "No S3 Buckets Found",
        severity: "Info",
        detail: `No publicly accessible S3 buckets found for common naming patterns of "${domain}". This is a good sign — either no S3 buckets are used or they are properly secured.`,
        evidence: `Checked ${bucketNames.length} common bucket name patterns`,
        remediation:
          "Continue monitoring for new S3 buckets. Use AWS Config rules to automatically detect public buckets.",
      });
    }

    results.summary = {
      bucketsChecked: bucketNames.length,
      bucketsFound: results.bucketsFound.length,
      vulnerableBuckets: results.vulnerableBuckets.length,
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
        type: "S3 Bucket Scan",
        userId: req.user?.id,
        target: domain,
        result: results,
        findings_count: results.vulnerableBuckets.length,
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
