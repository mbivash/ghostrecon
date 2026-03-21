const express = require("express");
const router = express.Router();
const axios = require("axios");
const cheerio = require("cheerio");

// Security headers to check
const SECURITY_HEADERS = [
  {
    name: "x-frame-options",
    severity: "Medium",
    desc: "Missing X-Frame-Options — site can be embedded in iframes (Clickjacking risk)",
  },
  {
    name: "x-content-type-options",
    severity: "Low",
    desc: "Missing X-Content-Type-Options — browser may misinterpret file types",
  },
  {
    name: "content-security-policy",
    severity: "High",
    desc: "Missing Content-Security-Policy — XSS attacks are much easier",
  },
  {
    name: "strict-transport-security",
    severity: "High",
    desc: "Missing HSTS — site can be downgraded to HTTP (man-in-the-middle risk)",
  },
  {
    name: "referrer-policy",
    severity: "Low",
    desc: "Missing Referrer-Policy — sensitive URLs may leak to third parties",
  },
  {
    name: "permissions-policy",
    severity: "Low",
    desc: "Missing Permissions-Policy — browser features not restricted",
  },
];

// XSS test payloads
const XSS_PAYLOADS = [
  "<script>alert(1)</script>",
  '"><script>alert(1)</script>',
  "'><img src=x onerror=alert(1)>",
  "<svg onload=alert(1)>",
];

// SQLi test payloads
const SQLI_PAYLOADS = [
  "'",
  "' OR '1'='1",
  "' OR 1=1--",
  '" OR "1"="1',
  "1' ORDER BY 1--",
];

// SQL error patterns in response
const SQL_ERRORS = [
  "you have an error in your sql syntax",
  "warning: mysql",
  "unclosed quotation mark",
  "quoted string not properly terminated",
  "pg::syntaxerror",
  "sqlite3::",
  "ora-00933",
  "microsoft ole db provider for sql server",
];

router.post("/scan", async (req, res) => {
  const { target, consent } = req.body;

  if (!consent) {
    return res.status(403).json({ error: "Authorization required." });
  }

  if (!target) {
    return res.status(400).json({ error: "Target URL is required." });
  }

  // Make sure URL has http/https
  let url = target;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "http://" + url;
  }

  const vulnerabilities = [];
  const info = {};

  try {
    // ── 1. Fetch the page ──────────────────────────────
    console.log("Fetching:", url);
    let response;
    try {
      response = await axios.get(url, {
        timeout: 15000,
        maxRedirects: 5,
        validateStatus: () => true,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; GhostRecon Security Scanner)",
        },
      });
    } catch (fetchErr) {
      return res
        .status(400)
        .json({ error: `Could not reach target: ${fetchErr.message}` });
    }

    const html = response.data || "";
    const headers = response.headers || {};
    const $ = cheerio.load(html);

    info.statusCode = response.status;
    info.server = headers["server"] || "hidden";
    info.contentType = headers["content-type"] || "unknown";

    // ── 2. Check security headers ──────────────────────
    console.log("Checking security headers...");
    SECURITY_HEADERS.forEach((h) => {
      if (!headers[h.name]) {
        vulnerabilities.push({
          type: "Missing Security Header",
          severity: h.severity,
          detail: h.desc,
          evidence: `Header "${h.name}" not present in response`,
        });
      }
    });

    // ── 3. Check for forms and test XSS + SQLi ─────────
    const forms = [];
    $("form").each((i, form) => {
      const action = $(form).attr("action") || url;
      const method = $(form).attr("method") || "get";
      const inputs = [];
      $(form)
        .find("input, textarea")
        .each((j, input) => {
          const name = $(input).attr("name");
          const type = $(input).attr("type") || "text";
          if (name && type !== "submit" && type !== "hidden") {
            inputs.push({ name, type });
          }
        });
      if (inputs.length > 0) {
        forms.push({ action, method, inputs });
      }
    });

    info.formsFound = forms.length;
    console.log(`Found ${forms.length} forms`);

    // Test first 3 forms to keep it fast
    const formsToTest = forms.slice(0, 3);

    for (const form of formsToTest) {
      const formUrl = form.action.startsWith("http")
        ? form.action
        : new URL(form.action, url).href;

      // XSS test
      for (const payload of XSS_PAYLOADS.slice(0, 2)) {
        try {
          const formData = {};
          form.inputs.forEach((input) => {
            formData[input.name] = payload;
          });

          const testRes = await axios({
            method: form.method.toLowerCase() === "post" ? "post" : "get",
            url:
              form.method.toLowerCase() === "post"
                ? formUrl
                : formUrl + "?" + new URLSearchParams(formData),
            data: form.method.toLowerCase() === "post" ? formData : undefined,
            timeout: 8000,
            validateStatus: () => true,
            headers: {
              "User-Agent":
                "Mozilla/5.0 (compatible; GhostRecon Security Scanner)",
            },
          });

          const responseText =
            typeof testRes.data === "string"
              ? testRes.data
              : JSON.stringify(testRes.data);

          if (responseText.includes(payload)) {
            vulnerabilities.push({
              type: "Cross-Site Scripting (XSS)",
              severity: "High",
              detail: `Form at "${formUrl}" reflects XSS payload in response without sanitization`,
              evidence: `Payload: ${payload}`,
            });
            break;
          }
        } catch (e) {
          console.log("XSS test error:", e.message);
        }
      }

      // SQLi test
      for (const payload of SQLI_PAYLOADS.slice(0, 2)) {
        try {
          const formData = {};
          form.inputs.forEach((input) => {
            formData[input.name] = payload;
          });

          const testRes = await axios({
            method: form.method.toLowerCase() === "post" ? "post" : "get",
            url:
              form.method.toLowerCase() === "post"
                ? formUrl
                : formUrl + "?" + new URLSearchParams(formData),
            data: form.method.toLowerCase() === "post" ? formData : undefined,
            timeout: 8000,
            validateStatus: () => true,
            headers: {
              "User-Agent":
                "Mozilla/5.0 (compatible; GhostRecon Security Scanner)",
            },
          });

          const responseText = (
            typeof testRes.data === "string"
              ? testRes.data
              : JSON.stringify(testRes.data)
          ).toLowerCase();

          const sqlErrorFound = SQL_ERRORS.some((err) =>
            responseText.includes(err),
          );
          if (sqlErrorFound) {
            vulnerabilities.push({
              type: "SQL Injection",
              severity: "Critical",
              detail: `Form at "${formUrl}" returned SQL error when injected with payload`,
              evidence: `Payload: ${payload}`,
            });
            break;
          }
        } catch (e) {
          console.log("SQLi test error:", e.message);
        }
      }
    }

    // ── 4. Check for open redirect ─────────────────────
    const links = [];
    $("a[href]").each((i, a) => {
      const href = $(a).attr("href") || "";
      if (
        href.includes("redirect=") ||
        href.includes("url=") ||
        href.includes("next=") ||
        href.includes("return=")
      ) {
        links.push(href);
      }
    });

    if (links.length > 0) {
      vulnerabilities.push({
        type: "Potential Open Redirect",
        severity: "Medium",
        detail: "Found links with redirect parameters that could be abused",
        evidence: links.slice(0, 2).join(", "),
      });
    }

    // ── 5. Check if server version exposed ────────────
    if (headers["server"] && /[\d.]+/.test(headers["server"])) {
      vulnerabilities.push({
        type: "Server Version Exposed",
        severity: "Low",
        detail: `Server header reveals version info: "${headers["server"]}"`,
        evidence: `Server: ${headers["server"]}`,
      });
    }

    // ── 6. Check for mixed content ─────────────────────
    if (url.startsWith("https://")) {
      const mixedContent = html.match(/src="http:\/\//g) || [];
      if (mixedContent.length > 0) {
        vulnerabilities.push({
          type: "Mixed Content",
          severity: "Medium",
          detail: "Page loads resources over HTTP on an HTTPS page",
          evidence: `Found ${mixedContent.length} HTTP resource(s) on HTTPS page`,
        });
      }
    }

    console.log(
      `Scan complete. ${vulnerabilities.length} vulnerabilities found.`,
    );
    console.log(
      `Scan complete. ${vulnerabilities.length} vulnerabilities found.`,
    );
    // Save to database
    try {
      const db = require("../database");
      const severity = vulnerabilities.some((v) => v.severity === "Critical")
        ? "critical"
        : vulnerabilities.some((v) => v.severity === "High")
          ? "high"
          : vulnerabilities.some((v) => v.severity === "Medium")
            ? "medium"
            : vulnerabilities.length > 0
              ? "low"
              : "info";

      db.prepare(
        `
        INSERT INTO scans (type, target, result, findings_count, severity)
        VALUES (?, ?, ?, ?, ?)
      `,
      ).run(
        "Web Vuln Scan",
        url,
        JSON.stringify({
          target: url,
          info,
          vulnerabilities,
          summary: {
            critical: vulnerabilities.filter((v) => v.severity === "Critical")
              .length,
            high: vulnerabilities.filter((v) => v.severity === "High").length,
            medium: vulnerabilities.filter((v) => v.severity === "Medium")
              .length,
            low: vulnerabilities.filter((v) => v.severity === "Low").length,
            total: vulnerabilities.length,
          },
          scannedAt: new Date().toISOString(),
        }),
        vulnerabilities.length,
        severity,
      );
      console.log("Web vuln scan saved to database");
    } catch (dbErr) {
      console.error("DB save error:", dbErr);
    }

    res.json({
      success: true,
      data: {
        target: url,
        info,
        vulnerabilities,
        summary: {
          critical: vulnerabilities.filter((v) => v.severity === "Critical")
            .length,
          high: vulnerabilities.filter((v) => v.severity === "High").length,
          medium: vulnerabilities.filter((v) => v.severity === "Medium").length,
          low: vulnerabilities.filter((v) => v.severity === "Low").length,
          total: vulnerabilities.length,
        },
        scannedAt: new Date().toISOString(),
      },
    });
  } catch (err) {
    console.error("Scan error:", err);
    res.status(500).json({ error: "Scan failed: " + err.message });
  }
});

module.exports = router;
