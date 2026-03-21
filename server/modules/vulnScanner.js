const axios = require("axios");
const cheerio = require("cheerio");
const url = require("url");

const XSS_PAYLOADS = [
  "<script>alert(1)</script>",
  '"><script>alert(1)</script>',
  "'><script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  '"><img src=x onerror=alert(1)>',
  "<svg onload=alert(1)>",
  "javascript:alert(1)",
  '"><svg onload=alert(1)>',
  "<body onload=alert(1)>",
  "{{7*7}}",
  "${7*7}",
  "<script>document.write(7*7)</script>",
];

const SQLI_PAYLOADS = [
  "'",
  "''",
  "` ",
  "' OR '1'='1",
  "' OR '1'='1'--",
  "' OR 1=1--",
  '" OR "1"="1',
  "1' ORDER BY 1--",
  "1' ORDER BY 2--",
  "1' ORDER BY 3--",
  "1 UNION SELECT null--",
  "' UNION SELECT null,null--",
  "' AND SLEEP(3)--",
  "1; DROP TABLE users--",
  "' OR SLEEP(3)--",
];

const SQL_ERRORS = [
  "you have an error in your sql syntax",
  "warning: mysql",
  "unclosed quotation mark",
  "quoted string not properly terminated",
  "pg::syntaxerror",
  "sqlite3::",
  "ora-00933",
  "microsoft ole db provider for sql server",
  "odbc sql server driver",
  "mysql_fetch",
  "num_rows",
  "mysql error",
  "supplied argument is not a valid mysql",
  "on mysql result",
  "mysqlclient",
];

const axiosInstance = axios.create({
  timeout: 10000,
  validateStatus: () => true,
  headers: {
    "User-Agent": "Mozilla/5.0 (compatible; GhostRecon Security Scanner)",
    Accept: "text/html,application/xhtml+xml,*/*",
  },
  maxRedirects: 3,
});

// Crawl a page and extract all links and forms
async function crawlPage(targetUrl, baseUrl, visited = new Set()) {
  if (visited.has(targetUrl) || visited.size > 20)
    return { links: [], forms: [] };
  visited.add(targetUrl);

  try {
    const response = await axiosInstance.get(targetUrl);
    const $ = cheerio.load(response.data);
    const links = [];
    const forms = [];

    // Extract links on same domain
    $("a[href]").each((i, el) => {
      const href = $(el).attr("href");
      if (!href) return;
      try {
        const absolute = new URL(href, baseUrl).href;
        if (absolute.startsWith(baseUrl) && !visited.has(absolute)) {
          links.push(absolute);
        }
      } catch (e) {}
    });

    // Extract forms
    $("form").each((i, form) => {
      const action = $(form).attr("action") || targetUrl;
      const method = ($(form).attr("method") || "get").toLowerCase();
      const inputs = [];

      $(form)
        .find("input, textarea, select")
        .each((j, input) => {
          const name = $(input).attr("name");
          const type = $(input).attr("type") || "text";
          const value = $(input).attr("value") || "test";
          if (
            name &&
            type !== "submit" &&
            type !== "hidden" &&
            type !== "file"
          ) {
            inputs.push({ name, type, value });
          }
        });

      if (inputs.length > 0) {
        try {
          forms.push({
            action: new URL(action, baseUrl).href,
            method,
            inputs,
            pageUrl: targetUrl,
          });
        } catch (e) {}
      }
    });

    // Extract URL parameters from current page
    const parsedUrl = new URL(targetUrl);
    if (parsedUrl.search) {
      const params = [];
      parsedUrl.searchParams.forEach((value, name) => {
        params.push({ name, value });
      });
      if (params.length > 0) {
        forms.push({
          action: targetUrl,
          method: "get",
          inputs: params,
          pageUrl: targetUrl,
          isUrlParam: true,
        });
      }
    }

    return { links, forms };
  } catch (e) {
    return { links: [], forms: [] };
  }
}

// Test a form/endpoint for XSS
async function testXSS(form, baseUrl) {
  const findings = [];

  for (const payload of XSS_PAYLOADS.slice(0, 6)) {
    try {
      const formData = {};
      form.inputs.forEach((input) => {
        formData[input.name] = payload;
      });

      let response;
      if (form.method === "post") {
        response = await axiosInstance.post(form.action, formData);
      } else {
        const testUrl = new URL(form.action);
        form.inputs.forEach((input) =>
          testUrl.searchParams.set(input.name, payload),
        );
        response = await axiosInstance.get(testUrl.href);
      }

      const body =
        typeof response.data === "string"
          ? response.data
          : JSON.stringify(response.data);

      // Check if payload is reflected unencoded
      if (
        body.includes(payload) &&
        !body.includes("&lt;") &&
        !body.includes("&#")
      ) {
        findings.push({
          type: "Cross-Site Scripting (XSS)",
          severity: "High",
          owasp: "A03:2021 - Injection",
          parameter: form.inputs.map((i) => i.name).join(", "),
          endpoint: form.action,
          method: form.method.toUpperCase(),
          payload,
          detail: `XSS payload reflected unencoded in response. An attacker can steal cookies, hijack sessions, or redirect users to malicious sites.`,
          evidence: `Payload "${payload}" found in response body without encoding`,
          remediation:
            "Encode all user input before outputting to HTML. Use Content-Security-Policy header. Use a framework that auto-escapes output.",
        });
        break;
      }
    } catch (e) {}
  }

  return findings;
}

// Test a form/endpoint for SQL injection
async function testSQLi(form, baseUrl) {
  const findings = [];

  for (const payload of SQLI_PAYLOADS.slice(0, 8)) {
    try {
      const formData = {};
      form.inputs.forEach((input) => {
        formData[input.name] = payload;
      });

      let response;
      if (form.method === "post") {
        response = await axiosInstance.post(form.action, formData);
      } else {
        const testUrl = new URL(form.action);
        form.inputs.forEach((input) =>
          testUrl.searchParams.set(input.name, payload),
        );
        response = await axiosInstance.get(testUrl.href);
      }

      const body = (
        typeof response.data === "string"
          ? response.data
          : JSON.stringify(response.data)
      ).toLowerCase();

      const sqlErrorFound = SQL_ERRORS.some((err) => body.includes(err));
      if (sqlErrorFound) {
        const matchedError = SQL_ERRORS.find((err) => body.includes(err));
        findings.push({
          type: "SQL Injection",
          severity: "Critical",
          owasp: "A03:2021 - Injection",
          parameter: form.inputs.map((i) => i.name).join(", "),
          endpoint: form.action,
          method: form.method.toUpperCase(),
          payload,
          detail: `SQL injection vulnerability detected. An attacker can read, modify or delete your entire database, bypass authentication, and potentially take over the server.`,
          evidence: `SQL error "${matchedError}" triggered by payload "${payload}"`,
          remediation:
            "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries. Use an ORM. Implement input validation.",
        });
        break;
      }
    } catch (e) {}
  }

  return findings;
}

// Check security headers
function checkSecurityHeaders(headers, targetUrl) {
  const findings = [];

  const checks = [
    {
      header: "content-security-policy",
      severity: "High",
      owasp: "A05:2021 - Security Misconfiguration",
      detail:
        "Missing Content-Security-Policy header makes XSS attacks much easier to exploit.",
      remediation:
        "Add: Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    {
      header: "strict-transport-security",
      severity: "High",
      owasp: "A02:2021 - Cryptographic Failures",
      detail:
        "Missing HSTS allows attackers to downgrade HTTPS connections to HTTP (man-in-the-middle attack).",
      remediation:
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
      header: "x-frame-options",
      severity: "Medium",
      owasp: "A05:2021 - Security Misconfiguration",
      detail:
        "Missing X-Frame-Options allows clickjacking attacks — attacker can embed your site in an iframe.",
      remediation: "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    {
      header: "x-content-type-options",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      detail:
        "Missing X-Content-Type-Options allows MIME type sniffing attacks.",
      remediation: "Add: X-Content-Type-Options: nosniff",
    },
    {
      header: "referrer-policy",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      detail:
        "Missing Referrer-Policy may leak sensitive URLs to third parties.",
      remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
      header: "permissions-policy",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      detail:
        "Missing Permissions-Policy allows unrestricted access to browser features.",
      remediation:
        "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
  ];

  checks.forEach((check) => {
    if (!headers[check.header]) {
      findings.push({
        type: `Missing Security Header: ${check.header}`,
        severity: check.severity,
        owasp: check.owasp,
        detail: check.detail,
        evidence: `Header "${check.header}" not present in HTTP response`,
        remediation: check.remediation,
      });
    }
  });

  // Check server version exposure
  if (headers["server"] && /[\d.]+/.test(headers["server"])) {
    findings.push({
      type: "Server Version Disclosed",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      detail: `Server header reveals version: "${headers["server"]}". Attackers use this to find known exploits.`,
      evidence: `Server: ${headers["server"]}`,
      remediation:
        "Configure your web server to hide the Server header or remove version information.",
    });
  }

  // Check X-Powered-By
  if (headers["x-powered-by"]) {
    findings.push({
      type: "Technology Stack Disclosed",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      detail: `X-Powered-By header reveals technology: "${headers["x-powered-by"]}". Attackers use this to target known vulnerabilities.`,
      evidence: `X-Powered-By: ${headers["x-powered-by"]}`,
      remediation:
        "Remove the X-Powered-By header from your server configuration.",
    });
  }

  return findings;
}

// Check cookie security
function checkCookies(headers) {
  const findings = [];
  const setCookie = headers["set-cookie"];
  if (!setCookie) return findings;

  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];

  cookies.forEach((cookie) => {
    const cookieName = cookie.split("=")[0].trim();

    if (!cookie.toLowerCase().includes("httponly")) {
      findings.push({
        type: "Cookie Missing HttpOnly Flag",
        severity: "Medium",
        owasp: "A02:2021 - Cryptographic Failures",
        detail: `Cookie "${cookieName}" is missing the HttpOnly flag. JavaScript can access this cookie, enabling XSS cookie theft.`,
        evidence: `Set-Cookie: ${cookie.substring(0, 80)}...`,
        remediation: `Add HttpOnly flag: Set-Cookie: ${cookieName}=value; HttpOnly; Secure; SameSite=Strict`,
      });
    }

    if (!cookie.toLowerCase().includes("secure")) {
      findings.push({
        type: "Cookie Missing Secure Flag",
        severity: "Medium",
        owasp: "A02:2021 - Cryptographic Failures",
        detail: `Cookie "${cookieName}" is missing the Secure flag. Cookie can be transmitted over HTTP (unencrypted).`,
        evidence: `Set-Cookie: ${cookie.substring(0, 80)}...`,
        remediation: `Add Secure flag: Set-Cookie: ${cookieName}=value; HttpOnly; Secure; SameSite=Strict`,
      });
    }

    if (!cookie.toLowerCase().includes("samesite")) {
      findings.push({
        type: "Cookie Missing SameSite Flag",
        severity: "Low",
        owasp: "A01:2021 - Broken Access Control",
        detail: `Cookie "${cookieName}" is missing SameSite attribute. May be vulnerable to CSRF attacks.`,
        evidence: `Set-Cookie: ${cookie.substring(0, 80)}...`,
        remediation: `Add SameSite: Set-Cookie: ${cookieName}=value; HttpOnly; Secure; SameSite=Strict`,
      });
    }
  });

  return findings;
}

// Check for open redirect
async function checkOpenRedirect(targetUrl) {
  const findings = [];
  const parsed = new URL(targetUrl);

  const redirectParams = [
    "redirect",
    "url",
    "next",
    "return",
    "returnUrl",
    "goto",
    "dest",
    "destination",
  ];
  const testPayload = "https://evil.com";

  for (const param of redirectParams) {
    try {
      const testUrl = new URL(targetUrl);
      testUrl.searchParams.set(param, testPayload);
      const response = await axiosInstance.get(testUrl.href, {
        maxRedirects: 0,
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers["location"] || "";
        if (location.includes("evil.com")) {
          findings.push({
            type: "Open Redirect",
            severity: "Medium",
            owasp: "A01:2021 - Broken Access Control",
            detail: `Open redirect via "${param}" parameter. Attackers can redirect users to phishing sites.`,
            evidence: `GET ${testUrl.href} → Location: ${location}`,
            remediation:
              "Validate redirect URLs against a whitelist of allowed domains. Never redirect to user-supplied URLs directly.",
          });
          break;
        }
      }
    } catch (e) {}
  }

  return findings;
}

// Check for sensitive files
async function checkSensitiveFiles(baseUrl) {
  const findings = [];
  const sensitiveFiles = [
    { path: "/.git/config", name: "Git repository exposed" },
    { path: "/.env", name: "Environment file exposed" },
    { path: "/wp-config.php", name: "WordPress config exposed" },
    { path: "/config.php", name: "PHP config exposed" },
    { path: "/phpinfo.php", name: "PHP info page exposed" },
    { path: "/admin", name: "Admin panel exposed" },
    { path: "/administrator", name: "Admin panel exposed" },
    { path: "/.htaccess", name: "Apache config exposed" },
    { path: "/backup.zip", name: "Backup file exposed" },
    { path: "/database.sql", name: "Database dump exposed" },
    { path: "/robots.txt", name: "Robots.txt found" },
    { path: "/sitemap.xml", name: "Sitemap found" },
  ];

  for (const file of sensitiveFiles) {
    try {
      const testUrl = new URL(file.path, baseUrl).href;
      const response = await axiosInstance.get(testUrl);

      if (response.status === 200) {
        const isCritical = [
          ".git",
          ".env",
          "wp-config",
          "config.php",
          "phpinfo",
          "backup",
          "database",
        ].some((k) => file.path.includes(k));
        findings.push({
          type: file.name,
          severity: isCritical ? "Critical" : "Low",
          owasp: "A05:2021 - Security Misconfiguration",
          detail: `${file.name} at ${testUrl} is publicly accessible. This could expose sensitive configuration data, credentials, or source code.`,
          evidence: `GET ${testUrl} returned HTTP ${response.status}`,
          remediation: `Restrict access to ${file.path} via server configuration. Move sensitive files outside the web root.`,
        });
      }
    } catch (e) {}
  }

  return findings;
}

// Main scanner function
async function deepScan(targetUrl, options = {}) {
  const results = {
    target: targetUrl,
    findings: [],
    pagesScanned: 0,
    formsFound: 0,
    startTime: new Date().toISOString(),
  };

  try {
    // Clean URL
    if (!targetUrl.startsWith("http")) targetUrl = "http://" + targetUrl;
    const baseUrl = new URL(targetUrl).origin;

    // 1. Fetch main page
    console.log("Fetching main page:", targetUrl);
    let mainResponse;
    try {
      mainResponse = await axiosInstance.get(targetUrl);
    } catch (e) {
      throw new Error(`Could not reach target: ${e.message}`);
    }

    results.pagesScanned++;
    const headers = mainResponse.headers;

    // 2. Check security headers
    console.log("Checking security headers...");
    const headerFindings = checkSecurityHeaders(headers, targetUrl);
    results.findings.push(...headerFindings);

    // 3. Check cookies
    console.log("Checking cookie security...");
    const cookieFindings = checkCookies(headers);
    results.findings.push(...cookieFindings);

    // 4. Check sensitive files
    console.log("Checking sensitive files...");
    const fileFindings = await checkSensitiveFiles(baseUrl);
    results.findings.push(...fileFindings);

    // 5. Check open redirect
    console.log("Checking open redirects...");
    const redirectFindings = await checkOpenRedirect(targetUrl);
    results.findings.push(...redirectFindings);

    // 6. Crawl and find forms
    console.log("Crawling for forms...");
    const visited = new Set();
    const { links, forms: mainForms } = await crawlPage(
      targetUrl,
      baseUrl,
      visited,
    );

    // Crawl up to 5 more pages
    const allForms = [...mainForms];
    for (const link of links.slice(0, 5)) {
      const { forms } = await crawlPage(link, baseUrl, visited);
      allForms.push(...forms);
      results.pagesScanned++;
    }

    results.formsFound = allForms.length;
    console.log(`Found ${allForms.length} forms/endpoints to test`);

    // 7. Test forms for XSS and SQLi
    for (const form of allForms.slice(0, 10)) {
      console.log(`Testing form at: ${form.action}`);

      const xssFindings = await testXSS(form, baseUrl);
      results.findings.push(...xssFindings);

      const sqliFindings = await testSQLi(form, baseUrl);
      results.findings.push(...sqliFindings);
    }

    // Remove duplicate findings
    const seen = new Set();
    results.findings = results.findings.filter((f) => {
      const key = `${f.type}-${f.endpoint || ""}-${f.parameter || ""}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Calculate summary
    results.summary = {
      critical: results.findings.filter((f) => f.severity === "Critical")
        .length,
      high: results.findings.filter((f) => f.severity === "High").length,
      medium: results.findings.filter((f) => f.severity === "Medium").length,
      low: results.findings.filter((f) => f.severity === "Low").length,
      total: results.findings.length,
    };

    results.riskScore = Math.min(
      100,
      results.summary.critical * 30 +
        results.summary.high * 15 +
        results.summary.medium * 8 +
        results.summary.low * 3,
    );

    results.endTime = new Date().toISOString();
    console.log(`Scan complete. ${results.findings.length} findings.`);

    return results;
  } catch (err) {
    throw err;
  }
}

module.exports = { deepScan };
