const axios = require("axios");
const cheerio = require("cheerio");

const { testBlindSSRF, testBlindXSS, testBlindSQLi } = require("./oobDetector");
const {
  validateSensitiveFile,
  validateOpenRedirect,
  addConfidenceToFindings,
  filterFalsePositives,
} = require("./validator");

const {
  testAdvancedXSS,
  testAdvancedSQLi,
  testSSTI,
  testPrototypePollution,
  scanForSecrets,
  fingerprintTechnologies,
  testRequestSmuggling,
} = require("./advancedScanner");

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
  '"><details open ontoggle=alert(1)>',
  "<input autofocus onfocus=alert(1)>",
  '"-alert(1)-"',
  "'-alert(1)-'",
  "<iframe src=javascript:alert(1)>",
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
  "1; DROP TABLE users--",
  "' OR SLEEP(3)--",
];

const BLIND_SQLI_PAYLOADS = [
  { payload: "1' AND SLEEP(4)--", delay: 4000, db: "MySQL" },
  { payload: "1; WAITFOR DELAY '0:0:4'--", delay: 4000, db: "MSSQL" },
  { payload: "1' AND pg_sleep(4)--", delay: 4000, db: "PostgreSQL" },
  { payload: "1 AND SLEEP(4)", delay: 4000, db: "MySQL" },
  { payload: "' OR SLEEP(4)--", delay: 4000, db: "MySQL" },
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
  "sql syntax",
  "syntax error",
  "database error",
];

const WAF_SIGNATURES = [
  {
    name: "Cloudflare",
    headers: ["cf-ray", "cf-cache-status"],
    cookies: ["__cfduid", "cf_clearance"],
  },
  {
    name: "AWS WAF",
    headers: ["x-amzn-requestid", "x-amz-cf-id"],
    cookies: [],
  },
  {
    name: "Akamai",
    headers: ["x-akamai-transformed", "akamai-origin-hop"],
    cookies: ["ak_bmsc"],
  },
  {
    name: "Incapsula",
    headers: ["x-iinfo", "x-cdn"],
    cookies: ["visid_incap", "incap_ses"],
  },
  { name: "Sucuri", headers: ["x-sucuri-id", "x-sucuri-cache"], cookies: [] },
  {
    name: "ModSecurity",
    headers: ["mod_security", "x-modsecurity"],
    cookies: [],
  },
  {
    name: "F5 BIG-IP",
    headers: ["x-wa-info", "x-cnection"],
    cookies: ["BIGipServer"],
  },
];

const CMS_SIGNATURES = [
  {
    name: "WordPress",
    paths: ["/wp-login.php", "/wp-admin/"],
    meta: ["wordpress"],
  },
  { name: "Joomla", paths: ["/administrator/"], meta: ["joomla"] },
  { name: "Drupal", paths: ["/user/login"], meta: ["drupal"] },
  { name: "Magento", paths: ["/admin/"], meta: [] },
  { name: "Shopify", paths: [], meta: ["shopify"] },
  { name: "Laravel", paths: ["/login"], meta: [] },
];

const axiosInstance = axios.create({
  timeout: 30000,
  validateStatus: () => true,
  headers: {
    "User-Agent": "Mozilla/5.0 (compatible; GhostRecon Security Scanner)",
    Accept: "text/html,application/xhtml+xml,*/*",
  },
  maxRedirects: 3,
});

// ── Page Crawler ──────────────────────────────────────
async function crawlPage(targetUrl, baseUrl, visited = new Set()) {
  if (visited.has(targetUrl) || visited.size > 20)
    return { links: [], forms: [], html: "", headers: {} };
  visited.add(targetUrl);
  try {
    const response = await axiosInstance.get(targetUrl);
    const $ = cheerio.load(response.data);
    const links = [];
    const forms = [];
    $("a[href]").each((i, el) => {
      const href = $(el).attr("href");
      if (!href) return;
      try {
        const absolute = new URL(href, baseUrl).href;
        if (absolute.startsWith(baseUrl) && !visited.has(absolute))
          links.push(absolute);
      } catch (e) {}
    });
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
    const parsedUrl = new URL(targetUrl);
    if (parsedUrl.search) {
      const params = [];
      parsedUrl.searchParams.forEach((value, name) =>
        params.push({ name, value }),
      );
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
    return {
      links: links || [],
      forms: forms || [],
      html: typeof response.data === "string" ? response.data : "",
      headers: response.headers || {},
    };
  } catch (e) {
    return { links: [], forms: [], html: "", headers: {} };
  }
}

// ── Security Headers ──────────────────────────────────
function checkSecurityHeaders(headers) {
  const findings = [];
  const checks = [
    {
      header: "content-security-policy",
      severity: "High",
      owasp: "A05:2021 - Security Misconfiguration",
      detail: "Missing CSP makes XSS attacks much easier.",
      remediation: "Add: Content-Security-Policy: default-src 'self'",
    },
    {
      header: "strict-transport-security",
      severity: "High",
      owasp: "A02:2021 - Cryptographic Failures",
      detail: "Missing HSTS allows HTTP downgrade attacks.",
      remediation:
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
      header: "x-frame-options",
      severity: "Medium",
      owasp: "A05:2021 - Security Misconfiguration",
      detail: "Missing X-Frame-Options allows clickjacking.",
      remediation: "Add: X-Frame-Options: DENY",
    },
    {
      header: "x-content-type-options",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      detail: "Missing X-Content-Type-Options allows MIME sniffing.",
      remediation: "Add: X-Content-Type-Options: nosniff",
    },
    {
      header: "referrer-policy",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      detail: "Missing Referrer-Policy leaks URLs.",
      remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
      header: "permissions-policy",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      detail:
        "Missing Permissions-Policy allows unrestricted browser features.",
      remediation: "Add: Permissions-Policy: camera=(), microphone=()",
    },
  ];
  checks.forEach((c) => {
    if (!headers[c.header]) {
      findings.push({
        type: `Missing Security Header: ${c.header}`,
        severity: c.severity,
        owasp: c.owasp,
        detail: c.detail,
        evidence: `Header "${c.header}" not present`,
        remediation: c.remediation,
      });
    }
  });
  if (headers["server"] && /[\d.]+/.test(headers["server"])) {
    findings.push({
      type: "Server Version Disclosed",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      detail: `Server reveals version: "${headers["server"]}"`,
      evidence: `Server: ${headers["server"]}`,
      remediation: "Hide server version in config.",
    });
  }
  if (headers["x-powered-by"]) {
    findings.push({
      type: "Technology Stack Disclosed",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      detail: `X-Powered-By: "${headers["x-powered-by"]}"`,
      evidence: `X-Powered-By: ${headers["x-powered-by"]}`,
      remediation: "Remove X-Powered-By header.",
    });
  }
  return findings;
}

// ── Cookie Security ───────────────────────────────────
function checkCookies(headers) {
  const findings = [];
  const setCookie = headers["set-cookie"];
  if (!setCookie) return findings;
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  cookies.forEach((cookie) => {
    const name = cookie.split("=")[0].trim();
    if (!cookie.toLowerCase().includes("httponly")) {
      findings.push({
        type: "Cookie Missing HttpOnly",
        severity: "Medium",
        owasp: "A02:2021 - Cryptographic Failures",
        detail: `Cookie "${name}" missing HttpOnly — JS can steal it via XSS.`,
        evidence: `Set-Cookie: ${cookie.substring(0, 80)}`,
        remediation: `Add HttpOnly to ${name} cookie.`,
      });
    }
    if (!cookie.toLowerCase().includes("secure")) {
      findings.push({
        type: "Cookie Missing Secure Flag",
        severity: "Medium",
        owasp: "A02:2021 - Cryptographic Failures",
        detail: `Cookie "${name}" missing Secure — sent over HTTP.`,
        evidence: `Set-Cookie: ${cookie.substring(0, 80)}`,
        remediation: `Add Secure to ${name} cookie.`,
      });
    }
    if (!cookie.toLowerCase().includes("samesite")) {
      findings.push({
        type: "Cookie Missing SameSite",
        severity: "Low",
        owasp: "A01:2021 - Broken Access Control",
        detail: `Cookie "${name}" missing SameSite — CSRF risk.`,
        evidence: `Set-Cookie: ${cookie.substring(0, 80)}`,
        remediation: `Add SameSite=Strict to ${name} cookie.`,
      });
    }
  });
  return findings;
}

// ── Clickjacking ──────────────────────────────────────
function checkClickjacking(headers) {
  const findings = [];
  const xfo = headers["x-frame-options"];
  const csp = headers["content-security-policy"];
  if (!xfo && !(csp && csp.includes("frame-ancestors"))) {
    findings.push({
      type: "Clickjacking Vulnerability",
      severity: "Medium",
      owasp: "A05:2021 - Security Misconfiguration",
      detail:
        "Page can be embedded in iframes. Attackers trick users into clicking malicious elements.",
      evidence: "No X-Frame-Options or CSP frame-ancestors found",
      remediation: "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'",
    });
  }
  return findings;
}

// ── CORS Check ────────────────────────────────────────
async function checkCORS(targetUrl) {
  const findings = [];
  try {
    const response = await axiosInstance.get(targetUrl, {
      headers: { Origin: "https://evil.com" },
    });
    const acao = response.headers["access-control-allow-origin"];
    const acac = response.headers["access-control-allow-credentials"];
    if (acao === "*") {
      findings.push({
        type: "CORS Wildcard Origin",
        severity: "Medium",
        owasp: "A01:2021 - Broken Access Control",
        detail:
          "CORS wildcard allows any website to make cross-origin requests.",
        evidence: "Access-Control-Allow-Origin: *",
        remediation: "Restrict CORS to specific trusted origins.",
      });
    }
    if (acao === "https://evil.com") {
      findings.push({
        type:
          acac === "true"
            ? "CORS Misconfiguration with Credentials"
            : "CORS Origin Reflection",
        severity: acac === "true" ? "Critical" : "High",
        owasp: "A01:2021 - Broken Access Control",
        detail:
          acac === "true"
            ? "Server reflects attacker origin with credentials — full account takeover possible."
            : "Server reflects attacker-controlled Origin.",
        evidence: `ACAO: ${acao}, ACAC: ${acac}`,
        remediation: "Validate Origin against strict whitelist.",
      });
    }
  } catch (e) {}
  return findings;
}

// ── WAF Detection ─────────────────────────────────────
async function detectWAF(targetUrl, headers) {
  const findings = [];
  const detectedWAFs = [];
  for (const waf of WAF_SIGNATURES) {
    let detected = waf.headers.some((h) => headers[h]);
    if (!detected) {
      const cookieHeader = (headers["set-cookie"] || "").toString();
      detected = waf.cookies.some((c) => cookieHeader.includes(c));
    }
    if (detected) detectedWAFs.push(waf.name);
  }
  if (detectedWAFs.length > 0) {
    findings.push({
      type: "WAF Detected",
      severity: "Info",
      owasp: "A05:2021 - Security Misconfiguration",
      detail: `WAF detected: ${detectedWAFs.join(", ")}. Good protection but should not be sole defense.`,
      evidence: `WAF signatures: ${detectedWAFs.join(", ")}`,
      remediation: "Keep WAF rules updated.",
    });
  } else {
    findings.push({
      type: "No WAF Detected",
      severity: "Medium",
      owasp: "A05:2021 - Security Misconfiguration",
      detail:
        "No Web Application Firewall detected. No automated protection against web attacks.",
      evidence: "No WAF signatures found",
      remediation: "Consider Cloudflare (free), AWS WAF, or ModSecurity.",
    });
  }
  return { findings, detectedWAFs };
}

// ── CMS Detection ─────────────────────────────────────
async function detectCMS(targetUrl, html, headers) {
  const findings = [];
  const detectedCMS = [];
  const $ = cheerio.load(html);
  for (const cms of CMS_SIGNATURES) {
    let detected = false;
    const generator = $('meta[name="generator"]').attr("content") || "";
    if (generator.toLowerCase().includes(cms.name.toLowerCase()))
      detected = true;
    if (!detected)
      detected = cms.meta.some((m) => html.toLowerCase().includes(m));
    if (!detected) {
      for (const path of cms.paths) {
        try {
          const res = await axiosInstance.get(new URL(path, targetUrl).href);
          if (res.status === 200 || res.status === 302) {
            detected = true;
            break;
          }
        } catch (e) {}
      }
    }
    if (detected) detectedCMS.push(cms.name);
  }
  if (detectedCMS.length > 0) {
    const cms = detectedCMS[0];
    findings.push({
      type: `CMS Detected: ${cms}`,
      severity: "Low",
      owasp: "A06:2021 - Vulnerable Components",
      detail: `${cms} detected. Attackers target known ${cms} vulnerabilities and outdated plugins.`,
      evidence: `${cms} signatures found`,
      remediation: `Keep ${cms} and all plugins updated. Harden configuration.`,
    });
    if (cms === "WordPress") {
      findings.push({
        type: "WordPress — Audit Plugins",
        severity: "Medium",
        owasp: "A06:2021 - Vulnerable Components",
        detail: "Over 90% of WordPress hacks are through vulnerable plugins.",
        evidence: "WordPress detected",
        remediation: "Use WPScan to audit plugins. Enable auto-updates.",
      });
    }
  }
  return { findings, detectedCMS };
}

// ── DOM XSS ───────────────────────────────────────────
function checkDOMXSS(html) {
  const findings = [];
  const sinks = [
    { pattern: /document\.write\s*\(/gi, name: "document.write()" },
    { pattern: /innerHTML\s*=/gi, name: "innerHTML" },
    { pattern: /outerHTML\s*=/gi, name: "outerHTML" },
    { pattern: /eval\s*\(/gi, name: "eval()" },
    { pattern: /setTimeout\s*\(\s*['"]/gi, name: "setTimeout(string)" },
    { pattern: /location\.href\s*=/gi, name: "location.href" },
  ];
  const sources = [
    /document\.URL/gi,
    /location\.search/gi,
    /location\.hash/gi,
    /document\.referrer/gi,
    /window\.name/gi,
  ];
  const sinkFound = sinks.find((s) => s.pattern.test(html));
  const sourceFound = sources.find((s) => s.test(html));
  if (sinkFound && sourceFound) {
    findings.push({
      type: "DOM-Based XSS (Potential)",
      severity: "High",
      owasp: "A03:2021 - Injection",
      detail: `Dangerous DOM sink "${sinkFound.name}" and user-controllable source detected. DOM XSS possible.`,
      evidence: `Sink: ${sinkFound.name} | Source detected`,
      remediation:
        "Use textContent instead of innerHTML. Sanitize with DOMPurify.",
    });
  } else if (sinkFound) {
    findings.push({
      type: "Dangerous DOM Sink",
      severity: "Medium",
      owasp: "A03:2021 - Injection",
      detail: `Dangerous sink "${sinkFound.name}" found. Could lead to DOM XSS if combined with user input.`,
      evidence: `Sink: ${sinkFound.name}`,
      remediation: "Review all uses of this sink and sanitize inputs.",
    });
  }
  return findings;
}

// ── CSRF Detection ────────────────────────────────────
function checkCSRF(forms) {
  if (!Array.isArray(forms)) return [];
  const findings = [];
  forms
    .filter((f) => f.method === "post")
    .forEach((form) => {
      const hasToken = form.inputs.some((i) => {
        const n = i.name.toLowerCase();
        return n.includes("csrf") || n.includes("token") || n.includes("nonce");
      });
      if (!hasToken) {
        findings.push({
          type: "CSRF Token Missing",
          severity: "High",
          owasp: "A01:2021 - Broken Access Control",
          detail: `POST form at "${form.action}" has no CSRF token.`,
          evidence: `POST ${form.action} — fields: ${form.inputs.map((i) => i.name).join(", ")}`,
          endpoint: form.action,
          method: "POST",
          remediation: "Add CSRF token to every POST form.",
        });
      }
    });
  return findings;
}

// ── SSRF ──────────────────────────────────────────────
async function testSSRF(targetUrl, forms) {
  if (!Array.isArray(forms)) return [];
  const findings = [];
  const ssrfPayloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://localhost/",
  ];
  const ssrfParams = [
    "url",
    "uri",
    "path",
    "dest",
    "redirect",
    "proxy",
    "fetch",
    "link",
    "src",
    "source",
    "file",
    "load",
    "image",
    "img",
  ];
  for (const form of forms.slice(0, 5)) {
    for (const input of form.inputs) {
      if (!ssrfParams.some((p) => input.name.toLowerCase().includes(p)))
        continue;
      for (const payload of ssrfPayloads) {
        try {
          const formData = {};
          form.inputs.forEach((i) => {
            formData[i.name] = i.name === input.name ? payload : i.value;
          });
          let response;
          if (form.method === "post") {
            response = await axiosInstance.post(form.action, formData);
          } else {
            const testUrl = new URL(form.action);
            testUrl.searchParams.set(input.name, payload);
            response = await axiosInstance.get(testUrl.href);
          }
          const body =
            typeof response.data === "string"
              ? response.data
              : JSON.stringify(response.data);
          if (
            body.includes("ami-id") ||
            body.includes("instance-id") ||
            body.includes("root:x:0:0")
          ) {
            findings.push({
              type: "Server-Side Request Forgery (SSRF)",
              severity: "Critical",
              owasp: "A10:2021 - Server-Side Request Forgery",
              parameter: input.name,
              endpoint: form.action,
              method: form.method.toUpperCase(),
              payload,
              detail:
                "SSRF confirmed. Attacker can access internal services and AWS metadata.",
              evidence: `"${input.name}" with "${payload}" returned internal data`,
              remediation: "Whitelist allowed URLs. Block private IP ranges.",
            });
            return findings;
          }
        } catch (e) {}
      }
    }
  }
  return findings;
}

// ── Directory Traversal / LFI ─────────────────────────
async function testDirectoryTraversal(forms) {
  if (!Array.isArray(forms)) return [];
  const findings = [];
  const payloads = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  ];
  const fileParams = [
    "file",
    "path",
    "page",
    "include",
    "doc",
    "template",
    "view",
    "content",
    "load",
    "read",
  ];
  for (const form of forms.slice(0, 5)) {
    for (const input of form.inputs) {
      if (!fileParams.some((p) => input.name.toLowerCase().includes(p)))
        continue;
      for (const payload of payloads) {
        try {
          const formData = {};
          form.inputs.forEach((i) => {
            formData[i.name] = i.name === input.name ? payload : i.value;
          });
          let response;
          if (form.method === "post") {
            response = await axiosInstance.post(form.action, formData);
          } else {
            const testUrl = new URL(form.action);
            testUrl.searchParams.set(input.name, payload);
            response = await axiosInstance.get(testUrl.href);
          }
          const body =
            typeof response.data === "string"
              ? response.data
              : JSON.stringify(response.data);
          if (
            body.includes("root:x:0:0") ||
            body.includes("[extensions]") ||
            body.includes("daemon:")
          ) {
            findings.push({
              type: "Directory Traversal / LFI",
              severity: "Critical",
              owasp: "A01:2021 - Broken Access Control",
              parameter: input.name,
              endpoint: form.action,
              method: form.method.toUpperCase(),
              payload,
              detail:
                "LFI confirmed. Attacker can read server files including passwords and configs.",
              evidence: `"${input.name}" with "${payload}" returned file contents`,
              remediation:
                "Never use user input in file paths. Whitelist allowed files.",
            });
            return findings;
          }
        } catch (e) {}
      }
    }
  }
  return findings;
}

// ── Broken Auth ───────────────────────────────────────
async function checkBrokenAuth(forms) {
  if (!Array.isArray(forms)) return [];
  const findings = [];
  const loginForms = forms.filter((form) => {
    const fields = form.inputs.map((i) => i.name.toLowerCase()).join(" ");
    return (
      fields.includes("password") ||
      fields.includes("pass") ||
      fields.includes("pwd")
    );
  });
  for (const form of loginForms) {
    try {
      const userField = form.inputs.find((i) =>
        ["user", "email", "login", "username"].some((k) =>
          i.name.toLowerCase().includes(k),
        ),
      );
      const passField = form.inputs.find((i) =>
        ["pass", "pwd", "password"].some((k) =>
          i.name.toLowerCase().includes(k),
        ),
      );
      if (!userField || !passField) continue;
      const weakCreds = [
        { user: "admin", pass: "admin" },
        { user: "admin", pass: "password" },
        { user: "admin", pass: "123456" },
        { user: "root", pass: "root" },
      ];
      for (const cred of weakCreds) {
        const formData = {};
        form.inputs.forEach((i) => {
          formData[i.name] = "x";
        });
        formData[userField.name] = cred.user;
        formData[passField.name] = cred.pass;
        const response = await axiosInstance.post(form.action, formData);
        const body = (
          typeof response.data === "string" ? response.data : ""
        ).toLowerCase();
        if (
          response.status === 302 ||
          body.includes("dashboard") ||
          body.includes("welcome") ||
          body.includes("logout")
        ) {
          findings.push({
            type: "Weak/Default Credentials",
            severity: "Critical",
            owasp: "A07:2021 - Identification and Authentication Failures",
            endpoint: form.action,
            method: "POST",
            detail: `Login succeeded with "${cred.user}/${cred.pass}".`,
            evidence: `POST ${form.action} with ${cred.user}/${cred.pass} → HTTP ${response.status}`,
            remediation:
              "Change default passwords. Enforce strong password policy. Enable MFA.",
          });
          break;
        }
      }
      let noRateLimit = true;
      for (let i = 0; i < 6; i++) {
        const formData = {};
        form.inputs.forEach((inp) => {
          formData[inp.name] = "x";
        });
        formData[userField.name] = "admin";
        formData[passField.name] = `wrongpass${i}`;
        const r = await axiosInstance.post(form.action, formData);
        if (r.status === 429 || r.status === 403) {
          noRateLimit = false;
          break;
        }
      }
      if (noRateLimit) {
        findings.push({
          type: "No Login Rate Limiting",
          severity: "High",
          owasp: "A07:2021 - Identification and Authentication Failures",
          endpoint: form.action,
          method: "POST",
          detail:
            "Login form has no rate limiting. Unlimited brute force attempts possible.",
          evidence: `6 failed attempts returned no 429/403 on ${form.action}`,
          remediation: "Add rate limiting. Lock after 5 attempts. Add CAPTCHA.",
        });
      }
    } catch (e) {}
  }
  return findings;
}

// ── JWT Check ─────────────────────────────────────────
async function checkJWT(headers) {
  const findings = [];
  const jwtRegex = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/;
  const authHeader = headers["authorization"] || "";
  const cookies = Array.isArray(headers["set-cookie"])
    ? headers["set-cookie"].join(" ")
    : headers["set-cookie"] || "";
  let token = null;
  const m1 = authHeader.match(jwtRegex);
  const m2 = cookies.match(jwtRegex);
  if (m1) token = m1[0];
  else if (m2) token = m2[0];
  if (!token) return findings;
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return findings;
    const header = JSON.parse(Buffer.from(parts[0], "base64").toString());
    const payload = JSON.parse(Buffer.from(parts[1], "base64").toString());
    if (header.alg === "none" || header.alg === "NONE") {
      findings.push({
        type: "JWT None Algorithm",
        severity: "Critical",
        owasp: "A02:2021 - Cryptographic Failures",
        detail:
          'JWT uses "none" algorithm. Attacker can forge tokens and bypass authentication.',
        evidence: `alg: ${header.alg}`,
        remediation:
          "Reject JWTs with none algorithm. Always verify signatures.",
      });
    }
    if (header.alg === "HS256") {
      findings.push({
        type: "JWT Weak Algorithm (HS256)",
        severity: "Medium",
        owasp: "A02:2021 - Cryptographic Failures",
        detail:
          "HS256 is symmetric. If secret is weak, tokens can be brute-forced.",
        evidence: "alg: HS256",
        remediation: "Upgrade to RS256. Use 256+ bit random secret.",
      });
    }
    if (!payload.exp) {
      findings.push({
        type: "JWT No Expiry",
        severity: "High",
        owasp: "A02:2021 - Cryptographic Failures",
        detail: "JWT has no expiry. Stolen tokens are valid forever.",
        evidence: "No exp claim",
        remediation: "Set short expiry (15-60 min). Use refresh tokens.",
      });
    } else {
      const days = Math.floor(
        (new Date(payload.exp * 1000) - new Date()) / 86400000,
      );
      if (days > 30) {
        findings.push({
          type: "JWT Long Expiry",
          severity: "Low",
          owasp: "A02:2021 - Cryptographic Failures",
          detail: `JWT expires in ${days} days. Long-lived tokens increase theft risk.`,
          evidence: `Expires in ${days} days`,
          remediation: "Use shorter expiry. Implement refresh token rotation.",
        });
      }
    }
  } catch (e) {}
  return findings;
}

// ── XXE ───────────────────────────────────────────────
async function testXXE(targetUrl) {
  const findings = [];
  const xxePayload = `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>`;
  try {
    const response = await axiosInstance.post(targetUrl, xxePayload, {
      headers: { "Content-Type": "application/xml" },
      timeout: 10000,
    });
    const body =
      typeof response.data === "string"
        ? response.data
        : JSON.stringify(response.data);
    if (
      body.includes("root:") ||
      body.includes("daemon:") ||
      body.includes("/bin/bash")
    ) {
      findings.push({
        type: "XML External Entity (XXE)",
        severity: "Critical",
        owasp: "A05:2021 - Security Misconfiguration",
        detail:
          "XXE confirmed. Server reads local files via XML entity injection.",
        evidence: "Server returned /etc/passwd contents",
        remediation:
          "Disable external entity processing. Use safe XML parsers.",
      });
    }
  } catch (e) {}
  return findings;
}

// ── Sensitive Files ───────────────────────────────────
async function checkSensitiveFiles(baseUrl) {
  const findings = [];
  const files = [
    { path: "/.git/config", name: "Git repository exposed", critical: true },
    { path: "/.env", name: "Environment file exposed", critical: true },
    {
      path: "/wp-config.php",
      name: "WordPress config exposed",
      critical: true,
    },
    {
      path: "/config.php",
      name: "PHP config exposed",
      critical: true,
      validate: true,
    },
    { path: "/phpinfo.php", name: "PHP info exposed", critical: true },
    { path: "/admin", name: "Admin panel exposed", critical: false },
    { path: "/administrator", name: "Admin panel exposed", critical: false },
    { path: "/.htaccess", name: "Apache config exposed", critical: false },
    {
      path: "/backup.zip",
      name: "Backup file exposed",
      critical: true,
      validate: true,
    },
    {
      path: "/database.sql",
      name: "Database dump exposed",
      critical: true,
      validate: true,
    },
    { path: "/.DS_Store", name: "DS_Store file exposed", critical: false },
    {
      path: "/web.config",
      name: "IIS config exposed",
      critical: true,
      validate: true,
    },
    {
      path: "/server-status",
      name: "Apache server status exposed",
      critical: false,
    },
  ];
  for (const file of files) {
    try {
      const fileUrl = new URL(file.path, baseUrl).href;
      const res = await axiosInstance.get(fileUrl);
      if (res.status !== 200) continue;
      const contentType = (res.headers["content-type"] || "").toLowerCase();
      if (contentType.includes("text/html") && file.validate) {
        const validation = await validateSensitiveFile(fileUrl, file.path);
        if (!validation.valid) continue;
        findings.push({
          type: file.name,
          severity: "Critical",
          confidence: validation.confidence,
          owasp: "A05:2021 - Security Misconfiguration",
          detail: `${file.name} is publicly accessible. ${validation.reason}`,
          evidence: `GET ${file.path} → HTTP 200 | ${validation.reason}`,
          remediation: `Restrict access to ${file.path} via server config.`,
        });
        continue;
      }
      if (file.validate) {
        const validation = await validateSensitiveFile(fileUrl, file.path);
        if (!validation.valid) continue;
        findings.push({
          type: file.name,
          severity: "Critical",
          confidence: validation.confidence,
          owasp: "A05:2021 - Security Misconfiguration",
          detail: `${file.name} CONFIRMED accessible. ${validation.reason}`,
          evidence: `GET ${file.path} → HTTP 200 (${validation.size || "?"} bytes) | ${validation.reason}`,
          remediation: `URGENT: Restrict access to ${file.path} via server config.`,
        });
      } else {
        findings.push({
          type: file.name,
          severity: file.critical ? "Critical" : "Low",
          confidence: "Probable",
          owasp: "A05:2021 - Security Misconfiguration",
          detail: `${file.name} is publicly accessible. May expose credentials or source code.`,
          evidence: `GET ${file.path} → HTTP 200`,
          remediation: `Restrict access to ${file.path} via server config.`,
        });
      }
    } catch (e) {}
  }
  return findings;
}

// ── Open Redirect ─────────────────────────────────────
async function checkOpenRedirect(targetUrl) {
  const findings = [];
  const params = [
    "redirect",
    "url",
    "next",
    "return",
    "returnUrl",
    "goto",
    "dest",
  ];
  const targetDomain = new URL(targetUrl).hostname;
  for (const param of params) {
    try {
      const testUrl = new URL(targetUrl);
      testUrl.searchParams.set(param, "https://evil.com");
      const response = await axiosInstance.get(testUrl.href, {
        maxRedirects: 0,
      });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers["location"] || "";
        const validation = validateOpenRedirect(location, targetDomain);
        if (!validation.valid) continue;
        findings.push({
          type: "Open Redirect",
          severity: "Medium",
          confidence: validation.confidence,
          owasp: "A01:2021 - Broken Access Control",
          detail: `Open redirect via "${param}". Attackers can redirect users to phishing sites.`,
          evidence: `${param}=https://evil.com → Location: ${location}`,
          remediation: "Validate redirects against strict whitelist.",
        });
        break;
      }
    } catch (e) {}
  }
  return findings;
}

// ── XSS Test ──────────────────────────────────────────
async function testXSS(form) {
  const findings = [];
  for (const payload of XSS_PAYLOADS.slice(0, 8)) {
    try {
      const formData = {};
      form.inputs.forEach((i) => {
        formData[i.name] = payload;
      });
      let response;
      if (form.method === "post") {
        response = await axiosInstance.post(form.action, formData);
      } else {
        const testUrl = new URL(form.action);
        form.inputs.forEach((i) => testUrl.searchParams.set(i.name, payload));
        response = await axiosInstance.get(testUrl.href);
      }
      const body =
        typeof response.data === "string"
          ? response.data
          : JSON.stringify(response.data);
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
          detail:
            "Reflected XSS confirmed. Attacker can steal cookies and hijack sessions.",
          evidence: `Payload "${payload}" reflected unencoded`,
          remediation: "Encode output. Use CSP. Use framework auto-escaping.",
        });
        break;
      }
    } catch (e) {}
  }
  return findings;
}

// ── SQLi Test ─────────────────────────────────────────
async function testSQLi(form) {
  const findings = [];
  for (const payload of SQLI_PAYLOADS.slice(0, 8)) {
    try {
      const formData = {};
      form.inputs.forEach((i) => {
        formData[i.name] = payload;
      });
      let response;
      if (form.method === "post") {
        response = await axiosInstance.post(form.action, formData);
      } else {
        const testUrl = new URL(form.action);
        form.inputs.forEach((i) => testUrl.searchParams.set(i.name, payload));
        response = await axiosInstance.get(testUrl.href);
      }
      const body = (
        typeof response.data === "string"
          ? response.data
          : JSON.stringify(response.data)
      ).toLowerCase();
      const err = SQL_ERRORS.find((e) => body.includes(e));
      if (err) {
        findings.push({
          type: "SQL Injection",
          severity: "Critical",
          owasp: "A03:2021 - Injection",
          parameter: form.inputs.map((i) => i.name).join(", "),
          endpoint: form.action,
          method: form.method.toUpperCase(),
          payload,
          detail:
            "SQL injection confirmed. Attacker can read, modify or delete entire database.",
          evidence: `SQL error "${err}" triggered by "${payload}"`,
          remediation:
            "Use parameterized queries. Never concatenate user input into SQL.",
        });
        break;
      }
    } catch (e) {}
  }
  return findings;
}

// ── IDOR Detection ────────────────────────────────────
async function testIDOR(urls, authedInstance, baseUrl) {
  const findings = [];
  const idPatterns = [
    /[?&](id|user_id|account_id|order_id|invoice_id|profile_id|doc_id|file_id)=(\d+)/gi,
    /\/(user|account|order|invoice|profile|document|file)\/(\d+)/gi,
  ];
  for (const url of urls) {
    for (const pattern of idPatterns) {
      const matches = [...url.matchAll(pattern)];
      for (const match of matches) {
        const paramValue = match[2];
        const numericValue = parseInt(paramValue);
        if (isNaN(numericValue)) continue;
        const testIds = [numericValue - 1, numericValue + 1, 1, 2];
        for (const testId of testIds) {
          if (testId <= 0) continue;
          try {
            const testUrl = url.replace(
              match[0],
              match[0].replace(paramValue, testId.toString()),
            );
            const response = await authedInstance.get(testUrl);
            if (
              response.status === 200 &&
              typeof response.data === "string" &&
              response.data.length > 100 &&
              !response.data.toLowerCase().includes("not found") &&
              !response.data.toLowerCase().includes("unauthorized") &&
              !response.data.toLowerCase().includes("forbidden")
            ) {
              findings.push({
                type: "Insecure Direct Object Reference (IDOR)",
                severity: "High",
                owasp: "A01:2021 - Broken Access Control",
                endpoint: testUrl,
                method: "GET",
                detail: `IDOR detected. Changing ID from ${paramValue} to ${testId} returns data.`,
                evidence: `GET ${testUrl} returned HTTP 200 with content`,
                remediation:
                  "Implement object-level authorization. Check user owns resource before returning it.",
              });
              return findings;
            }
          } catch (e) {}
        }
      }
    }
  }
  return findings;
}

// ── Authenticated Scanner ─────────────────────────────
async function authenticatedScan(targetUrl, credentials) {
  const results = {
    loginSuccessful: false,
    pagesScanned: 0,
    findings: [],
    authenticatedUrls: [],
  };
  let loginPageUrl = credentials.loginUrl || targetUrl;
  if (!loginPageUrl.startsWith("http")) loginPageUrl = "http://" + loginPageUrl;
  let loginPage;
  try {
    loginPage = await axiosInstance.get(loginPageUrl);
  } catch (e) {
    throw new Error("Could not reach login page: " + e.message);
  }
  const $ = cheerio.load(loginPage.data);
  let loginForm = null;
  $("form").each((i, form) => {
    const inputs = [];
    $(form)
      .find("input")
      .each((j, input) => {
        inputs.push({
          name: $(input).attr("name"),
          type: $(input).attr("type") || "text",
          value: $(input).attr("value") || "",
        });
      });
    const hasPassword = inputs.some(
      (i) =>
        i.type === "password" ||
        (i.name && i.name.toLowerCase().includes("pass")),
    );
    if (hasPassword && !loginForm) {
      loginForm = {
        action: new URL($(form).attr("action") || loginPageUrl, loginPageUrl)
          .href,
        method: ($(form).attr("method") || "post").toLowerCase(),
        inputs,
      };
    }
  });
  if (!loginForm) {
    results.findings.push({
      type: "Login Form Not Found",
      severity: "Info",
      detail: "Could not find a login form.",
      evidence: `Searched ${loginPageUrl}`,
      remediation: "Provide the exact URL of the login page.",
    });
    return results;
  }
  const formData = {};
  loginForm.inputs.forEach((input) => {
    if (!input.name) return;
    const name = input.name.toLowerCase();
    if (
      input.type === "password" ||
      name.includes("pass") ||
      name.includes("pwd")
    ) {
      formData[input.name] = credentials.password;
    } else if (
      name.includes("user") ||
      name.includes("email") ||
      name.includes("login")
    ) {
      formData[input.name] = credentials.username;
    } else if (input.value) {
      formData[input.name] = input.value;
    }
  });
  let loginResponse;
  try {
    loginResponse = await axiosInstance.post(loginForm.action, formData, {
      maxRedirects: 5,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
  } catch (e) {
    throw new Error("Login request failed: " + e.message);
  }
  const loginBody =
    typeof loginResponse.data === "string"
      ? loginResponse.data.toLowerCase()
      : "";
  const loginCookies = loginResponse.headers["set-cookie"] || [];
  const loginFailed =
    loginBody.includes("invalid") ||
    loginBody.includes("incorrect") ||
    loginBody.includes("wrong password") ||
    loginBody.includes("login failed");
  const loginSucceeded =
    loginResponse.status === 302 ||
    loginBody.includes("dashboard") ||
    loginBody.includes("welcome") ||
    loginBody.includes("logout") ||
    loginCookies.length > 0;
  if (loginFailed && !loginSucceeded) {
    results.findings.push({
      type: "Authentication Failed",
      severity: "Info",
      detail: "Login failed with provided credentials.",
      evidence: `POST ${loginForm.action} returned ${loginResponse.status}`,
      remediation: "Verify username and password.",
    });
    return results;
  }
  results.loginSuccessful = true;
  const cookieHeader = loginCookies.join("; ");
  const authedInstance = axios.create({
    timeout: 15000,
    validateStatus: () => true,
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; GhostRecon Security Scanner)",
      Cookie: cookieHeader,
    },
    maxRedirects: 3,
  });
  const baseUrl = new URL(targetUrl).origin;
  const visited = new Set();
  const queue = [targetUrl];
  const allForms = [];
  while (queue.length > 0 && visited.size < 15) {
    const pageUrl = queue.shift();
    if (visited.has(pageUrl)) continue;
    visited.add(pageUrl);
    try {
      const response = await authedInstance.get(pageUrl);
      const $page = cheerio.load(response.data);
      results.pagesScanned++;
      results.authenticatedUrls.push(pageUrl);
      $page("form").each((i, form) => {
        const action = $page(form).attr("action") || pageUrl;
        const method = ($page(form).attr("method") || "get").toLowerCase();
        const inputs = [];
        $page(form)
          .find("input, textarea, select")
          .each((j, input) => {
            const name = $page(input).attr("name");
            const type = $page(input).attr("type") || "text";
            if (name && type !== "submit" && type !== "file") {
              inputs.push({
                name,
                type,
                value: $page(input).attr("value") || "test",
              });
            }
          });
        if (inputs.length > 0) {
          try {
            allForms.push({
              action: new URL(action, baseUrl).href,
              method,
              inputs,
              pageUrl,
            });
          } catch (e) {}
        }
      });
      $page("a[href]").each((i, el) => {
        const href = $page(el).attr("href");
        if (!href) return;
        try {
          const absolute = new URL(href, baseUrl).href;
          if (absolute.startsWith(baseUrl) && !visited.has(absolute))
            queue.push(absolute);
        } catch (e) {}
      });
    } catch (e) {}
  }
  for (const form of allForms.slice(0, 10)) {
    for (const payload of XSS_PAYLOADS.slice(0, 5)) {
      try {
        const fd = {};
        form.inputs.forEach((i) => {
          fd[i.name] = payload;
        });
        const response = await authedInstance.post(form.action, fd);
        const body = typeof response.data === "string" ? response.data : "";
        if (body.includes(payload) && !body.includes("&lt;")) {
          results.findings.push({
            type: "Authenticated XSS",
            severity: "High",
            owasp: "A03:2021 - Injection",
            parameter: form.inputs.map((i) => i.name).join(", "),
            endpoint: form.action,
            method: "POST",
            payload,
            detail: "XSS found in authenticated page.",
            evidence: `Payload "${payload}" reflected in authenticated response`,
            remediation: "Encode all output. Use CSP.",
          });
          break;
        }
      } catch (e) {}
    }
    for (const payload of SQLI_PAYLOADS.slice(0, 5)) {
      try {
        const fd = {};
        form.inputs.forEach((i) => {
          fd[i.name] = payload;
        });
        const response = await authedInstance.post(form.action, fd);
        const body = (
          typeof response.data === "string" ? response.data : ""
        ).toLowerCase();
        const err = SQL_ERRORS.find((e) => body.includes(e));
        if (err) {
          results.findings.push({
            type: "Authenticated SQL Injection",
            severity: "Critical",
            owasp: "A03:2021 - Injection",
            parameter: form.inputs.map((i) => i.name).join(", "),
            endpoint: form.action,
            method: "POST",
            payload,
            detail: "SQL injection found in authenticated area.",
            evidence: `SQL error "${err}" in authenticated endpoint`,
            remediation: "Use parameterized queries everywhere.",
          });
          break;
        }
      } catch (e) {}
    }
  }
  const idorFindings = await testIDOR(
    results.authenticatedUrls,
    authedInstance,
    baseUrl,
  );
  results.findings.push(...idorFindings);
  return results;
}

// ── Main Deep Scan ────────────────────────────────────
async function deepScan(targetUrl) {
  const results = {
    target: targetUrl,
    findings: [],
    pagesScanned: 0,
    formsFound: 0,
    waf: [],
    cms: [],
    startTime: new Date().toISOString(),
  };
  try {
    if (!targetUrl.startsWith("http")) targetUrl = "http://" + targetUrl;
    const baseUrl = new URL(targetUrl).origin;
    console.log("Fetching:", targetUrl);
    let mainResponse;
    try {
      mainResponse = await axiosInstance.get(targetUrl);
    } catch (e) {
      throw new Error(`Could not reach target: ${e.message}`);
    }
    results.pagesScanned++;
    const headers = mainResponse.headers;
    const html = typeof mainResponse.data === "string" ? mainResponse.data : "";
    console.log("Running parallel checks...");
    const [
      headerF,
      cookieF,
      fileF,
      redirectF,
      wafR,
      cmsR,
      domXssF,
      xxeF,
      corsF,
    ] = await Promise.all([
      Promise.resolve(checkSecurityHeaders(headers)),
      Promise.resolve(checkCookies(headers)),
      checkSensitiveFiles(baseUrl),
      checkOpenRedirect(targetUrl),
      detectWAF(targetUrl, headers),
      detectCMS(targetUrl, html, headers),
      Promise.resolve(checkDOMXSS(html)),
      testXXE(targetUrl),
      checkCORS(targetUrl),
    ]);
    results.findings.push(
      ...headerF,
      ...cookieF,
      ...fileF,
      ...redirectF,
      ...wafR.findings,
      ...cmsR.findings,
      ...domXssF,
      ...xxeF,
      ...corsF,
      ...checkClickjacking(headers),
    );
    results.waf = wafR.detectedWAFs;
    results.cms = cmsR.detectedCMS;

    // ── FIXED: Safe crawl with array checks ──────────
    console.log("Crawling pages...");
    const visited = new Set();
    const crawlResult = await crawlPage(targetUrl, baseUrl, visited);
    const mainForms = Array.isArray(crawlResult.forms) ? crawlResult.forms : [];
    const mainLinks = Array.isArray(crawlResult.links) ? crawlResult.links : [];
    const allForms = [...mainForms];

    for (const link of mainLinks.slice(0, 5)) {
      const subResult = await crawlPage(link, baseUrl, visited);
      const subForms = Array.isArray(subResult.forms) ? subResult.forms : [];
      allForms.push(...subForms);
      results.pagesScanned++;
    }

    results.formsFound = allForms.length;
    results.findings.push(...checkCSRF(allForms));
    const [authF, jwtF, ssrfF, traversalF] = await Promise.all([
      checkBrokenAuth(allForms),
      checkJWT(headers),
      testSSRF(targetUrl, allForms),
      testDirectoryTraversal(allForms),
    ]);
    results.findings.push(...authF, ...jwtF, ...ssrfF, ...traversalF);
    console.log(
      `Testing ${Math.min(allForms.length, 10)} forms with advanced payloads...`,
    );
    for (const form of allForms.slice(0, 10)) {
      const [xss, sqli, blind, advXss, advSqli, ssti] = await Promise.all([
        testXSS(form),
        testSQLi(form),
        testBlindSQLi(form),
        testAdvancedXSS(form, baseUrl),
        testAdvancedSQLi(form, baseUrl),
        testSSTI(form, baseUrl),
      ]);
      results.findings.push(
        ...xss,
        ...sqli,
        ...blind,
        ...advXss,
        ...advSqli,
        ...ssti,
      );
    }
    console.log("Running advanced security checks...");
    const [protoFindings, secretResult, techResult, smugglingFindings] =
      await Promise.all([
        testPrototypePollution(targetUrl),
        scanForSecrets(targetUrl, baseUrl, html),
        fingerprintTechnologies(targetUrl, html, headers),
        testRequestSmuggling(targetUrl),
      ]);
    console.log("Running out-of-band blind detection...");
    const [blindSSRF, blindXSS, blindSQLi] = await Promise.all([
      testBlindSSRF(targetUrl, allForms, axiosInstance),
      testBlindXSS(allForms, axiosInstance),
      testBlindSQLi(allForms, axiosInstance),
    ]);
    results.findings.push(...blindSSRF, ...blindXSS, ...blindSQLi);
    results.findings.push(
      ...protoFindings,
      ...secretResult.findings,
      ...techResult.findings,
      ...smugglingFindings,
    );
    results.secretsFound = secretResult.secretsFound;
    results.technologies = techResult.detected;
    console.log("Testing for stored XSS...");
    const storedXssFindings = await testStoredXSS(targetUrl, allForms, baseUrl);
    results.findings.push(...storedXssFindings);

    // ── FIXED: Dedup, false positive filter, confidence scoring ──
    const seen = new Set();
    results.findings = results.findings.filter((f) => {
      const key = `${f.type}-${f.endpoint || ""}-${f.parameter || ""}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Filter false positives
    results.findings = filterFalsePositives(results.findings);

    // Add confidence scores
    results.findings = addConfidenceToFindings(results.findings);

    // Sort by confidence then severity
    const confidenceOrder = { Confirmed: 0, Probable: 1, Possible: 2 };
    const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    results.findings.sort((a, b) => {
      const cA = confidenceOrder[a.confidence] ?? 3;
      const cB = confidenceOrder[b.confidence] ?? 3;
      if (cA !== cB) return cA - cB;
      return (
        (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
      );
    });

    results.summary = {
      critical: results.findings.filter((f) => f.severity === "Critical")
        .length,
      high: results.findings.filter((f) => f.severity === "High").length,
      medium: results.findings.filter((f) => f.severity === "Medium").length,
      low: results.findings.filter((f) => f.severity === "Low").length,
      info: results.findings.filter((f) => f.severity === "Info").length,
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

// ── Stored XSS Detection ──────────────────────────────
async function testStoredXSS(targetUrl, forms, baseUrl) {
  if (!Array.isArray(forms)) return [];
  const findings = [];
  const storedPayloads = [
    {
      payload: '<script>alert("ghostrecon-xss-test")</script>',
      marker: "ghostrecon-xss-test",
    },
    {
      payload: "<img src=x onerror=\"alert('ghostrecon-stored')\">",
      marker: "ghostrecon-stored",
    },
    {
      payload: '"><script>alert("gr-stored-xss")</script>',
      marker: "gr-stored-xss",
    },
    { payload: "javascript:alert('gr-xss')", marker: "gr-xss" },
    { payload: "<svg onload=\"alert('gr-svg-xss')\">", marker: "gr-svg-xss" },
  ];
  const checkPages = new Set([targetUrl]);
  for (const form of forms.filter((f) => f.method === "post").slice(0, 8)) {
    for (const { payload, marker } of storedPayloads.slice(0, 3)) {
      try {
        const formData = {};
        form.inputs.forEach((input) => {
          const name = input.name.toLowerCase();
          if (name.includes("email")) {
            formData[input.name] = `test${Date.now()}@ghostrecon-test.com`;
          } else if (name.includes("phone") || name.includes("tel")) {
            formData[input.name] = "9999999999";
          } else if (
            name.includes("price") ||
            name.includes("amount") ||
            name.includes("qty")
          ) {
            formData[input.name] = "1";
          } else if (input.type === "number") {
            formData[input.name] = "1";
          } else {
            formData[input.name] = payload;
          }
        });
        const submitResponse = await axiosInstance.post(form.action, formData);
        if (submitResponse.status === 200 || submitResponse.status === 302) {
          checkPages.add(form.action);
          checkPages.add(form.pageUrl || targetUrl);
          if (
            submitResponse.status === 302 &&
            submitResponse.headers["location"]
          ) {
            try {
              checkPages.add(
                new URL(submitResponse.headers["location"], baseUrl).href,
              );
            } catch (e) {}
          }
        }
        const immediateBody =
          typeof submitResponse.data === "string"
            ? submitResponse.data
            : JSON.stringify(submitResponse.data);
        if (immediateBody.includes(marker) && !immediateBody.includes("&lt;")) {
          findings.push({
            type: "Stored XSS (Immediate Reflection)",
            severity: "High",
            owasp: "A03:2021 - Injection",
            parameter: form.inputs.map((i) => i.name).join(", "),
            endpoint: form.action,
            method: "POST",
            payload,
            detail:
              "XSS payload submitted via POST form and immediately reflected in response.",
            evidence: `Marker "${marker}" found in POST response from ${form.action}`,
            remediation: "Encode all user input before storing and displaying.",
          });
        }
      } catch (e) {}
    }
  }
  for (const pageUrl of checkPages) {
    try {
      const response = await axiosInstance.get(pageUrl);
      const body =
        typeof response.data === "string"
          ? response.data
          : JSON.stringify(response.data);
      for (const { payload, marker } of storedPayloads) {
        if (
          body.includes(marker) &&
          !body.includes("&lt;") &&
          !body.includes("&#")
        ) {
          findings.push({
            type: "Stored XSS Confirmed",
            severity: "Critical",
            owasp: "A03:2021 - Injection",
            endpoint: pageUrl,
            method: "GET",
            payload,
            detail: `Stored XSS confirmed at ${pageUrl}.`,
            evidence: `Marker "${marker}" found stored and unencoded at ${pageUrl}`,
            remediation:
              "Immediately sanitize all stored data. Implement output encoding.",
          });
          break;
        }
      }
    } catch (e) {}
  }
  for (const form of forms.filter((f) => f.method === "get").slice(0, 5)) {
    for (const { payload, marker } of storedPayloads.slice(0, 2)) {
      try {
        const testUrl = new URL(form.action);
        form.inputs.forEach((input) =>
          testUrl.searchParams.set(input.name, payload),
        );
        const response = await axiosInstance.get(testUrl.href);
        const body =
          typeof response.data === "string"
            ? response.data
            : JSON.stringify(response.data);
        if (body.includes(marker) && !body.includes("&lt;")) {
          findings.push({
            type: "XSS in Search/Filter Results",
            severity: "High",
            owasp: "A03:2021 - Injection",
            parameter: form.inputs.map((i) => i.name).join(", "),
            endpoint: testUrl.href,
            method: "GET",
            payload,
            detail: "XSS payload reflected in search or filter results.",
            evidence: `Marker "${marker}" found unencoded in search results at ${testUrl.href}`,
            remediation: "Encode all output including search terms.",
          });
        }
      } catch (e) {}
    }
  }
  const seen = new Set();
  return findings.filter((f) => {
    const key = `${f.type}-${f.endpoint}-${f.payload}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = { deepScan, authenticatedScan, testStoredXSS };
