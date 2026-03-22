const { validateSecret, CONFIDENCE } = require("./validator");
const axios = require("axios");
const cheerio = require("cheerio");
const {
  ALL_XSS_PAYLOADS,
  XSS_EVENT_HANDLERS,
  XSS_BYPASS_WAF,
  XSS_POLYGLOT,
  ALL_SQLI_PAYLOADS,
  SQLI_BLIND_TIME,
  SQLI_BLIND_BOOLEAN,
  SQLI_UNION_BASED,
  SSTI_PAYLOADS,
  PROTOTYPE_POLLUTION_PAYLOADS,
  SECRET_PATTERNS,
  TECH_FINGERPRINTS,
  SQL_ERROR_SIGNATURES,
} = require("./payloads");

const axiosInstance = axios.create({
  timeout: 30000,
  validateStatus: () => true,
  headers: {
    "User-Agent": "Mozilla/5.0 (compatible; GhostRecon Pro Scanner)",
    Accept: "text/html,application/xhtml+xml,*/*",
  },
  maxRedirects: 3,
});

// ── Advanced XSS Testing ──────────────────────────────────────
async function testAdvancedXSS(form, baseUrl) {
  const findings = [];

  // Test with multiple payload categories
  const payloadSets = [
    { payloads: XSS_EVENT_HANDLERS.slice(0, 10), context: "Event Handler" },
    { payloads: XSS_BYPASS_WAF.slice(0, 10), context: "WAF Bypass" },
    { payloads: XSS_POLYGLOT.slice(0, 5), context: "Polyglot" },
  ];

  for (const { payloads, context } of payloadSets) {
    for (const payload of payloads) {
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

        // Check for unencoded reflection
        if (
          body.includes(payload) &&
          !body.includes("&lt;") &&
          !body.includes("&#")
        ) {
          findings.push({
            type: `XSS — ${context}`,
            severity: "High",
            owasp: "A03:2021 - Injection",
            parameter: form.inputs.map((i) => i.name).join(", "),
            endpoint: form.action,
            method: form.method.toUpperCase(),
            payload,
            context,
            detail: `${context} XSS payload reflected unencoded. Attacker can steal cookies, hijack sessions, redirect users to malicious sites.`,
            evidence: `Payload reflected: ${payload.substring(0, 80)}`,
            remediation:
              "Implement context-aware output encoding. Use Content-Security-Policy. Use framework auto-escaping.",
          });
          break;
        }

        // Check for partial reflection that could still be exploitable
        const partialMarkers = [
          "onerror=",
          "onload=",
          "onclick=",
          "javascript:",
          "alert(",
        ];
        for (const marker of partialMarkers) {
          if (
            body.includes(marker) &&
            !body.toLowerCase().includes("&amp;") &&
            !body.includes("&lt;")
          ) {
            findings.push({
              type: `Partial XSS Reflection — ${context}`,
              severity: "Medium",
              owasp: "A03:2021 - Injection",
              parameter: form.inputs.map((i) => i.name).join(", "),
              endpoint: form.action,
              method: form.method.toUpperCase(),
              payload,
              detail: `Partial XSS payload reflected. Event handler "${marker}" found unencoded in response. Manual verification recommended.`,
              evidence: `Marker "${marker}" found in response`,
              remediation:
                "Encode all user input. Implement strict CSP. Review output encoding implementation.",
            });
          }
        }
      } catch (e) {}
    }
  }

  return findings;
}

// ── Advanced SQLi Testing ─────────────────────────────────────
async function testAdvancedSQLi(form, baseUrl) {
  const findings = [];

  // Error-based SQLi with DB detection
  for (const payload of ALL_SQLI_PAYLOADS.slice(0, 30)) {
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

      for (const sig of SQL_ERROR_SIGNATURES) {
        if (sig.pattern.test(body)) {
          findings.push({
            type: `SQL Injection — Error Based (${sig.db})`,
            severity: "Critical",
            owasp: "A03:2021 - Injection",
            parameter: form.inputs.map((i) => i.name).join(", "),
            endpoint: form.action,
            method: form.method.toUpperCase(),
            payload,
            database: sig.db,
            detail: `${sig.db} SQL injection confirmed via error message. Attacker can read, modify or delete entire database, bypass authentication, and potentially execute OS commands.`,
            evidence: `${sig.db} error pattern detected with payload: ${payload.substring(0, 60)}`,
            remediation:
              "Use parameterized queries immediately. Never concatenate user input into SQL. Use an ORM. Disable verbose SQL errors in production.",
          });
          return findings;
        }
      }
    } catch (e) {}
  }

  // Boolean-based blind SQLi
  try {
    const truePayload = "' AND '1'='1";
    const falsePayload = "' AND '1'='2";

    const formDataTrue = {};
    const formDataFalse = {};
    form.inputs.forEach((input) => {
      formDataTrue[input.name] = truePayload;
      formDataFalse[input.name] = falsePayload;
    });

    let trueResponse, falseResponse;
    if (form.method === "post") {
      trueResponse = await axiosInstance.post(form.action, formDataTrue);
      falseResponse = await axiosInstance.post(form.action, formDataFalse);
    } else {
      const trueUrl = new URL(form.action);
      const falseUrl = new URL(form.action);
      form.inputs.forEach((input) => {
        trueUrl.searchParams.set(input.name, truePayload);
        falseUrl.searchParams.set(input.name, falsePayload);
      });
      trueResponse = await axiosInstance.get(trueUrl.href);
      falseResponse = await axiosInstance.get(falseUrl.href);
    }

    const trueBody =
      typeof trueResponse.data === "string" ? trueResponse.data : "";
    const falseBody =
      typeof falseResponse.data === "string" ? falseResponse.data : "";

    // Significant difference in response indicates boolean-based SQLi
    if (Math.abs(trueBody.length - falseBody.length) > 50) {
      findings.push({
        type: "SQL Injection — Boolean Based Blind",
        severity: "Critical",
        owasp: "A03:2021 - Injection",
        parameter: form.inputs.map((i) => i.name).join(", "),
        endpoint: form.action,
        method: form.method.toUpperCase(),
        detail:
          "Boolean-based blind SQL injection detected. True condition returns different response than false condition. Attacker can extract entire database character by character.",
        evidence: `True condition (${trueBody.length} bytes) vs False condition (${falseBody.length} bytes) — ${Math.abs(trueBody.length - falseBody.length)} byte difference`,
        remediation:
          "Use parameterized queries. Even without visible errors, blind SQLi gives full database access.",
      });
    }
  } catch (e) {}

  return findings;
}

// ── SSTI Testing ──────────────────────────────────────────────
async function testSSTI(form, baseUrl) {
  const findings = [];

  for (const { payload, expected, engine } of SSTI_PAYLOADS.slice(0, 8)) {
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

      if (body.includes("49") && payload.includes("7*7")) {
        findings.push({
          type: `Server Side Template Injection — ${engine}`,
          severity: "Critical",
          owasp: "A03:2021 - Injection",
          parameter: form.inputs.map((i) => i.name).join(", "),
          endpoint: form.action,
          method: form.method.toUpperCase(),
          payload,
          engine,
          detail: `SSTI confirmed with ${engine}. Template expression ${payload} evaluated to 49. This can lead to Remote Code Execution — full server takeover possible.`,
          evidence: `Payload "${payload}" returned "49" — template engine is evaluating expressions`,
          remediation:
            "Never pass user input to template engines. Use sandboxed template rendering. Upgrade to latest template engine version. Implement input validation.",
        });
        break;
      }

      if (expected !== "49" && body.includes(expected)) {
        findings.push({
          type: `Server Side Template Injection — ${engine}`,
          severity: "Critical",
          owasp: "A03:2021 - Injection",
          parameter: form.inputs.map((i) => i.name).join(", "),
          endpoint: form.action,
          method: form.method.toUpperCase(),
          payload,
          engine,
          detail: `SSTI detected with ${engine}. Template injection may allow reading server configuration or Remote Code Execution.`,
          evidence: `Payload "${payload}" produced expected output for ${engine}`,
          remediation:
            "Never pass user input directly to template engines. Sanitize all template variables.",
        });
        break;
      }
    } catch (e) {}
  }

  return findings;
}

// ── Prototype Pollution Testing ───────────────────────────────
async function testPrototypePollution(targetUrl) {
  const findings = [];

  for (const payload of PROTOTYPE_POLLUTION_PAYLOADS.slice(0, 5)) {
    try {
      const testUrl = new URL(targetUrl);
      const [key, value] = payload.split("=");
      if (key && value) {
        testUrl.searchParams.set(key, value);
        const response = await axiosInstance.get(testUrl.href);
        const body =
          typeof response.data === "string"
            ? response.data
            : JSON.stringify(response.data);

        if (
          body.includes('"admin":true') ||
          body.includes('"admin": true') ||
          body.includes('"polluted"')
        ) {
          findings.push({
            type: "Prototype Pollution",
            severity: "High",
            owasp: "A03:2021 - Injection",
            endpoint: testUrl.href,
            payload,
            detail:
              "Prototype pollution vulnerability detected. Attacker can modify JavaScript object prototypes, potentially escalating privileges or causing denial of service.",
            evidence: `Payload "${payload}" reflected admin=true in response`,
            remediation:
              "Freeze Object.prototype. Use Object.create(null) for objects that store user data. Implement input validation for object keys. Use libraries that protect against prototype pollution.",
          });
          break;
        }
      }
    } catch (e) {}
  }

  return findings;
}

// ── Secret Scanner ────────────────────────────────────────────
async function scanForSecrets(targetUrl, baseUrl, html) {
  const findings = [];
  const secretsFound = [];

  // Fetch JS files
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

  const allContent = [html];

  for (const jsUrl of jsUrls.slice(0, 10)) {
    try {
      const res = await axiosInstance.get(jsUrl);
      if (typeof res.data === "string") allContent.push(res.data);
    } catch (e) {}
  }

  const combinedContent = allContent.join("\n");

  for (const { name, pattern, severity } of SECRET_PATTERNS) {
    const matches = [...combinedContent.matchAll(pattern)];
    if (matches.length === 0) continue;

    const match = matches[0][0];
    const masked =
      match.substring(0, 8) + "..." + match.substring(match.length - 4);

    // Skip obvious false positives — variable names, not real secrets
    const falsePositivePatterns = [
      /password[_-]?field/i,
      /password[_-]?input/i,
      /update[_-]?password/i,
      /reset[_-]?password/i,
      /confirm[_-]?password/i,
      /old[_-]?password/i,
      /new[_-]?password/i,
      /password[_-]?placeholder/i,
      /example|sample|dummy|test|fake|mock|placeholder/i,
    ];

    const context = combinedContent.substring(
      Math.max(0, combinedContent.indexOf(match) - 30),
      combinedContent.indexOf(match) + match.length + 30,
    );

    if (falsePositivePatterns.some((p) => p.test(context))) continue;

    // Try to validate the secret is actually live
    const validation = await validateSecret(name, match);

    // Upgrade severity if confirmed live, downgrade to Possible if can't validate
    let finalSeverity = severity;
    let confidence = CONFIDENCE.POSSIBLE;
    let validationNote = "";

    if (validation.valid === true) {
      finalSeverity = "Critical"; // Always critical if confirmed live
      confidence = CONFIDENCE.CONFIRMED;
      validationNote = ` LIVE KEY CONFIRMED: ${validation.message}`;
    } else if (validation.valid === false) {
      finalSeverity = "Low"; // Inactive/revoked key — low priority
      confidence = CONFIDENCE.CONFIRMED;
      validationNote = ` Key appears inactive: ${validation.message}`;
    } else {
      // Can't auto-validate — keep original severity but mark as Possible
      confidence = CONFIDENCE.POSSIBLE;
      validationNote = ` ${validation.message}`;
    }

    secretsFound.push({
      name,
      match: masked,
      severity: finalSeverity,
      confidence,
    });

    findings.push({
      type: `Secret Exposed: ${name}`,
      severity: finalSeverity,
      confidence,
      owasp: "A02:2021 - Cryptographic Failures",
      endpoint: targetUrl,
      detail: `${name} found in page source or JavaScript files.${validationNote}`,
      evidence: `Pattern matched: ${masked} (${matches.length} occurrence${matches.length > 1 ? "s" : ""})`,
      remediation:
        validation.valid === true
          ? `URGENT: Immediately rotate/revoke this ${name} — it is currently active and exploitable.`
          : `Rotate/revoke this ${name}. Never hardcode secrets in frontend code. Use environment variables. Remove from git history using git-filter-repo.`,
    });
  }

  return { findings, secretsFound };
}

// ── Technology Fingerprinting ────────────────────────────────
async function fingerprintTechnologies(targetUrl, html, headers) {
  const findings = [];
  const detected = [];

  const headerStr = JSON.stringify(headers).toLowerCase();
  const lowerHtml = html.toLowerCase();

  for (const tech of TECH_FINGERPRINTS) {
    const found = tech.patterns.some(
      (pattern) =>
        lowerHtml.includes(pattern.toLowerCase()) ||
        headerStr.includes(pattern.toLowerCase()),
    );

    if (found) {
      detected.push(tech.name);
    }
  }

  if (detected.length > 0) {
    findings.push({
      type: "Technology Stack Fingerprinted",
      severity: "Info",
      owasp: "A05:2021 - Security Misconfiguration",
      endpoint: targetUrl,
      detail: `Detected technologies: ${detected.join(", ")}. This information helps attackers find known vulnerabilities for these specific technologies.`,
      evidence: `${detected.length} technologies identified: ${detected.join(", ")}`,
      remediation:
        "Remove version information from headers and page source. Use generic error pages. Consider obfuscating technology stack details.",
      technologies: detected,
    });
  }

  return { findings, detected };
}

// ── HTTP Request Smuggling ────────────────────────────────────
async function testRequestSmuggling(targetUrl) {
  const findings = [];

  try {
    // CL.TE test
    const cltePayload =
      "POST / HTTP/1.1\r\nHost: " +
      new URL(targetUrl).hostname +
      "\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG";

    const response = await axiosInstance.post(targetUrl, cltePayload, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Transfer-Encoding": "chunked",
        "Content-Length": "6",
      },
      timeout: 10000,
    });

    if (response.status === 400 || response.status === 500) {
      const body =
        typeof response.data === "string" ? response.data.toLowerCase() : "";
      if (
        body.includes("bad request") ||
        body.includes("invalid") ||
        body.includes("malformed")
      ) {
        findings.push({
          type: "Possible HTTP Request Smuggling (CL.TE)",
          severity: "High",
          owasp: "A04:2021 - Insecure Design",
          endpoint: targetUrl,
          detail:
            "Server may be vulnerable to HTTP Request Smuggling (CL.TE). This can allow attackers to poison the request queue, bypass security controls, and hijack other users requests.",
          evidence: `Conflicting Content-Length and Transfer-Encoding headers produced unexpected ${response.status} response`,
          remediation:
            "Ensure consistent handling of Content-Length and Transfer-Encoding headers. Use HTTP/2 end-to-end. Configure front-end servers to reject ambiguous requests.",
        });
      }
    }
  } catch (e) {}

  return findings;
}

module.exports = {
  testAdvancedXSS,
  testAdvancedSQLi,
  testSSTI,
  testPrototypePollution,
  scanForSecrets,
  fingerprintTechnologies,
  testRequestSmuggling,
};
