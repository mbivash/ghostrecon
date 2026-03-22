const express = require("express");
const router = express.Router();
const axios = require("axios");
const { scansDb } = require("../database");

const axiosInstance = axios.create({
  timeout: 15000,
  validateStatus: () => true,
  headers: {
    "User-Agent": "GhostRecon API Security Scanner",
    Accept: "application/json",
    "Content-Type": "application/json",
  },
});

const SENSITIVE_PATTERNS = [
  { pattern: /"password"\s*:\s*"[^"]+"/i, name: "Password in response" },
  { pattern: /"passwd"\s*:\s*"[^"]+"/i, name: "Password in response" },
  { pattern: /"secret"\s*:\s*"[^"]+"/i, name: "Secret in response" },
  { pattern: /"api_key"\s*:\s*"[^"]+"/i, name: "API key in response" },
  { pattern: /"apikey"\s*:\s*"[^"]+"/i, name: "API key in response" },
  { pattern: /"token"\s*:\s*"[^"]{20,}"/i, name: "Token in response" },
  { pattern: /"private_key"\s*:\s*"[^"]+"/i, name: "Private key in response" },
  { pattern: /"credit_card"\s*:\s*"[^"]+"/i, name: "Credit card in response" },
  { pattern: /"ssn"\s*:\s*"[^"]+"/i, name: "SSN in response" },
  {
    pattern: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/,
    name: "JWT token exposed in response",
  },
];

const ERROR_PATTERNS = [
  "stack trace",
  "at Object.",
  "at Function.",
  "syntax error",
  "exception",
  "traceback",
  "fatal error",
  "internal server error",
  "sql syntax",
  "mysql_",
  "pg::",
  "undefined method",
  "null pointer",
  "array index out of bounds",
];

const SQL_PAYLOADS = [
  "'",
  "' OR '1'='1",
  "1 UNION SELECT null--",
  "' AND SLEEP(3)--",
];
const XSS_PAYLOADS = [
  "<script>alert(1)</script>",
  '"><img src=x onerror=alert(1)>',
];

async function discoverAPIEndpoints(baseUrl) {
  const discovered = [];
  const commonPaths = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/users",
    "/api/user",
    "/api/me",
    "/api/profile",
    "/api/products",
    "/api/items",
    "/api/orders",
    "/api/auth",
    "/api/login",
    "/api/logout",
    "/api/register",
    "/api/admin",
    "/api/config",
    "/api/settings",
    "/api/health",
    "/api/status",
    "/api/version",
    "/api/search",
    "/api/data",
    "/api/list",
    "/v1",
    "/v2",
    "/v1/users",
    "/v2/users",
    "/graphql",
    "/graphiql",
    "/swagger",
    "/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/api-docs",
    "/docs",
  ];

  for (const path of commonPaths) {
    try {
      const url = new URL(path, baseUrl).href;
      const response = await axiosInstance.get(url);
      if (response.status !== 404) {
        discovered.push({
          url,
          path,
          status: response.status,
          contentType: response.headers["content-type"] || "",
          isJSON: (response.headers["content-type"] || "").includes("json"),
        });
      }
    } catch (e) {}
  }

  return discovered;
}

async function testHTTPMethods(endpoint) {
  const findings = [];
  const methods = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "HEAD",
    "TRACE",
  ];
  const allowedMethods = [];
  const dangerousMethods = [];

  for (const method of methods) {
    try {
      const response = await axiosInstance.request({
        method,
        url: endpoint.url,
        data:
          method !== "GET" && method !== "HEAD"
            ? { test: "ghostrecon" }
            : undefined,
      });

      if (
        response.status !== 405 &&
        response.status !== 404 &&
        response.status !== 501
      ) {
        allowedMethods.push(method);
        if (["PUT", "DELETE", "PATCH", "TRACE"].includes(method)) {
          dangerousMethods.push(method);
        }
      }
    } catch (e) {}
  }

  if (dangerousMethods.length > 0) {
    findings.push({
      type: "Dangerous HTTP Methods Allowed",
      severity: "Medium",
      owasp: "A05:2021 - Security Misconfiguration",
      endpoint: endpoint.url,
      detail: `Potentially dangerous HTTP methods are enabled: ${dangerousMethods.join(", ")}. These methods can be used to modify or delete resources.`,
      evidence: `Methods returning non-405: ${dangerousMethods.join(", ")}`,
      remediation:
        "Disable unused HTTP methods. Only allow GET and POST unless specifically needed. Block TRACE always.",
    });
  }

  if (allowedMethods.includes("TRACE")) {
    findings.push({
      type: "HTTP TRACE Method Enabled",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      endpoint: endpoint.url,
      detail:
        "TRACE method is enabled. Can be used in Cross-Site Tracing (XST) attacks to steal cookies.",
      evidence: "HTTP TRACE returned non-405 response",
      remediation: "Disable TRACE method in web server configuration.",
    });
  }

  return { findings, allowedMethods };
}

async function testAPIAuth(endpoint) {
  const findings = [];

  try {
    const withoutAuth = await axiosInstance.get(endpoint.url);

    if (withoutAuth.status === 200) {
      const body =
        typeof withoutAuth.data === "object"
          ? JSON.stringify(withoutAuth.data)
          : withoutAuth.data;
      const hasUserData =
        body.includes("email") ||
        body.includes("username") ||
        body.includes("user_id") ||
        body.includes("account");

      if (hasUserData) {
        findings.push({
          type: "Unauthenticated API Endpoint",
          severity: "High",
          owasp: "A01:2021 - Broken Access Control",
          endpoint: endpoint.url,
          detail:
            "API endpoint returns user data without authentication. Anyone can access this data.",
          evidence: `GET ${endpoint.url} returned HTTP 200 with user data without auth`,
          remediation:
            "Require authentication for all API endpoints that return user data. Implement JWT or API key authentication.",
        });
      }
    }

    const withFakeToken = await axiosInstance.get(endpoint.url, {
      headers: { Authorization: "Bearer fake_token_12345" },
    });

    if (withFakeToken.status === 200 && withoutAuth.status === 401) {
      findings.push({
        type: "Weak API Token Validation",
        severity: "Critical",
        owasp: "A07:2021 - Identification and Authentication Failures",
        endpoint: endpoint.url,
        detail:
          "API accepts fake/invalid tokens. Token validation is not working correctly.",
        evidence: "Fake Bearer token accepted with HTTP 200",
        remediation:
          "Implement proper JWT validation. Verify token signature, expiry, and issuer on every request.",
      });
    }
  } catch (e) {}

  return findings;
}

async function testRateLimiting(endpoint) {
  const findings = [];

  try {
    let rateLimited = false;
    for (let i = 0; i < 15; i++) {
      const response = await axiosInstance.get(endpoint.url);
      if (response.status === 429) {
        rateLimited = true;
        break;
      }
    }

    if (!rateLimited) {
      findings.push({
        type: "No API Rate Limiting",
        severity: "Medium",
        owasp: "A04:2021 - Insecure Design",
        endpoint: endpoint.url,
        detail:
          "API endpoint has no rate limiting. Attackers can make unlimited requests for data harvesting, brute force, or DoS attacks.",
        evidence: "15 consecutive requests returned no 429 Too Many Requests",
        remediation:
          "Implement rate limiting: max 100 requests per minute per IP. Return 429 with Retry-After header. Use Redis for distributed rate limiting.",
      });
    }
  } catch (e) {}

  return findings;
}

async function testSensitiveDataExposure(endpoint) {
  const findings = [];

  try {
    const response = await axiosInstance.get(endpoint.url);
    const body =
      typeof response.data === "string"
        ? response.data
        : JSON.stringify(response.data);

    for (const pattern of SENSITIVE_PATTERNS) {
      if (pattern.pattern.test(body)) {
        findings.push({
          type: `Sensitive Data Exposed: ${pattern.name}`,
          severity: "High",
          owasp: "A02:2021 - Cryptographic Failures",
          endpoint: endpoint.url,
          detail: `API response contains sensitive data: ${pattern.name}. This data should never be exposed in API responses.`,
          evidence: `Pattern matched in response from ${endpoint.url}`,
          remediation:
            "Never expose passwords, tokens, or keys in API responses. Filter sensitive fields before returning data. Use field whitelisting in API responses.",
        });
      }
    }
  } catch (e) {}

  return findings;
}

async function testErrorDisclosure(endpoint) {
  const findings = [];
  const badPayloads = [
    {
      method: "POST",
      data: { id: "' OR '1'='1" },
      desc: "SQL injection payload",
    },
    {
      method: "POST",
      data: { id: null, user: undefined },
      desc: "null values",
    },
    {
      method: "GET",
      params: "?id=../../../../etc/passwd",
      desc: "path traversal",
    },
  ];

  for (const test of badPayloads) {
    try {
      let response;
      if (test.method === "POST") {
        response = await axiosInstance.post(endpoint.url, test.data);
      } else {
        response = await axiosInstance.get(endpoint.url + test.params);
      }

      const body = (
        typeof response.data === "string"
          ? response.data
          : JSON.stringify(response.data)
      ).toLowerCase();
      const errorFound = ERROR_PATTERNS.find((e) => body.includes(e));

      if (errorFound && response.status >= 500) {
        findings.push({
          type: "Verbose Error Disclosure",
          severity: "Medium",
          owasp: "A05:2021 - Security Misconfiguration",
          endpoint: endpoint.url,
          detail: `API returns detailed error messages including stack traces or internal information when receiving unexpected input. Attackers use this to understand your tech stack.`,
          evidence: `${test.desc} triggered error containing "${errorFound}"`,
          remediation:
            "Return generic error messages in production. Log detailed errors server-side only. Never expose stack traces to clients.",
        });
        break;
      }
    } catch (e) {}
  }

  return findings;
}

async function testMassAssignment(endpoint) {
  const findings = [];

  if (!endpoint.isJSON) return findings;

  try {
    const adminPayloads = [
      { is_admin: true, role: "admin", admin: true },
      { isAdmin: true, userRole: "administrator" },
      { privilege: "admin", verified: true, active: true },
    ];

    for (const payload of adminPayloads) {
      const response = await axiosInstance.post(endpoint.url, payload);
      const body = typeof response.data === "object" ? response.data : {};

      const massAssigned = Object.keys(payload).some(
        (key) => body[key] !== undefined && body[key] === payload[key],
      );

      if (massAssigned && response.status === 200) {
        findings.push({
          type: "Mass Assignment Vulnerability",
          severity: "High",
          owasp: "A03:2021 - Injection",
          endpoint: endpoint.url,
          method: "POST",
          detail:
            "API accepts and processes unexpected fields that could allow privilege escalation. Sending is_admin=true may grant admin privileges.",
          evidence: `POST ${endpoint.url} with admin fields reflected in response`,
          remediation:
            "Use an allowlist for accepted fields. Explicitly define which fields can be mass assigned. Never bind request data directly to models.",
        });
        break;
      }
    }
  } catch (e) {}

  return findings;
}

async function testAPIInjection(endpoint) {
  const findings = [];

  for (const payload of SQL_PAYLOADS.slice(0, 3)) {
    try {
      const testData = {
        id: payload,
        search: payload,
        q: payload,
        query: payload,
      };
      const response = await axiosInstance.post(endpoint.url, testData);
      const body = (
        typeof response.data === "string"
          ? response.data
          : JSON.stringify(response.data)
      ).toLowerCase();

      const sqlErrors = [
        "sql syntax",
        "mysql_",
        "pg::",
        "sqlite",
        "ora-",
        "syntax error in",
      ];
      const errFound = sqlErrors.find((e) => body.includes(e));

      if (errFound) {
        findings.push({
          type: "SQL Injection in API",
          severity: "Critical",
          owasp: "A03:2021 - Injection",
          endpoint: endpoint.url,
          method: "POST",
          payload,
          detail:
            "SQL injection vulnerability in API endpoint. Attacker can extract, modify or delete the entire database via the API.",
          evidence: `SQL error "${errFound}" triggered by JSON payload`,
          remediation:
            "Use parameterized queries. Validate and sanitize all API inputs. Use an ORM.",
        });
        break;
      }
    } catch (e) {}
  }

  for (const payload of XSS_PAYLOADS.slice(0, 2)) {
    try {
      const testData = { name: payload, value: payload, input: payload };
      const response = await axiosInstance.post(endpoint.url, testData);
      const body =
        typeof response.data === "string"
          ? response.data
          : JSON.stringify(response.data);

      if (body.includes(payload) && !body.includes("&lt;")) {
        findings.push({
          type: "XSS in API Response",
          severity: "High",
          owasp: "A03:2021 - Injection",
          endpoint: endpoint.url,
          method: "POST",
          payload,
          detail:
            "API reflects XSS payload unencoded. If this data is rendered in a browser, it leads to XSS attacks.",
          evidence: `XSS payload "${payload}" reflected in API response`,
          remediation:
            "Encode all data in API responses. Set Content-Type: application/json. Use CSP headers.",
        });
        break;
      }
    } catch (e) {}
  }

  return findings;
}

async function checkAPIHeaders(endpoint, headers) {
  const findings = [];

  if (!headers["content-type"] || !headers["content-type"].includes("json")) {
    if (endpoint.isJSON) {
      findings.push({
        type: "Missing Content-Type Header",
        severity: "Low",
        owasp: "A05:2021 - Security Misconfiguration",
        endpoint: endpoint.url,
        detail:
          "API does not set proper Content-Type header. May lead to MIME sniffing attacks.",
        evidence: `Content-Type: ${headers["content-type"] || "not set"}`,
        remediation: "Always set Content-Type: application/json for JSON APIs.",
      });
    }
  }

  if (!headers["x-content-type-options"]) {
    findings.push({
      type: "Missing X-Content-Type-Options",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      endpoint: endpoint.url,
      detail: "API missing X-Content-Type-Options header.",
      evidence: "Header not present",
      remediation: "Add X-Content-Type-Options: nosniff",
    });
  }

  const acao = headers["access-control-allow-origin"];
  if (acao === "*") {
    findings.push({
      type: "API CORS Wildcard",
      severity: "High",
      owasp: "A01:2021 - Broken Access Control",
      endpoint: endpoint.url,
      detail:
        "API allows cross-origin requests from any domain. Malicious websites can read API responses.",
      evidence: "Access-Control-Allow-Origin: *",
      remediation:
        "Restrict CORS to specific trusted origins. Never use wildcard for authenticated APIs.",
    });
  }

  return findings;
}

router.post("/scan", async (req, res) => {
  const { target, authToken, consent } = req.body;

  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target)
    return res.status(400).json({ error: "Target URL is required." });

  let baseUrl = target.trim();
  if (!baseUrl.startsWith("http")) baseUrl = "http://" + baseUrl;

  console.log("Starting API security scan on:", baseUrl);

  try {
    const results = {
      target: baseUrl,
      endpointsFound: 0,
      findings: [],
      endpoints: [],
      scannedAt: new Date().toISOString(),
    };

    const headers = authToken ? { Authorization: `Bearer ${authToken}` } : {};

    // Discover API endpoints
    console.log("Discovering API endpoints...");
    const endpoints = await discoverAPIEndpoints(baseUrl);
    results.endpointsFound = endpoints.length;
    results.endpoints = endpoints.map((e) => ({
      url: e.url,
      status: e.status,
      isJSON: e.isJSON,
    }));

    if (endpoints.length === 0) {
      results.findings.push({
        type: "No API Endpoints Found",
        severity: "Info",
        detail:
          "No common API endpoints were discovered. The target may use non-standard paths or require authentication to discover endpoints.",
        evidence: `Checked ${baseUrl}/api, /api/v1, /graphql and 25+ common paths`,
        remediation:
          "Provide the exact API base URL or specific endpoint paths for a more thorough scan.",
      });
    }

    // Test each discovered endpoint
    for (const endpoint of endpoints.slice(0, 8)) {
      console.log(`Testing: ${endpoint.url}`);

      try {
        const endpointResponse = await axiosInstance.get(endpoint.url, {
          headers,
        });
        const endpointHeaders = endpointResponse.headers;

        const [
          methodF,
          authF,
          rateF,
          sensitiveF,
          errorF,
          massF,
          injectionF,
          headerF,
        ] = await Promise.all([
          testHTTPMethods(endpoint),
          testAPIAuth(endpoint),
          testRateLimiting(endpoint),
          testSensitiveDataExposure(endpoint),
          testErrorDisclosure(endpoint),
          testMassAssignment(endpoint),
          testAPIInjection(endpoint),
          checkAPIHeaders(endpoint, endpointHeaders),
        ]);

        results.findings.push(
          ...methodF.findings,
          ...authF,
          ...rateF,
          ...sensitiveF,
          ...errorF,
          ...massF,
          ...injectionF,
          ...headerF,
        );
      } catch (e) {
        console.log(`Error testing ${endpoint.url}:`, e.message);
      }
    }

    // Check for GraphQL
    const graphqlEndpoints = endpoints.filter((e) => e.url.includes("graphql"));
    if (graphqlEndpoints.length > 0) {
      try {
        const introspectionQuery = { query: "{ __schema { types { name } } }" };
        const response = await axiosInstance.post(
          graphqlEndpoints[0].url,
          introspectionQuery,
        );
        if (response.status === 200 && response.data.__schema) {
          results.findings.push({
            type: "GraphQL Introspection Enabled",
            severity: "Medium",
            owasp: "A05:2021 - Security Misconfiguration",
            endpoint: graphqlEndpoints[0].url,
            detail:
              "GraphQL introspection is enabled in production. Attackers can map your entire API schema including all queries, mutations, and types.",
            evidence: "GraphQL introspection query returned full schema",
            remediation:
              "Disable introspection in production. Only enable during development.",
          });
        }
      } catch (e) {}
    }

    // Remove duplicates
    const seen = new Set();
    results.findings = results.findings.filter((f) => {
      const key = `${f.type}-${f.endpoint || ""}`;
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

    const severity =
      results.summary.critical > 0
        ? "critical"
        : results.summary.high > 0
          ? "high"
          : results.summary.medium > 0
            ? "medium"
            : results.summary.low > 0
              ? "low"
              : "info";

    scansDb
      .insert({
        type: "API Security Scan",
        userId: req.user?.id,
        target: baseUrl,
        result: results,
        findings_count: results.summary.total,
        severity,
        scanned_at: new Date().toISOString(),
      })
      .catch((e) => console.error(e));

    res.json({ success: true, data: results });
  } catch (err) {
    console.error("API scan error:", err);
    res.status(500).json({ error: err.message });
  }
});
// ── OpenAPI/Swagger Scanner ───────────────────────────────────
router.post("/swagger", async (req, res) => {
  const { target, specUrl, consent } = req.body;

  if (!consent)
    return res.status(403).json({ error: "Authorization required." });
  if (!target)
    return res.status(400).json({ error: "Target URL is required." });

  let baseUrl = target.trim();
  if (!baseUrl.startsWith("http")) baseUrl = "http://" + baseUrl;

  const findings = [];
  let spec = null;
  let specSource = null;

  // Try to find the spec
  const specUrls = specUrl
    ? [specUrl]
    : [
        `${baseUrl}/swagger.json`,
        `${baseUrl}/openapi.json`,
        `${baseUrl}/api-docs`,
        `${baseUrl}/swagger/v1/swagger.json`,
        `${baseUrl}/swagger/v2/swagger.json`,
        `${baseUrl}/v1/swagger.json`,
        `${baseUrl}/v2/swagger.json`,
        `${baseUrl}/api/swagger.json`,
        `${baseUrl}/api/openapi.json`,
        `${baseUrl}/docs/swagger.json`,
        `${baseUrl}/.well-known/openapi.json`,
      ];

  for (const url of specUrls) {
    try {
      const res2 = await axiosInstance.get(url);
      if (
        res2.status === 200 &&
        res2.data &&
        (res2.data.swagger || res2.data.openapi || res2.data.paths)
      ) {
        spec = res2.data;
        specSource = url;
        findings.push({
          type: "API Specification Exposed",
          severity: "Medium",
          owasp: "A05:2021 - Security Misconfiguration",
          endpoint: url,
          detail: `API specification found at ${url}. This gives attackers a complete map of all API endpoints, parameters, and authentication requirements.`,
          evidence: `${url} returned valid ${spec.swagger ? "Swagger" : "OpenAPI"} specification`,
          remediation:
            "Restrict access to API documentation. Require authentication to view specs. Consider removing public API docs in production.",
        });
        break;
      }
    } catch (e) {}
  }

  if (!spec) {
    return res.json({
      success: true,
      data: {
        target: baseUrl,
        specFound: false,
        findings: [
          {
            type: "No API Specification Found",
            severity: "Info",
            detail: `No OpenAPI/Swagger specification found at common paths for ${baseUrl}.`,
            evidence: `Checked ${specUrls.length} common spec paths`,
            remediation:
              "If you have an API spec, provide the URL directly for testing.",
          },
        ],
        endpoints: [],
        summary: { total: 0, critical: 0, high: 0, medium: 1, low: 0 },
      },
    });
  }

  // Extract all endpoints from spec
  const endpoints = [];
  const paths = spec.paths || {};
  const basePath = spec.basePath || "";
  const servers = spec.servers || [];
  const serverUrl = servers.length > 0 ? servers[0].url : baseUrl;

  Object.entries(paths).forEach(([path, methods]) => {
    Object.entries(methods).forEach(([method, operation]) => {
      if (
        ["get", "post", "put", "delete", "patch", "options"].includes(
          method.toLowerCase(),
        )
      ) {
        const fullUrl = `${baseUrl}${basePath}${path}`;
        endpoints.push({
          method: method.toUpperCase(),
          path,
          fullUrl,
          summary: operation.summary || "",
          parameters: operation.parameters || [],
          security: operation.security,
          tags: operation.tags || [],
          requiresAuth:
            operation.security !== undefined && operation.security !== null,
        });
      }
    });
  });

  console.log(`Found ${endpoints.length} endpoints in spec`);

  // Test each endpoint
  for (const endpoint of endpoints.slice(0, 20)) {
    try {
      // Test without auth
      const noAuthRes = await axiosInstance.request({
        method: endpoint.method,
        url: endpoint.fullUrl,
        timeout: 8000,
      });

      // Endpoint marked as requiring auth but returns 200 without auth
      if (endpoint.requiresAuth && noAuthRes.status === 200) {
        findings.push({
          type: "API Authentication Not Enforced",
          severity: "Critical",
          owasp: "A07:2021 - Identification and Authentication Failures",
          endpoint: endpoint.fullUrl,
          method: endpoint.method,
          detail: `Endpoint ${endpoint.method} ${endpoint.path} is documented as requiring authentication but returns HTTP 200 without any credentials. Authentication is not being enforced.`,
          evidence: `${endpoint.method} ${endpoint.fullUrl} returned 200 without auth token`,
          remediation:
            "Implement authentication middleware on all protected endpoints. Verify auth checks are applied server-side, not just client-side.",
        });
      }

      // Check for sensitive data in response
      if (noAuthRes.status === 200) {
        const body =
          typeof noAuthRes.data === "string"
            ? noAuthRes.data
            : JSON.stringify(noAuthRes.data);
        const sensitivePatterns = [
          { pattern: /password/i, name: "password field" },
          { pattern: /secret/i, name: "secret field" },
          { pattern: /api_key/i, name: "API key" },
          { pattern: /token/i, name: "token" },
          { pattern: /private_key/i, name: "private key" },
          { pattern: /ssn/i, name: "SSN" },
          { pattern: /credit_card/i, name: "credit card" },
        ];

        for (const { pattern, name } of sensitivePatterns) {
          if (pattern.test(body)) {
            findings.push({
              type: `Sensitive Data in API Response: ${name}`,
              severity: "High",
              owasp: "A02:2021 - Cryptographic Failures",
              endpoint: endpoint.fullUrl,
              method: endpoint.method,
              detail: `API endpoint returns response containing ${name}. Sensitive data should never be exposed in API responses.`,
              evidence: `${endpoint.method} ${endpoint.fullUrl} response contains ${name}`,
              remediation:
                "Use field filtering to exclude sensitive data from API responses. Implement response masking for sensitive fields.",
            });
            break;
          }
        }
      }

      // Test for injection in query parameters
      for (const param of endpoint.parameters
        .filter((p) => p.in === "query")
        .slice(0, 3)) {
        const sqliPayload = "' OR '1'='1";
        try {
          const testUrl = new URL(endpoint.fullUrl);
          testUrl.searchParams.set(param.name, sqliPayload);
          const sqliRes = await axiosInstance.request({
            method: endpoint.method,
            url: testUrl.href,
            timeout: 8000,
          });
          const body = (
            typeof sqliRes.data === "string"
              ? sqliRes.data
              : JSON.stringify(sqliRes.data)
          ).toLowerCase();
          const sqlErr = [
            "sql syntax",
            "mysql_",
            "pg::",
            "ora-",
            "sqlite",
          ].find((e) => body.includes(e));
          if (sqlErr) {
            findings.push({
              type: "SQL Injection in API Parameter",
              severity: "Critical",
              owasp: "A03:2021 - Injection",
              endpoint: endpoint.fullUrl,
              method: endpoint.method,
              parameter: param.name,
              detail: `SQL injection in query parameter "${param.name}" of ${endpoint.method} ${endpoint.path}. Full database access possible.`,
              evidence: `SQL error triggered in parameter "${param.name}"`,
              remediation: "Use parameterized queries for all API parameters.",
            });
          }
        } catch (e) {}
      }
    } catch (e) {}
  }

  // Check for security definitions
  const securityDefs =
    spec.securityDefinitions || spec.components?.securitySchemes || {};
  if (Object.keys(securityDefs).length === 0) {
    findings.push({
      type: "No Security Schemes Defined",
      severity: "High",
      owasp: "A07:2021 - Identification and Authentication Failures",
      detail:
        "The API specification defines no security schemes. This may indicate authentication is not implemented or not documented.",
      evidence: "No securityDefinitions or securitySchemes found in spec",
      remediation:
        "Define security schemes in your API spec. Implement JWT, API key, or OAuth2 authentication.",
    });
  }

  // Check for HTTP in server URLs
  if (servers.some((s) => s.url && s.url.startsWith("http:"))) {
    findings.push({
      type: "API Uses HTTP (Not HTTPS)",
      severity: "High",
      owasp: "A02:2021 - Cryptographic Failures",
      detail:
        "API specification defines HTTP server URLs. API traffic will be unencrypted, exposing all data and credentials.",
      evidence: `Server URL uses HTTP: ${servers.find((s) => s.url.startsWith("http:"))?.url}`,
      remediation:
        "Update all server URLs to use HTTPS. Redirect HTTP to HTTPS.",
    });
  }

  // Remove duplicates
  const seen = new Set();
  const uniqueFindings = findings.filter((f) => {
    const key = `${f.type}-${f.endpoint}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const summary = {
    endpointsTested: Math.min(endpoints.length, 20),
    totalEndpoints: endpoints.length,
    specSource,
    critical: uniqueFindings.filter((f) => f.severity === "Critical").length,
    high: uniqueFindings.filter((f) => f.severity === "High").length,
    medium: uniqueFindings.filter((f) => f.severity === "Medium").length,
    low: uniqueFindings.filter((f) => f.severity === "Low").length,
    total: uniqueFindings.length,
  };

  res.json({
    success: true,
    data: {
      target: baseUrl,
      specFound: true,
      specUrl: specSource,
      endpoints: endpoints.slice(0, 50),
      findings: uniqueFindings,
      summary,
    },
  });
});

module.exports = router;
